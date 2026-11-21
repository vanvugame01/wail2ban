# Cac ham loi khong tu khoi dong listener hoac sua firewall.
function ConvertTo-Wail2banIPv4 {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $null }
    $value = $Address.Trim()
    $parsed = $null
    if (-not [net.ipaddress]::TryParse($value, [ref]$parsed)) { return $null }
    if ($parsed.IsIPv4MappedToIPv6) { return $parsed.MapToIPv4().ToString() }
    if ($parsed.AddressFamily -ne [net.sockets.AddressFamily]::InterNetwork -or $value -notmatch '^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$') { return $null }
    return $parsed.ToString()
}

function Test-Wail2banWhitelist {
    param([string]$Ip, [string[]]$Whitelist, [string[]]$SelfList)
    $normalized = ConvertTo-Wail2banIPv4 $Ip
    if (-not $normalized) { return $false }
    foreach ($self in $SelfList) { if ((ConvertTo-Wail2banIPv4 $self) -eq $normalized) { return $true } }
    foreach ($entry in $Whitelist) {
        $parts = $entry.Trim().Split('/')
        $network = ConvertTo-Wail2banIPv4 $parts[0]
        if (-not $network) { throw 'Địa chỉ whitelist không hợp lệ.' }
        if ($parts.Count -eq 1) { if ($network -eq $normalized) { return $true }; continue }
        $prefix = 0
        if ($parts.Count -ne 2 -or -not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32) { throw 'CIDR whitelist không hợp lệ.' }
        $sourceBytes = ([net.ipaddress]$normalized).GetAddressBytes()
        $networkBytes = ([net.ipaddress]$network).GetAddressBytes()
        $matchesNetwork = $true
        for ($index = 0; $index -lt 4; $index++) {
            $bits = [math]::Min(8, [math]::Max(0, $prefix - (8 * $index)))
            $mask = if ($bits -eq 0) { 0 } else { (255 -shl (8 - $bits)) -band 255 }
            if (($sourceBytes[$index] -band $mask) -ne ($networkBytes[$index] -band $mask)) { $matchesNetwork = $false; break }
        }
        if ($matchesNetwork) { return $true }
    }
    return $false
}

function New-Wail2banState {
    param([datetime]$NowUtc = [datetime]::UtcNow, [string[]]$Whitelist = @(), [string[]]$SelfList = @(), [string]$LogPath, [string]$HistoryPath,
        [string]$ConfigPath, [datetime]$ConfigLoadedAtUtc = $NowUtc)
    return [pscustomobject]@{
        StartedAtUtc = $NowUtc.ToUniversalTime(); InstanceId = [guid]::NewGuid().ToString()
        Attempts = @{}; Seen = @{}; BanCounts = @{}; Whitelist = $Whitelist; SelfList = $SelfList
        ConfigPath = $ConfigPath; ConfigLoadedAtUtc = $ConfigLoadedAtUtc.ToUniversalTime()
        Counters = [pscustomobject]@{Processed = 0; Skipped = 0; Banned = 0; Released = 0}
        RecentIssues = @(); Faults = @{}; LogPath = $LogPath; HistoryPath = $HistoryPath
        Bans = @(); FirewallReadSucceeded = $false; Status = 'Running'
        ControlProtocolVersion = 0; ControlRoot = ''; StopRequested = $false; StopRequest = $null
    }
}

function Add-Wail2banIssue {
    param($State, [string]$Message, [ValidateSet('Warning','Error')][string]$Level = 'Warning', [datetime]$NowUtc = [datetime]::UtcNow)
    $State.RecentIssues = @($State.RecentIssues | Select-Object -Last 19) + @([pscustomobject]@{TimestampUtc = $NowUtc.ToUniversalTime().ToString('o'); Level = $Level; Message = $Message})
    Write-Wail2banLog $State $Level $Message $NowUtc
}

function Write-Wail2banLog {
    param($State, [string]$Level, [string]$Message, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $State.LogPath) { return }
    try {
        Add-Content -LiteralPath $State.LogPath -Value ('{0} [{1}] {2}' -f $NowUtc.ToUniversalTime().ToString('o'), $Level, $Message) -Encoding UTF8 -ErrorAction Stop
        $State.Faults.Remove('log')
    } catch { $State.Faults['log'] = $true }
}

function Remove-Wail2banOldAttempts {
    param($State, [datetime]$NowUtc)
    $cutoff = $NowUtc.ToUniversalTime().AddSeconds(-120)
    foreach ($key in @($State.Attempts.Keys)) { if ($State.Attempts[$key].TimeUtc -lt $cutoff) { $State.Attempts.Remove($key) } }
    foreach ($key in @($State.Seen.Keys)) { if ($State.Seen[$key] -lt $cutoff) { $State.Seen.Remove($key) } }
}

function ConvertFrom-Wail2banEventXml {
    param([string]$Xml, [string]$Message)
    $document = New-Object System.Xml.XmlDocument
    $document.XmlResolver = $null
    if ($Xml -match '<!DOCTYPE') { throw 'Event XML không hợp lệ.' }
    $document.LoadXml($Xml)
    $root = $document.DocumentElement
    if ($root.LocalName -ne 'Event') { throw 'Event XML không hợp lệ.' }
    $system = $root.SelectSingleNode("*[local-name()='System']")
    if (-not $system) { throw 'Event XML thiếu System.' }
    $providerNode = $system.SelectSingleNode("*[local-name()='Provider']")
    $idNode = $system.SelectSingleNode("*[local-name()='EventID']")
    $channelNode = $system.SelectSingleNode("*[local-name()='Channel']")
    $recordNode = $system.SelectSingleNode("*[local-name()='EventRecordID']")
    $timeNode = $system.SelectSingleNode("*[local-name()='TimeCreated']")
    if (-not $providerNode -or -not $idNode -or -not $channelNode -or -not $recordNode -or -not $timeNode) { throw 'Event XML thiếu trường bắt buộc.' }
    $provider = $providerNode.GetAttribute('Name')
    $eventId = [int]$idNode.InnerText
    $recordId = [long]$recordNode.InnerText
    if ($recordId -lt 0) { throw 'Record ID không hợp lệ.' }
    $time = [datetimeoffset]::Parse($timeNode.GetAttribute('SystemTime'), [globalization.cultureinfo]::InvariantCulture).UtcDateTime
    $fields = @{}
    foreach ($node in $root.SelectNodes("*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = $node.GetAttribute('Name')
        if ($name) { if ($fields.ContainsKey($name)) { throw 'Event XML trùng trường.' }; $fields[$name] = $node.InnerText }
    }
    $ip = $null
    if ($eventId -eq 4625 -and $channelNode.InnerText -eq 'Security' -and $provider -eq 'Microsoft-Windows-Security-Auditing') {
        $ip = ConvertTo-Wail2banIPv4 $fields['IpAddress']
    } elseif ($eventId -eq 18456 -and $channelNode.InnerText -eq 'Application' -and $provider -match '^MSSQL(SERVER|\$[A-Za-z0-9_]+)$') {
        foreach ($name in @('IpAddress','ClientIP','ClientIPAddress','ClientAddress')) {
            if ($fields.ContainsKey($name)) {
                $candidate = ConvertTo-Wail2banIPv4 $fields[$name]
                if (-not $candidate -or ($ip -and $candidate -ne $ip)) { throw 'Địa chỉ SQL không hợp lệ hoặc không duy nhất.' }
                $ip = $candidate
            }
        }
        if (-not $ip -and $Message -match '\[CLIENT:\s*(?<Address>[^\]\r\n]+)\]\s*$') { $ip = ConvertTo-Wail2banIPv4 $Matches.Address }
    }
    if (-not $ip) { throw 'Không xác định được IPv4 nguồn từ provider và event được hỗ trợ.' }
    return [pscustomobject]@{Ip = $ip; TimeUtc = $time; Channel = $channelNode.InnerText; RecordId = $recordId; EventId = $eventId}
}

function Read-Wail2banBanHistory {
    param($State)
    if (-not $State.HistoryPath -or -not (Test-Path -LiteralPath $State.HistoryPath)) { return }
    foreach ($line in Get-Content -LiteralPath $State.HistoryPath -ErrorAction Stop) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^(?<Ip>\S+)\s+(?<Count>\d+)\s*$') { throw 'Lịch sử ban không hợp lệ.' }
        $ip = ConvertTo-Wail2banIPv4 $Matches.Ip
        $count = 0
        if (-not $ip -or -not [int]::TryParse($Matches.Count, [ref]$count)) { throw 'Lịch sử ban không hợp lệ.' }
        $State.BanCounts[$ip] = $count
    }
}

function Save-Wail2banBanHistory {
    param($State)
    if (-not $State.HistoryPath) { return }
    $temporary = $State.HistoryPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $lines = @($State.BanCounts.Keys | Sort-Object | ForEach-Object { '{0} {1}' -f $_, $State.BanCounts[$_] })
        [io.file]::WriteAllLines($temporary, [string[]]$lines, (New-Object text.utf8encoding($true)))
        if ([io.file]::Exists($State.HistoryPath)) { [io.file]::Replace($temporary, $State.HistoryPath, [System.Management.Automation.Language.NullString]::Value) }
        else { [io.file]::Move($temporary, $State.HistoryPath) }
    } finally { if ([io.file]::Exists($temporary)) { [io.file]::Delete($temporary) } }
}

function Invoke-Wail2banAttempt {
    param($State, $Attempt, [datetime]$NowUtc)
    Remove-Wail2banOldAttempts $State $NowUtc
    if ($Attempt.TimeUtc -lt $NowUtc.AddSeconds(-120) -or $Attempt.TimeUtc -gt $NowUtc) {
        $State.Counters.Skipped++; Add-Wail2banIssue $State 'Bỏ sự kiện ngoài cửa sổ thời gian.' Warning $NowUtc; return
    }
    $key = '{0}:{1}' -f $Attempt.Channel, $Attempt.RecordId
    if ($State.Seen.ContainsKey($key)) { $State.Counters.Skipped++; return }
    $State.Seen[$key] = $Attempt.TimeUtc
    if (Test-Wail2banWhitelist $Attempt.Ip $State.Whitelist $State.SelfList) { $State.Counters.Skipped++; return }
    $State.Counters.Processed++
    $State.Attempts[$key] = $Attempt
    $ip = $Attempt.Ip
    $count = @($State.Attempts.Values | Where-Object { $_.Ip -eq $ip }).Count
    if ($count -lt 5) { return }
    try {
        $existing = @(Get-Wail2banFirewallRules | Where-Object { $_.Ip -eq $ip })
        if ($existing.Count -eq 0) {
            $previous = if ($State.BanCounts.ContainsKey($ip)) { [int]$State.BanCounts[$ip] } else { 0 }
            $next = [math]::Min([int]::MaxValue, ([long]$previous + 1))
            $duration = [math]::Min(([math]::Pow(5, $next) * 60), 7776000)
            Add-Wail2banFirewallRule $ip ($NowUtc.AddSeconds($duration))
            $State.BanCounts[$ip] = [int]$next
            $State.Counters.Banned++
            Write-Wail2banLog $State 'Action' ('Đã chặn IP {0}.' -f $ip) $NowUtc
            try { Save-Wail2banBanHistory $State; $State.Faults.Remove('history') }
            catch { $State.Faults['history'] = $true; Add-Wail2banIssue $State 'Không ghi được lịch sử ban.' Error $NowUtc }
        }
        $State.Faults.Remove('ban:' + $ip)
        foreach ($attemptKey in @($State.Attempts.Keys)) { if ($State.Attempts[$attemptKey].Ip -eq $ip) { $State.Attempts.Remove($attemptKey) } }
    } catch { $State.Faults['ban:' + $ip] = $true; Add-Wail2banIssue $State ('Không chặn được IP {0}; sẽ thử lại khi có sự kiện.' -f $ip) Error $NowUtc }
}

function Invoke-Wail2banMaintenance {
    param($State, [datetime]$NowUtc)
    Remove-Wail2banOldAttempts $State $NowUtc
    try {
        $rules = @(Get-Wail2banFirewallRules)
        $State.FirewallReadSucceeded = $true; $State.Faults.Remove('firewall-read')
    } catch {
        $State.FirewallReadSucceeded = $false; $State.Bans = @(); $State.Faults['firewall-read'] = $true
        Add-Wail2banIssue $State 'Không đọc được danh sách firewall.' Error $NowUtc; return
    }
    $remaining = @()
    $presentIps = @($rules | ForEach-Object { $_.Ip })
    foreach ($faultKey in @($State.Faults.Keys)) {
        if ($faultKey -match '^(release|expiry):(.+)$' -and $presentIps -notcontains $Matches[2]) { $State.Faults.Remove($faultKey) }
        elseif ($faultKey -match '^ban:(.+)$' -and $presentIps -contains $Matches[1]) { $State.Faults.Remove($faultKey) }
    }
    foreach ($rule in $rules) {
        if ($null -eq $rule.ExpiresAtUtc) {
            $State.Faults['expiry:' + $rule.Ip] = $true
            Add-Wail2banIssue $State ('Rule của IP {0} thiếu thời hạn hợp lệ.' -f $rule.Ip) Warning $NowUtc
            $remaining += $rule; continue
        }
        $State.Faults.Remove('expiry:' + $rule.Ip)
        if ($rule.ExpiresAtUtc -le $NowUtc) {
            try {
                Remove-Wail2banFirewallRule $rule.Ip
                $State.Faults.Remove('release:' + $rule.Ip); $State.Counters.Released++
                Write-Wail2banLog $State 'Action' ('Đã gỡ chặn IP {0}.' -f $rule.Ip) $NowUtc
            } catch {
                $State.Faults['release:' + $rule.Ip] = $true; $remaining += $rule
                Add-Wail2banIssue $State ('Không gỡ chặn được IP {0}; sẽ thử lại.' -f $rule.Ip) Error $NowUtc
            }
        } else { $remaining += $rule }
    }
    $State.Bans = @($remaining)
    if ($State.Faults.ContainsKey('history')) {
        try { Save-Wail2banBanHistory $State; $State.Faults.Remove('history') } catch { }
    }
}

function New-Wail2banSnapshot {
    param($State, [datetime]$NowUtc)
    $status = if ($State.Status -eq 'Stopped') { 'Stopped' } elseif ($State.Faults.Count -gt 0) { 'Degraded' } else { 'Running' }
    return [pscustomobject]@{
        SchemaVersion = 1; Hostname = [environment]::MachineName; ProcessId = $PID; InstanceId = $State.InstanceId
        StartedAtUtc = $State.StartedAtUtc.ToString('o'); HeartbeatUtc = $NowUtc.ToUniversalTime().ToString('o'); Status = $status
        Counters = $State.Counters; FirewallReadSucceeded = $State.FirewallReadSucceeded
        Whitelist = @($State.Whitelist); SelfList = @($State.SelfList)
        ConfigPath = $State.ConfigPath; ConfigLoadedAtUtc = $State.ConfigLoadedAtUtc.ToString('o')
        ControlProtocolVersion = $State.ControlProtocolVersion; ControlRoot = $State.ControlRoot
        Bans = @($State.Bans | ForEach-Object { [pscustomobject]@{Ip = $_.Ip; ExpiresAtUtc = if ($null -ne $_.ExpiresAtUtc) { $_.ExpiresAtUtc.ToUniversalTime().ToString('o') } else { $null }} })
        RecentIssues = @($State.RecentIssues)
    }
}
