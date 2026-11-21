param(
    [switch]$Config,
    [switch]$Jail,
    [switch]$Jailbreak,
    [string]$Unban,
    [switch]$Help,
    [switch]$LibraryOnly
)

. (Join-Path $PSScriptRoot 'wail2ban_core.ps1')

# Cac adapter IO duoc tach de kiem thu bang mock.
function Get-Wail2banConfiguration {
    param([string]$Path)
    $events = @(); $whitelist = @(); $section = ''
    foreach ($rawLine in Get-Content -LiteralPath $Path -ErrorAction Stop) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        if ($line -match '^\[(?<Section>[^\]]+)\]$') { $section = $Matches.Section; continue }
        if ($line -notmatch '^(?<Key>[^=]+)=(?<Value>.*)$') { throw 'Dòng cấu hình không hợp lệ.' }
        $key = $Matches.Key.Trim(); $value = $Matches.Value.Trim()
        if ($section -eq 'Whitelist') {
            $null = Test-Wail2banWhitelist '0.0.0.0' @($key) @()
            $whitelist += $key
        } elseif ($section -in @('Security','Application','System')) {
            $eventId = 0
            if (-not [int]::TryParse($key, [ref]$eventId) -or $eventId -lt 1 -or $eventId -gt 65535) { throw 'Event ID không hợp lệ.' }
            $events += [pscustomobject]@{Channel = $section; EventId = $eventId; Description = $value}
        } else { throw 'Mục cấu hình không được hỗ trợ.' }
    }
    if ($events.Count -eq 0) { throw 'Cấu hình phải có ít nhất một event.' }
    return [pscustomobject]@{Events = @($events); Whitelist = @($whitelist)}
}

function Get-Wail2banSelfAddresses {
    $addresses = @('127.0.0.1')
    foreach ($adapter in [net.networkinformation.networkinterface]::GetAllNetworkInterfaces()) {
        foreach ($address in $adapter.GetIPProperties().UnicastAddresses) {
            $ip = ConvertTo-Wail2banIPv4 $address.Address.ToString()
            if ($ip) { $addresses += $ip }
        }
    }
    return @($addresses | Select-Object -Unique)
}

function New-Wail2banFirewallPolicy { return (New-Object -ComObject HNetCfg.FwPolicy2 -ErrorAction Stop) }
function New-Wail2banFirewallRuleObject { return (New-Object -ComObject HNetCfg.FWRule -ErrorAction Stop) }

function Get-Wail2banFirewallRules {
    $policy = $null
    try {
        $policy = New-Wail2banFirewallPolicy
        foreach ($rule in $policy.Rules) {
            if (-not $rule.Name.StartsWith('wail2ban block: ', [StringComparison]::OrdinalIgnoreCase)) { continue }
            $ip = ConvertTo-Wail2banIPv4 $rule.Name.Substring('wail2ban block: '.Length)
            $remote = [string]$rule.RemoteAddresses
            if ($remote -match '^([^/]+)/(32|255\.255\.255\.255)$') { $remote = $Matches[1] }
            if (-not $ip -or -not $rule.Enabled -or $rule.Action -ne 0 -or $rule.Direction -ne 1 -or (ConvertTo-Wail2banIPv4 $remote) -ne $ip -or
                $rule.Protocol -ne 256 -or $rule.Profiles -ne 2147483647 -or
                -not [string]::IsNullOrEmpty([string]$rule.ApplicationName) -or -not [string]::IsNullOrEmpty([string]$rule.ServiceName) -or
                [string]$rule.LocalAddresses -notin @('','*') -or [string]$rule.LocalPorts -notin @('','*') -or [string]$rule.RemotePorts -notin @('','*') -or
                [string]$rule.InterfaceTypes -notin @('','All') -or $null -ne $rule.Interfaces) {
                throw 'Rule thuộc wail2ban không hợp lệ.'
            }
            $expires = $null
            if ($rule.Description -match '^Expire: (.+)$') {
                $parsed = [datetimeoffset]::MinValue
                if ([datetimeoffset]::TryParse($Matches[1], [globalization.cultureinfo]::InvariantCulture, [globalization.datetimestyles]::AssumeLocal, [ref]$parsed)) { $expires = $parsed.UtcDateTime }
            }
            [pscustomobject]@{Ip = $ip; ExpiresAtUtc = $expires}
        }
    } finally { if ($null -ne $policy -and [runtime.interopservices.marshal]::IsComObject($policy)) { $null = [runtime.interopservices.marshal]::ReleaseComObject($policy) } }
}

function Add-Wail2banFirewallRule {
    param([string]$Ip, [datetime]$ExpiresAtUtc)
    $normalized = ConvertTo-Wail2banIPv4 $Ip
    if (-not $normalized) { throw 'IPv4 không hợp lệ.' }
    $policy = $null; $rule = $null
    try {
        $policy = New-Wail2banFirewallPolicy
        $rule = New-Wail2banFirewallRuleObject
        $rule.Name = 'wail2ban block: ' + $normalized
        $rule.Description = 'Expire: ' + $ExpiresAtUtc.ToUniversalTime().ToString('o')
        $rule.Direction = 1; $rule.Protocol = 256; $rule.Action = 0
        $rule.RemoteAddresses = $normalized; $rule.Enabled = $true; $rule.Profiles = 2147483647
        $policy.Rules.Add($rule)
        $confirmed = @(Get-Wail2banFirewallRules | Where-Object { $_.Ip -eq $normalized -and $null -ne $_.ExpiresAtUtc -and [math]::Abs(($_.ExpiresAtUtc - $ExpiresAtUtc).TotalSeconds) -lt 1 })
        if ($confirmed.Count -ne 1) { throw 'Không xác minh được rule vừa thêm.' }
    } finally {
        foreach ($item in @($rule,$policy)) { if ($null -ne $item -and [runtime.interopservices.marshal]::IsComObject($item)) { $null = [runtime.interopservices.marshal]::ReleaseComObject($item) } }
    }
}

function Remove-Wail2banFirewallRule {
    param([string]$Ip)
    $normalized = ConvertTo-Wail2banIPv4 $Ip
    if (-not $normalized) { throw 'IPv4 không hợp lệ.' }
    $policy = $null
    try {
        $policy = New-Wail2banFirewallPolicy
        $policy.Rules.Remove('wail2ban block: ' + $normalized)
        if (@(Get-Wail2banFirewallRules | Where-Object { $_.Ip -eq $normalized }).Count -gt 0) { throw 'Rule vẫn tồn tại sau khi gỡ.' }
    } finally { if ($null -ne $policy -and [runtime.interopservices.marshal]::IsComObject($policy)) { $null = [runtime.interopservices.marshal]::ReleaseComObject($policy) } }
}

function Get-Wail2banEventAttempt {
    param($Target, $State)
    $recordId = [long]$Target.RecordNumber
    $channel = [string]$Target.LogFile
    if ($recordId -lt 0 -or $channel -notin @('Security','Application','System')) { throw 'Định danh event không hợp lệ.' }
    try { $record = Get-WinEvent -LogName $channel -FilterXPath ("*[System[EventRecordID={0}]]" -f $recordId) -MaxEvents 1 -ErrorAction Stop }
    catch { throw [io.ioexception]::new('Không đọc được Event Log.') }
    if ($null -ne $State) { $State.Faults.Remove('event-read') }
    $attempt = ConvertFrom-Wail2banEventXml -Xml $record.ToXml() -Message $record.Message
    if ($attempt.RecordId -ne $recordId -or $attempt.Channel -ne $channel -or $attempt.EventId -ne [int]$Target.EventCode) { throw 'Event trả về không khớp listener.' }
    return $attempt
}

function Invoke-Wail2banQueuedEvent {
    param($State, $QueuedEvent, [datetime]$NowUtc)
    try {
        $attempt = Get-Wail2banEventAttempt -Target $QueuedEvent.SourceEventArgs.NewEvent.TargetInstance -State $State
        Invoke-Wail2banAttempt $State $attempt $NowUtc
    } catch [io.ioexception] {
        $State.Counters.Skipped++
        $State.Faults['event-read'] = $true
        Add-Wail2banIssue $State 'Không đọc được Event Log; cần kiểm tra quyền và dịch vụ.' Error $NowUtc
    } catch {
        $State.Counters.Skipped++
        Add-Wail2banIssue $State 'Bỏ sự kiện không đọc được hoặc không xác định được IPv4 nguồn.' Warning $NowUtc
    } finally { Remove-Event -EventIdentifier $QueuedEvent.EventIdentifier -ErrorAction SilentlyContinue }
}

function Publish-Wail2banStatus {
    param($State, [datetime]$NowUtc, [string]$Root)
    $snapshot = New-Wail2banSnapshot $State $NowUtc
    try {
        Write-Wail2banSnapshot -Snapshot $snapshot -Path (Join-Path $Root 'runtime\wail2ban_status.json')
        Write-Wail2banHtml -Snapshot $snapshot -Path (Join-Path $Root 'public_html\index.html')
        $State.Faults.Remove('monitor-write')
    } catch { $State.Faults['monitor-write'] = $true; Add-Wail2banIssue $State 'Không ghi được monitor JSON hoặc HTML.' Error $NowUtc }
}

function Get-Wail2banMonotonicSeconds { return ([diagnostics.stopwatch]::GetTimestamp() / [double][diagnostics.stopwatch]::Frequency) }
function Get-Wail2banUtcNow { return [datetime]::UtcNow }

function Start-Wail2banLoop {
    param($State, $Settings, [string]$Root)
    $sinkName = 'Wail2ban-' + $State.InstanceId
    $clauses = @($Settings.Events | ForEach-Object { "(TargetInstance.EventCode=$($_.EventId) AND TargetInstance.LogFile='$($_.Channel)')" })
    $query = "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent' AND (" + ($clauses -join ' OR ') + ')'
    $registered = $false
    $nextMaintenance = 0.0
    try {
        $null = Register-WmiEvent -Query $query -SourceIdentifier $sinkName -ErrorAction Stop
        $registered = $true
        Write-Wail2banLog $State 'Action' 'Đã khởi động listener.'
        while ($true) {
            if ((Get-Wail2banMonotonicSeconds) -ge $nextMaintenance) {
                $nextMaintenance = (Get-Wail2banMonotonicSeconds) + 5
                $now = Get-Wail2banUtcNow
                Invoke-Wail2banMaintenance $State $now
                Publish-Wail2banStatus $State (Get-Wail2banUtcNow) $Root
            }
            $timeout = [int][math]::Min(5, [math]::Max(1, [math]::Ceiling($nextMaintenance - (Get-Wail2banMonotonicSeconds))))
            $queuedEvent = Wait-Event -SourceIdentifier $sinkName -Timeout $timeout -ErrorAction Stop
            if ($null -ne $queuedEvent) { Invoke-Wail2banQueuedEvent $State $queuedEvent (Get-Wail2banUtcNow) }
        }
    } catch {
        $State.Faults['listener'] = $true
        Add-Wail2banIssue $State 'Listener dừng do lỗi; cần quản trị viên kiểm tra quyền và dịch vụ Event Log.' Error
        throw 'Wail2ban đã dừng do lỗi listener. Xem log và monitor.'
    } finally {
        if ($registered) { Unregister-Event -SourceIdentifier $sinkName -ErrorAction SilentlyContinue }
        Get-Event -ErrorAction SilentlyContinue | Where-Object { $_.SourceIdentifier -eq $sinkName } | Remove-Event -ErrorAction SilentlyContinue
        $State.Status = 'Stopped'
        Publish-Wail2banStatus $State (Get-Wail2banUtcNow) $Root
    }
}

if ($LibraryOnly) { return }
if ($Help) {
    Write-Output 'Wail2ban: -Config, -Jail, -Jailbreak, -Unban <IPv4>, -Help. Monitor: .\wail2ban_monitor.ps1'
    return
}
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) { throw 'Cần Windows PowerShell 5.1 để chạy wail2ban.' }
$settings = Get-Wail2banConfiguration (Join-Path $PSScriptRoot 'wail2ban_config.ini')
if ($Config) {
    [pscustomobject]@{CheckWindowSeconds = 120; CheckCount = 5; MaxBanSeconds = 7776000; Events = $settings.Events; Whitelist = $settings.Whitelist}
    return
}
$state = New-Wail2banState -Whitelist $settings.Whitelist -SelfList (Get-Wail2banSelfAddresses) -LogPath (Join-Path $PSScriptRoot 'wail2ban_log.log') -HistoryPath (Join-Path $PSScriptRoot 'bannedIPLog.ini')
Read-Wail2banBanHistory $state
if ($Jail) { Get-Wail2banFirewallRules; return }
if ($Jailbreak -or $Unban) {
    if ($Unban -and -not (ConvertTo-Wail2banIPv4 $Unban)) { throw 'IPv4 không hợp lệ.' }
    $ipToRelease = if ($Unban) { ConvertTo-Wail2banIPv4 $Unban } else { $null }
    foreach ($rule in @(Get-Wail2banFirewallRules)) {
        if (-not $ipToRelease -or $rule.Ip -eq $ipToRelease) { Remove-Wail2banFirewallRule $rule.Ip; Write-Wail2banLog $state 'Action' ('Đã gỡ chặn IP {0} theo yêu cầu quản trị viên.' -f $rule.Ip) }
    }
    if ($ipToRelease) { $state.BanCounts.Remove($ipToRelease) } else { $state.BanCounts.Clear() }
    Save-Wail2banBanHistory $state
    return
}
. (Join-Path $PSScriptRoot 'wail2ban_monitoring.ps1')
Start-Wail2banLoop $state $settings $PSScriptRoot
