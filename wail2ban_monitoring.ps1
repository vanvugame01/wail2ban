function ConvertTo-Wail2banUtc {
    param([object]$Value)
    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, [globalization.cultureinfo]::InvariantCulture,
            [globalization.datetimestyles]::AssumeUniversal, [ref]$parsed)) { return $parsed.UtcDateTime }
    return $null
}

function Test-Wail2banSnapshot {
    param([object]$Snapshot)
    if ($null -eq $Snapshot) { return $false }
    foreach ($name in @('SchemaVersion','Hostname','ProcessId','InstanceId','StartedAtUtc','HeartbeatUtc',
            'Status','Counters','FirewallReadSucceeded','Bans','RecentIssues')) {
        if ($null -eq $Snapshot.PSObject.Properties[$name]) { return $false }
    }
    if ($Snapshot.SchemaVersion -ne 1 -or $Snapshot.Status -notin @('Running','Degraded','Stopped') -or
            $Snapshot.FirewallReadSucceeded -isnot [bool] -or
            $null -eq (ConvertTo-Wail2banUtc $Snapshot.StartedAtUtc) -or
            $null -eq (ConvertTo-Wail2banUtc $Snapshot.HeartbeatUtc)) { return $false }
    foreach ($name in @('Processed','Skipped','Banned','Released')) {
        if ($null -eq $Snapshot.Counters -or $null -eq $Snapshot.Counters.PSObject.Properties[$name]) { return $false }
        $number = 0L
        if (-not [long]::TryParse([string]$Snapshot.Counters.$name, [ref]$number) -or $number -lt 0) { return $false }
    }
    foreach ($ban in @($Snapshot.Bans)) {
        if ($null -eq $ban -or $null -eq $ban.PSObject.Properties['Ip'] -or
                $null -eq $ban.PSObject.Properties['ExpiresAtUtc'] -or
                ($null -ne $ban.ExpiresAtUtc -and $null -eq (ConvertTo-Wail2banUtc $ban.ExpiresAtUtc))) { return $false }
    }
    foreach ($issue in @($Snapshot.RecentIssues)) {
        if ($null -eq $issue -or $null -eq $issue.PSObject.Properties['Message'] -or
                $null -eq $issue.PSObject.Properties['Level'] -or
                $null -eq (ConvertTo-Wail2banUtc $issue.TimestampUtc)) { return $false }
    }
    return $true
}

function Read-Wail2banSnapshot {
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        $content = [io.file]::ReadAllText($Path, [text.encoding]::UTF8)
        $snapshot = ConvertFrom-Json -InputObject $content -ErrorAction Stop
        if (Test-Wail2banSnapshot $snapshot) { return $snapshot }
    } catch { }
    return $null
}

function Write-Wail2banAtomicText {
    param([Parameter(Mandatory=$true)][string]$Path, [AllowEmptyString()][string]$Content)
    $destination = [io.path]::GetFullPath($Path)
    $directory = [io.path]::GetDirectoryName($destination)
    $null = [io.directory]::CreateDirectory($directory)
    $temporary = [io.path]::Combine($directory, ([io.path]::GetFileName($destination) + '.' + [guid]::NewGuid().ToString('N') + '.tmp'))
    try {
        [io.file]::WriteAllText($temporary, $Content, (New-Object text.UTF8Encoding($true)))
        if ([io.file]::Exists($destination)) { [io.file]::Replace($temporary, $destination, [System.Management.Automation.Language.NullString]::Value) }
        else {
            try { [io.file]::Move($temporary, $destination) }
            catch {
                if ([io.file]::Exists($temporary) -and [io.file]::Exists($destination)) {
                    [io.file]::Replace($temporary, $destination, [System.Management.Automation.Language.NullString]::Value)
                } else { throw }
            }
        }
    } finally {
        if ([io.file]::Exists($temporary)) { [io.file]::Delete($temporary) }
    }
}

function Write-Wail2banSnapshot {
    param([Parameter(Mandatory=$true)][object]$Snapshot, [Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Wail2banSnapshot $Snapshot)) { throw 'Invalid monitor snapshot.' }
    Write-Wail2banAtomicText -Path $Path -Content (ConvertTo-Json -InputObject $Snapshot -Depth 8)
}

function Get-Wail2banMonitorStatus {
    param([object]$Snapshot, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Test-Wail2banSnapshot $Snapshot)) { return 'Chưa có dữ liệu' }
    if ($Snapshot.Status -eq 'Stopped') { return 'Đã dừng' }
    if (($NowUtc.ToUniversalTime() - (ConvertTo-Wail2banUtc $Snapshot.HeartbeatUtc)).TotalSeconds -gt 30) {
        return 'Heartbeat quá 30 giây'
    }
    if ($Snapshot.Status -eq 'Degraded' -or -not $Snapshot.FirewallReadSucceeded) { return 'Có lỗi' }
    return 'Đang chạy'
}

function Get-Wail2banMonitorText {
    param([object]$Snapshot, [datetime]$NowUtc = [datetime]::UtcNow)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Wail2ban - Giám sát quản trị')
    $lines.Add(('Trạng thái: {0}' -f (Get-Wail2banMonitorStatus -Snapshot $Snapshot -NowUtc $NowUtc)))
    if (-not (Test-Wail2banSnapshot $Snapshot)) {
        $lines.Add('Snapshot chưa tồn tại hoặc không hợp lệ. Chờ cập nhật tiếp theo.')
        return $lines.ToArray() -join [environment]::NewLine
    }
    $lines.Add(('Máy: {0} | PID: {1} | Phiên: {2}' -f $Snapshot.Hostname,$Snapshot.ProcessId,$Snapshot.InstanceId))
    $lines.Add(('Bắt đầu UTC: {0} | Heartbeat UTC: {1}' -f $Snapshot.StartedAtUtc,$Snapshot.HeartbeatUtc))
    $lines.Add('Heartbeat chỉ xác nhận vòng xử lý còn hoạt động.')
    $lines.Add(('Từ lúc khởi động: xử lý {0} | bỏ qua {1} | chặn {2} | gỡ {3}' -f
            $Snapshot.Counters.Processed,$Snapshot.Counters.Skipped,$Snapshot.Counters.Banned,$Snapshot.Counters.Released))
    if (-not $Snapshot.FirewallReadSucceeded) { $lines.Add('IP đang bị chặn: không xác định (không đọc được firewall).') }
    else {
        $lines.Add(('IP đang bị chặn: {0}' -f @($Snapshot.Bans).Count))
        foreach ($ban in @($Snapshot.Bans)) {
            $expiry = if ($null -eq $ban.ExpiresAtUtc) { 'không xác định' } else { $ban.ExpiresAtUtc }
            $lines.Add(('{0} | hết hạn UTC: {1}' -f $ban.Ip,$expiry))
        }
    }
    $lines.Add('Lỗi và cảnh báo gần nhất:')
    foreach ($issue in @($Snapshot.RecentIssues | Select-Object -Last 20)) {
        $safeMessage = ([string]$issue.Message) -replace '[\x00-\x1F\x7F]', ' '
        $lines.Add(('{0} [{1}] {2}' -f $issue.TimestampUtc,$issue.Level,$safeMessage))
    }
    if (@($Snapshot.RecentIssues).Count -eq 0) { $lines.Add('Không có.') }
    return $lines.ToArray() -join [environment]::NewLine
}

function ConvertTo-Wail2banHtmlText {
    param([object]$Value)
    return [net.webutility]::HtmlEncode([string]$Value)
}

function Write-Wail2banHtml {
    param([object]$Snapshot, [Parameter(Mandatory=$true)][string]$Path)
    $valid = Test-Wail2banSnapshot $Snapshot
    $status = ConvertTo-Wail2banHtmlText (Get-Wail2banMonitorStatus $Snapshot)
    $heartbeat = ''; $runStatus = ''; $details = '<p>Snapshot chưa tồn tại hoặc không hợp lệ. Chờ cập nhật tiếp theo.</p>'
    if ($valid) {
        $heartbeat = ConvertTo-Wail2banHtmlText $Snapshot.HeartbeatUtc
        $runStatus = ConvertTo-Wail2banHtmlText $Snapshot.Status
        $rows = New-Object 'System.Collections.Generic.List[string]'
        if ($Snapshot.FirewallReadSucceeded) {
            foreach ($ban in @($Snapshot.Bans)) {
                $expiry = if ($null -eq $ban.ExpiresAtUtc) { 'không xác định' } else { $ban.ExpiresAtUtc }
                $rows.Add(('<tr><td>{0}</td><td>{1}</td></tr>' -f
                        (ConvertTo-Wail2banHtmlText $ban.Ip),(ConvertTo-Wail2banHtmlText $expiry)))
            }
            $banCount = [string]@($Snapshot.Bans).Count
            if ($rows.Count -eq 0) { $rows.Add('<tr><td colspan="2">Không có IP bị chặn.</td></tr>') }
        } else {
            $banCount = 'không xác định'
            $rows.Add('<tr><td colspan="2">Không đọc được firewall; danh sách hiện tại không xác định.</td></tr>')
        }
        $issues = New-Object 'System.Collections.Generic.List[string]'
        foreach ($issue in @($Snapshot.RecentIssues | Select-Object -Last 20)) {
            $issues.Add(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f
                    (ConvertTo-Wail2banHtmlText $issue.TimestampUtc),(ConvertTo-Wail2banHtmlText $issue.Level),
                    (ConvertTo-Wail2banHtmlText $issue.Message)))
        }
        if ($issues.Count -eq 0) { $issues.Add('<tr><td colspan="3">Không có.</td></tr>') }
        $details = @"
<dl><dt>Máy</dt><dd>$(ConvertTo-Wail2banHtmlText $Snapshot.Hostname)</dd>
<dt>PID / phiên chạy</dt><dd>$(ConvertTo-Wail2banHtmlText $Snapshot.ProcessId) / $(ConvertTo-Wail2banHtmlText $Snapshot.InstanceId)</dd>
<dt>Bắt đầu UTC</dt><dd>$(ConvertTo-Wail2banHtmlText $Snapshot.StartedAtUtc)</dd>
<dt>Heartbeat UTC</dt><dd>$heartbeat</dd></dl>
<h2>Bộ đếm từ lúc khởi động</h2>
<p>Đã xử lý: $(ConvertTo-Wail2banHtmlText $Snapshot.Counters.Processed) · Bỏ qua: $(ConvertTo-Wail2banHtmlText $Snapshot.Counters.Skipped) · Chặn thành công: $(ConvertTo-Wail2banHtmlText $Snapshot.Counters.Banned) · Gỡ thành công: $(ConvertTo-Wail2banHtmlText $Snapshot.Counters.Released)</p>
<h2>IP đang bị chặn: $banCount</h2><table><thead><tr><th>IP</th><th>Hết hạn UTC</th></tr></thead><tbody>$($rows -join '')</tbody></table>
<h2>20 lỗi và cảnh báo gần nhất</h2><table><thead><tr><th>UTC</th><th>Mức</th><th>Nội dung</th></tr></thead><tbody>$($issues -join '')</tbody></table>
"@
    }
    $html = @"
<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="5">
<title>Wail2ban - Giám sát quản trị</title>
<style>body{font:16px system-ui,sans-serif;margin:2rem auto;padding:0 1rem;max-width:1100px;background:#f4f6fa;color:#172033}h1{font-size:1.7rem}h2{font-size:1.15rem;margin-top:2rem}#status{padding:1rem;background:#fff2ce;border-left:5px solid #aa7500}table{border-collapse:collapse;width:100%;background:white}th,td{text-align:left;padding:.7rem;border:1px solid #d6deea;overflow-wrap:anywhere}dt{font-weight:600}dd{margin:0 0 .65rem;overflow-wrap:anywhere}.note{color:#4d5b70}</style></head>
<body><h1>Wail2ban - Giám sát quản trị</h1>
<p id="status" data-heartbeat="$heartbeat" data-run-status="$runStatus">$status</p>
<p class="note">Tự tải lại mỗi 5 giây. Heartbeat chỉ xác nhận vòng xử lý còn hoạt động. Dữ liệu đọc từ snapshot cục bộ.</p>
$details
<script>(function(){var node=document.getElementById('status');function update(){var stamp=Date.parse(node.getAttribute('data-heartbeat'));if(node.getAttribute('data-run-status')!=='Stopped'&&Number.isFinite(stamp)&&Date.now()-stamp>30000){node.textContent='Heartbeat quá 30 giây';}}update();setInterval(update,1000);})();</script>
</body></html>
"@
    Write-Wail2banAtomicText -Path $Path -Content $html
}
