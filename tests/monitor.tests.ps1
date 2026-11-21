$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'wail2ban_monitoring.ps1')
$script:assertions = 0
function Assert-Monitor {
    param([bool]$Condition, [string]$Name)
    if (-not $Condition) { throw "FAIL: $Name" }
    $script:assertions++
}

$temporaryRoot = Join-Path ([io.path]::GetTempPath()) ('wail2ban-monitor-tests-' + [guid]::NewGuid().ToString('N'))
$null = [io.directory]::CreateDirectory($temporaryRoot)
try {
    $now = [datetime]::UtcNow
    $snapshot = [pscustomobject]@{
        SchemaVersion = 1; Hostname = 'test-server'; ProcessId = 123; InstanceId = 'test-instance'
        StartedAtUtc = $now.AddMinutes(-1).ToString('o'); HeartbeatUtc = $now.ToString('o'); Status = 'Running'
        Counters = [pscustomobject]@{ Processed=0; Skipped=0; Banned=0; Released=0 }
        FirewallReadSucceeded = $true; Bans = @(); RecentIssues = @()
    }
    $jsonPath = Join-Path $temporaryRoot 'runtime\status.json'
    $htmlPath = Join-Path $temporaryRoot 'public_html\index.html'
    Assert-Monitor ($null -eq (Read-Wail2banSnapshot $jsonPath)) 'Missing snapshot'
    Assert-Monitor ((Get-Wail2banMonitorStatus $null) -eq 'Chưa có dữ liệu') 'Missing data status'
    Write-Wail2banSnapshot -Snapshot $snapshot -Path $jsonPath
    $loaded = Read-Wail2banSnapshot $jsonPath
    Assert-Monitor ($null -ne $loaded -and $loaded.SchemaVersion -eq 1) 'Round-trip snapshot'
    Assert-Monitor ((Get-Wail2banMonitorStatus $loaded -NowUtc $now) -eq 'Đang chạy') 'Running status'
    Assert-Monitor ((Get-Wail2banMonitorStatus $loaded -NowUtc $now.AddSeconds(30)) -eq 'Đang chạy') 'Heartbeat boundary'
    Assert-Monitor ((Get-Wail2banMonitorStatus $loaded -NowUtc $now.AddSeconds(31)) -eq 'Heartbeat quá 30 giây') 'Stale heartbeat'
    Write-Wail2banHtml -Snapshot $loaded -Path $htmlPath
    $html = [io.file]::ReadAllText($htmlPath)
    Assert-Monitor ($html.Contains('Không có IP bị chặn.')) 'Empty bans displayed'
    Assert-Monitor ($html.Contains('Đã xử lý: 0')) 'Zero counters displayed'
    Assert-Monitor ($html.Contains('http-equiv="refresh" content="5"')) 'Refresh interval'
    Assert-Monitor ($html.Contains('setInterval(update,1000)') -and $html.Contains('Date.now()-stamp>30000')) 'Independent stale detection'
    Assert-Monitor ($html -notmatch '(?i)(?:src|href)\s*=\s*["'']https?://' -and $html -notmatch '(?i)fetch\s*\(') 'No external resources'
    $legacyText = Get-Wail2banMonitorText $loaded -NowUtc $now
    Assert-Monitor ($legacyText.Contains('Snapshot cũ chưa có dữ liệu whitelist') -and -not $legacyText.Contains('Whitelist đã nạp: 0')) 'Legacy snapshot does not claim empty whitelist'
    Assert-Monitor ($html.Contains('Snapshot cũ chưa có dữ liệu whitelist')) 'Legacy whitelist explained in HTML'
    $configPath = Join-Path $temporaryRoot 'config.ini'
    [io.file]::WriteAllText($configPath, "[Whitelist]`n198.51.100.99 = edited on disk")
    $snapshot | Add-Member -MemberType NoteProperty -Name Whitelist -Value @('203.0.113.9','198.51.100.0/24')
    $snapshot | Add-Member -MemberType NoteProperty -Name SelfList -Value @('127.0.0.1','192.0.2.20')
    $snapshot | Add-Member -MemberType NoteProperty -Name ConfigPath -Value $configPath
    $snapshot | Add-Member -MemberType NoteProperty -Name ConfigLoadedAtUtc -Value $now.ToString('o')
    $whitelistText = Get-Wail2banMonitorText $snapshot -NowUtc $now
    Assert-Monitor ($whitelistText.Contains('Whitelist đã nạp: 2') -and $whitelistText.Contains('198.51.100.0/24')) 'Runtime configured whitelist displayed'
    Assert-Monitor ($whitelistText.Contains('IP máy chủ tự miễn chặn: 2') -and $whitelistText.Contains('192.0.2.20')) 'Self addresses displayed separately'
    Assert-Monitor ($whitelistText.Contains($configPath) -and $whitelistText.Contains($now.ToString('o'))) 'Configuration path and loaded time displayed'
    Assert-Monitor ($whitelistText.Contains('Sửa tệp INI cần chạy lại chương trình bảo vệ')) 'Reload instruction displayed'
    Assert-Monitor (-not $whitelistText.Contains('198.51.100.99')) 'Monitor does not read current INI as applied configuration'
    Write-Wail2banSnapshot -Snapshot $snapshot -Path $jsonPath
    $monitorPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'wail2ban_monitor.ps1'
    $onceText = (& $monitorPath -StatusPath $jsonPath -Once) -join "`n"
    Assert-Monitor ($onceText.Contains('Whitelist đã nạp: 2') -and $onceText.Contains('203.0.113.9')) 'Terminal entrypoint shows loaded whitelist'
    Write-Wail2banHtml -Snapshot $snapshot -Path $htmlPath
    $html = [io.file]::ReadAllText($htmlPath)
    Assert-Monitor ($html.Contains('Whitelist đã nạp: 2') -and $html.Contains('198.51.100.0/24')) 'Whitelist in HTML'
    Assert-Monitor ($html.Contains('IP máy chủ tự miễn chặn: 2') -and $html.Contains($now.ToString('o'))) 'Self list and loaded time in HTML'
    $snapshot.Whitelist = @(); $snapshot.SelfList = @()
    $emptyWhitelistText = Get-Wail2banMonitorText $snapshot -NowUtc $now
    Assert-Monitor ($emptyWhitelistText.Contains('Whitelist đã nạp: 0') -and $emptyWhitelistText.Contains('Chưa cấu hình whitelist bổ sung.')) 'Empty configured whitelist explicit'
    Assert-Monitor ($emptyWhitelistText.Contains('IP máy chủ tự miễn chặn: 0')) 'Empty self list explicit'
    Write-Wail2banHtml -Snapshot $snapshot -Path $htmlPath
    Assert-Monitor ([io.file]::ReadAllText($htmlPath).Contains('Chưa cấu hình whitelist bổ sung.')) 'Empty whitelist HTML'
    $snapshot.Whitelist = @('<script>alert(1)</script>')
    $snapshot.SelfList = @('<img src=x onerror=alert(1)>')
    $snapshot.ConfigPath = '<b>config</b>'
    $snapshot.ConfigLoadedAtUtc = $null
    Write-Wail2banHtml -Snapshot $snapshot -Path $htmlPath
    $html = [io.file]::ReadAllText($htmlPath)
    Assert-Monitor ($html.Contains('&lt;script&gt;') -and -not $html.Contains('<script>alert(1)')) 'Whitelist entry HTML escaped'
    Assert-Monitor ($html.Contains('&lt;img') -and -not $html.Contains('<img')) 'Self list entry HTML escaped'
    Assert-Monitor ($html.Contains('&lt;b&gt;config&lt;/b&gt;') -and -not $html.Contains('<b>config</b>')) 'Configuration path HTML escaped'
    Assert-Monitor ($html.Contains((ConvertTo-Wail2banHtmlText 'không xác định'))) 'Unknown loaded time explained'
    $snapshot.Whitelist = @("203.0.113.9$([char]27)[31m")
    $snapshot.SelfList = @("127.0.0.1`nforged line")
    $snapshot.ConfigPath = "C:\config$([char]27)[31m.ini"
    $safeText = Get-Wail2banMonitorText $snapshot -NowUtc $now
    Assert-Monitor ($safeText -notmatch [string][char]27) 'Whitelist and path terminal controls removed'
    Assert-Monitor ($safeText.Contains('- 127.0.0.1 forged line')) 'Self list terminal newline removed'
    $snapshot.Whitelist = @('203.0.113.9'); $snapshot.SelfList = @('127.0.0.1')
    $snapshot.ConfigPath = $configPath; $snapshot.ConfigLoadedAtUtc = $now.ToString('o')
    $snapshot.Status = 'Degraded'
    Assert-Monitor ((Get-Wail2banMonitorStatus $snapshot -NowUtc $now) -eq 'Có lỗi') 'Degraded status'
    $snapshot.Status = 'Stopped'
    Assert-Monitor ((Get-Wail2banMonitorStatus $snapshot -NowUtc $now.AddMinutes(2)) -eq 'Đã dừng') 'Stopped status preserved'
    $snapshot.Status = 'Running'; $snapshot.FirewallReadSucceeded = $false
    Assert-Monitor ((Get-Wail2banMonitorStatus $snapshot -NowUtc $now) -eq 'Có lỗi') 'Firewall failure status'
    Assert-Monitor ((Get-Wail2banMonitorText $snapshot).Contains('IP đang bị chặn: không xác định')) 'Unknown firewall text'
    Write-Wail2banHtml -Snapshot $snapshot -Path $htmlPath
    Assert-Monitor ([io.file]::ReadAllText($htmlPath).Contains('IP đang bị chặn: không xác định')) 'Unknown firewall HTML'
    $snapshot.FirewallReadSucceeded = $true
    $snapshot.Bans = @([pscustomobject]@{ Ip='203.0.113.8'; ExpiresAtUtc=$null })
    Assert-Monitor (Test-Wail2banSnapshot $snapshot) 'Unknown expiry does not invalidate snapshot'
    Assert-Monitor ((Get-Wail2banMonitorText $snapshot).Contains('hết hạn UTC: không xác định')) 'Unknown expiry text'
    Write-Wail2banHtml -Snapshot $snapshot -Path $htmlPath
    Assert-Monitor ([io.file]::ReadAllText($htmlPath).Contains(('<td>{0}</td>' -f (ConvertTo-Wail2banHtmlText 'không xác định')))) 'Unknown expiry HTML'
    $snapshot.Hostname = '<script>alert("host")</script>'
    $snapshot.RecentIssues = @(1..25 | ForEach-Object {
        [pscustomobject]@{ TimestampUtc=$now.ToString('o'); Level='Warning'; Message=('issue-{0:D2} <img src=x onerror=alert(1)>' -f $_) }
    })
    Write-Wail2banHtml -Snapshot $snapshot -Path $htmlPath
    $html = [io.file]::ReadAllText($htmlPath)
    Assert-Monitor ($html.Contains('&lt;script&gt;') -and -not $html.Contains('<script>alert')) 'Hostname escaped'
    Assert-Monitor ($html.Contains('&lt;img') -and -not $html.Contains('<img')) 'Issue HTML escaped'
    Assert-Monitor (-not $html.Contains('issue-05') -and $html.Contains('issue-06') -and $html.Contains('issue-25')) 'Only last twenty issues displayed'
    $snapshot.RecentIssues[24].Message = "line1`nline2$([char]27)[31m"
    Assert-Monitor ((Get-Wail2banMonitorText $snapshot) -notmatch [string][char]27) 'Terminal control character removed'
    $snapshot.Hostname = 'updated'
    Write-Wail2banSnapshot -Snapshot $snapshot -Path $jsonPath
    Assert-Monitor ((Read-Wail2banSnapshot $jsonPath).Hostname -eq 'updated') 'Atomic replace existing snapshot'
    Assert-Monitor (@(Get-ChildItem -LiteralPath (Split-Path $jsonPath -Parent) -Filter '*.tmp').Count -eq 0) 'Temporary files cleaned'
    [io.file]::WriteAllText($jsonPath, '{not JSON')
    Assert-Monitor ($null -eq (Read-Wail2banSnapshot $jsonPath)) 'Malformed JSON tolerated'
    [io.file]::WriteAllText($jsonPath, '{"SchemaVersion":1}')
    Assert-Monitor ($null -eq (Read-Wail2banSnapshot $jsonPath)) 'Incomplete schema tolerated'
    $snapshot.HeartbeatUtc = 'invalid date'
    Assert-Monitor (-not (Test-Wail2banSnapshot $snapshot)) 'Invalid heartbeat rejected'
    Write-Wail2banHtml -Snapshot $null -Path $htmlPath
    Assert-Monitor ([io.file]::ReadAllText($htmlPath).Contains((ConvertTo-Wail2banHtmlText 'Chưa có dữ liệu'))) 'Missing data HTML'
    $monitorPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'wail2ban_monitor.ps1'
    Assert-Monitor ((& $monitorPath -StatusPath $jsonPath -Once) -match 'Chưa có dữ liệu') 'Terminal Once tolerates invalid snapshot'
    $generatorPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'wail2ban_htmlgen.ps1'
    & $generatorPath -StatusPath $jsonPath -OutputPath $htmlPath
    Assert-Monitor ([io.file]::ReadAllText($htmlPath).Contains((ConvertTo-Wail2banHtmlText 'Chưa có dữ liệu'))) 'Standalone HTML generator'
    Write-Output ('Monitor tests: {0} assertions passed; PowerShell {1}' -f $script:assertions,$PSVersionTable.PSVersion)
} finally {
    $resolvedTemporary = [io.path]::GetFullPath($temporaryRoot)
    $allowedPrefix = [io.path]::Combine([io.path]::GetTempPath(), 'wail2ban-monitor-tests-')
    if ($resolvedTemporary.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            [io.directory]::Exists($resolvedTemporary)) { [io.directory]::Delete($resolvedTemporary, $true) }
}
