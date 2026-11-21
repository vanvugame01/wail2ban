[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'wail2ban.ps1') -LibraryOnly
. (Join-Path $root 'wail2ban_monitoring.ps1')
$temporaryRoot = Join-Path ([io.path]::GetTempPath()) ('wail2ban-integration-' + [guid]::NewGuid().ToString('N'))
$null = [io.directory]::CreateDirectory($temporaryRoot)
$script:passed = 0

function Assert-Integration {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-IntegrationCase {
    param([string]$Name, [scriptblock]$Body)
    & $Body
    $script:passed++
    Write-Output ('PASS integration: ' + $Name)
}

try {
    $now = [datetime]::UtcNow
    $state = New-Wail2banState -NowUtc $now
    $state.FirewallReadSucceeded = $true
    Invoke-IntegrationCase 'core snapshot round trip and both monitor entrypoints' {
        Publish-Wail2banStatus -State $state -NowUtc $now -Root $temporaryRoot
        $statusPath = Join-Path $temporaryRoot 'runtime\wail2ban_status.json'
        $snapshot = Read-Wail2banSnapshot $statusPath
        Assert-Integration ($null -ne $snapshot) 'Core snapshot was rejected by monitor.'
        Assert-Integration ($snapshot.InstanceId -eq $state.InstanceId) 'Instance identity changed.'
        Assert-Integration ((Get-Wail2banMonitorStatus $snapshot $now) -eq 'Đang chạy') 'Fresh snapshot did not show running.'
        $monitorOutput = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -File (Join-Path $root 'wail2ban_monitor.ps1') -Once -StatusPath $statusPath
        Assert-Integration ($LASTEXITCODE -eq 0) 'Terminal entrypoint failed.'
        Assert-Integration (($monitorOutput -join "`n") -match [regex]::Escape($state.InstanceId)) 'Terminal did not display this snapshot.'
        $htmlPath = Join-Path $temporaryRoot 'public_html\index.html'
        Assert-Integration ([io.file]::Exists($htmlPath)) 'HTML was not published.'
        Assert-Integration ([io.file]::ReadAllText($htmlPath).Contains($state.InstanceId)) 'HTML did not display this snapshot.'
        Publish-Wail2banStatus -State $state -NowUtc $now.AddSeconds(5) -Root $temporaryRoot
        $updated = Read-Wail2banSnapshot $statusPath
        Assert-Integration ((ConvertTo-Wail2banUtc $updated.HeartbeatUtc) -eq $now.AddSeconds(5)) 'Atomic replacement did not publish a new heartbeat.'
    }
    Invoke-IntegrationCase 'unknown expiration preserves snapshot' {
        $state.Bans = @([pscustomobject]@{Ip='203.0.113.9'; ExpiresAtUtc=$null})
        $snapshot = New-Wail2banSnapshot $state $now
        Assert-Integration (Test-Wail2banSnapshot $snapshot) 'Unknown expiration invalidated the whole snapshot.'
        Assert-Integration ((Get-Wail2banMonitorText $snapshot $now) -match 'không xác định') 'Unknown expiration was not explained.'
    }
    Invoke-IntegrationCase 'firewall read failure remains unknown' {
        $state.FirewallReadSucceeded = $false
        $state.Faults['firewall-read'] = $true
        $snapshot = New-Wail2banSnapshot $state $now
        Assert-Integration ($snapshot.Status -eq 'Degraded') 'Firewall failure did not degrade status.'
        Assert-Integration ((Get-Wail2banMonitorText $snapshot $now) -match 'không xác định') 'Firewall failure was displayed as an empty firewall.'
        Assert-Integration ((Get-Wail2banMonitorStatus $snapshot $now.AddSeconds(31)) -eq 'Heartbeat quá 30 giây') 'Stale heartbeat did not override degraded status.'
    }
    Invoke-IntegrationCase 'controlled shutdown is visible in snapshot' {
        $state.Status = 'Stopped'
        $snapshot = New-Wail2banSnapshot $state $now
        Assert-Integration ((Get-Wail2banMonitorStatus $snapshot $now.AddMinutes(2)) -eq 'Đã dừng') 'Controlled stop was not preserved.'
    }
    Invoke-IntegrationCase 'history survives repeated atomic writes' {
        $state.HistoryPath = Join-Path $temporaryRoot 'history.ini'
        $state.BanCounts['203.0.113.9'] = 1
        Save-Wail2banBanHistory $state
        $state.BanCounts['203.0.113.9'] = 2
        Save-Wail2banBanHistory $state
        $restored = New-Wail2banState -HistoryPath $state.HistoryPath
        Read-Wail2banBanHistory $restored
        Assert-Integration ($restored.BanCounts['203.0.113.9'] -eq 2) 'History failed repeated write/read.'
    }
    Write-Output ('Integration tests passed: {0} on PowerShell {1}.' -f $script:passed, $PSVersionTable.PSVersion)
} finally {
    # Chi xoa thu muc tam do chinh bo kiem thu tao ra.
    $resolvedTemporaryRoot = [io.path]::GetFullPath($temporaryRoot)
    $expectedPrefix = [io.path]::Combine([io.path]::GetTempPath(), 'wail2ban-integration-')
    if ($resolvedTemporaryRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
