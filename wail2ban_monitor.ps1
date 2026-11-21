param(
    [string]$StatusPath = (Join-Path $PSScriptRoot 'runtime\wail2ban_status.json'),
    [switch]$Once
)

. (Join-Path $PSScriptRoot 'wail2ban_monitoring.ps1')
do {
    $snapshot = Read-Wail2banSnapshot -Path $StatusPath
    if (-not $Once) { Clear-Host }
    Write-Output (Get-Wail2banMonitorText -Snapshot $snapshot)
    if ($Once) { break }
    Write-Output "`nLàm mới sau 5 giây. Nhấn Ctrl+C để thoát."
    Start-Sleep -Seconds 5
} while ($true)
