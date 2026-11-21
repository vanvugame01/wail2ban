param(
    [string]$StatusPath = (Join-Path $PSScriptRoot 'runtime\wail2ban_status.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'public_html\index.html')
)

. (Join-Path $PSScriptRoot 'wail2ban_monitoring.ps1')
Write-Wail2banHtml -Snapshot (Read-Wail2banSnapshot -Path $StatusPath) -Path $OutputPath