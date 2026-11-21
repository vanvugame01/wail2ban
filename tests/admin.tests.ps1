$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\wail2ban_admin.ps1') -LibraryOnly
$script:Passed = 0
$script:IsAdministrator = $false
$script:ReadConfigFails = $false
$script:Inputs = New-Object 'System.Collections.Generic.Queue[string]'
$script:Calls = New-Object 'System.Collections.Generic.List[string]'
$temporaryRoot = Join-Path ([io.path]::GetTempPath()) ('wail2ban-admin-test-' + [guid]::NewGuid().ToString('N'))
$null = [io.directory]::CreateDirectory($temporaryRoot)

function Assert-Admin {
    param([bool]$Condition, [string]$Name)
    if (-not $Condition) { throw ('FAIL: ' + $Name) }
    $script:Passed++
}
function Assert-AdminThrows {
    param([scriptblock]$Action, [string]$Name)
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    Assert-Admin $failed $Name
}
function Set-AdminInput {
    param([string[]]$Values)
    $script:Inputs.Clear()
    foreach ($value in $Values) { $script:Inputs.Enqueue($value) }
}
function Read-Wail2banAdminInput {
    param($Prompt)
    if ($script:Inputs.Count -eq 0) { throw 'Unexpected interactive prompt.' }
    return $script:Inputs.Dequeue()
}
function Test-Wail2banAdministrator { return $script:IsAdministrator }
function New-AdminTestResult {
    param([string]$Name)
    $script:Calls.Add($Name)
    return [pscustomobject]@{Success=$true;Status='Completed';Message='mock success';RequestId='test-request'}
}
function Start-Wail2banManagedProtection { param($Root,$TimeoutSeconds); New-AdminTestResult 'Start' }
function Stop-Wail2banManagedProtection { param($Root,$TimeoutSeconds); New-AdminTestResult 'Stop' }
function Restart-Wail2banManagedProtection { param($Root,$TimeoutSeconds); New-AdminTestResult 'Restart' }
function Invoke-Wail2banManagedUnban { param($Root,$Ip,[switch]$All,$TimeoutSeconds); New-AdminTestResult ('Unban:' + $(if ($All) { 'All' } else { $Ip })) }
function Get-Wail2banControlStatus { param($Root); return [pscustomobject]@{State=$script:ControlState;Snapshot=$script:Snapshot;Message='mock control'} }
function Get-Wail2banFirewallRules { return @([pscustomobject]@{Ip='203.0.113.9';ExpiresAtUtc=$null}) }
function Read-Wail2banConfigurationDocument { param($Path); if ($script:ReadConfigFails) { throw 'mock invalid config' }; return $script:Document }
function Add-Wail2banWhitelistEntry { param($Document,$Address,$Comment); $script:Calls.Add(('EditAdd:' + $Address)); return $Document }
function Remove-Wail2banWhitelistEntry { param($Document,$Index); $script:Calls.Add(('EditRemove:' + $Index)); return $Document }
function Save-Wail2banConfigurationDocument { param($Document); $script:Calls.Add('Save'); return [pscustomobject]@{Path='test.ini';BackupPath='test.ini.bak'} }
function Start-Process { param($FilePath,$ArgumentList,$ErrorAction); $script:Calls.Add(('Open:' + $FilePath)); $script:LastOpenArguments=$ArgumentList }

try {
    $now = [datetime]::UtcNow
    $state = New-Wail2banState -NowUtc $now -Whitelist @('203.0.113.9') -SelfList @('127.0.0.1') -ConfigPath 'C:\test\config.ini'
    $state.FirewallReadSucceeded = $true
    $script:Snapshot = New-Wail2banSnapshot $state $now
    $script:ControlState = 'Running'
    $script:Document = [pscustomobject]@{Whitelist=@('203.0.113.9');WhitelistEntries=@([pscustomobject]@{Address='203.0.113.9';Comment='Management';LineIndex=3})}
    $menu = Get-Wail2banAdminMenuText
    Assert-Admin ($menu.Contains('13. Chạy lại bảo vệ') -and $menu.Contains('0. Thoát menu')) 'menu has thirteen actions and exit'
    $menuEntrypoint = Join-Path $PSScriptRoot '..\wail2ban_admin.ps1'
    $helpOutput = @(& (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -File $menuEntrypoint -Help) -join "`n"
    Assert-Admin ($LASTEXITCODE -eq 0 -and $helpOutput.Contains('13. Chạy lại bảo vệ')) 'real help entrypoint survives imported script parameter names'
    $report = Get-Wail2banAdminWhitelistText $temporaryRoot
    Assert-Admin ($report.Contains('khớp whitelist tiến trình đang sử dụng')) 'running saved whitelist matches applied list'
    $script:ReadConfigFails = $true
    $report = Get-Wail2banAdminWhitelistText $temporaryRoot
    Assert-Admin ($report.Contains('203.0.113.9') -and $report.Contains('Không đọc/kiểm tra được cấu hình đang lưu')) 'applied whitelist remains visible when saved INI is invalid'
    $script:ReadConfigFails = $false
    $script:Document.Whitelist = @('203.0.113.10')
    $report = Get-Wail2banAdminWhitelistText $temporaryRoot
    Assert-Admin ($report.Contains('Whitelist đã thay đổi, cần chạy lại bảo vệ')) 'unapplied whitelist difference explained'
    $script:Document.Whitelist = @('203.0.113.9'); $script:ControlState = 'Stopped'
    Assert-Admin ((Get-Wail2banAdminWhitelistText $temporaryRoot).Contains('chưa xác nhận có tiến trình')) 'stopped snapshot not presented as active configuration'
    $script:ControlState = 'Running'; $script:Document.Whitelist = @(); $script:Snapshot.Whitelist = @()
    Assert-Admin ((Get-Wail2banAdminWhitelistText $temporaryRoot).Contains('khớp whitelist')) 'empty whitelist comparison works'
    $script:Snapshot.PSObject.Properties.Remove('Whitelist')
    Assert-Admin ((Get-Wail2banAdminWhitelistText $temporaryRoot).Contains('Snapshot chưa có dữ liệu whitelist')) 'legacy snapshot does not imply empty whitelist'
    $script:Snapshot = New-Wail2banSnapshot $state $now

    foreach ($action in @('Start','Stop','Restart','Unban','UnbanAll','AddWhitelist','RemoveWhitelist','OpenConfig')) {
        Assert-AdminThrows { Invoke-Wail2banAdminAction $temporaryRoot $action } ('non-admin mutation rejected: ' + $action)
    }
    Assert-Admin ($script:Calls.Count -eq 0) 'permission rejection has no mutation or launch'
    $script:IsAdministrator = $true
    Set-AdminInput @('Tôi đồng ý')
    Assert-Admin (-not (Confirm-Wail2banAdminChange 'test')) 'confirmation is case-sensitive'
    Set-AdminInput @('tôi đồng ý ')
    Assert-Admin (-not (Confirm-Wail2banAdminChange 'test')) 'confirmation rejects extra whitespace'
    Set-AdminInput @('tôi đồng ý')
    Assert-Admin (Confirm-Wail2banAdminChange 'test') 'exact Vietnamese confirmation accepted'
    foreach ($action in @('Start','Stop','Restart','UnbanAll')) {
        Set-AdminInput @('no')
        $null = Invoke-Wail2banAdminAction $temporaryRoot $action
    }
    Assert-Admin ($script:Calls.Count -eq 0) 'canceled actions have no side effects'
    Set-AdminInput @('203.0.113.9 & whoami')
    Assert-AdminThrows { Invoke-Wail2banAdminAction $temporaryRoot Unban } 'shell-like input rejected as invalid IP'
    Assert-Admin ($script:Calls.Count -eq 0) 'invalid IP not passed to command helper'
    Set-AdminInput @('203.0.113.9','tôi đồng ý')
    $null = Invoke-Wail2banAdminAction $temporaryRoot Unban
    Assert-Admin ($script:Calls.Count -eq 1 -and $script:Calls[0] -eq 'Unban:203.0.113.9') 'one-IP unban routed structurally once'
    foreach ($action in @('Start','Stop','Restart','UnbanAll')) {
        Set-AdminInput @('tôi đồng ý')
        $null = Invoke-Wail2banAdminAction $temporaryRoot $action
    }
    Assert-Admin ($script:Calls.Count -eq 5) 'confirmed lifecycle and unban-all each dispatched once'
    $script:Calls.Clear()
    Set-AdminInput @('203.0.113.10','new management','no')
    $null = Invoke-Wail2banAdminAction $temporaryRoot AddWhitelist
    Assert-Admin ($script:Calls -notcontains 'Save') 'canceling whitelist add does not save'
    $script:Calls.Clear()
    Set-AdminInput @('203.0.113.10','new management','tôi đồng ý')
    $output = @(Invoke-Wail2banAdminAction $temporaryRoot AddWhitelist) -join "`n"
    Assert-Admin ($script:Calls -contains 'Save' -and $script:Calls.Count -eq 2) 'whitelist add saves without lifecycle changes'
    Assert-Admin ($output.Contains('cần chạy lại bảo vệ') -and $output.Contains('test.ini.bak')) 'save reports backup and pending application'
    $script:Calls.Clear()
    Set-AdminInput @('0')
    Assert-AdminThrows { Invoke-Wail2banAdminAction $temporaryRoot RemoveWhitelist } 'invalid one-based whitelist index rejected'
    Set-AdminInput @('1','tôi đồng ý')
    $null = Invoke-Wail2banAdminAction $temporaryRoot RemoveWhitelist
    Assert-Admin ($script:Calls[0] -eq 'EditRemove:0' -and $script:Calls[1] -eq 'Save') 'one-based UI selection maps to zero-based editor index'

    $script:Calls.Clear()
    Set-AdminInput @('0')
    $null = Start-Wail2banAdminMenu $temporaryRoot
    Assert-Admin ($script:Calls.Count -eq 0) 'exiting menu does not stop protection'
    Set-AdminInput @('99','','abc','','1','','0')
    $menuOutput = @(Start-Wail2banAdminMenu $temporaryRoot) -join "`n"
    Assert-Admin ($menuOutput.Contains('Lựa chọn không hợp lệ') -and $menuOutput.Contains('mock control')) 'invalid choices recover and status action returns to menu'
    $pending = [pscustomobject]@{Success=$false;Status='Pending';Message='wait';RequestId='pending-id'}
    $pendingOutput = @(Write-Wail2banAdminResult $pending) -join "`n"
    Assert-Admin ($pendingOutput.Contains('pending-id') -and $pendingOutput.Contains('Không gửi lại')) 'pending response is not treated as completion'
    $partial = [pscustomobject]@{Success=$false;Status='Partial';Message='partial';ReleasedIps=@('203.0.113.9');FailedIps=@('203.0.113.10')}
    $partialOutput = @(Write-Wail2banAdminResult $partial) -join "`n"
    Assert-Admin ($partialOutput.Contains('IP đã gỡ chặn: 203.0.113.9') -and $partialOutput.Contains('giữ lịch sử: 203.0.113.10')) 'partial result displays released and failed IPs separately'
    $logPath = Join-Path $temporaryRoot 'wail2ban_log.log'
    [io.file]::WriteAllLines($logPath, [string[]](1..105 | ForEach-Object { 'line-' + $_ }), (New-Object text.UTF8Encoding($true)))
    $logOutput = @(Invoke-Wail2banAdminAction $temporaryRoot Log)
    Assert-Admin ($logOutput.Count -eq 100 -and $logOutput[0] -eq 'line-6' -and $logOutput[99] -eq 'line-105') 'log action shows only last hundred lines'
    $null = [io.directory]::CreateDirectory((Join-Path $temporaryRoot 'public_html'))
    [io.file]::WriteAllText((Join-Path $temporaryRoot 'public_html\index.html'), '<html></html>')
    $null = Invoke-Wail2banAdminAction $temporaryRoot Html
    Assert-Admin ($script:Calls[$script:Calls.Count - 1] -eq ('Open:' + (Join-Path $temporaryRoot 'public_html\index.html'))) 'HTML opens fixed package path'
    $bans = @(Invoke-Wail2banAdminAction $temporaryRoot Bans) -join "`n"
    Assert-Admin ($bans.Contains('203.0.113.9') -and $bans.Contains('không xác định')) 'admin reads live bans and unknown expiration safely'
    $script:IsAdministrator = $false
    Assert-Admin ((@(Invoke-Wail2banAdminAction $temporaryRoot Bans) -join "`n").Contains('snapshot gần nhất')) 'non-admin bans explicitly use snapshot'
    $source = [io.file]::ReadAllText((Join-Path $PSScriptRoot '..\wail2ban_admin.ps1'))
    Assert-Admin ($source -notmatch '(?i)Invoke-Expression|Stop-Process|taskkill|ExecutionPolicy\s+Bypass') 'menu contains no evaluated shell input or forced termination'
    Write-Output ('Admin tests passed: {0} assertions; PowerShell {1}.' -f $script:Passed,$PSVersionTable.PSVersion)
} finally {
    # Chi don du lieu tam cua bo kiem thu nay.
    $resolved = [io.path]::GetFullPath($temporaryRoot)
    if ($resolved.StartsWith([io.path]::Combine([io.path]::GetTempPath(),'wail2ban-admin-test-'), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
