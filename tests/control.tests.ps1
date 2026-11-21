$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\wail2ban.ps1') -LibraryOnly
$script:actualProcessScanner = (Get-Item Function:Get-Wail2banProtectionProcessRecords).ScriptBlock
$script:passed = 0
function Assert-Control { param([bool]$Condition,[string]$Name); if (-not $Condition) { throw ('FAIL: ' + $Name) }; $script:passed++; Write-Output ('PASS control: ' + $Name) }
function Assert-ControlThrows { param([scriptblock]$Action,[string]$Name); $threw=$false;try { & $Action | Out-Null } catch {$threw=$true};Assert-Control $threw $Name }
$temporaryRoot = Join-Path ([io.path]::GetTempPath()) ('wail2ban-control-tests-' + [guid]::NewGuid().ToString('N'))
$null = [io.directory]::CreateDirectory($temporaryRoot)
$script:records=@();$script:busy=$false;$script:admin=$true;$script:tick=0.0;$script:removeCalls=@();$script:failedIp='';$script:rules=@()
function Get-Wail2banProtectionProcessRecords { return $script:records }
function Get-Wail2banProcessRecord { param($ProcessId); return ($script:records | Where-Object { $_.ProcessId -eq $ProcessId } | Select-Object -First 1) }
function Test-Wail2banProtectionLockBusy { return $script:busy }
function Test-Wail2banAdministrator { return $script:admin }
function Get-Wail2banControlTime { return $script:tick }
function Wait-Wail2banControlPoll { $script:tick += 0.25 }
function Get-Wail2banFirewallRules { return $script:rules }
function Remove-Wail2banFirewallRule { param($Ip); $script:removeCalls += $Ip; if ($Ip -eq $script:failedIp) {throw 'mock remove failure'}; $script:rules=@($script:rules | Where-Object {$_.Ip -ne $Ip}) }
function New-ControlState {
    $value=New-Wail2banState -HistoryPath (Join-Path $temporaryRoot 'history.ini')
    $value.ControlProtocolVersion=1;$value.ControlRoot=$temporaryRoot;$value.FirewallReadSucceeded=$true
    return $value
}
function Publish-ControlFixture {
    param($State,[string]$Status='Running')
    $State.Status=$Status
    $snapshot=New-Wail2banSnapshot $State ([datetime]::UtcNow)
    $snapshot.ProcessId=3456
    Write-Wail2banSnapshot $snapshot (Join-Path $temporaryRoot 'runtime\wail2ban_status.json')
    return $snapshot
}
try {
    [io.file]::WriteAllLines((Join-Path $temporaryRoot 'wail2ban_config.ini'),@('[Security]','4625=RDP','[Whitelist]'),(New-Object text.utf8encoding($true)))
    Assert-Control ((Get-Wail2banControlStatus $temporaryRoot).State -eq 'Stopped') 'empty installation is stopped'
    $script:busy=$true
    Assert-Control ((Get-Wail2banControlStatus $temporaryRoot).State -eq 'Unknown') 'busy lock without identity fails closed'
    $script:busy=$false
    $state=New-ControlState
    $snapshot=Publish-ControlFixture $state
    $script:records=@([pscustomobject]@{ProcessId=3456;CommandLine=('powershell.exe -NoProfile -File "' + (Join-Path $temporaryRoot 'wail2ban.ps1') + '"')})
    Assert-Control ((Get-Wail2banControlStatus $temporaryRoot).State -eq 'Running') 'verified current snapshot and process are running'
    $snapshot.ControlProtocolVersion=0
    Write-Wail2banSnapshot $snapshot (Join-Path $temporaryRoot 'runtime\wail2ban_status.json')
    Assert-Control ((Get-Wail2banControlStatus $temporaryRoot).State -eq 'Legacy') 'legacy process blocks managed start'
    $script:admin=$false
    Assert-Control (-not (Start-Wail2banManagedProtection $temporaryRoot).Success) 'start requires administrator'
    Assert-Control (-not (Stop-Wail2banManagedProtection $temporaryRoot).Success) 'stop requires administrator'
    Assert-Control (-not (Restart-Wail2banManagedProtection $temporaryRoot).Success) 'restart requires administrator'
    Assert-Control (-not (Invoke-Wail2banManagedUnban -Root $temporaryRoot -Ip '203.0.113.9').Success) 'unban requires administrator'
    $script:admin=$true
    Assert-Control ((Start-Wail2banManagedProtection $temporaryRoot).Status -eq 'Rejected') 'legacy start is rejected without spawning'
    Assert-Control ((Stop-Wail2banManagedProtection $temporaryRoot).Status -eq 'Rejected') 'legacy stop does not kill process'
    $script:records=@()
    $savedIdentityReader=(Get-Item Function:Get-Wail2banProcessRecord).ScriptBlock
    function Get-Wail2banProcessRecord { param($ProcessId); return [pscustomobject]@{ProcessId=$ProcessId;CommandLine=$null} }
    Assert-Control ((Get-Wail2banControlStatus $temporaryRoot).State -eq 'Unknown') 'live snapshot PID without readable identity is not stopped'
    Set-Item Function:Get-Wail2banProcessRecord -Value $savedIdentityReader

    $state=New-ControlState
    $state.BanCounts['203.0.113.9']=3;$state.BanCounts['203.0.113.10']=2;$state.BanCounts['198.51.100.9']=7
    $state.Attempts['Security:9']=[pscustomobject]@{Ip='203.0.113.9';TimeUtc=[datetime]::UtcNow}
    $state.Attempts['Security:10']=[pscustomobject]@{Ip='203.0.113.10';TimeUtc=[datetime]::UtcNow}
    $script:rules=@([pscustomobject]@{Ip='203.0.113.9';ExpiresAtUtc=[datetime]::UtcNow.AddMinutes(5)},[pscustomobject]@{Ip='203.0.113.10';ExpiresAtUtc=[datetime]::UtcNow.AddMinutes(5)})
    $script:failedIp='203.0.113.10'
    $result=Invoke-Wail2banManualUnban $state -All
    Assert-Control ($result.Status -eq 'Partial' -and $result.FailedIps -contains '203.0.113.10') 'partial all-unban exposes failed IP'
    Assert-Control (-not $state.BanCounts.ContainsKey('203.0.113.9') -and $state.BanCounts['203.0.113.10'] -eq 2 -and -not $state.BanCounts.ContainsKey('198.51.100.9')) 'partial unban resets successes and preserves failed history'
    Assert-Control ($state.Attempts.Count -eq 1 -and $state.Attempts['Security:10'].Ip -eq '203.0.113.10') 'manual unban clears successful attempt cache only'
    $loaded=New-Wail2banState -HistoryPath $state.HistoryPath;Read-Wail2banBanHistory $loaded
    Assert-Control ($loaded.BanCounts.Count -eq 1 -and $loaded.BanCounts['203.0.113.10'] -eq 2) 'partial history persisted consistently'
    $script:failedIp=''
    $result=Invoke-Wail2banManualUnban $state -Ip '203.0.113.10'
    Assert-Control ($result.Success -and $state.BanCounts.Count -eq 0 -and $state.Attempts.Count -eq 0) 'single unban succeeds and resets live state'
    Assert-Control ((Invoke-Wail2banManualUnban $state -Ip '1.2.3.4;calc.exe').Status -eq 'Rejected') 'unban rejects command injection text'

    $state=New-ControlState;$script:rules=@();$script:removeCalls=@()
    $state.BanCounts['203.0.113.9']=2
    $script:rules=@([pscustomobject]@{Ip='203.0.113.9';ExpiresAtUtc=[datetime]::UtcNow.AddMinutes(5)})
    $request=New-Wail2banControlRequest $temporaryRoot $state.InstanceId 'Unban' '203.0.113.9'
    Invoke-Wail2banControlQueue $state $temporaryRoot ([datetime]::UtcNow)
    $response=Read-Wail2banControlJson (Join-Path $temporaryRoot ('runtime\control\responses\'+$request.RequestId+'.json'))
    Assert-Control ($response.Success -and $response.RequestId -eq $request.RequestId -and $state.BanCounts.Count -eq 0) 'queued unban returns correlated response and updates state'
    Invoke-Wail2banControlQueue $state $temporaryRoot ([datetime]::UtcNow)
    Assert-Control ($script:removeCalls.Count -eq 1) 'duplicate request does not execute twice'
    $old=New-Wail2banControlRequest $temporaryRoot ([guid]::NewGuid().ToString()) 'UnbanAll'
    Invoke-Wail2banControlQueue $state $temporaryRoot ([datetime]::UtcNow)
    $oldResponse=Read-Wail2banControlJson (Join-Path $temporaryRoot ('runtime\control\responses\'+$old.RequestId+'.json'))
    Assert-Control ($oldResponse.Status -eq 'Rejected' -and $script:removeCalls.Count -eq 1) 'old instance request rejected'
    $incomplete=New-Wail2banControlRequest $temporaryRoot $state.InstanceId 'UnbanAll'
    Write-Wail2banControlJson (Join-Path $temporaryRoot ('runtime\control\journal\'+$incomplete.RequestId+'.json')) ([pscustomobject]@{Started=$true})
    Invoke-Wail2banControlQueue $state $temporaryRoot ([datetime]::UtcNow)
    $incompleteResponse=Read-Wail2banControlJson (Join-Path $temporaryRoot ('runtime\control\responses\'+$incomplete.RequestId+'.json'))
    Assert-Control ($incompleteResponse.Status -eq 'Rejected') 'incomplete journal prevents replay after uncertain outcome'
    $invalid=New-Wail2banControlRequest $temporaryRoot $state.InstanceId 'UnbanAll'
    $invalid.Action='cmd.exe';Write-Wail2banControlJson (Join-Path $temporaryRoot ('runtime\control\requests\'+$invalid.RequestId+'.json')) $invalid
    Invoke-Wail2banControlQueue $state $temporaryRoot ([datetime]::UtcNow)
    Assert-Control ((Read-Wail2banControlJson (Join-Path $temporaryRoot ('runtime\control\responses\'+$invalid.RequestId+'.json'))).Status -eq 'Rejected') 'unknown action rejected'
    $responseDirectory=Join-Path $temporaryRoot 'runtime\control\responses'
    $responsesBefore=@(Get-ChildItem -LiteralPath $responseDirectory -File).Count
    1..21 | ForEach-Object { $null=New-Wail2banControlRequest $temporaryRoot $state.InstanceId 'Unban' '198.51.100.9' }
    Invoke-Wail2banControlQueue $state $temporaryRoot ([datetime]::UtcNow)
    Assert-Control ((@(Get-ChildItem -LiteralPath $responseDirectory -File).Count - $responsesBefore) -eq 20) 'queue handles at most twenty requests per cycle'
    Invoke-Wail2banControlQueue $state $temporaryRoot ([datetime]::UtcNow)
    Assert-Control ((@(Get-ChildItem -LiteralPath $responseDirectory -File).Count - $responsesBefore) -eq 21) 'completed requests do not starve later pending requests'

    $script:tick=0
    $missingId=[guid]::NewGuid().ToString()
    Assert-Control ((Wait-Wail2banControlResponse $temporaryRoot $missingId $state.InstanceId -TimeoutSeconds 1).Status -eq 'Pending') 'response timeout stays pending without reissuing'
    $script:tick=0
    $result=Wait-Wail2banControlResponse $temporaryRoot $request.RequestId ([guid]::NewGuid().ToString()) -TimeoutSeconds 1
    Assert-Control ($result.Status -eq 'Pending') 'response for wrong instance ignored'
    $tamperedId=[guid]::NewGuid().ToString()
    Write-Wail2banControlJson (Join-Path $temporaryRoot ('runtime\control\responses\'+$tamperedId+'.json')) ([pscustomobject]@{RequestId=$tamperedId;InstanceId=$state.InstanceId;Status='Failed';Success=$true;Message='inconsistent result'})
    Assert-Control (-not (Wait-Wail2banControlResponse $temporaryRoot $tamperedId $state.InstanceId -TimeoutSeconds 1).Success) 'response success is derived from terminal status'

    $state=New-ControlState
    $stop=New-Wail2banControlRequest $temporaryRoot $state.InstanceId 'Stop'
    $script:unregistered=$false
    function Register-WmiEvent { param($Query,$SourceIdentifier,$ErrorAction) }
    function Unregister-Event { param($SourceIdentifier,$ErrorAction);$script:unregistered=$true }
    function Get-Wail2banMonotonicSeconds { return 0 }
    function Wait-Event { throw 'stop request must prevent waiting' }
    Start-Wail2banLoop $state ([pscustomobject]@{Events=@([pscustomobject]@{EventId=4625;Channel='Security'})}) $temporaryRoot
    $stopped=Read-Wail2banSnapshot (Join-Path $temporaryRoot 'runtime\wail2ban_status.json')
    $stopResult=Read-Wail2banControlJson (Join-Path $temporaryRoot ('runtime\control\responses\'+$stop.RequestId+'.json'))
    Assert-Control ($script:unregistered -and $stopped.Status -eq 'Stopped' -and $stopResult.Success) 'stop acknowledges only after unsubscribe and stopped publication'
    $script:tick=0
    Assert-Control ((Wait-Wail2banControlResponse $temporaryRoot $stop.RequestId $state.InstanceId -TimeoutSeconds 1 -WaitForStop).Success) 'stop waiter verifies stopped snapshot and free process state'

    $script:records=@();$script:startCalls=0
    function Start-Wail2banProtectionProcess {
        param($Root,$InstanceId)
        $script:startCalls++
        $ready=New-ControlState;$ready.InstanceId=$InstanceId
        $null=Publish-ControlFixture $ready
        $script:records=@([pscustomobject]@{ProcessId=3456;CommandLine=('powershell.exe -File "'+(Join-Path $Root 'wail2ban.ps1')+'"')})
        return [pscustomobject]@{Id=3456;HasExited=$false}
    }
    $script:tick=0
    Assert-Control ((Start-Wail2banManagedProtection $temporaryRoot -TimeoutSeconds 1).Success -and $script:startCalls -eq 1) 'start verifies exact new instance and process ID'
    Assert-Control ((Start-Wail2banManagedProtection $temporaryRoot -TimeoutSeconds 1).Status -eq 'Rejected' -and $script:startCalls -eq 1) 'running instance prevents duplicate start'
    $script:records=@();$state=New-ControlState;$null=Publish-ControlFixture $state 'Stopped'
    function Start-Wail2banProtectionProcess { param($Root,$InstanceId);$script:startCalls++;return [pscustomobject]@{Id=3456;HasExited=$false} }
    $script:tick=0
    Assert-Control ((Start-Wail2banManagedProtection $temporaryRoot -TimeoutSeconds 1).Status -eq 'Pending' -and $script:startCalls -eq 2) 'startup timeout remains pending and starts only once'
    $script:actualStop=(Get-Item Function:Stop-Wail2banManagedProtection).ScriptBlock
    $script:actualStart=(Get-Item Function:Start-Wail2banManagedProtection).ScriptBlock
    function Stop-Wail2banManagedProtection { param($Root,$TimeoutSeconds);return (New-Wail2banControlResult 'Pending' 'mock pending stop') }
    function Start-Wail2banManagedProtection { param($Root,$TimeoutSeconds);throw 'must not start before verified stop' }
    Assert-Control ((Restart-Wail2banManagedProtection $temporaryRoot).Status -eq 'Pending') 'restart never starts after uncertain stop'
    Set-Item Function:Stop-Wail2banManagedProtection -Value $script:actualStop
    Set-Item Function:Start-Wail2banManagedProtection -Value $script:actualStart

    $script:released=0;$script:disposed=0;$script:lockAcquired=$false
    function New-Wail2banProtectionMutex {
        $fake=[pscustomobject]@{}
        $fake | Add-Member ScriptMethod WaitOne {param($Timeout);return $script:lockAcquired}
        $fake | Add-Member ScriptMethod ReleaseMutex {$script:released++}
        $fake | Add-Member ScriptMethod Dispose {$script:disposed++}
        return $fake
    }
    $lease=Enter-Wail2banProtectionLock;Exit-Wail2banProtectionLock $lease
    Assert-Control (-not $lease.Owned -and $script:released -eq 0 -and $script:disposed -eq 1) 'busy mutex is not released by nonowner'
    $script:lockAcquired=$true
    $lease=Enter-Wail2banProtectionLock;Exit-Wail2banProtectionLock $lease
    Assert-Control ($lease.Owned -and $script:released -eq 1 -and $script:disposed -eq 2) 'owned mutex is released exactly once'
    function New-Wail2banProtectionMutex {throw 'mock denied'}
    Assert-ControlThrows {Enter-Wail2banProtectionLock} 'mutex access failure fails closed'

    function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec,$ErrorAction);return $script:scanRecords}
    $script:scanRecords=@(
        [pscustomobject]@{ProcessId=4001;CommandLine='powershell.exe -File wail2ban.ps1'},
        [pscustomobject]@{ProcessId=4002;CommandLine='powershell.exe -File .\wail2ban.ps1'},
        [pscustomobject]@{ProcessId=4003;CommandLine='powershell.exe -File "C:\some path\wail2ban.ps1"'},
        [pscustomobject]@{ProcessId=4004;CommandLine='powershell.exe -Command "& .\wail2ban.ps1"'},
        [pscustomobject]@{ProcessId=4005;CommandLine='powershell.exe -File wail2ban.ps1 -Config'},
        [pscustomobject]@{ProcessId=4006;CommandLine='powershell.exe -Command "& .\wail2ban.ps1; Write-Output -Config"'},
        [pscustomobject]@{ProcessId=$PID;CommandLine='powershell.exe -File wail2ban.ps1'}
    )
    $scan=@(& $script:actualProcessScanner)
    Assert-Control ($scan.Count -eq 5 -and @($scan.ProcessId) -contains 4001 -and @($scan.ProcessId) -contains 4002 -and @($scan.ProcessId) -contains 4003) 'scanner detects bare relative and quoted absolute protection scripts'
    Assert-Control (@($scan.ProcessId) -contains 4004 -and @($scan.ProcessId) -contains 4006 -and @($scan.ProcessId) -notcontains 4005 -and @($scan.ProcessId) -notcontains $PID) 'command invocation remains suspect while standalone config and self are excluded'

    Write-Output ('Control tests passed: {0}; PowerShell {1}.' -f $script:passed,$PSVersionTable.PSVersion)
} finally {
    $resolved=[io.path]::GetFullPath($temporaryRoot)
    $prefix=[io.path]::Combine([io.path]::GetTempPath(),'wail2ban-control-tests-')
    if ($resolved.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue}
}
