$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\wail2ban.ps1') -LibraryOnly
$script:ActualGetFirewall = (Get-Item Function:Get-Wail2banFirewallRules).ScriptBlock
$script:ActualAddFirewall = (Get-Item Function:Add-Wail2banFirewallRule).ScriptBlock
$script:ActualRemoveFirewall = (Get-Item Function:Remove-Wail2banFirewallRule).ScriptBlock
$script:ActualGetAttempt = (Get-Item Function:Get-Wail2banEventAttempt).ScriptBlock
$script:Passed = 0
function Assert-True { param([bool]$Condition, [string]$Name); if (-not $Condition) { throw ('FAIL: ' + $Name) }; $script:Passed++; Write-Output ('PASS: ' + $Name) }
function Assert-Throws { param([scriptblock]$Action, [string]$Name); $threw = $false; try { & $Action | Out-Null } catch { $threw = $true }; Assert-True $threw $Name }
$script:Rules = @(); $script:ReadFails = $false; $script:RemoveFails = $false; $script:AddFails = $false; $script:AddCalls = 0
function Get-Wail2banFirewallRules { if ($script:ReadFails) { throw 'mock read' }; return $script:Rules }
function Add-Wail2banFirewallRule { param($Ip,$ExpiresAtUtc); if ($script:AddFails) { throw 'mock add' }; $script:AddCalls++; $script:Rules += [pscustomobject]@{Ip=$Ip;ExpiresAtUtc=$ExpiresAtUtc} }
function Remove-Wail2banFirewallRule { param($Ip); if ($script:RemoveFails) { throw 'mock remove' }; $script:Rules = @($script:Rules | Where-Object { $_.Ip -ne $Ip }) }
function New-TestAttempt { param([long]$RecordId, [datetime]$TimeUtc, [string]$Ip = '203.0.113.9', [string]$Channel = 'Security'); return [pscustomobject]@{RecordId=$RecordId;TimeUtc=$TimeUtc;Ip=$Ip;Channel=$Channel;EventId=4625} }
function New-TestXml {
    param([int]$EventId=4625, [string]$Channel='Security', [string]$Provider='Microsoft-Windows-Security-Auditing', [long]$RecordId=1, [string]$Data='<Data Name="IpAddress">203.0.113.9</Data>')
    return '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="'+$Provider+'"/><EventID>'+$EventId+'</EventID><Channel>'+$Channel+'</Channel><EventRecordID>'+$RecordId+'</EventRecordID><TimeCreated SystemTime="2026-11-21T00:00:00Z"/></System><EventData>'+$Data+'</EventData></Event>'
}
$now = [datetime]::SpecifyKind([datetime]'2026-11-21T00:00:00', [DateTimeKind]::Utc)
$tempRoot = Join-Path ([io.path]::GetTempPath()) ('wail2ban-core-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tempRoot
try {
    Assert-True ((ConvertTo-Wail2banIPv4 '203.0.113.9') -eq '203.0.113.9') 'IPv4 normalization'
    Assert-True ($null -eq (ConvertTo-Wail2banIPv4 '010.0.0.1')) 'ambiguous leading zero rejected'
    Assert-True ($null -eq (ConvertTo-Wail2banIPv4 '2001:db8::1')) 'native IPv6 skipped'
    Assert-True ((ConvertTo-Wail2banIPv4 '::ffff:203.0.113.9') -eq '203.0.113.9') 'mapped IPv4 normalized'
    Assert-True (-not (Test-Wail2banWhitelist '192.168.1.1' @() @('192.168.1.10'))) 'self list uses exact IP'
    Assert-True (Test-Wail2banWhitelist '192.168.1.10' @() @('192.168.1.10')) 'self list exact match'
    Assert-True (Test-Wail2banWhitelist '203.0.113.9' @('203.0.113.9') @()) 'single IP whitelist'
    Assert-True (Test-Wail2banWhitelist '203.0.113.9' @('203.0.113.0/24') @()) 'CIDR whitelist match'
    Assert-True (-not (Test-Wail2banWhitelist '203.0.114.9' @('203.0.113.0/24') @())) 'CIDR whitelist nonmatch'
    Assert-Throws { Test-Wail2banWhitelist '203.0.113.9' @('203.0.113.0/33') @() } 'invalid CIDR rejected'

    $state = New-Wail2banState -NowUtc $now
    1..5 | ForEach-Object { Invoke-Wail2banAttempt $state (New-TestAttempt $_ $now) $now }
    Assert-True ($state.Counters.Banned -eq 1 -and $script:AddCalls -eq 1 -and $state.BanCounts['203.0.113.9'] -eq 1) 'five valid attempts ban once'
    Invoke-Wail2banAttempt $state (New-TestAttempt 5 $now) $now
    Assert-True ($state.Counters.Processed -eq 5 -and $state.Counters.Skipped -eq 1) 'dedup survives attempts clear after ban'
    6..10 | ForEach-Object { Invoke-Wail2banAttempt $state (New-TestAttempt $_ $now) $now }
    Assert-True ($state.BanCounts['203.0.113.9'] -eq 1 -and $script:AddCalls -eq 1) 'existing rule does not increase punishment'
    Assert-True ($script:Rules[0].ExpiresAtUtc -eq $now.AddMinutes(5)) 'first ban remains five minutes'

    $script:Rules = @(); $state = New-Wail2banState -NowUtc $now
    1..4 | ForEach-Object { Invoke-Wail2banAttempt $state (New-TestAttempt $_ ($now.AddSeconds(-119))) $now }
    Invoke-Wail2banAttempt $state (New-TestAttempt 5 ($now.AddSeconds(2))) ($now.AddSeconds(2))
    Assert-True ($state.Counters.Banned -eq 0 -and $state.Attempts.Count -eq 1) 'expired attempts removed before counting'
    Invoke-Wail2banAttempt $state (New-TestAttempt 6 ($now.AddSeconds(-121))) $now
    Invoke-Wail2banAttempt $state (New-TestAttempt 7 ($now.AddSeconds(1))) $now
    Assert-True ($state.Counters.Skipped -eq 2) 'old and future events skipped'

    $state = New-Wail2banState -NowUtc $now
    Invoke-Wail2banAttempt $state (New-TestAttempt 1 $now '203.0.113.9' 'Security') $now
    Invoke-Wail2banAttempt $state (New-TestAttempt 1 $now '203.0.113.9' 'Application') $now
    Assert-True ($state.Attempts.Count -eq 2) 'channel included in event key'
    Invoke-Wail2banAttempt $state (New-TestAttempt 1 $now) $now
    Assert-True ($state.Attempts.Count -eq 2 -and $state.Counters.Skipped -eq 1) 'duplicate does not increment'

    $script:Rules = @([pscustomobject]@{Ip='203.0.113.9';ExpiresAtUtc=$now.AddSeconds(-1)})
    $state = New-Wail2banState -NowUtc $now
    $script:RemoveFails = $true
    Invoke-Wail2banMaintenance $state $now
    Assert-True ($state.Counters.Released -eq 0 -and $state.Bans.Count -eq 1 -and $state.Faults.ContainsKey('release:203.0.113.9')) 'failed unban retained and reported'
    $script:RemoveFails = $false
    Invoke-Wail2banMaintenance $state ($now.AddSeconds(5))
    Assert-True ($state.Counters.Released -eq 1 -and $script:Rules.Count -eq 0 -and $state.Bans.Count -eq 0) 'idle maintenance retries and releases expired rule'
    $script:ReadFails = $true
    Invoke-Wail2banMaintenance $state $now
    $snapshot = New-Wail2banSnapshot $state $now
    Assert-True (-not $snapshot.FirewallReadSucceeded -and $snapshot.Status -eq 'Degraded') 'firewall read failure is unknown and degraded'
    $script:ReadFails = $false
    Invoke-Wail2banMaintenance $state $now
    Assert-True ((New-Wail2banSnapshot $state $now).Status -eq 'Running') 'firewall read recovery restores status'
    $state.Faults['release:203.0.113.10'] = $true
    $state.Faults['expiry:203.0.113.10'] = $true
    Invoke-Wail2banMaintenance $state $now
    Assert-True ($state.Faults.Count -eq 0) 'external removal clears stale rule faults'

    $attempt = ConvertFrom-Wail2banEventXml (New-TestXml -Data '<Data Name="TargetUserName">198.51.100.7</Data><Data Name="IpAddress">203.0.113.9</Data>') '198.51.100.7'
    Assert-True ($attempt.Ip -eq '203.0.113.9') '4625 reads source field only'
    Assert-Throws { ConvertFrom-Wail2banEventXml (New-TestXml -Provider 'OtherProvider') '' } 'wrong security provider rejected'
    Assert-Throws { ConvertFrom-Wail2banEventXml (New-TestXml -Data '<Data Name="TargetUserName">198.51.100.7</Data>') '203.0.113.9' } 'missing source rejected without whole message fallback'
    Assert-Throws { ConvertFrom-Wail2banEventXml '<invalid' '' } 'malformed XML rejected'
    $sqlXml = New-TestXml -EventId 18456 -Channel 'Application' -Provider 'MSSQLSERVER' -Data ''
    $attempt = ConvertFrom-Wail2banEventXml $sqlXml "Login failed for user '198.51.100.7'. [CLIENT: 203.0.113.9]"
    Assert-True ($attempt.Ip -eq '203.0.113.9') 'SQL terminal CLIENT source'
    Assert-Throws { ConvertFrom-Wail2banEventXml $sqlXml '[CLIENT: 203.0.113.9] other text' } 'SQL nonterminal CLIENT rejected'
    Assert-Throws { ConvertFrom-Wail2banEventXml (New-TestXml -EventId 18456 -Channel 'Application' -Provider 'OtherProvider' -Data '') '[CLIENT: 203.0.113.9]' } 'wrong SQL provider rejected'
    $attempt = ConvertFrom-Wail2banEventXml (New-TestXml -EventId 18456 -Channel 'Application' -Provider 'MSSQL$INSTANCE' -Data '<Data Name="ClientIP">203.0.113.10</Data>') '[CLIENT: 203.0.113.9]'
    Assert-True ($attempt.Ip -eq '203.0.113.10') 'SQL structured source has priority'

    $state = New-Wail2banState -NowUtc $now -LogPath (Join-Path $tempRoot 'test.log') -HistoryPath (Join-Path $tempRoot 'bannedIPLog.ini')
    $state.BanCounts['203.0.113.9'] = 2
    Save-Wail2banBanHistory $state
    $state.BanCounts['203.0.113.9'] = 3
    Save-Wail2banBanHistory $state
    $loaded = New-Wail2banState -NowUtc $now -HistoryPath $state.HistoryPath
    Read-Wail2banBanHistory $loaded
    Assert-True ($loaded.BanCounts['203.0.113.9'] -eq 3) 'history format roundtrip and atomic overwrite'
    1..25 | ForEach-Object { Add-Wail2banIssue $state ('safe message ' + $_) Warning $now }
    Assert-True ($state.RecentIssues.Count -eq 20 -and $state.RecentIssues[0].Message -eq 'safe message 6') 'recent issues capped at twenty'
    Assert-True (@(Get-Content -LiteralPath $state.LogPath).Count -eq 25) 'warnings persisted to file log'
    $state.Status = 'Stopped'
    Assert-True ((New-Wail2banSnapshot $state $now).Status -eq 'Stopped') 'stopped snapshot explicit'

    $script:EventXml = New-TestXml -RecordId 88
    function Get-WinEvent {
        param($LogName,$FilterXPath,$MaxEvents,$ErrorAction)
        $record = [pscustomobject]@{Message='198.51.100.7'}
        $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $script:EventXml }
        return $record
    }
    $target = [pscustomobject]@{RecordNumber=88;LogFile='Security';EventCode=4625}
    $attempt = Get-Wail2banEventAttempt $target
    Assert-True ($attempt.RecordId -eq 88 -and $attempt.Ip -eq '203.0.113.9') 'adapter reads and validates exact record XML'
    $target.RecordNumber = 89
    Assert-Throws { Get-Wail2banEventAttempt $target } 'adapter rejects mismatched record'

    $queueName = 'Wail2banCoreTest-' + [guid]::NewGuid().ToString('N')
    try {
        function Get-Wail2banEventAttempt { param($Target,$State); return (New-TestAttempt 101 $now) }
        $first = New-Event -SourceIdentifier $queueName
        $second = New-Event -SourceIdentifier $queueName
        $first | Add-Member -MemberType NoteProperty -Name SourceEventArgs -Value ([pscustomobject]@{NewEvent=[pscustomobject]@{TargetInstance=$null}}) -Force
        $state = New-Wail2banState -NowUtc $now
        Invoke-Wail2banQueuedEvent $state $first $now
        $remaining = @(Get-Event -SourceIdentifier $queueName)
        Assert-True ($remaining.Count -eq 1 -and $remaining[0].EventIdentifier -eq $second.EventIdentifier) 'processing one event preserves queued sibling'
    } finally { Get-Event -ErrorAction SilentlyContinue | Where-Object { $_.SourceIdentifier -eq $queueName } | Remove-Event }

    Set-Item Function:Get-Wail2banEventAttempt -Value $script:ActualGetAttempt
    $script:EventReadFails = $true
    function Get-WinEvent {
        param($LogName,$FilterXPath,$MaxEvents,$ErrorAction)
        if ($script:EventReadFails) { throw 'mock permission failure' }
        $record = [pscustomobject]@{Message='safe test'}
        $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $script:EventXml }
        return $record
    }
    $target.RecordNumber = 88
    $queued = [pscustomobject]@{EventIdentifier=999999;SourceEventArgs=[pscustomobject]@{NewEvent=[pscustomobject]@{TargetInstance=$target}}}
    $state = New-Wail2banState -NowUtc $now
    Invoke-Wail2banQueuedEvent $state $queued $now
    Assert-True ($state.Faults.ContainsKey('event-read') -and (New-Wail2banSnapshot $state $now).Status -eq 'Degraded') 'Event Log IO failure degrades monitor'
    $script:EventReadFails = $false
    $script:EventXml = New-TestXml -RecordId 88 -Data '<Data Name="IpAddress">-</Data>'
    Invoke-Wail2banQueuedEvent $state $queued $now
    Assert-True (-not $state.Faults.ContainsKey('event-read') -and $state.Counters.Skipped -eq 2) 'successful read clears IO fault even unsupported source'

    Add-Type -TypeDefinition @'
using System;
using System.Collections;
public sealed class Wail2banTestRule {
    public string Name {get;set;}
    public string Description {get;set;}
    public bool Enabled {get;set;}
    public int Action {get;set;}
    public int Direction {get;set;}
    public int Protocol {get;set;}
    public int Profiles {get;set;}
    public string RemoteAddresses {get;set;}
    public string LocalAddresses {get;set;}
    public string LocalPorts {get;set;}
    public string RemotePorts {get;set;}
    public string ApplicationName {get;set;}
    public string ServiceName {get;set;}
    public string InterfaceTypes {get;set;}
    public object Interfaces {get;set;}
    public Wail2banTestRule() {LocalAddresses="*";LocalPorts="*";RemotePorts="*";InterfaceTypes="All";}
}
public sealed class Wail2banTestRules : CollectionBase {
    public bool IgnoreAdd;
    public bool IgnoreRemove;
    public void Add(Wail2banTestRule rule) {if(!IgnoreAdd) List.Add(rule);}
    public void Remove(string name) {if(IgnoreRemove)return;for(int i=List.Count-1;i>=0;i--)if(((Wail2banTestRule)List[i]).Name==name)List.RemoveAt(i);}
}
'@
    $script:Policy = [pscustomobject]@{Rules=(New-Object Wail2banTestRules)}
    function New-Wail2banFirewallPolicy { return $script:Policy }
    function New-Wail2banFirewallRuleObject { return (New-Object Wail2banTestRule) }
    Set-Item Function:Get-Wail2banFirewallRules -Value $script:ActualGetFirewall
    & $script:ActualAddFirewall '203.0.113.20' ($now.AddMinutes(5))
    $fakeRule = @($script:Policy.Rules)[0]
    Assert-True ($fakeRule.Enabled -and $fakeRule.Action -eq 0 -and $fakeRule.Direction -eq 1 -and $fakeRule.Protocol -eq 256 -and $fakeRule.Profiles -eq 2147483647) 'adapter constructs full inbound block and verifies it'
    $fakeRule.RemoteAddresses = '203.0.113.20/32'
    Assert-True (@(Get-Wail2banFirewallRules).Count -eq 1) 'single host slash32 firewall address accepted'
    $fakeRule.RemoteAddresses = '203.0.113.20/255.255.255.255'
    Assert-True (@(Get-Wail2banFirewallRules).Count -eq 1) 'single host netmask firewall address accepted'
    $fakeRule.Protocol = 6; $fakeRule.LocalPorts = '22'
    Assert-Throws { Get-Wail2banFirewallRules } 'restricted protocol and port rule not accepted as full ban'
    $fakeRule.Protocol = 256; $fakeRule.LocalPorts = '*'; $fakeRule.Profiles = 1
    Assert-Throws { Get-Wail2banFirewallRules } 'restricted profile rule not accepted'
    $fakeRule.Profiles = 2147483647; $fakeRule.ApplicationName = 'C:\only-this.exe'
    Assert-Throws { Get-Wail2banFirewallRules } 'restricted application rule not accepted'
    $fakeRule.ApplicationName = ''; $fakeRule.ServiceName = 'service'
    Assert-Throws { Get-Wail2banFirewallRules } 'restricted service rule not accepted'
    $fakeRule.ServiceName = ''; $fakeRule.InterfaceTypes = 'Wireless'
    Assert-Throws { Get-Wail2banFirewallRules } 'restricted interface rule not accepted'
    $fakeRule.InterfaceTypes = 'All'; $fakeRule.LocalAddresses = '127.0.0.1'
    Assert-Throws { Get-Wail2banFirewallRules } 'restricted local address rule not accepted'
    $fakeRule.LocalAddresses = '*'
    $script:Policy.Rules.IgnoreRemove = $true
    Assert-Throws { & $script:ActualRemoveFirewall '203.0.113.20' } 'adapter refuses unconfirmed deletion'
    $script:Policy.Rules.IgnoreRemove = $false
    & $script:ActualRemoveFirewall '203.0.113.20'
    Assert-True (@(Get-Wail2banFirewallRules).Count -eq 0) 'adapter verifies successful deletion'
    $script:Policy.Rules.IgnoreAdd = $true
    Assert-Throws { & $script:ActualAddFirewall '203.0.113.20' ($now.AddMinutes(5)) } 'adapter refuses unconfirmed addition'

    $script:Tick = 0; $script:MaintenanceTicks = @(); $script:ControlTicks = @(); $script:Timeouts = @(); $script:PublishedStates = @(); $script:Unregistered = $false
    function Get-Wail2banMonotonicSeconds { return $script:Tick }
    function Get-Wail2banUtcNow { return $now.AddSeconds($script:Tick) }
    function Register-WmiEvent { param($Query,$SourceIdentifier,$ErrorAction); return $null }
    function Unregister-Event { param($SourceIdentifier,$ErrorAction); $script:Unregistered = $true }
    function Invoke-Wail2banMaintenance { param($State,$NowUtc); $script:MaintenanceTicks += $script:Tick }
    function Invoke-Wail2banControlQueue { param($State,$Root,$NowUtc); $script:ControlTicks += $script:Tick }
    function Publish-Wail2banStatus { param($State,$NowUtc,$Root); $script:PublishedStates += $State.Status }
    function Wait-Event {
        param($SourceIdentifier,$Timeout,$ErrorAction)
        $script:Timeouts += $Timeout
        $script:Tick++
        if ($script:Tick -gt 12) { throw 'mock end loop' }
        return [pscustomobject]@{EventIdentifier=$script:Tick}
    }
    function Invoke-Wail2banQueuedEvent { param($State,$QueuedEvent,$NowUtc); $State.Counters.Processed++ }
    $state = New-Wail2banState -NowUtc $now
    $settings = [pscustomobject]@{Events=@([pscustomobject]@{EventId=4625;Channel='Security'})}
    Assert-Throws { Start-Wail2banLoop $state $settings $tempRoot } 'loop exits on listener failure'
    Assert-True (($script:MaintenanceTicks -join ',') -eq '0,5,10' -and $state.Counters.Processed -eq 12) 'maintenance runs on schedule during continuous event load'
    Assert-True (($script:ControlTicks -join ',') -eq '0,5,10') 'control queue runs on schedule during continuous event load'
    Assert-True (@($script:Timeouts | Where-Object { $_ -lt 1 -or $_ -gt 5 }).Count -eq 0) 'event wait timeout bounded by five seconds'
    Assert-True ($script:Unregistered -and $script:PublishedStates[-1] -eq 'Stopped') 'listener shutdown unsubscribes and publishes stopped'

    Write-Output ('Core tests passed: ' + $script:Passed)
} finally {
    Get-ChildItem -LiteralPath $tempRoot -File | Remove-Item -Force
    Remove-Item -LiteralPath $tempRoot -Force
}
