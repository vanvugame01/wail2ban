# Cac ham dieu khien chi thao tac IO khi duoc goi ro rang.
function Test-Wail2banAdministrator {
    try {
        $identity = [security.principal.windowsidentity]::GetCurrent()
        return (New-Object security.principal.windowsprincipal($identity)).IsInRole([security.principal.windowsbuiltinrole]::Administrator)
    } catch { return $false }
}

function New-Wail2banControlResult {
    param([string]$Status, [string]$Message, [string]$RequestId, [string[]]$ReleasedIps = @(), [string[]]$FailedIps = @())
    return [pscustomobject]@{ Success = ($Status -eq 'Completed'); Status = $Status; Message = $Message; RequestId = $RequestId; ReleasedIps = @($ReleasedIps); FailedIps = @($FailedIps) }
}

function New-Wail2banProtectionMutex { return (New-Object threading.mutex($false, 'Global\Wail2ban.Protection')) }

function Enter-Wail2banProtectionLock {
    $mutex = $null
    try {
        $mutex = New-Wail2banProtectionMutex
        $owned = $false
        try { $owned = $mutex.WaitOne(0) } catch [threading.abandonedmutexexception] { $owned = $true }
        return [pscustomobject]@{ Mutex = $mutex; Owned = $owned }
    } catch {
        if ($null -ne $mutex) { $mutex.Dispose() }
        throw 'Không thể kiểm tra khóa Wail2ban; không thực hiện thao tác thay đổi.'
    }
}

function Exit-Wail2banProtectionLock {
    param($Lease)
    if ($null -eq $Lease) { return }
    try { if ($Lease.Owned) { $Lease.Mutex.ReleaseMutex() } } finally { $Lease.Mutex.Dispose() }
}

function Test-Wail2banProtectionLockBusy {
    $lease = Enter-Wail2banProtectionLock
    try { return (-not $lease.Owned) } finally { Exit-Wail2banProtectionLock $lease }
}

function Get-Wail2banProtectionProcessRecords {
    return @(Get-CimInstance -ClassName Win32_Process -Filter "Name='powershell.exe' OR Name='powershell_ise.exe' OR Name='pwsh.exe'" -OperationTimeoutSec 3 -ErrorAction Stop | Where-Object {
        if ($_.ProcessId -eq $PID) { return $false }
        $command = [string]$_.CommandLine
        $fileInvocation = $command -match '(?i)(?:^|\s)-(?:File|f)\s+(?:"(?:[^"\r\n]*[\\/])?wail2ban\.ps1"|(?:[^\s"]*[\\/])?wail2ban\.ps1)(?:\s|$)'
        $readOnlyInvocation = $fileInvocation -and $command -match '(?i)(?:^|\s)-(?:Config|Jail|Jailbreak|Unban|Help|LibraryOnly)(?:\s|$)'
        $commandInvocation = $command -match '(?i)(?:^|\s)-(?:Command|c)\s+.*wail2ban\.ps1(?:\b|["''])'
        return (($fileInvocation -and -not $readOnlyInvocation) -or $commandInvocation)
    })
}

function Get-Wail2banProcessRecord {
    param([int]$ProcessId)
    if ($ProcessId -le 0) { return $null }
    return (Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId={0}" -f $ProcessId) -OperationTimeoutSec 3 -ErrorAction Stop)
}

function Test-Wail2banProcessRoot {
    param($ProcessRecord, [string]$Root)
    $scriptPath = [io.path]::GetFullPath((Join-Path $Root 'wail2ban.ps1'))
    $escaped = [regex]::Escape($scriptPath)
    return ([string]$ProcessRecord.CommandLine -match ('(?i)(?:^|\s)-(?:File|f)\s+(?:"' + $escaped + '"|' + $escaped + ')(?:\s|$)'))
}

function Get-Wail2banControlStatus {
    param([Parameter(Mandatory=$true)][string]$Root)
    $snapshot = $null
    try {
        $rootPath = [io.path]::GetFullPath($Root).TrimEnd('\')
        $snapshot = Read-Wail2banSnapshot (Join-Path $rootPath 'runtime\wail2ban_status.json')
        $records = @(Get-Wail2banProtectionProcessRecords)
        $matching = @($records | Where-Object { Test-Wail2banProcessRoot $_ $rootPath })
        if ($null -ne $snapshot) {
            $process = @($matching | Where-Object { $_.ProcessId -eq $snapshot.ProcessId })
            if ($process.Count -eq 1) {
                if ($snapshot.Status -eq 'Stopped') { return [pscustomobject]@{State='Unknown';Snapshot=$snapshot;Message='Tiến trình đang hoàn tất dừng; chờ xác nhận thoát.'} }
                if ($snapshot.ControlProtocolVersion -eq 1 -and [string]$snapshot.ControlRoot -eq $rootPath) {
                    return [pscustomobject]@{State='Running';Snapshot=$snapshot;Message='Tiến trình hỗ trợ điều khiển an toàn; kiểm tra heartbeat trên monitor.'}
                }
                return [pscustomobject]@{State='Legacy';Snapshot=$snapshot;Message='Bản cũ đang chạy; dừng cửa sổ bảo vệ cũ thủ công trước khi cập nhật.'}
            }
        }
        if ($records.Count -gt 0) { return [pscustomobject]@{State='Legacy';Snapshot=$snapshot;Message='Có tiến trình bảo vệ chưa xác minh được phiên hoặc thuộc thư mục khác; không khởi động thêm.'} }
        if ($null -ne $snapshot -and $null -ne (Get-Wail2banProcessRecord -ProcessId $snapshot.ProcessId)) {
            return [pscustomobject]@{State='Unknown';Snapshot=$snapshot;Message='PID trong snapshot vẫn tồn tại nhưng chưa xác minh được lệnh khởi chạy; không coi bảo vệ đã dừng.'}
        }
        if (Test-Wail2banProtectionLockBusy) { return [pscustomobject]@{State='Unknown';Snapshot=$snapshot;Message='Khóa bảo vệ đang bận; chưa xác định được tiến trình sở hữu.'} }
        return [pscustomobject]@{State='Stopped';Snapshot=$snapshot;Message='Không có tiến trình bảo vệ được phát hiện; khóa đang rảnh.'}
    } catch { return [pscustomobject]@{State='Unknown';Snapshot=$snapshot;Message='Không xác minh được tiến trình hoặc khóa bảo vệ; không thực hiện thay đổi.'} }
}

function Write-Wail2banControlJson {
    param([string]$Path, $Value)
    Write-Wail2banAtomicText -Path $Path -Content (ConvertTo-Json -InputObject $Value -Depth 8)
}

function Read-Wail2banControlJson {
    param([string]$Path)
    try {
        $info = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($info.Length -gt 65536) { return $null }
        return (ConvertFrom-Json -InputObject ([io.file]::ReadAllText($Path, [text.encoding]::UTF8)) -ErrorAction Stop)
    } catch { return $null }
}

function Get-Wail2banControlTime { return ([diagnostics.stopwatch]::GetTimestamp() / [double][diagnostics.stopwatch]::Frequency) }
function Wait-Wail2banControlPoll { Start-Sleep -Milliseconds 200 }

function New-Wail2banControlRequest {
    param([string]$Root, [string]$InstanceId, [ValidateSet('Stop','Unban','UnbanAll')][string]$Action, [string]$Ip)
    $requestId = [guid]::NewGuid().ToString('D')
    $request = [pscustomobject]@{SchemaVersion=1;RequestId=$requestId;InstanceId=$InstanceId;Action=$Action;Ip=$Ip;RequestedAtUtc=[datetime]::UtcNow.ToString('o')}
    Write-Wail2banControlJson -Path (Join-Path $Root ('runtime\control\requests\' + $requestId + '.json')) -Value $request
    return $request
}

function Wait-Wail2banControlResponse {
    param([string]$Root, [string]$RequestId, [string]$InstanceId, [ValidateRange(1,60)][int]$TimeoutSeconds=15, [switch]$WaitForStop)
    $deadline = (Get-Wail2banControlTime) + $TimeoutSeconds
    do {
        $response = Read-Wail2banControlJson (Join-Path $Root ('runtime\control\responses\' + $RequestId + '.json'))
        if ($null -ne $response -and $response.RequestId -eq $RequestId -and $response.InstanceId -eq $InstanceId -and
            $response.Status -in @('Completed','Partial','Failed','Rejected')) {
            $result = New-Wail2banControlResult $response.Status ([string]$response.Message) $RequestId @($response.ReleasedIps) @($response.FailedIps)
            if (-not $WaitForStop -or $response.Status -ne 'Completed') { return $result }
            $status = Get-Wail2banControlStatus -Root $Root
            if ($status.State -eq 'Stopped' -and $null -ne $status.Snapshot -and $status.Snapshot.InstanceId -eq $InstanceId -and $status.Snapshot.Status -eq 'Stopped') { return $result }
        }
        Wait-Wail2banControlPoll
    } while ((Get-Wail2banControlTime) -lt $deadline)
    return (New-Wail2banControlResult 'Pending' 'Chưa có xác nhận hoàn tất. Không gửi lại hoặc chạy lại bảo vệ tự động; kiểm tra trạng thái và mã yêu cầu.' $RequestId)
}

function Invoke-Wail2banManualUnban {
    param($State, [string]$Ip, [switch]$All, [datetime]$NowUtc = [datetime]::UtcNow)
    $normalized = if ($All) { $null } else { ConvertTo-Wail2banIPv4 $Ip }
    if (-not $All -and -not $normalized) { return (New-Wail2banControlResult 'Rejected' 'IPv4 cần gỡ không hợp lệ.') }
    try { $rules = @(Get-Wail2banFirewallRules) } catch { return (New-Wail2banControlResult 'Failed' 'Không đọc được firewall; chưa thay đổi lịch sử chặn.') }
    $targets = if ($All) { @(@($rules | ForEach-Object Ip) + @($State.BanCounts.Keys) | Sort-Object -Unique) } else { @($normalized) }
    $released = @(); $failed = @(); $completed = @()
    foreach ($target in $targets) {
        try {
            if (@($rules | Where-Object { $_.Ip -eq $target }).Count -gt 0) {
                Remove-Wail2banFirewallRule $target
                $released += $target; $State.Counters.Released++
            }
            $State.BanCounts.Remove($target)
            foreach ($key in @($State.Attempts.Keys)) { if ($State.Attempts[$key].Ip -eq $target) { $State.Attempts.Remove($key) } }
            foreach ($prefix in @('ban:','release:','expiry:')) { $State.Faults.Remove($prefix + $target) }
            $completed += $target
            Write-Wail2banLog $State 'Action' ('Đã gỡ chặn hoặc xóa lịch sử IP {0} theo yêu cầu quản trị viên.' -f $target) $NowUtc
        } catch {
            $failed += $target
            Add-Wail2banIssue $State ('Không gỡ chặn được IP {0}; giữ lịch sử tương ứng.' -f $target) Error $NowUtc
        }
    }
    $historySaved = $true
    if ($completed.Count -gt 0) {
        try { Save-Wail2banBanHistory $State; $State.Faults.Remove('history') }
        catch { $historySaved = $false; $State.Faults['history'] = $true; Add-Wail2banIssue $State 'Đã cập nhật bộ nhớ nhưng chưa lưu được lịch sử chặn; cần kiểm tra nhật ký.' Error $NowUtc }
    }
    $State.Bans = @($rules | Where-Object { $released -notcontains $_.Ip })
    $State.FirewallReadSucceeded = $true
    if ($failed.Count -eq 0 -and $historySaved) { return (New-Wail2banControlResult 'Completed' 'Đã hoàn tất gỡ chặn và cập nhật lịch sử.' $null $released $failed) }
    $outcome = if ($completed.Count -gt 0) { 'Partial' } else { 'Failed' }
    return (New-Wail2banControlResult $outcome 'Chỉ hoàn tất một phần hoặc chưa lưu được lịch sử; xem IP thất bại và nhật ký.' $null $released $failed)
}

function Complete-Wail2banControlResponse {
    param([string]$Root, $Request, $Result)
    $response = [pscustomobject]@{SchemaVersion=1;RequestId=$Request.RequestId;InstanceId=$Request.InstanceId;Success=$Result.Success;Status=$Result.Status;Message=$Result.Message;ReleasedIps=@($Result.ReleasedIps);FailedIps=@($Result.FailedIps);CompletedAtUtc=[datetime]::UtcNow.ToString('o')}
    Write-Wail2banControlJson -Path (Join-Path $Root ('runtime\control\responses\' + $Request.RequestId + '.json')) -Value $response
}

function Invoke-Wail2banControlQueue {
    param($State, [string]$Root, [datetime]$NowUtc)
    $directory = Join-Path $Root 'runtime\control\requests'
    if (-not [io.directory]::Exists($directory)) { return }
    try {
        $files = @(Get-ChildItem -LiteralPath $directory -Filter '*.json' -File -ErrorAction Stop | Where-Object {
            $_.BaseName -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -and
            -not [io.file]::Exists((Join-Path $Root ('runtime\control\responses\' + $_.Name)))
        } | Sort-Object CreationTimeUtc,Name | Select-Object -First 20)
        foreach ($file in $files) {
            $request = Read-Wail2banControlJson $file.FullName
            $valid = $null -ne $request -and $request.SchemaVersion -eq 1 -and $request.RequestId -eq $file.BaseName -and
                $request.Action -in @('Stop','Unban','UnbanAll') -and $null -ne (ConvertTo-Wail2banUtc $request.RequestedAtUtc)
            if (-not $valid) {
                $request = [pscustomobject]@{RequestId=$file.BaseName;InstanceId=$State.InstanceId}
                Complete-Wail2banControlResponse $Root $request (New-Wail2banControlResult 'Rejected' 'Yêu cầu điều khiển không hợp lệ.')
                continue
            }
            if ($request.InstanceId -ne $State.InstanceId) {
                Complete-Wail2banControlResponse $Root $request (New-Wail2banControlResult 'Rejected' 'Yêu cầu nhắm phiên bảo vệ cũ; không thực hiện.')
                continue
            }
            if ($request.Action -eq 'Unban' -and -not (ConvertTo-Wail2banIPv4 $request.Ip)) {
                Complete-Wail2banControlResponse $Root $request (New-Wail2banControlResult 'Rejected' 'IPv4 cần gỡ không hợp lệ.')
                continue
            }
            $journal = Join-Path $Root ('runtime\control\journal\' + $request.RequestId + '.json')
            if ([io.file]::Exists($journal)) {
                Complete-Wail2banControlResponse $Root $request (New-Wail2banControlResult 'Rejected' 'Yêu cầu đã bắt đầu xử lý trước đó nhưng chưa có kết quả xác nhận; không thực thi lặp.')
                continue
            }
            Write-Wail2banControlJson $journal ([pscustomobject]@{RequestId=$request.RequestId;InstanceId=$State.InstanceId;StartedAtUtc=$NowUtc.ToUniversalTime().ToString('o')})
            if ($request.Action -eq 'Stop') { $State.StopRequested=$true; $State.StopRequest=$request; break }
            $result = if ($request.Action -eq 'UnbanAll') { Invoke-Wail2banManualUnban -State $State -All -NowUtc $NowUtc } else { Invoke-Wail2banManualUnban -State $State -Ip $request.Ip -NowUtc $NowUtc }
            Complete-Wail2banControlResponse $Root $request $result
        }
        $State.Faults.Remove('control')
    } catch { $State.Faults['control']=$true; Add-Wail2banIssue $State 'Không xử lý được hàng đợi điều khiển; kiểm tra quyền ghi thư mục runtime.' Error $NowUtc }
}

function Start-Wail2banProtectionProcess {
    param([string]$Root, [string]$InstanceId)
    $scriptPath = [io.path]::GetFullPath((Join-Path $Root 'wail2ban.ps1'))
    $executable = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    return (Start-Process -FilePath $executable -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-File',('"' + $scriptPath + '"'),'-ManagedInstanceId',$InstanceId) -WorkingDirectory ([io.path]::GetFullPath($Root)) -WindowStyle Hidden -PassThru -ErrorAction Stop)
}

function Start-Wail2banManagedProtection {
    param([Parameter(Mandatory=$true)][string]$Root, [ValidateRange(1,60)][int]$TimeoutSeconds=15)
    if (-not (Test-Wail2banAdministrator)) { return (New-Wail2banControlResult 'Rejected' 'Cần mở menu bằng quyền quản trị để khởi động bảo vệ.') }
    $status = Get-Wail2banControlStatus $Root
    if ($status.State -ne 'Stopped') { return (New-Wail2banControlResult 'Rejected' ('Không khởi động thêm. ' + $status.Message)) }
    try {
        $null = Get-Wail2banConfiguration (Join-Path $Root 'wail2ban_config.ini')
        $instanceId = [guid]::NewGuid().ToString('D')
        $process = Start-Wail2banProtectionProcess $Root $instanceId
        $deadline = (Get-Wail2banControlTime) + $TimeoutSeconds
        do {
            $current = Get-Wail2banControlStatus $Root
            if ($current.State -eq 'Running' -and $current.Snapshot.InstanceId -eq $instanceId -and $current.Snapshot.ProcessId -eq $process.Id -and
                ([datetime]::UtcNow - (ConvertTo-Wail2banUtc $current.Snapshot.HeartbeatUtc)).TotalSeconds -le 30) {
                return (New-Wail2banControlResult 'Completed' ('Đã khởi động bảo vệ, phiên ' + $instanceId + '.'))
            }
            if ($process.HasExited) { return (New-Wail2banControlResult 'Failed' 'Tiến trình mới đã thoát trước khi xác nhận sẵn sàng; kiểm tra cấu hình, quyền và nhật ký.') }
            Wait-Wail2banControlPoll
        } while ((Get-Wail2banControlTime) -lt $deadline)
        return (New-Wail2banControlResult 'Pending' ('Chưa xác nhận khởi động phiên ' + $instanceId + '. Không khởi động thêm; xem trạng thái.'))
    } catch { return (New-Wail2banControlResult 'Failed' 'Không khởi động được bảo vệ; kiểm tra cấu hình, quyền và đường dẫn script.') }
}

function Stop-Wail2banManagedProtection {
    param([Parameter(Mandatory=$true)][string]$Root, [ValidateRange(1,60)][int]$TimeoutSeconds=15)
    if (-not (Test-Wail2banAdministrator)) { return (New-Wail2banControlResult 'Rejected' 'Cần quyền quản trị để dừng bảo vệ.') }
    $status = Get-Wail2banControlStatus $Root
    if ($status.State -eq 'Stopped') { return (New-Wail2banControlResult 'Completed' 'Bảo vệ đã dừng.') }
    if ($status.State -ne 'Running') { return (New-Wail2banControlResult 'Rejected' $status.Message) }
    try {
        $request = New-Wail2banControlRequest $Root $status.Snapshot.InstanceId 'Stop'
        return (Wait-Wail2banControlResponse $Root $request.RequestId $request.InstanceId $TimeoutSeconds -WaitForStop)
    } catch { return (New-Wail2banControlResult 'Failed' 'Không gửi được yêu cầu dừng; không cưỡng bức kết thúc tiến trình.') }
}

function Restart-Wail2banManagedProtection {
    param([Parameter(Mandatory=$true)][string]$Root, [ValidateRange(1,60)][int]$TimeoutSeconds=15)
    if (-not (Test-Wail2banAdministrator)) { return (New-Wail2banControlResult 'Rejected' 'Cần quyền quản trị để chạy lại bảo vệ.') }
    $stopped = Stop-Wail2banManagedProtection $Root $TimeoutSeconds
    if (-not $stopped.Success) { return $stopped }
    return (Start-Wail2banManagedProtection $Root $TimeoutSeconds)
}

function Invoke-Wail2banManagedUnban {
    [CmdletBinding(DefaultParameterSetName='Single')]
    param([Parameter(Mandatory=$true)][string]$Root, [Parameter(Mandatory=$true,ParameterSetName='Single')][string]$Ip,
        [Parameter(Mandatory=$true,ParameterSetName='All')][switch]$All, [ValidateRange(1,60)][int]$TimeoutSeconds=15)
    if (-not (Test-Wail2banAdministrator)) { return (New-Wail2banControlResult 'Rejected' 'Cần quyền quản trị để gỡ chặn.') }
    if (-not $All -and -not (ConvertTo-Wail2banIPv4 $Ip)) { return (New-Wail2banControlResult 'Rejected' 'IPv4 cần gỡ không hợp lệ.') }
    $status = Get-Wail2banControlStatus $Root
    if ($status.State -eq 'Running') {
        try {
            $action = if ($All) { 'UnbanAll' } else { 'Unban' }
            $request = New-Wail2banControlRequest $Root $status.Snapshot.InstanceId $action $Ip
            return (Wait-Wail2banControlResponse $Root $request.RequestId $request.InstanceId $TimeoutSeconds)
        } catch { return (New-Wail2banControlResult 'Failed' 'Không gửi được yêu cầu gỡ chặn.') }
    }
    if ($status.State -ne 'Stopped') { return (New-Wail2banControlResult 'Rejected' $status.Message) }
    $lease = $null
    try {
        $lease = Enter-Wail2banProtectionLock
        if (-not $lease.Owned -or @(Get-Wail2banProtectionProcessRecords).Count -gt 0) { return (New-Wail2banControlResult 'Rejected' 'Có tiến trình bảo vệ đang chạy hoặc khóa đang bận; không gỡ trực tiếp.') }
        $state = New-Wail2banState -LogPath (Join-Path $Root 'wail2ban_log.log') -HistoryPath (Join-Path $Root 'bannedIPLog.ini')
        Read-Wail2banBanHistory $state
        if ($All) { return (Invoke-Wail2banManualUnban $state -All) }
        return (Invoke-Wail2banManualUnban $state -Ip $Ip)
    } catch { return (New-Wail2banControlResult 'Failed' 'Không gỡ chặn được; kiểm tra khóa, lịch sử và firewall.') }
    finally { Exit-Wail2banProtectionLock $lease }
}
