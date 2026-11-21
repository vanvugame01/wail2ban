[CmdletBinding()]
param(
    [switch]$LibraryOnly,
    [switch]$Help,
    [ValidateSet('Menu','Status','Whitelist','Bans','Unban','UnbanAll','AddWhitelist','RemoveWhitelist','OpenConfig','Log','Html','Start','Stop','Restart')]
    [string]$Action = 'Menu'
)

# Giu tham so menu vi dot-source script chinh co cac tham so trung ten.
$adminLibraryOnly = $LibraryOnly
$adminHelp = $Help
$adminAction = $Action
. (Join-Path $PSScriptRoot 'wail2ban.ps1') -LibraryOnly
. (Join-Path $PSScriptRoot 'wail2ban_configuration.ps1')

function Read-Wail2banAdminInput {
    param([string]$Prompt)
    return (Read-Host -Prompt $Prompt)
}

function Get-Wail2banAdminMenuText {
    return @'
WAIL2BAN - QUẢN TRỊ
 1. Xem trạng thái bảo vệ
 2. Xem whitelist đã nạp và đang lưu
 3. Xem IP bị chặn
 4. Gỡ chặn một IPv4
 5. Gỡ chặn tất cả IP thuộc Wail2ban
 6. Thêm IP/CIDR vào whitelist
 7. Xóa một mục whitelist
 8. Mở cấu hình bằng Notepad
 9. Xem 100 dòng nhật ký gần nhất
10. Mở báo cáo HTML
11. Khởi động bảo vệ
12. Dừng bảo vệ
13. Chạy lại bảo vệ
 0. Thoát menu (không dừng bảo vệ)
'@
}

function Assert-Wail2banAdminPermission {
    if (-not (Test-Wail2banAdministrator)) {
        throw 'Thao tác này cần quyền quản trị. Mở admin_wail2ban.bat bằng Run as administrator; menu không tự nâng quyền.'
    }
}

function Confirm-Wail2banAdminChange {
    param([string]$Description)
    Assert-Wail2banAdminPermission
    Write-Host $Description
    $answer = Read-Wail2banAdminInput 'Nhập đúng "tôi đồng ý" để thực hiện, nhập khác để hủy'
    return [string]::Equals($answer, 'tôi đồng ý', [StringComparison]::Ordinal)
}

function Write-Wail2banAdminResult {
    param($Result)
    if ($null -eq $Result) { throw 'Không nhận được kết quả thao tác.' }
    Write-Output ('Kết quả [{0}]: {1}' -f (ConvertTo-Wail2banTerminalText $Result.Status), (ConvertTo-Wail2banTerminalText $Result.Message))
    if ($null -ne $Result.PSObject.Properties['ReleasedIps'] -and @($Result.ReleasedIps).Count -gt 0) { Write-Output ('IP đã gỡ chặn: {0}' -f ((@($Result.ReleasedIps) | ForEach-Object { ConvertTo-Wail2banTerminalText $_ }) -join ', ')) }
    if ($null -ne $Result.PSObject.Properties['FailedIps'] -and @($Result.FailedIps).Count -gt 0) { Write-Output ('IP chưa gỡ được, giữ lịch sử: {0}' -f ((@($Result.FailedIps) | ForEach-Object { ConvertTo-Wail2banTerminalText $_ }) -join ', ')) }
    if ($Result.RequestId) { Write-Output ('Mã yêu cầu: {0}' -f (ConvertTo-Wail2banTerminalText $Result.RequestId)) }
    if ($Result.Status -eq 'Pending') { Write-Output 'Chưa xác nhận hoàn tất. Không gửi lại hoặc khởi động thêm tiến trình; kiểm tra trạng thái và nhật ký.' }
}

function Write-Wail2banAdminLog {
    param([string]$Root, [string]$Message)
    try {
        Add-Content -LiteralPath (Join-Path $Root 'wail2ban_log.log') -Value ('{0} [Admin] {1}' -f [datetime]::UtcNow.ToString('o'), $Message) -Encoding UTF8 -ErrorAction Stop
    } catch { Write-Output 'Thao tác đã hoàn tất nhưng không ghi được nhật ký quản trị.' }
}

function Get-Wail2banAdminWhitelistText {
    param([string]$Root)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $control = Get-Wail2banControlStatus -Root $Root
    $snapshot = $control.Snapshot
    $view = if ($null -ne $snapshot) { Get-Wail2banWhitelistView $snapshot } else { $null }
    if ($null -eq $view) { $lines.Add('Snapshot chưa có dữ liệu whitelist đã nạp. Cập nhật và chạy chương trình bảo vệ để kiểm tra.') }
    else {
        $stateLabels = @{Running='đang chạy';Stopped='đã dừng';Legacy='bản cũ';Unknown='chưa xác minh'}
        $stateLabel = if ($stateLabels.ContainsKey([string]$control.State)) { $stateLabels[[string]$control.State] } else { 'chưa xác minh' }
        $lines.Add(('Whitelist trong snapshot gần nhất ({0}):' -f $stateLabel))
        $lines.Add(('Tệp đã nạp: {0} | Nạp lúc UTC: {1}' -f (ConvertTo-Wail2banTerminalText $view.ConfigPath),$view.LoadedAtUtc))
        foreach ($entry in $view.Whitelist) { $lines.Add(('  {0}' -f (ConvertTo-Wail2banTerminalText $entry))) }
        if ($view.Whitelist.Count -eq 0) { $lines.Add('  Chưa cấu hình whitelist bổ sung.') }
        $lines.Add('IP máy chủ tự miễn chặn:')
        foreach ($entry in $view.SelfList) { $lines.Add(('  {0}' -f (ConvertTo-Wail2banTerminalText $entry))) }
    }
    try { $document = Read-Wail2banConfigurationDocument -Path (Join-Path $Root 'wail2ban_config.ini') }
    catch {
        $lines.Add(('Không đọc/kiểm tra được cấu hình đang lưu: {0}' -f (ConvertTo-Wail2banTerminalText $_.Exception.Message)))
        return $lines.ToArray() -join [environment]::NewLine
    }
    $lines.Add('Whitelist đang lưu trong INI:')
    $number = 0
    foreach ($entry in $document.WhitelistEntries) {
        $number++
        $lines.Add(('  {0}. {1} = {2}' -f $number,(ConvertTo-Wail2banTerminalText $entry.Address),(ConvertTo-Wail2banTerminalText $entry.Comment)))
    }
    if ($number -eq 0) { $lines.Add('  Chưa cấu hình whitelist bổ sung.') }
    if ($null -ne $view) {
        $loaded = [string]::Join("`n", [string[]]@($view.Whitelist | Sort-Object -Unique))
        $saved = [string]::Join("`n", [string[]]@($document.Whitelist | Sort-Object -Unique))
        if ($loaded -ne $saved) { $lines.Add('Whitelist đã thay đổi, cần chạy lại bảo vệ.') }
        elseif ($control.State -eq 'Running') { $lines.Add('Whitelist đang lưu khớp whitelist tiến trình đang sử dụng.') }
        else { $lines.Add('Danh sách khớp snapshot gần nhất; chưa xác nhận có tiến trình bảo vệ đang hoạt động.') }
    }
    return $lines.ToArray() -join [environment]::NewLine
}

function Open-Wail2banAdminFile {
    param([string]$Root, [ValidateSet('Config','Html')][string]$Kind)
    $path = if ($Kind -eq 'Config') { Join-Path $Root 'wail2ban_config.ini' } else { Join-Path $Root 'public_html\index.html' }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Chưa có tệp cần mở. Báo cáo HTML chỉ xuất hiện sau khi bảo vệ cập nhật trạng thái.' }
    if ($Kind -eq 'Config') {
        $notepadPath = Join-Path $env:SystemRoot 'System32\notepad.exe'
        Start-Process -FilePath $notepadPath -ArgumentList ('"{0}"' -f $path) -ErrorAction Stop
    } else { Start-Process -FilePath $path -ErrorAction Stop }
}

function Invoke-Wail2banAdminAction {
    param([string]$Root, [string]$Action)
    switch ($Action) {
        'Status' {
            $control = Get-Wail2banControlStatus -Root $Root
            Write-Output ('Điều khiển: {0}' -f (ConvertTo-Wail2banTerminalText $control.Message))
            Write-Output (Get-Wail2banMonitorText -Snapshot $control.Snapshot)
        }
        'Whitelist' { Write-Output (Get-Wail2banAdminWhitelistText $Root) }
        'Bans' {
            if (Test-Wail2banAdministrator) {
                $rules = @(Get-Wail2banFirewallRules)
                Write-Output ('Rule Wail2ban hiện tại: {0}' -f $rules.Count)
                foreach ($rule in $rules) {
                    $expiry = if ($null -eq $rule.ExpiresAtUtc) { 'không xác định' } else { $rule.ExpiresAtUtc.ToUniversalTime().ToString('o') }
                    Write-Output ('{0} | Hết hạn UTC: {1}' -f (ConvertTo-Wail2banTerminalText $rule.Ip),$expiry)
                }
            } else {
                Write-Output 'Chưa có quyền đọc firewall trực tiếp; dữ liệu dưới đây lấy từ snapshot gần nhất.'
                $control = Get-Wail2banControlStatus -Root $Root
                Write-Output (Get-Wail2banMonitorText -Snapshot $control.Snapshot)
            }
        }
        'Unban' {
            Assert-Wail2banAdminPermission
            $ip = ConvertTo-Wail2banIPv4 (Read-Wail2banAdminInput 'IPv4 cần gỡ chặn')
            if (-not $ip) { throw 'IPv4 không hợp lệ; không thực hiện lệnh.' }
            if (Confirm-Wail2banAdminChange ('Gỡ chặn IP {0}, xóa lịch sử phạt và lần thất bại đang ghi nhận cho IP này.' -f $ip)) {
                Write-Wail2banAdminResult (Invoke-Wail2banManagedUnban -Root $Root -Ip $ip -TimeoutSeconds 15)
            } else { Write-Output 'Đã hủy.' }
        }
        'UnbanAll' {
            if (Confirm-Wail2banAdminChange 'Gỡ tất cả IP thuộc Wail2ban; xóa lịch sử phạt tương ứng với những IP gỡ thành công.') {
                Write-Wail2banAdminResult (Invoke-Wail2banManagedUnban -Root $Root -All -TimeoutSeconds 15)
            } else { Write-Output 'Đã hủy.' }
        }
        'AddWhitelist' {
            Assert-Wail2banAdminPermission
            $document = Read-Wail2banConfigurationDocument -Path (Join-Path $Root 'wail2ban_config.ini')
            $address = Read-Wail2banAdminInput 'IP hoặc CIDR cần thêm'
            $comment = Read-Wail2banAdminInput 'Ghi chú'
            $updated = Add-Wail2banWhitelistEntry -Document $document -Address $address -Comment $comment
            if (Confirm-Wail2banAdminChange ('Thêm whitelist {0}. Lưu cấu hình chưa áp dụng cho tiến trình đang chạy; không tự gỡ rule hiện có.' -f (ConvertTo-Wail2banTerminalText $address))) {
                $saved = Save-Wail2banConfigurationDocument -Document $updated
                Write-Output ('Đã lưu. Bản sao lưu: {0}' -f (ConvertTo-Wail2banTerminalText $saved.BackupPath))
                Write-Output 'Whitelist đã thay đổi, cần chạy lại bảo vệ.'
                Write-Wail2banAdminLog $Root 'Đã thêm một mục whitelist qua menu; chưa nạp lại bảo vệ.'
            } else { Write-Output 'Đã hủy; cấu hình không thay đổi.' }
        }
        'RemoveWhitelist' {
            Assert-Wail2banAdminPermission
            $document = Read-Wail2banConfigurationDocument -Path (Join-Path $Root 'wail2ban_config.ini')
            $number = 0
            foreach ($entry in $document.WhitelistEntries) { $number++; Write-Output ('{0}. {1} = {2}' -f $number,(ConvertTo-Wail2banTerminalText $entry.Address),(ConvertTo-Wail2banTerminalText $entry.Comment)) }
            if ($number -eq 0) { Write-Output 'Chưa có whitelist để xóa.'; return }
            $selected = 0
            if (-not [int]::TryParse((Read-Wail2banAdminInput 'Số thứ tự cần xóa'), [ref]$selected) -or $selected -lt 1 -or $selected -gt $number) { throw 'Số thứ tự không hợp lệ.' }
            $address = $document.WhitelistEntries[$selected - 1].Address
            $updated = Remove-Wail2banWhitelistEntry -Document $document -Index ($selected - 1)
            if (Confirm-Wail2banAdminChange ('Xóa whitelist {0}. IP có thể bị chặn sau khi chạy lại bảo vệ.' -f (ConvertTo-Wail2banTerminalText $address))) {
                $saved = Save-Wail2banConfigurationDocument -Document $updated
                Write-Output ('Đã lưu. Bản sao lưu: {0}' -f (ConvertTo-Wail2banTerminalText $saved.BackupPath))
                Write-Output 'Whitelist đã thay đổi, cần chạy lại bảo vệ.'
                Write-Wail2banAdminLog $Root 'Đã xóa một mục whitelist qua menu; chưa nạp lại bảo vệ.'
            } else { Write-Output 'Đã hủy; cấu hình không thay đổi.' }
        }
        'OpenConfig' {
            if (Confirm-Wail2banAdminChange 'Mở cấu hình để chỉnh thủ công. Notepad không tự sao lưu hoặc kiểm tra cấu hình; cần chạy lại bảo vệ sau khi sửa.') { Open-Wail2banAdminFile $Root Config }
            else { Write-Output 'Đã hủy.' }
        }
        'Log' {
            $path = Join-Path $Root 'wail2ban_log.log'
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Write-Output 'Chưa có nhật ký.'; return }
            Get-Content -LiteralPath $path -Tail 100 -Encoding UTF8 -ErrorAction Stop | ForEach-Object { ConvertTo-Wail2banTerminalText $_ }
        }
        'Html' { Open-Wail2banAdminFile $Root Html }
        'Start' {
            if (Confirm-Wail2banAdminChange 'Khởi động bảo vệ. Tiến trình có thể tạo rule firewall khi phát hiện đăng nhập thất bại.') {
                Write-Wail2banAdminResult (Start-Wail2banManagedProtection -Root $Root -TimeoutSeconds 15)
            } else { Write-Output 'Đã hủy.' }
        }
        'Stop' {
            if (Confirm-Wail2banAdminChange 'Dừng bảo vệ có kiểm soát. Rule hiện có được giữ lại; khi đã dừng sẽ không tự phát hiện hoặc gỡ rule hết hạn.') {
                Write-Wail2banAdminResult (Stop-Wail2banManagedProtection -Root $Root -TimeoutSeconds 15)
            } else { Write-Output 'Đã hủy.' }
        }
        'Restart' {
            if (Confirm-Wail2banAdminChange 'Dừng rồi chạy lại bảo vệ để nạp cấu hình mới. Có khoảng gián đoạn phát hiện trong lúc chuyển phiên; rule hiện có được giữ lại.') {
                Write-Wail2banAdminResult (Restart-Wail2banManagedProtection -Root $Root -TimeoutSeconds 15)
            } else { Write-Output 'Đã hủy.' }
        }
        default { throw 'Lựa chọn không hợp lệ.' }
    }
}

function Clear-Wail2banAdminScreen {
    # Chi xoa man hinh tuong tac, khong chen ma dieu khien vao output chuyen huong.
    if (-not [Console]::IsOutputRedirected) { Clear-Host }
}

function Start-Wail2banAdminMenu {
    param([string]$Root)
    $actions = @('Status','Whitelist','Bans','Unban','UnbanAll','AddWhitelist','RemoveWhitelist','OpenConfig','Log','Html','Start','Stop','Restart')
    while ($true) {
        Clear-Wail2banAdminScreen
        Write-Output (Get-Wail2banAdminMenuText)
        $choice = Read-Wail2banAdminInput 'Chọn số'
        if ($null -eq $choice -or $choice -eq '0') { Write-Output 'Đã thoát menu; tiến trình bảo vệ không bị dừng.'; return }
        $number = 0
        Clear-Wail2banAdminScreen
        if (-not [int]::TryParse($choice, [ref]$number) -or $number -lt 1 -or $number -gt $actions.Count) { Write-Output 'Lựa chọn không hợp lệ.' }
        else {
            try { Invoke-Wail2banAdminAction -Root $Root -Action $actions[$number - 1] }
            catch { Write-Output ('Lỗi: {0}' -f (ConvertTo-Wail2banTerminalText $_.Exception.Message)) }
        }
        $null = Read-Wail2banAdminInput 'Nhấn Enter để quay lại menu'
    }
}

if ($adminLibraryOnly) { return }
if ($adminHelp) { Write-Output (Get-Wail2banAdminMenuText); return }
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Menu cần Windows PowerShell 5.1.' }
if ($adminAction -eq 'Menu') { Start-Wail2banAdminMenu -Root $PSScriptRoot }
else {
    try { Invoke-Wail2banAdminAction -Root $PSScriptRoot -Action $adminAction }
    catch { Write-Error ('Lỗi: {0}' -f (ConvertTo-Wail2banTerminalText $_.Exception.Message)); exit 1 }
}
