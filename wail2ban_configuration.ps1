# Cac ham chi sua whitelist, khong nap lai tien trinh hoac thao tac firewall.
function Get-Wail2banConfigurationBytesHash {
    param([byte[]]$Bytes)
    $algorithm = [security.cryptography.sha256]::Create()
    try { return [bitconverter]::ToString($algorithm.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

function Get-Wail2banConfigurationEncoding {
    param([byte[]]$Bytes)
    $codePage = [text.encoding]::Default.CodePage
    $preambleLength = 0
    if ($Bytes.Length -ge 4 -and $Bytes[0] -eq 255 -and $Bytes[1] -eq 254 -and $Bytes[2] -eq 0 -and $Bytes[3] -eq 0) { $codePage = 12000; $preambleLength = 4 }
    elseif ($Bytes.Length -ge 4 -and $Bytes[0] -eq 0 -and $Bytes[1] -eq 0 -and $Bytes[2] -eq 254 -and $Bytes[3] -eq 255) { $codePage = 12001; $preambleLength = 4 }
    elseif ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) { $codePage = 65001; $preambleLength = 3 }
    elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 255 -and $Bytes[1] -eq 254) { $codePage = 1200; $preambleLength = 2 }
    elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 254 -and $Bytes[1] -eq 255) { $codePage = 1201; $preambleLength = 2 }
    $encoding = [text.encoding]::GetEncoding($codePage, [text.encoderexceptionfallback]::new(), [text.decoderexceptionfallback]::new())
    [byte[]]$preamble = @()
    if ($preambleLength -gt 0) { $preamble = [byte[]]$Bytes[0..($preambleLength - 1)] }
    $content = $encoding.GetString($Bytes, $preambleLength, $Bytes.Length - $preambleLength)
    return [pscustomobject]@{EncodingCodePage=$codePage; Preamble=$preamble; Content=$content}
}

function Get-Wail2banWhitelistCanonicalAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address) -or $Address -match '[\x00-\x20\x7F`"'']') { throw 'IP/CIDR không hợp lệ; không dùng khoảng trắng, dấu nháy hoặc backtick quanh địa chỉ.' }
    $parts = $Address.Split('/')
    if ($parts.Count -gt 2) { throw 'CIDR không hợp lệ.' }
    $ip = ConvertTo-Wail2banIPv4 $parts[0]
    if (-not $ip) { throw 'Địa chỉ phải là IPv4 hợp lệ.' }
    $prefix = 32
    if ($parts.Count -eq 2) {
        if ($parts[1] -notmatch '^\d{1,2}$' -or -not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32) { throw 'CIDR phải có độ dài từ 0 đến 32.' }
    }
    $null = Test-Wail2banWhitelist '0.0.0.0' @($Address) @()
    $bytes = ([net.ipaddress]$ip).GetAddressBytes()
    for ($index = 0; $index -lt 4; $index++) {
        $bits = [math]::Min(8, [math]::Max(0, $prefix - 8 * $index))
        $mask = if ($bits -eq 0) { 0 } else { (255 -shl (8 - $bits)) -band 255 }
        $bytes[$index] = $bytes[$index] -band $mask
    }
    $network = ([net.ipaddress]::new($bytes)).ToString()
    if ($prefix -eq 32) { return $network }
    return '{0}/{1}' -f $network, $prefix
}

function Get-Wail2banConfigurationLayout {
    param([string]$Content)
    $lines = @(); $entries = @(); $section = ''; $headerIndex = -1; $sectionEnd = $Content.Length; $canonical = @{}
    foreach ($match in [regex]::Matches($Content, '[^\r\n]*(?:\r\n|\n|\r|$)')) {
        if ($match.Length -eq 0) { continue }
        $text = $match.Value -replace '(\r\n|\n|\r)$', ''
        $lineIndex = $lines.Count
        $lines += [pscustomobject]@{Text=$text; StartIndex=$match.Index; FullLength=$match.Length}
        $trimmed = $text.Trim()
        if ($trimmed -match '^\[(?<Section>[^\]]+)\]$') {
            if ($section -eq 'Whitelist' -and $sectionEnd -eq $Content.Length) { $sectionEnd = $match.Index }
            $section = $Matches.Section
            if ($section -eq 'Whitelist') {
                if ($headerIndex -ge 0) { throw 'Cấu hình có nhiều mục [Whitelist]; cần giữ một mục duy nhất.' }
                $headerIndex = $lineIndex
            }
            continue
        }
        if ($section -ne 'Whitelist' -or -not $trimmed -or $trimmed.StartsWith('#') -or $trimmed.StartsWith(';')) { continue }
        if ($trimmed -notmatch '^(?<Address>[^=]+)=(?<Comment>.*)$') { throw 'Dòng whitelist không hợp lệ.' }
        $address = $Matches.Address.Trim(); $comment = $Matches.Comment.Trim()
        $key = Get-Wail2banWhitelistCanonicalAddress $address
        if ($canonical.ContainsKey($key)) { throw ('Whitelist bị trùng địa chỉ hoặc mạng: {0}.' -f $address) }
        $canonical[$key] = $true
        $entries += [pscustomobject]@{Address=$address; Comment=$comment; LineIndex=$lineIndex; CanonicalAddress=$key; StartIndex=$match.Index; FullLength=$match.Length}
    }
    return [pscustomobject]@{Lines=@($lines); Entries=@($entries); HeaderIndex=$headerIndex; SectionEnd=$sectionEnd}
}

function New-Wail2banConfigurationDocumentCopy {
    param($Document, [string]$Content)
    $layout = Get-Wail2banConfigurationLayout $Content
    return [pscustomobject]@{
        Path=$Document.Path; Content=$Content; OriginalContent=$Document.OriginalContent
        OriginalBytes=[byte[]]$Document.OriginalBytes.Clone(); Hash=$Document.Hash
        EncodingCodePage=$Document.EncodingCodePage; Preamble=[byte[]]$Document.Preamble.Clone(); NewLine=$Document.NewLine
        WhitelistEntries=@($layout.Entries); Whitelist=@($layout.Entries | ForEach-Object { $_.Address })
    }
}

function Read-Wail2banConfigurationDocument {
    param([Parameter(Mandatory=$true)][string]$Path)
    $resolvedPath = [io.path]::GetFullPath($Path)
    $readStream = [io.file]::Open($resolvedPath, [io.filemode]::Open, [io.fileaccess]::Read, [io.fileshare]::Read)
    $memory = New-Object io.memorystream
    try {
        $readStream.CopyTo($memory)
        $bytes = $memory.ToArray()
        $decoded = Get-Wail2banConfigurationEncoding $bytes
        $null = Get-Wail2banConfiguration -Path $resolvedPath
    } finally { $memory.Dispose(); $readStream.Dispose() }
    $newLine = [environment]::NewLine
    $match = [regex]::Match($decoded.Content, '\r\n|\n|\r')
    if ($match.Success) { $newLine = $match.Value }
    $source = [pscustomobject]@{
        Path=$resolvedPath; OriginalContent=$decoded.Content; OriginalBytes=$bytes
        Hash=(Get-Wail2banConfigurationBytesHash $bytes); EncodingCodePage=$decoded.EncodingCodePage; Preamble=$decoded.Preamble; NewLine=$newLine
    }
    return New-Wail2banConfigurationDocumentCopy -Document $source -Content $decoded.Content
}

function Add-Wail2banWhitelistEntry {
    param([Parameter(Mandatory=$true)]$Document, [Parameter(Mandatory=$true)][string]$Address, [AllowEmptyString()][string]$Comment = '')
    $canonical = Get-Wail2banWhitelistCanonicalAddress $Address
    if ($Comment -match '[\x00-\x1F\x7F]') { throw 'Ghi chú không được chứa xuống dòng hoặc ký tự điều khiển.' }
    foreach ($entry in $Document.WhitelistEntries) {
        if ($entry.CanonicalAddress -eq $canonical) { throw 'Địa chỉ hoặc mạng này đã có trong whitelist.' }
    }
    $layout = Get-Wail2banConfigurationLayout $Document.Content
    $position = $layout.SectionEnd
    $prefix = ''
    if ($position -gt 0 -and $Document.Content[$position - 1] -notin @([char]10,[char]13)) { $prefix = $Document.NewLine }
    $hasFinalNewLine = $Document.Content -match '(\r\n|\n|\r)$'
    $suffix = if ($position -lt $Document.Content.Length -or $hasFinalNewLine) { $Document.NewLine } else { '' }
    $header = if ($layout.HeaderIndex -lt 0) { '[Whitelist]' + $Document.NewLine } else { '' }
    $line = $canonical + ' = ' + $Comment.Trim()
    $content = $Document.Content.Insert($position, $prefix + $header + $line + $suffix)
    return New-Wail2banConfigurationDocumentCopy -Document $Document -Content $content
}

function Remove-Wail2banWhitelistEntry {
    param([Parameter(Mandatory=$true)]$Document, [Parameter(Mandatory=$true)][int]$Index)
    if ($Index -lt 0 -or $Index -ge $Document.WhitelistEntries.Count) { throw 'Số thứ tự whitelist không hợp lệ.' }
    $entry = $Document.WhitelistEntries[$Index]
    $content = $Document.Content.Remove($entry.StartIndex, $entry.FullLength)
    if ($Document.Content -notmatch '(\r\n|\n|\r)$' -and $content -match '(\r\n|\n|\r)$') { $content = [regex]::Replace($content, '(\r\n|\n|\r)$', '') }
    return New-Wail2banConfigurationDocumentCopy -Document $Document -Content $content
}

function Save-Wail2banConfigurationDocument {
    param([Parameter(Mandatory=$true)]$Document)
    $administratorCheck = Get-Command -Name Test-Wail2banAdministrator -CommandType Function -ErrorAction SilentlyContinue
    if ($null -eq $administratorCheck -or -not (Test-Wail2banAdministrator)) { throw 'Cần quyền quản trị để lưu cấu hình whitelist.' }
    $path = [io.path]::GetFullPath($Document.Path)
    $temporary = $path + '.wail2ban-' + [guid]::NewGuid().ToString('N') + '.tmp'
    $lock = $null; $source = $null; $restoreTemporary = $null
    try {
        $encoding = [text.encoding]::GetEncoding([int]$Document.EncodingCodePage, [text.encoderexceptionfallback]::new(), [text.decoderexceptionfallback]::new())
        try { [byte[]]$candidate = [byte[]]$Document.Preamble + $encoding.GetBytes($Document.Content) }
        catch { throw 'Mã hóa hiện tại không biểu diễn được ký tự mới. Hãy lưu cấu hình bằng UTF-8 có BOM rồi mở lại menu.' }
        $candidateHash = Get-Wail2banConfigurationBytesHash $candidate
        # Kiem tra lai cau truc va toan bo cau hinh truoc khi cham vao file dich.
        $null = Get-Wail2banConfigurationLayout $Document.Content
        [io.file]::WriteAllBytes($temporary, $candidate)
        $null = Get-Wail2banConfiguration -Path $temporary
        $watch = [diagnostics.stopwatch]::StartNew()
        while ($null -eq $lock) {
            try { $lock = [io.file]::Open($path + '.wail2ban.lock', [io.filemode]::OpenOrCreate, [io.fileaccess]::ReadWrite, [io.fileshare]::None) }
            catch [io.ioexception] {
                if ($watch.Elapsed.TotalSeconds -ge 3) { throw 'Một phiên quản trị khác đang lưu cấu hình; hãy thử lại sau.' }
                Start-Sleep -Milliseconds 50
            }
        }
        if ((Get-Wail2banConfigurationBytesHash ([io.file]::ReadAllBytes($path))) -ne $Document.Hash) { throw 'File cấu hình đã thay đổi bên ngoài. Mở lại danh sách trước khi lưu.' }
        # Giu file nguon khong cho ghi truc tiep trong luc tao backup va thay the.
        $source = [io.file]::Open($path, [io.filemode]::Open, [io.fileaccess]::Read, ([io.fileshare]::Read -bor [io.fileshare]::Delete))
        $backupPath = $path + '.backup-' + [datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N') + '.ini'
        if ((Get-Wail2banConfigurationBytesHash ([io.file]::ReadAllBytes($path))) -ne $Document.Hash) { throw 'File cấu hình đã thay đổi bên ngoài. Mở lại danh sách trước khi lưu.' }
        # Backup cung thao tac nguyen tu de giu dung phien ban thuc te bi thay the.
        [io.file]::Replace($temporary, $path, $backupPath)
        try { $capturedHash = Get-Wail2banConfigurationBytesHash ([io.file]::ReadAllBytes($backupPath)) }
        catch { throw ('Không xác minh được phiên bản vừa thay thế. Giữ nguyên các file để kiểm tra; bản khôi phục: {0}.' -f $backupPath) }
        if ($capturedHash -ne $Document.Hash) {
            $message = 'Phát hiện xung đột cấu hình ngay lúc lưu; không báo lưu thành công. Bản thay đổi bên ngoài được giữ tại: ' + $backupPath + '.'
            $rollbackBackupPath = $null
            try {
                if ((Get-Wail2banConfigurationBytesHash ([io.file]::ReadAllBytes($path))) -eq $candidateHash) {
                    $restoreTemporary = $path + '.wail2ban-restore-' + [guid]::NewGuid().ToString('N') + '.tmp'
                    [io.file]::Copy($backupPath, $restoreTemporary, $false)
                    $rollbackBackupPath = $path + '.conflict-current-' + [datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N') + '.ini'
                    # Chi thu khoi phuc mot lan, van chup lai file dich neu co them race.
                    [io.file]::Replace($restoreTemporary, $path, $rollbackBackupPath)
                    if ((Get-Wail2banConfigurationBytesHash ([io.file]::ReadAllBytes($rollbackBackupPath))) -eq $candidateHash) {
                        $message += ' Đã khôi phục thay đổi bên ngoài về file cấu hình. Hãy mở lại danh sách trước khi sửa tiếp.'
                    } else {
                        $message += ' Có thêm thay đổi bên ngoài trong lúc khôi phục. Không ghi thêm; cần đối chiếu và khôi phục thủ công từ: ' + $rollbackBackupPath + '.'
                    }
                } else { $message += ' File đích đã đổi tiếp; không ghi đè thêm. Hãy đối chiếu file hiện tại với bản khôi phục.' }
            } catch {
                $message += ' Không thể xác nhận khôi phục an toàn; không ghi thêm. Hãy đối chiếu file hiện tại và bản khôi phục.'
                if ($rollbackBackupPath -and [io.file]::Exists($rollbackBackupPath)) { $message += ' Bản file đích trước khôi phục: ' + $rollbackBackupPath + '.' }
            }
            throw $message
        }
        return [pscustomobject]@{Path=$path; BackupPath=$backupPath}
    } finally {
        if ($null -ne $source) { $source.Dispose() }
        if ($null -ne $lock) { $lock.Dispose() }
        if ([io.file]::Exists($temporary)) { [io.file]::Delete($temporary) }
        if ($restoreTemporary -and [io.file]::Exists($restoreTemporary)) { [io.file]::Delete($restoreTemporary) }
    }
}
