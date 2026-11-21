$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'wail2ban.ps1') -LibraryOnly
. (Join-Path $root 'wail2ban_configuration.ps1')
$script:AdministratorAllowed = $true
function Test-Wail2banAdministrator { return $script:AdministratorAllowed }
$script:passed = 0
function Assert-Configuration {
    param([bool]$Condition, [string]$Name)
    if (-not $Condition) { throw ('FAIL: ' + $Name) }
    $script:passed++
    Write-Output ('PASS configuration: ' + $Name)
}
function Assert-ConfigurationThrows {
    param([scriptblock]$Action, [string]$Name)
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    Assert-Configuration $threw $Name
}
function Write-TestConfiguration {
    param([string]$Path, [string]$Content, [text.encoding]$Encoding = (New-Object text.UTF8Encoding($true)))
    [io.file]::WriteAllText($Path, $Content, $Encoding)
}

$temporaryRoot = Join-Path ([io.path]::GetTempPath()) ('wail2ban-configuration-tests-' + [guid]::NewGuid().ToString('N'))
$null = [io.directory]::CreateDirectory($temporaryRoot)
try {
    $path = Join-Path $temporaryRoot 'configuration with spaces.ini'
    $original = "# Ghi chú giữ nguyên`r`n[Security]`r`n4625 = RDP Logins`r`n`r`n[Whitelist]`r`n# Vi tri whitelist`r`n192.168.4.96 = Máy quản trị`r`n; Comment giu nguyen`r`n[Application]`r`n18456=MSSQL Logins`r`n"
    Write-TestConfiguration $path $original
    $originalBytes = [io.file]::ReadAllBytes($path)
    $document = Read-Wail2banConfigurationDocument $path
    Assert-Configuration ($document.WhitelistEntries.Count -eq 1 -and $document.WhitelistEntries[0].Address -eq '192.168.4.96') 'reads whitelist in file order'
    Assert-Configuration ($document.WhitelistEntries[0].Comment -eq 'Máy quản trị' -and $document.WhitelistEntries[0].LineIndex -eq 6) 'reads comment and zero based line index'
    Assert-Configuration ($document.Content -ceq $original -and $document.NewLine -ceq "`r`n") 'preserves complete CRLF source content'
    Assert-Configuration ($document.EncodingCodePage -eq 65001 -and $document.Preamble.Count -eq 3) 'detects UTF8 BOM'
    $updated = Add-Wail2banWhitelistEntry $document '10.10.10.1' 'Máy quản trị 2'
    Assert-Configuration ($updated.Whitelist.Count -eq 2 -and $document.Whitelist.Count -eq 1) 'editing returns separate in memory document'
    Assert-Configuration ((Get-Wail2banConfigurationBytesHash ([io.file]::ReadAllBytes($path))) -eq $document.Hash) 'editing does not write source file'
    Assert-Configuration ($updated.Content.Contains("10.10.10.1 = Máy quản trị 2`r`n[Application]`r`n18456=MSSQL Logins`r`n")) 'inserts entry inside whitelist before next section'
    Assert-Configuration ($updated.Content.StartsWith("# Ghi chú giữ nguyên`r`n[Security]`r`n4625 = RDP Logins`r`n`r`n[Whitelist]`r`n# Vi tri whitelist`r`n192.168.4.96 = Máy quản trị`r`n; Comment giu nguyen`r`n")) 'preserves unrelated sections and comments'
    Assert-Configuration ($updated.Hash -eq $document.Hash -and $updated.OriginalContent -ceq $original) 'keeps original identity for conflict checks'
    $saved = Save-Wail2banConfigurationDocument $updated
    Assert-Configuration ([io.file]::Exists($saved.BackupPath) -and $saved.Path -eq [io.path]::GetFullPath($path)) 'save returns backup and destination paths'
    Assert-Configuration ((Get-Wail2banConfigurationBytesHash ([io.file]::ReadAllBytes($saved.BackupPath))) -eq (Get-Wail2banConfigurationBytesHash $originalBytes)) 'backup is byte exact original'
    $loaded = Read-Wail2banConfigurationDocument $path
    Assert-Configuration ($loaded.Whitelist.Count -eq 2 -and $loaded.Content -ceq $updated.Content) 'atomic save persists valid candidate'
    Assert-Configuration ($loaded.EncodingCodePage -eq 65001 -and $loaded.Preamble.Count -eq 3 -and $loaded.NewLine -ceq "`r`n") 'save preserves encoding BOM and newline'

    $removed = Remove-Wail2banWhitelistEntry $loaded 0
    Assert-Configuration ($removed.Whitelist.Count -eq 1 -and $removed.Whitelist[0] -eq '10.10.10.1') 'remove uses zero based selected index'
    Assert-Configuration ($removed.Content.Contains('# Vi tri whitelist') -and $removed.Content.Contains('; Comment giu nguyen') -and $removed.Content.Contains('[Application]')) 'remove keeps comments and other sections'
    Assert-ConfigurationThrows { Remove-Wail2banWhitelistEntry $loaded -1 } 'rejects negative remove index'
    Assert-ConfigurationThrows { Remove-Wail2banWhitelistEntry $loaded 2 } 'rejects missing remove index'

    foreach ($badAddress in @('`192.168.4.96','192.168.4.96`','"192.168.4.96"',"'192.168.4.96'",'999.0.0.1','203.0.113.1/33','203.0.113.1/24/1','203.0.113.1;calc',' 203.0.113.1',"203.0.113.1`n")) {
        Assert-ConfigurationThrows { Add-Wail2banWhitelistEntry $loaded $badAddress 'test' } ('rejects invalid address ' + ($badAddress -replace '[\r\n]','?'))
    }
    Assert-ConfigurationThrows { Add-Wail2banWhitelistEntry $loaded '198.51.100.9' "comment`n[Security]`n99=bad" } 'rejects multiline comment injection'
    Assert-ConfigurationThrows { Add-Wail2banWhitelistEntry $loaded '198.51.100.9' ("comment" + [char]27 + '[31m') } 'rejects terminal control in comment'
    Assert-ConfigurationThrows { Add-Wail2banWhitelistEntry $loaded '192.168.4.96/32' 'duplicate' } 'rejects plain IP slash32 duplicate'
    $networkDocument = Add-Wail2banWhitelistEntry $loaded '203.0.113.99/24' 'Company network'
    Assert-Configuration ($networkDocument.Whitelist -contains '203.0.113.0/24') 'canonicalizes CIDR network bits'
    Assert-ConfigurationThrows { Add-Wail2banWhitelistEntry $networkDocument '203.0.113.1/24' 'duplicate network' } 'rejects equivalent CIDR network duplicate'
    $literalComment = '$(Write-Output injected) = text'
    $literalDocument = Add-Wail2banWhitelistEntry $loaded '198.51.100.9' $literalComment
    Assert-Configuration ($literalDocument.Content.Contains($literalComment)) 'comment metacharacters remain literal data'

    $conflict = Add-Wail2banWhitelistEntry $loaded '198.51.100.9' 'pending'
    $externalContent = $loaded.Content + '# external edit' + "`r`n"
    Write-TestConfiguration $path $externalContent
    Assert-ConfigurationThrows { Save-Wail2banConfigurationDocument $conflict } 'rejects external edit since read'
    Assert-Configuration ([io.file]::ReadAllText($path) -ceq $externalContent) 'conflict preserves external bytes'
    $conflict = Read-Wail2banConfigurationDocument $path
    $invalid = Add-Wail2banWhitelistEntry $conflict '198.51.100.9' 'candidate'
    $invalid.Content = $invalid.Content.Replace('4625 = RDP Logins','bad = RDP Logins')
    Assert-ConfigurationThrows { Save-Wail2banConfigurationDocument $invalid } 'validates whole candidate before replacement'
    Assert-Configuration ([io.file]::ReadAllText($path) -ceq $externalContent) 'failed validation leaves source intact'
    $script:AdministratorAllowed = $false
    Assert-ConfigurationThrows { Save-Wail2banConfigurationDocument $conflict } 'saving requires administrator'
    $script:AdministratorAllowed = $true
    $lock = [io.file]::Open($path + '.wail2ban.lock', [io.filemode]::OpenOrCreate, [io.fileaccess]::ReadWrite, [io.fileshare]::None)
    try { Assert-ConfigurationThrows { Save-Wail2banConfigurationDocument $conflict } 'concurrent editor lock times out safely' }
    finally { $lock.Dispose() }

    # Gia lap editor ngoai thay file nguyen tu sau lan hash cuoi, truoc Replace.
    $racePath = Join-Path $temporaryRoot 'atomic external race.ini'
    Write-TestConfiguration $racePath "[Security]`n4625=RDP`n[Whitelist]`n203.0.113.10=original`n"
    $raceDocument = Read-Wail2banConfigurationDocument $racePath
    $raceDocument = Add-Wail2banWhitelistEntry $raceDocument '198.51.100.9' 'menu edit'
    $script:RaceExternalContent = "[Security]`n4625=RDP`n[Whitelist]`n203.0.113.20=external first`n"
    $script:RaceSecondContent = "[Security]`n4625=RDP`n[Whitelist]`n203.0.113.30=external second`n"
    $script:RacePath = $racePath
    $script:RaceOriginalHash = $raceDocument.Hash
    $script:RaceCandidateHash = Get-Wail2banConfigurationBytesHash ([byte[]]$raceDocument.Preamble + [text.encoding]::UTF8.GetBytes($raceDocument.Content))
    $script:RaceOriginalMatches = 0
    $script:RaceStage = 0
    $script:RaceTwice = $false
    $script:OriginalConfigurationHasher = ${function:Get-Wail2banConfigurationBytesHash}
    function Get-Wail2banConfigurationBytesHash {
        param([byte[]]$Bytes)
        $result = & $script:OriginalConfigurationHasher $Bytes
        if ($result -eq $script:RaceOriginalHash) {
            $script:RaceOriginalMatches++
            if ($script:RaceOriginalMatches -eq 2) {
                $externalTemporary = $script:RacePath + '.external.tmp'
                Write-TestConfiguration $externalTemporary $script:RaceExternalContent
                [io.file]::Replace($externalTemporary, $script:RacePath, [System.Management.Automation.Language.NullString]::Value)
                $script:RaceStage = 1
            }
        } elseif ($script:RaceTwice -and $script:RaceStage -eq 1 -and $result -eq $script:RaceCandidateHash) {
            $externalTemporary = $script:RacePath + '.external-second.tmp'
            Write-TestConfiguration $externalTemporary $script:RaceSecondContent
            [io.file]::Replace($externalTemporary, $script:RacePath, [System.Management.Automation.Language.NullString]::Value)
            $script:RaceStage = 2
        }
        return $result
    }
    try {
        $raceError = $null
        try { $null = Save-Wail2banConfigurationDocument $raceDocument } catch { $raceError = $_.Exception.Message }
        Assert-Configuration ($null -ne $raceError -and $raceError.Contains('xung đột')) 'last moment atomic external edit is not reported successful'
        Assert-Configuration ([io.file]::ReadAllText($racePath) -ceq $script:RaceExternalContent) 'single atomic race restores external content to destination'
        $raceBackups = @(Get-ChildItem -LiteralPath $temporaryRoot -Filter 'atomic external race.ini.backup-*.ini')
        Assert-Configuration ($raceBackups.Count -eq 1 -and [io.file]::ReadAllText($raceBackups[0].FullName) -ceq $script:RaceExternalContent) 'atomic replacement backup captures actual external version'
        Assert-Configuration ($raceError.Contains($raceBackups[0].FullName)) 'race failure reports recovery backup path'

        Write-TestConfiguration $racePath "[Security]`n4625=RDP`n[Whitelist]`n203.0.113.10=original`n"
        $script:RaceOriginalMatches = 0; $script:RaceStage = 0; $script:RaceTwice = $true
        $secondRaceError = $null
        try { $null = Save-Wail2banConfigurationDocument $raceDocument } catch { $secondRaceError = $_.Exception.Message }
        Assert-Configuration ($null -ne $secondRaceError -and $secondRaceError.Contains('thủ công')) 'second external race stops automatic recovery with explicit warning'
        $rollbackBackups = @(Get-ChildItem -LiteralPath $temporaryRoot -Filter 'atomic external race.ini.conflict-current-*.ini')
        $secondExternalPreserved = @($rollbackBackups | Where-Object { [io.file]::ReadAllText($_.FullName) -ceq $script:RaceSecondContent }).Count -eq 1
        Assert-Configuration $secondExternalPreserved 'second race preserves latest external version in rollback backup'
        $recoveryFiles = @($rollbackBackups | Where-Object { [io.file]::ReadAllText($_.FullName) -ceq $script:RaceSecondContent })
        Assert-Configuration ($secondRaceError.Contains($recoveryFiles[0].FullName)) 'second race reports the latest recovery file path'
    } finally { Set-Item -Path Function:Get-Wail2banConfigurationBytesHash -Value $script:OriginalConfigurationHasher }

    $lfPath = Join-Path $temporaryRoot 'lf no ending.ini'
    Write-TestConfiguration $lfPath "[Security]`n4625=RDP`n# keep" (New-Object text.UTF8Encoding($false))
    $lf = Read-Wail2banConfigurationDocument $lfPath
    $lfAdded = Add-Wail2banWhitelistEntry $lf '203.0.113.9' 'plain ascii'
    Assert-Configuration ($lfAdded.Content -ceq "[Security]`n4625=RDP`n# keep`n[Whitelist]`n203.0.113.9 = plain ascii") 'adds absent section and preserves missing final newline'
    $lfSave = Save-Wail2banConfigurationDocument $lfAdded
    $lfLoaded = Read-Wail2banConfigurationDocument $lfPath
    Assert-Configuration ($lfLoaded.Preamble.Count -eq 0 -and $lfLoaded.NewLine -ceq "`n") 'preserves no BOM and LF encoding layout'
    $lfRemoved = Remove-Wail2banWhitelistEntry $lfLoaded 0
    Assert-Configuration ($lfRemoved.Content -ceq "[Security]`n4625=RDP`n# keep`n[Whitelist]") 'remove last entry preserves missing final newline'

    $utf16Path = Join-Path $temporaryRoot 'utf16.ini'
    Write-TestConfiguration $utf16Path "[Security]`r`n4625=RDP`r`n[Whitelist]`r`n" ([text.encoding]::Unicode)
    $utf16 = Read-Wail2banConfigurationDocument $utf16Path
    $utf16 = Add-Wail2banWhitelistEntry $utf16 '203.0.113.9' 'Ghi chú tiếng Việt'
    $null = Save-Wail2banConfigurationDocument $utf16
    $utf16Read = Read-Wail2banConfigurationDocument $utf16Path
    Assert-Configuration ($utf16Read.EncodingCodePage -eq 1200 -and $utf16Read.Preamble.Count -eq 2 -and $utf16Read.WhitelistEntries[0].Comment -eq 'Ghi chú tiếng Việt') 'UTF16 stays lossless through save'

    $ansiPath = Join-Path $temporaryRoot 'ansi.ini'
    Write-TestConfiguration $ansiPath "[Security]`n4625=RDP`n[Whitelist]`n" ([text.encoding]::Default)
    $ansi = Read-Wail2banConfigurationDocument $ansiPath
    $ansi = Add-Wail2banWhitelistEntry $ansi '203.0.113.9' ([string][char]0x4E2D)
    $strictAnsi = [text.encoding]::GetEncoding($ansi.EncodingCodePage, [text.encoderexceptionfallback]::new(), [text.decoderexceptionfallback]::new())
    $canEncode = $true
    try { $null = $strictAnsi.GetBytes([string][char]0x4E2D) } catch { $canEncode = $false }
    if (-not $canEncode) {
        Assert-ConfigurationThrows { Save-Wail2banConfigurationDocument $ansi } 'rejects unrepresentable comment without changing encoding'
        Assert-Configuration ((Get-Wail2banConfigurationBytesHash ([io.file]::ReadAllBytes($ansiPath))) -eq $ansi.Hash) 'encoding failure preserves original bytes'
    }

    $duplicatePath = Join-Path $temporaryRoot 'duplicate.ini'
    Write-TestConfiguration $duplicatePath "[Security]`n4625=RDP`n[Whitelist]`n203.0.113.9=x`n203.0.113.9/32=y`n"
    Assert-ConfigurationThrows { Read-Wail2banConfigurationDocument $duplicatePath } 'existing duplicate entries rejected clearly'
    Write-TestConfiguration $duplicatePath "[Security]`n4625=RDP`n[Whitelist]`n[Whitelist]`n"
    Assert-ConfigurationThrows { Read-Wail2banConfigurationDocument $duplicatePath } 'duplicate whitelist headers rejected'
    Write-TestConfiguration $duplicatePath "[Security]`n4625=RDP`n[Whitelist]`n``192.168.4.96 = My Machine```n"
    Assert-ConfigurationThrows { Read-Wail2banConfigurationDocument $duplicatePath } 'screenshot backtick syntax rejected'
    Assert-Configuration (@(Get-ChildItem -LiteralPath $temporaryRoot -Filter '*.tmp').Count -eq 0) 'temporary validation files cleaned'
    Write-Output ('Configuration tests passed: {0}; PowerShell {1}.' -f $script:passed, $PSVersionTable.PSVersion)
} finally {
    # Chi xoa thu muc tam do bo kiem thu nay tao ra.
    $resolved = [io.path]::GetFullPath($temporaryRoot)
    $allowedPrefix = [io.path]::Combine([io.path]::GetTempPath(), 'wail2ban-configuration-tests-')
    if ($resolved.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase) -and [io.directory]::Exists($resolved)) { [io.directory]::Delete($resolved, $true) }
}
