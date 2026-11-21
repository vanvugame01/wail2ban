[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Run the suite with Windows PowerShell 5.1 (powershell.exe).'
}

# Moi bo kiem thu chay trong tien trinh rieng de cach ly mock.
$testFiles = @('core.tests.ps1', 'monitor.tests.ps1', 'integration.tests.ps1')
foreach ($testFile in $testFiles) {
    $testPath = Join-Path $PSScriptRoot $testFile
    if (-not (Test-Path -LiteralPath $testPath)) { throw "Missing test suite: $testFile" }
    & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -File $testPath
    if ($LASTEXITCODE -ne 0) { throw "Test suite failed: $testFile" }
}

$sourceRoot = Split-Path $PSScriptRoot -Parent
$scripts = @(Get-ChildItem -LiteralPath $sourceRoot -Filter '*.ps1' -File) + @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File)
foreach ($script in $scripts) {
    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "Syntax errors in $($script.Name): $($parseErrors.Message -join '; ')" }
}
Write-Output ("Syntax checks passed: {0} scripts; all suites passed on PowerShell {1}." -f $scripts.Count, $PSVersionTable.PSVersion)
