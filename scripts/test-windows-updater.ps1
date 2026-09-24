Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'installer\windows\Update-WeDecent.ps1'
$source = Get-Content -LiteralPath $target -Raw
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $target).Path,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    $parseErrors | ForEach-Object { Write-Error $_.Message }
    throw 'Update-WeDecent.ps1 does not parse.'
}

$wanted = @(
    'Parse-WeDecentVersion',
    'Compare-WeDecentVersion',
    'Get-Sha256FileHash',
    'Read-CanonicalManifest',
    'Assert-ManifestFiles',
    'Expand-VerifiedInstallerArchive',
    'Assert-PathUnderRoot',
    'Quote-WindowsArgument'
)
$functions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true))
foreach ($name in $wanted) {
    $node = $functions | Where-Object { $_.Name -ceq $name } | Select-Object -First 1
    if (-not $node) { throw "Missing updater helper function: $name" }
    Invoke-Expression $node.Extent.Text
}

Assert-True ((Compare-WeDecentVersion 'v0.3.0' '0.3.0') -eq 0) 'version prefix normalization failed'
Assert-True ((Compare-WeDecentVersion 'v0.4.0' '0.3.9') -gt 0) 'minor upgrade comparison failed'
Assert-True ((Compare-WeDecentVersion 'v1.0.0' 'v0.99.99') -gt 0) 'major upgrade comparison failed'
Assert-True ((Compare-WeDecentVersion 'v0.4.0-rc.10' 'v0.4.0-rc.2') -gt 0) 'numeric prerelease ordering failed'
Assert-True ((Compare-WeDecentVersion 'v0.4.0' 'v0.4.0-rc.9') -gt 0) 'stable release must sort after prerelease'
Assert-True ((Compare-WeDecentVersion 'v0.4.0-alpha' 'v0.4.0-1') -gt 0) 'nonnumeric prerelease ordering failed'
try {
    [void](Parse-WeDecentVersion 'v0.4.0+build.1')
    throw 'build-metadata version unexpectedly parsed'
} catch {
    if ($_.Exception.Message -eq 'build-metadata version unexpectedly parsed') { throw }
}

$work = Join-Path $env:TEMP ('wedecent-updater-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $payload = Join-Path $work 'payload'
    New-Item -ItemType Directory -Path $payload | Out-Null
    Set-Content -LiteralPath (Join-Path $payload 'a.txt') -Value 'a' -NoNewline
    Set-Content -LiteralPath (Join-Path $payload 'b.txt') -Value 'b' -NoNewline
    $aHash = Get-Sha256FileHash (Join-Path $payload 'a.txt')
    $bHash = Get-Sha256FileHash (Join-Path $payload 'b.txt')
    $manifestPath = Join-Path $payload 'MANIFEST.txt'
    Set-Content -LiteralPath $manifestPath -Value @(
        "$aHash  a.txt",
        "$bHash  b.txt"
    ) -Encoding ASCII
    $manifest = Read-CanonicalManifest -Path $manifestPath -ExpectedNames @('a.txt', 'b.txt') -Label 'fixture manifest'
    Assert-ManifestFiles -Manifest $manifest -Directory $payload -Names @('a.txt', 'b.txt') -Label 'fixture payload'

    Add-Content -LiteralPath $manifestPath -Value "$aHash  extra.txt" -Encoding ASCII
    try {
        [void](Read-CanonicalManifest -Path $manifestPath -ExpectedNames @('a.txt', 'b.txt') -Label 'fixture manifest')
        throw 'manifest with extra entry unexpectedly succeeded'
    } catch {
        if ($_.Exception.Message -eq 'manifest with extra entry unexpectedly succeeded') { throw }
    }

    Set-Content -LiteralPath $manifestPath -Value @(
        "$aHash  a.txt",
        "$bHash b.txt"
    ) -Encoding ASCII
    try {
        [void](Read-CanonicalManifest -Path $manifestPath -ExpectedNames @('a.txt', 'b.txt') -Label 'fixture manifest')
        throw 'noncanonical manifest spacing unexpectedly succeeded'
    } catch {
        if ($_.Exception.Message -eq 'noncanonical manifest spacing unexpectedly succeeded') { throw }
    }

    $script:InstallerNames = @(
        'Install-WeDecent.ps1', 'PACKAGE_SHA256SUMS.txt', 'README.md', 'SHA256SUMS.txt',
        'Test-WeDecentInstall.ps1', 'Uninstall-WeDecent.ps1', 'Update-WeDecent.ps1', 'VERSION.txt',
        'wd-agent.exe', 'wd-core.exe', 'wd-routerctl.exe', 'wd-ui.exe', 'wd.exe'
    )
    $script:MaxArchiveBytes = 1024 * 1024
    $script:MaxExtractedBytes = 4 * 1024 * 1024
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    function New-FixtureZip([string]$Path, [string[]]$Names) {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
            try {
                foreach ($name in $Names) {
                    $entry = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::NoCompression)
                    $writer = New-Object IO.StreamWriter($entry.Open())
                    try { $writer.Write('fixture') } finally { $writer.Dispose() }
                }
            } finally {
                $zip.Dispose()
            }
        } finally {
            $stream.Dispose()
        }
    }

    $goodZip = Join-Path $work 'good.zip'
    New-FixtureZip $goodZip $script:InstallerNames
    $expanded = Join-Path $work 'expanded'
    Expand-VerifiedInstallerArchive -ArchivePath $goodZip -Destination $expanded
    Assert-True ((Get-ChildItem -LiteralPath $expanded -File).Count -eq 13) 'exact installer archive did not extract thirteen files'

    $badZip = Join-Path $work 'bad.zip'
    $badNames = @($script:InstallerNames[0..11] + @('../escape.txt'))
    New-FixtureZip $badZip $badNames
    try {
        Expand-VerifiedInstallerArchive -ArchivePath $badZip -Destination (Join-Path $work 'bad-expanded')
        throw 'path-bearing archive entry unexpectedly succeeded'
    } catch {
        if ($_.Exception.Message -eq 'path-bearing archive entry unexpectedly succeeded') { throw }
    }

    $rootPath = Join-Path $work 'root'
    $childPath = Join-Path $rootPath 'child\Update-WeDecent.ps1'
    New-Item -ItemType Directory -Path (Split-Path -Parent $childPath) -Force | Out-Null
    Set-Content -LiteralPath $childPath -Value 'fixture'
    $resolved = Assert-PathUnderRoot -Path $childPath -Root $rootPath -Label 'fixture path'
    Assert-True ($resolved.EndsWith('Update-WeDecent.ps1')) 'safe-child path was not accepted'
    try {
        [void](Assert-PathUnderRoot -Path $rootPath -Root $rootPath -Label 'fixture root')
        throw 'root path unexpectedly accepted as child'
    } catch {
        if ($_.Exception.Message -eq 'root path unexpectedly accepted as child') { throw }
    }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Assert-True ($source.Contains("`$script:DownloadOrigin = 'https://downloads.wedecent.com'")) 'updater does not pin the public HTTPS origin'
Assert-True ($source.Contains('AllowAutoRedirect = $false')) 'updater does not disable HTTP redirects'
Assert-True (-not $source.Contains('-ExecutionPolicy')) 'updater weakens PowerShell execution policy'
Assert-True (-not $source.Contains('Invoke-Expression')) 'updater evaluates dynamic PowerShell text'
Assert-True ($source.Contains('Get-AuthenticodeSignature')) 'updater does not verify Authenticode signatures'
Assert-True ($source.Contains('Authenticode signer continuity check failed')) 'updater does not enforce signer continuity'

Write-Host 'Windows updater security behavior verified.'
