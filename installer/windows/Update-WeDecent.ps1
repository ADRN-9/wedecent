[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$')]
    [string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:DownloadOrigin = 'https://downloads.wedecent.com'
$script:MaxManifestBytes = 16384
$script:MaxArchiveBytes = 268435456
$script:MaxExtractedBytes = 536870912
$script:BinaryNames = @('wd.exe', 'wd-agent.exe', 'wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe')
$script:InstallerScriptNames = @('Install-WeDecent.ps1', 'Uninstall-WeDecent.ps1', 'Test-WeDecentInstall.ps1', 'Update-WeDecent.ps1')
$script:PackagePayloadNames = @($script:BinaryNames + @('VERSION.txt', 'SHA256SUMS.txt') + $script:InstallerScriptNames + @('README.md'))
$script:InstallerNames = @($script:PackagePayloadNames + @('PACKAGE_SHA256SUMS.txt'))

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-WindowsArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') {
            $slashes++
            continue
        }
        if ($ch -eq '"') {
            [void]$builder.Append(('\' * (($slashes * 2) + 1)))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append(('\' * $slashes))
            $slashes = 0
        }
        [void]$builder.Append($ch)
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * ($slashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Get-SystemPowerShellPath {
    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        throw 'SystemRoot is unavailable.'
    }
    $path = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'System Windows PowerShell is unavailable.'
    }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'System Windows PowerShell path is a reparse point.'
    }
    return $item.FullName
}

function Assert-PathUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if ($full -ieq $rootFull -or -not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be a child of $rootFull."
    }
    $cursor = $full
    while ($cursor.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label crosses a reparse point."
            }
        }
        if ($cursor -ieq $rootFull) { break }
        $cursor = Split-Path -Parent $cursor
    }
    return $full
}

function Get-TrustedInstallerMetadata {
    $metadataPath = Join-Path (Join-Path $env:ProgramData 'WeDecent') 'installer.json'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw 'Trusted installer metadata is missing.'
    }
    $item = Get-Item -LiteralPath $metadataPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer metadata must not be a reparse point.'
    }
    $acl = Get-Acl -LiteralPath $metadataPath
    if (-not $acl.AreAccessRulesProtected) {
        throw 'Installer metadata ACL is not protected.'
    }
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    try {
        $ownerSid = (New-Object Security.Principal.NTAccount -ArgumentList $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw 'Installer metadata owner cannot be resolved.'
    }
    if ($trusted -notcontains $ownerSid) {
        throw 'Installer metadata owner is not trusted.'
    }
    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            throw 'Installer metadata ACL contains an unresolvable identity.'
        }
        if ($trusted -notcontains $sid) {
            throw 'Installer metadata ACL grants access to an untrusted identity.'
        }
    }
    try {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    } catch {
        throw 'Installer metadata is malformed.'
    }
    if ([int]$metadata.schema -ne 1 -or [string]$metadata.product -ne 'WeDecent') {
        throw 'Installer metadata schema/product is unsupported.'
    }
    if ([string]$metadata.service_name -notmatch '^[A-Za-z0-9_.-]{1,128}$') {
        throw 'Installer metadata service name is invalid.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$metadata.install_dir) -or [string]::IsNullOrWhiteSpace([string]$metadata.state_dir)) {
        throw 'Installer metadata is missing installation paths.'
    }
    return $metadata
}

function Get-ValidSignerThumbprint {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Signed artifact is missing: $([IO.Path]::GetFileName($Path))"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Signed artifact must not be a reparse point: $($item.Name)"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or -not $signature.SignerCertificate) {
        throw "Authenticode verification failed: $($item.Name)"
    }
    $thumbprint = [string]$signature.SignerCertificate.Thumbprint
    if ($thumbprint -notmatch '^[0-9A-Fa-f]{40,128}$') {
        throw "Authenticode signer thumbprint is invalid: $($item.Name)"
    }
    return $thumbprint.ToUpperInvariant()
}

function Parse-WeDecentVersion {
    param([Parameter(Mandatory = $true)][string]$Value)
    $match = [regex]::Match($Value.Trim(), '^v?(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:[-.](?<pre>[0-9A-Za-z][0-9A-Za-z.-]*))?$')
    if (-not $match.Success) { throw "Unsupported version: $Value" }
    return [pscustomobject]@{
        Major = [uint64]$match.Groups['major'].Value
        Minor = [uint64]$match.Groups['minor'].Value
        Patch = [uint64]$match.Groups['patch'].Value
        Pre   = [string]$match.Groups['pre'].Value
    }
}

function Compare-WeDecentVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )
    $a = Parse-WeDecentVersion $Left
    $b = Parse-WeDecentVersion $Right
    foreach ($property in @('Major', 'Minor', 'Patch')) {
        if ($a.$property -lt $b.$property) { return -1 }
        if ($a.$property -gt $b.$property) { return 1 }
    }
    if ([string]::IsNullOrEmpty($a.Pre) -and [string]::IsNullOrEmpty($b.Pre)) { return 0 }
    if ([string]::IsNullOrEmpty($a.Pre)) { return 1 }
    if ([string]::IsNullOrEmpty($b.Pre)) { return -1 }
    $ap = @($a.Pre -split '\.')
    $bp = @($b.Pre -split '\.')
    $count = [Math]::Max($ap.Count, $bp.Count)
    for ($i = 0; $i -lt $count; $i++) {
        if ($i -ge $ap.Count) { return -1 }
        if ($i -ge $bp.Count) { return 1 }
        $an = $ap[$i] -match '^[0-9]+$'
        $bn = $bp[$i] -match '^[0-9]+$'
        if ($an -and $bn) {
            $av = [uint64]$ap[$i]
            $bv = [uint64]$bp[$i]
            if ($av -lt $bv) { return -1 }
            if ($av -gt $bv) { return 1 }
            continue
        }
        if ($an -and -not $bn) { return -1 }
        if (-not $an -and $bn) { return 1 }
        $cmp = [StringComparer]::Ordinal.Compare($ap[$i], $bp[$i])
        if ($cmp -lt 0) { return -1 }
        if ($cmp -gt 0) { return 1 }
    }
    return 0
}

function Get-InstalledVersion {
    param([Parameter(Mandatory = $true)][string]$AgentPath)
    $output = @(& $AgentPath version 2>$null)
    if ($LASTEXITCODE -ne 0 -or $output.Count -lt 1) {
        throw 'Cannot read the installed WeDecent version.'
    }
    $match = [regex]::Match([string]$output[0], '^wd-agent\s+(?<version>\S+)\s*$')
    if (-not $match.Success) {
        throw 'Installed wd-agent returned malformed version output.'
    }
    [void](Parse-WeDecentVersion $match.Groups['version'].Value)
    return $match.Groups['version'].Value
}

function Get-Sha256FileHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hash.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
    } finally {
        $hash.Dispose()
        $stream.Dispose()
    }
}

function Read-CanonicalManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$ExpectedNames,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $lines = @([IO.File]::ReadAllLines($Path))
    if ($lines.Count -ne $ExpectedNames.Count) {
        throw "$Label must contain exactly $($ExpectedNames.Count) entries."
    }
    $expected = @{}
    foreach ($name in $ExpectedNames) { $expected[$name] = $true }
    $result = @{}
    foreach ($line in $lines) {
        $match = [regex]::Match($line, '^(?<hash>[0-9A-Fa-f]{64})  (?<name>[A-Za-z0-9_.-]+)$')
        if (-not $match.Success) { throw "$Label contains a malformed entry." }
        $name = $match.Groups['name'].Value
        if (-not $expected.ContainsKey($name) -or $result.ContainsKey($name)) {
            throw "$Label contains an unexpected or duplicate file."
        }
        $result[$name] = $match.Groups['hash'].Value.ToLowerInvariant()
    }
    foreach ($name in $ExpectedNames) {
        if (-not $result.ContainsKey($name)) { throw "$Label does not cover $name." }
    }
    return $result
}

function Assert-ManifestFiles {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Manifest,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [Parameter(Mandatory = $true)][string]$Label
    )
    foreach ($name in $Names) {
        $path = Join-Path $Directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "$Label is missing $name." }
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "$Label entry is a reparse point: $name" }
        if ((Get-Sha256FileHash $item.FullName) -ne $Manifest[$name]) { throw "$Label checksum mismatch: $name" }
    }
}

function Write-HttpFile {
    param(
        [Parameter(Mandatory = $true)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )
    $response = $Client.GetAsync($Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    try {
        if ([int]$response.StatusCode -ne 200) { throw "Download failed with HTTP $([int]$response.StatusCode)." }
        if ($response.Headers.Location) { throw 'Redirected update downloads are not accepted.' }
        if ($response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength.Value -gt $MaximumBytes) {
            throw 'Update download exceeds the size limit.'
        }
        $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $buffer = New-Object byte[] 65536
            [long]$total = 0
            while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $read
                if ($total -gt $MaximumBytes) { throw 'Update download exceeds the size limit.' }
                $output.Write($buffer, 0, $read)
            }
            $output.Flush($true)
        } finally {
            $output.Dispose()
            $input.Dispose()
        }
    } finally {
        $response.Dispose()
    }
}

function Expand-VerifiedInstallerArchive {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $expected = @{}
    foreach ($name in $script:InstallerNames) { $expected[$name] = $true }
    $seen = @{}
    [long]$declaredTotal = 0
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        if ($archive.Entries.Count -ne $script:InstallerNames.Count) {
            throw "Installer archive must contain exactly $($script:InstallerNames.Count) files."
        }
        foreach ($entry in $archive.Entries) {
            $name = [string]$entry.FullName
            if (-not $expected.ContainsKey($name) -or $seen.ContainsKey($name) -or $name.Contains('/') -or $name.Contains('\')) {
                throw 'Installer archive contains an unexpected, duplicate, or path-bearing entry.'
            }
            if ([string]::IsNullOrEmpty($entry.Name)) { throw 'Installer archive contains a directory entry.' }
            $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
            if ($unixType -ne 0 -and $unixType -ne 0x8000) { throw "Installer archive entry is not a regular file: $name" }
            if ($entry.Length -lt 0 -or $entry.Length -gt $script:MaxArchiveBytes) { throw "Installer archive entry exceeds the size limit: $name" }
            $declaredTotal += $entry.Length
            if ($declaredTotal -gt $script:MaxExtractedBytes) { throw 'Installer archive extracted payload exceeds the size limit.' }
            $seen[$name] = $true
        }
        New-Item -ItemType Directory -Path $Destination | Out-Null
        [long]$actualTotal = 0
        foreach ($entry in $archive.Entries) {
            $path = Join-Path $Destination $entry.FullName
            $input = $entry.Open()
            $output = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $buffer = New-Object byte[] 65536
                [long]$written = 0
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += $read
                    $actualTotal += $read
                    if ($written -gt $entry.Length -or $written -gt $script:MaxArchiveBytes -or $actualTotal -gt $script:MaxExtractedBytes) {
                        throw "Installer archive extracted data exceeds declared limits: $($entry.FullName)"
                    }
                    $output.Write($buffer, 0, $read)
                }
                if ($written -ne $entry.Length) { throw "Installer archive extracted length mismatch: $($entry.FullName)" }
                $output.Flush($true)
            } finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }
}

function Assert-InstallerPackage {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$TargetVersion,
        [Parameter(Mandatory = $true)][string]$TrustedSignerThumbprint
    )
    $versionLines = @(Get-Content -LiteralPath (Join-Path $Directory 'VERSION.txt') | Where-Object { $_ -like 'version=*' })
    if ($versionLines.Count -ne 1 -or $versionLines[0] -cne ('version=' + $TargetVersion.TrimStart('v'))) {
        throw 'Downloaded installer VERSION.txt does not match the requested version.'
    }

    $releaseManifest = Read-CanonicalManifest -Path (Join-Path $Directory 'SHA256SUMS.txt') -ExpectedNames $script:BinaryNames -Label 'SHA256SUMS.txt'
    Assert-ManifestFiles -Manifest $releaseManifest -Directory $Directory -Names $script:BinaryNames -Label 'release payload'

    $packageManifest = Read-CanonicalManifest -Path (Join-Path $Directory 'PACKAGE_SHA256SUMS.txt') -ExpectedNames $script:PackagePayloadNames -Label 'PACKAGE_SHA256SUMS.txt'
    Assert-ManifestFiles -Manifest $packageManifest -Directory $Directory -Names $script:PackagePayloadNames -Label 'installer package'

    foreach ($name in @($script:BinaryNames + $script:InstallerScriptNames)) {
        $thumbprint = Get-ValidSignerThumbprint (Join-Path $Directory $name)
        if ($thumbprint -cne $TrustedSignerThumbprint) {
            throw "Authenticode signer continuity check failed: $name"
        }
    }
}

function Invoke-ElevatedSelf {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellPath,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$TargetVersion
    )
    $arguments = @('-NoProfile', '-File', $ScriptPath, '-Version', $TargetVersion)
    $argumentText = (($arguments | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ')
    $process = Start-Process -FilePath $PowerShellPath -Verb RunAs -ArgumentList $argumentText -Wait -PassThru
    if (-not $process) { throw 'Failed to start the elevated updater.' }
    return [int]$process.ExitCode
}

function Invoke-WeDecentUpdate {
    param([Parameter(Mandatory = $true)][string]$TargetVersion)

    if ($env:OS -ne 'Windows_NT') { throw 'WeDecent updater is supported only on Windows.' }
    $powerShell = Get-SystemPowerShellPath
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($programFiles)) { throw 'Program Files path is unavailable.' }
    $self = (Get-Item -LiteralPath $PSCommandPath -Force).FullName
    $self = Assert-PathUnderRoot -Path $self -Root $programFiles -Label 'Updater path'
    if ([IO.Path]::GetFileName($self) -cne 'Update-WeDecent.ps1') { throw 'Updater file name is invalid.' }

    if (-not (Test-Administrator)) {
        $exitCode = Invoke-ElevatedSelf -PowerShellPath $powerShell -ScriptPath $self -TargetVersion $TargetVersion
        if ($exitCode -ne 0) { throw "Elevated updater failed with exit code $exitCode." }
        return
    }

    $metadata = Get-TrustedInstallerMetadata
    $installDir = [IO.Path]::GetFullPath([string]$metadata.install_dir).TrimEnd('\', '/')
    $selfDir = [IO.Path]::GetDirectoryName($self).TrimEnd('\', '/')
    if (-not $selfDir.Equals($installDir, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Updater path does not match trusted installer metadata.'
    }
    [void](Assert-PathUnderRoot -Path $self -Root $programFiles -Label 'Updater path')
    $agentPath = Join-Path $installDir 'wd-agent.exe'
    $currentSigner = Get-ValidSignerThumbprint $self
    $agentSigner = Get-ValidSignerThumbprint $agentPath
    if ($agentSigner -cne $currentSigner) { throw 'Installed updater and agent are not signed by the same publisher certificate.' }

    $currentVersion = Get-InstalledVersion $agentPath
    if ([string]$metadata.version -and (Compare-WeDecentVersion ([string]$metadata.version) $currentVersion) -ne 0) {
        throw 'Installed version metadata does not match the signed agent version.'
    }
    if ((Compare-WeDecentVersion $TargetVersion $currentVersion) -le 0) {
        throw "Target version $TargetVersion must be newer than installed version $currentVersion."
    }

    $stateDir = [string]$metadata.state_dir
    $serviceName = [string]$metadata.service_name
    $workRoot = Join-Path $installDir ('.update-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $workRoot | Out-Null
    try {
        $manifestName = 'INSTALLER_SHA256SUMS.txt'
        $archiveName = "wedecent-$TargetVersion-windows-installer.zip"
        $prefix = "$($script:DownloadOrigin)/windows/$TargetVersion"
        $manifestPath = Join-Path $workRoot $manifestName
        $archivePath = Join-Path $workRoot $archiveName

        Add-Type -AssemblyName System.Net.Http
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromMinutes(3)
        try {
            Write-HttpFile -Client $client -Uri ([Uri]("$prefix/$manifestName")) -Destination $manifestPath -MaximumBytes $script:MaxManifestBytes
            $outer = Read-CanonicalManifest -Path $manifestPath -ExpectedNames @($archiveName) -Label $manifestName
            Write-HttpFile -Client $client -Uri ([Uri]("$prefix/$archiveName")) -Destination $archivePath -MaximumBytes $script:MaxArchiveBytes
        } finally {
            $client.Dispose()
            $handler.Dispose()
        }
        if ((Get-Sha256FileHash $archivePath) -ne $outer[$archiveName]) {
            throw 'Public installer archive SHA-256 mismatch.'
        }

        $extracted = Join-Path $workRoot 'package'
        Expand-VerifiedInstallerArchive -ArchivePath $archivePath -Destination $extracted
        Assert-InstallerPackage -Directory $extracted -TargetVersion $TargetVersion -TrustedSignerThumbprint $currentSigner

        $installerPath = Join-Path $extracted 'Install-WeDecent.ps1'
        $arguments = @(
            '-NoProfile',
            '-File', $installerPath,
            '-BundlePath', $extracted,
            '-InstallDir', $installDir,
            '-StateDir', $stateDir,
            '-ServiceName', $serviceName
        )
        $argumentText = (($arguments | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ')
        $process = Start-Process -FilePath $powerShell -ArgumentList $argumentText -Wait -PassThru
        if (-not $process -or $process.ExitCode -ne 0) {
            $code = if ($process) { $process.ExitCode } else { -1 }
            throw "WeDecent installer failed with exit code $code."
        }
    } finally {
        Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "WeDecent updated successfully: $currentVersion -> $TargetVersion"
}

Invoke-WeDecentUpdate -TargetVersion $Version
