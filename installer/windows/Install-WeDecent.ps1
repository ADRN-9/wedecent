[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$BundlePath,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'WeDecent'),
    [string]$StateDir = (Join-Path $env:ProgramData 'WeDecent\agent'),
    [ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')]
    [string]$ServiceName = 'WeDecentAgent',
    [string]$DisplayName = 'WeDecent Agent',
    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$ServiceAccountName = 'WeDecentSvc',
    [string]$WebRelay = 'https://relay.wedecent.com',
    [ValidateRange(1, 32)]
    [int]$RelaySlots = 4,
    [string]$DeviceName = $env:COMPUTERNAME,
    [string]$Shell = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),
    [bool]$AddToMachinePath = $true,
    [System.Management.Automation.PSCredential]$ServiceAccountCredential,
    [switch]$AdoptExistingServiceAccount
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:BinaryNames = @('wd.exe', 'wd-agent.exe', 'wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe')
$script:VerifiedBinaryHashes = @{}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Install-WeDecent.ps1 must be run from an elevated PowerShell session.'
    }
}

function Assert-SafeChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path)).TrimEnd('\', '/')
    $rootFull = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Root)).TrimEnd('\', '/')
    if ($full -ieq $rootFull -or -not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be a child of $rootFull; got $full"
    }
    $cursor = $full
    while ($cursor.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label crosses a reparse point at $cursor"
            }
        }
        if ($cursor -ieq $rootFull) { break }
        $cursor = Split-Path -Parent $cursor
    }
    return $full
}

function Get-WeDecentMetadataPath {
    $root = Join-Path $env:ProgramData 'WeDecent'
    return Join-Path $root 'installer.json'
}

function Protect-WeDecentMetadataAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-WeDecentMetadataTrusted {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { return $false }
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    try {
        $ownerSid = (New-Object Security.Principal.NTAccount -ArgumentList $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $false
    }
    if ($trusted -notcontains $ownerSid) { return $false }
    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            return $false
        }
        if ($trusted -notcontains $sid) { return $false }
    }
    return $true
}

function Assert-WeDecentMetadataShape {
    param([Parameter(Mandatory = $true)]$Metadata)
    if ([int]$Metadata.schema -ne 1 -or [string]$Metadata.product -ne 'WeDecent') {
        throw 'Installer metadata has an unsupported schema or product.'
    }
    if ([string]$Metadata.service_name -notmatch '^[A-Za-z0-9_.-]{1,128}$') {
        throw 'Installer metadata contains an invalid service name.'
    }
    if ([string]$Metadata.service_account_name -notmatch '^[A-Za-z0-9_.-]{1,64}$') {
        throw 'Installer metadata contains an invalid service account name.'
    }
    try {
        $null = [Security.Principal.SecurityIdentifier]::new([string]$Metadata.service_account_sid)
    } catch {
        throw 'Installer metadata contains an invalid service account SID.'
    }
}

function Read-WeDecentMetadata {
    $path = Get-WeDecentMetadataPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $metadata = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        Assert-WeDecentMetadataShape $metadata
        return $metadata
    } catch {
        throw "Cannot read existing installer metadata at $path : $($_.Exception.Message)"
    }
}

function Write-WeDecentMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$AccountSid,
        [Parameter(Mandatory = $true)][bool]$ManagedAccount,
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][string]$Version
    )
    $path = Get-WeDecentMetadataPath
    $parent = Split-Path -Parent $path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $payload = [ordered]@{
        schema                  = 1
        product                 = 'WeDecent'
        version                 = $Version
        service_name            = $ServiceName
        service_account_name    = $AccountName
        service_account_sid     = $AccountSid
        managed_service_account = $ManagedAccount
        install_dir             = $InstallDir
        state_dir               = $StateDir
        updated_at              = [DateTime]::UtcNow.ToString('o')
    }
    $temp = Join-Path $parent ('.installer-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $null
    try {
        $payload | ConvertTo-Json | Set-Content -LiteralPath $temp -Encoding UTF8
        Protect-WeDecentMetadataAcl $temp
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $backup = Join-Path $parent ('.installer-' + [Guid]::NewGuid().ToString('N') + '.bak')
            [IO.File]::Replace($temp, $path, $backup, $true)
        } else {
            Move-Item -LiteralPath $temp -Destination $path
        }
        Protect-WeDecentMetadataAcl $path
    } finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        if ($backup) { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
    }
}

function Get-LocalAccountName {
    param([Parameter(Mandatory = $true)][string]$Account)
    $value = $Account.Trim()
    $localPrefix = "$env:COMPUTERNAME\"
    if ($value.StartsWith('.\', [StringComparison]::OrdinalIgnoreCase)) { return $value.Substring(2) }
    if ($value.StartsWith($localPrefix, [StringComparison]::OrdinalIgnoreCase)) { return $value.Substring($localPrefix.Length) }
    return $null
}

function Assert-StandardLocalAccount {
    param([Parameter(Mandatory = $true)]$LocalUser)
    $adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    if ($adminMembers | Where-Object { $_.SID -and $_.SID.Value -eq $LocalUser.SID.Value }) {
        throw "Refusing to run the terminal service as local administrator $($LocalUser.Name)."
    }
}

function Get-ManifestHashes {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)
    $result = @{}
    foreach ($line in Get-Content -LiteralPath $ManifestPath) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^(?<hash>[0-9A-Fa-f]{64})\s+\*?(?<name>.+)$') {
            throw "Malformed checksum line in $ManifestPath : $line"
        }
        $name = [IO.Path]::GetFileName($Matches['name'].Trim())
        if ($result.ContainsKey($name)) {
            throw "Duplicate checksum entry for $name"
        }
        $result[$name] = $Matches['hash'].ToLowerInvariant()
    }
    return $result
}

function Get-Sha256FileHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($stream)
        return ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Assert-ReleaseBundle {
    $required = @($script:BinaryNames + @('VERSION.txt', 'SHA256SUMS.txt'))
    foreach ($name in $required) {
        $path = Join-Path $BundlePath $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Release bundle is missing $name at $path"
        }
    }

    $hashes = Get-ManifestHashes (Join-Path $BundlePath 'SHA256SUMS.txt')
    $verifiedHashes = @{}
    foreach ($name in $script:BinaryNames) {
        if (-not $hashes.ContainsKey($name)) {
            throw "SHA256SUMS.txt has no entry for $name"
        }
        $actual = Get-Sha256FileHash (Join-Path $BundlePath $name)
        if ($actual -ne $hashes[$name]) {
            throw "Checksum mismatch for $name"
        }
        $verifiedHashes[$name] = $hashes[$name]
    }
    $script:VerifiedBinaryHashes = $verifiedHashes

    $versionLine = Get-Content -LiteralPath (Join-Path $BundlePath 'VERSION.txt') |
        Where-Object { $_ -like 'version=*' } |
        Select-Object -First 1
    if (-not $versionLine) {
        throw 'VERSION.txt is missing version= metadata'
    }
    return $versionLine.Substring('version='.Length).Trim()
}

function Get-CryptoInt {
    param([Parameter(Mandatory = $true)][int]$UpperExclusive)
    if ($UpperExclusive -lt 1) { throw 'UpperExclusive must be positive' }
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] 4
        $range = [uint64]4294967296
        $limit = $range - ($range % [uint64]$UpperExclusive)
        do {
            $rng.GetBytes($bytes)
            $value = [BitConverter]::ToUInt32($bytes, 0)
        } while ([uint64]$value -ge $limit)
        return [int]([uint64]$value % [uint64]$UpperExclusive)
    } finally {
        $rng.Dispose()
    }
}

function New-ServiceAccountPassword {
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower = 'abcdefghijkmnopqrstuvwxyz'
    $digit = '23456789'
    $symbol = '!@#$%_-+='
    $all = $upper + $lower + $digit + $symbol
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($set in @($upper, $lower, $digit, $symbol)) {
        $chars.Add($set[(Get-CryptoInt $set.Length)])
    }
    while ($chars.Count -lt 32) {
        $chars.Add($all[(Get-CryptoInt $all.Length)])
    }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-CryptoInt ($i + 1)
        $tmp = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $tmp
    }
    return -join $chars
}

function ConvertFrom-SecureStringTransient {
    param([Parameter(Mandatory = $true)][Security.SecureString]$SecureString)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Resolve-AccountSid {
    param([Parameter(Mandatory = $true)][string]$Account)
    $localName = Get-LocalAccountName $Account
    if (-not $localName) {
        throw "Installer-managed services must use a dedicated local account; got '$Account'."
    }
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $localUser = Get-LocalUser -Name $localName -ErrorAction Stop
    Assert-StandardLocalAccount $localUser
    return $localUser.SID.Value
}

function Test-ServiceLogonRight {
    param([Parameter(Mandatory = $true)][string]$Sid)
    $work = Join-Path $env:TEMP ("wedecent-secedit-check-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $export = Join-Path $work 'export.inf'
    try {
        & secedit.exe /export /cfg $export /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit export failed with exit code $LASTEXITCODE" }
        $line = Get-Content -LiteralPath $export |
            Where-Object { $_ -match '^SeServiceLogonRight\s*=' } |
            Select-Object -First 1
        if (-not $line) { return $false }
        $needle = "*$Sid"
        foreach ($entry in ((($line -split '=', 2)[1]) -split ',')) {
            $trimmed = $entry.Trim()
            if ($trimmed -eq $needle -or $trimmed -eq $Sid) { return $true }
        }
        return $false
    } finally {
        Remove-Item -LiteralPath $work -Force -Recurse -ErrorAction SilentlyContinue
    }
}

function Set-ServiceLogonRight {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][bool]$Present
    )
    $work = Join-Path $env:TEMP ("wedecent-secedit-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $export = Join-Path $work 'export.inf'
    $apply = Join-Path $work 'apply.inf'
    $db = Join-Path $work 'rights.sdb'
    try {
        & secedit.exe /export /cfg $export /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit export failed with exit code $LASTEXITCODE" }

        $entries = New-Object System.Collections.Generic.List[string]
        $line = Get-Content -LiteralPath $export |
            Where-Object { $_ -match '^SeServiceLogonRight\s*=' } |
            Select-Object -First 1
        if ($line) {
            $rhs = ($line -split '=', 2)[1]
            foreach ($entry in ($rhs -split ',')) {
                $trimmed = $entry.Trim()
                if ($trimmed) { $entries.Add($trimmed) }
            }
        }

        $needle = "*$Sid"
        for ($i = $entries.Count - 1; $i -ge 0; $i--) {
            if ($entries[$i] -eq $needle -or $entries[$i] -eq $Sid) {
                $entries.RemoveAt($i)
            }
        }
        if ($Present) { $entries.Add($needle) }
        $rights = ($entries | Sort-Object -Unique) -join ','

        $content = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeServiceLogonRight = {0}
'@ -f $rights
        Set-Content -LiteralPath $apply -Value $content -Encoding Unicode
        & secedit.exe /configure /db $db /cfg $apply /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit configure failed with exit code $LASTEXITCODE" }
    } finally {
        Remove-Item -LiteralPath $work -Force -Recurse -ErrorAction SilentlyContinue
    }
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

function Invoke-AgentServiceInstall {
    param(
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [Parameter(Mandatory = $true)][Security.SecureString]$Password
    )
    $arguments = @(
        'service', 'install',
        "--service-name=$ServiceName",
        "--display-name=$DisplayName",
        "--account=.\$ServiceAccountName",
        '--account-password-stdin',
        "--state=$StateDir",
        "--name=$DeviceName",
        '--listen=',
        "--web-relay=$WebRelay",
        "--relay-slots=$RelaySlots",
        "--shell=$Shell",
        '--automatic=true',
        '--start=true'
    )
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $AgentPath
    $psi.Arguments = (($arguments | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'Failed to start wd-agent.exe service installer' }
    $plain = $null
    try {
        $plain = ConvertFrom-SecureStringTransient $Password
        $process.StandardInput.WriteLine($plain)
        $process.StandardInput.Close()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
    } finally {
        $plain = $null
        $process.Dispose()
    }
    if ($exitCode -ne 0) {
        throw "wd-agent.exe service install failed with exit code $exitCode"
    }
}

function Install-Binary {
    param([string]$Source, [string]$Destination)
    $newPath = "$Destination.new"
    $backupPath = "$Destination.bak"
    Remove-Item -LiteralPath $newPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $Source -Destination $newPath -Force
    if (Test-Path -LiteralPath $Destination) {
        Move-Item -LiteralPath $Destination -Destination $backupPath -Force
    }
    Move-Item -LiteralPath $newPath -Destination $Destination -Force
}

function Rollback-Binary {
    param(
        [string]$Destination,
        [bool]$HadOriginal
    )
    $backupPath = "$Destination.bak"
    if (Test-Path -LiteralPath $backupPath) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $backupPath -Destination $Destination -Force
    } elseif (-not $HadOriginal) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath "$Destination.new" -Force -ErrorAction SilentlyContinue
}

function Remove-BinaryBackup {
    param([string]$Destination)
    Remove-Item -LiteralPath "$Destination.bak" -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$Destination.new" -Force -ErrorAction SilentlyContinue
}

function Get-BinaryDestinations {
    param([Parameter(Mandatory = $true)][string]$Directory)
    $destinations = @{}
    foreach ($name in $script:BinaryNames) {
        $destinations[$name] = Join-Path $Directory $name
    }
    return $destinations
}

function Install-Binaries {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][hashtable]$Destinations,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$AttemptedNames,
        [Parameter(Mandatory = $true)][hashtable]$OriginalState
    )
    foreach ($name in $script:BinaryNames) {
        if (-not $script:VerifiedBinaryHashes.ContainsKey($name)) {
            throw "No pinned verified hash for $name"
        }
        $source = Join-Path $SourceDirectory $name
        $sourceHash = Get-Sha256FileHash $source
        if ($sourceHash -ne $script:VerifiedBinaryHashes[$name]) {
            throw "Release bundle changed after verification: $name"
        }
        $destination = $Destinations[$name]
        $OriginalState[$name] = Test-Path -LiteralPath $destination -PathType Leaf
        $AttemptedNames.Add($name)
        Install-Binary $source $destination
    }
}

function Assert-InstalledBinaries {
    param([Parameter(Mandatory = $true)][hashtable]$Destinations)
    foreach ($name in $script:BinaryNames) {
        if (-not $script:VerifiedBinaryHashes.ContainsKey($name)) {
            throw "No pinned verified hash for $name"
        }
        $destination = $Destinations[$name]
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            throw "Installed binary is missing: $destination"
        }
        $actual = Get-Sha256FileHash $destination
        if ($actual -ne $script:VerifiedBinaryHashes[$name]) {
            throw "Installed checksum mismatch for $name"
        }
    }
}

function Rollback-Binaries {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$AttemptedNames,
        [Parameter(Mandatory = $true)][hashtable]$OriginalState,
        [Parameter(Mandatory = $true)][hashtable]$Destinations
    )
    for ($i = $AttemptedNames.Count - 1; $i -ge 0; $i--) {
        $name = $AttemptedNames[$i]
        Rollback-Binary -Destination $Destinations[$name] -HadOriginal ([bool]$OriginalState[$name])
    }
}

function Remove-BinaryBackups {
    param([Parameter(Mandatory = $true)][hashtable]$Destinations)
    foreach ($name in $script:BinaryNames) {
        Remove-BinaryBackup $Destinations[$name]
    }
}

function Add-MachinePathEntry {
    param([string]$PathEntry)
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($machine -split ';' | Where-Object { $_ })
    if ($parts | Where-Object { $_.TrimEnd('\') -ieq $PathEntry.TrimEnd('\') }) { return }
    [Environment]::SetEnvironmentVariable('Path', (($parts + $PathEntry) -join ';'), 'Machine')
}

function Remove-EmptyDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    $child = Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop |
        Select-Object -First 1
    if (-not $child) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
}

function Invoke-RollbackStep {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    try {
        & $Action
    } catch {
        Write-Warning "Rollback step failed ($Description): $($_.Exception.Message)"
    }
}

Assert-Administrator
if ([string]::IsNullOrWhiteSpace($BundlePath)) { $BundlePath = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($BundlePath)) { throw 'Cannot determine installer bundle path.' }
$BundlePath = (Resolve-Path -LiteralPath $BundlePath).Path
$InstallDir = Assert-SafeChildPath -Path $InstallDir -Root $env:ProgramFiles -Label 'InstallDir'
$StateDir = Assert-SafeChildPath -Path $StateDir -Root (Join-Path $env:ProgramData 'WeDecent') -Label 'StateDir'
$version = Assert-ReleaseBundle
$metadataPath = Get-WeDecentMetadataPath
$metadata = Read-WeDecentMetadata
$metadataTrusted = $false
if ($metadata) {
    $metadataTrusted = Test-WeDecentMetadataTrusted $metadataPath
    if (-not $metadataTrusted) {
        Write-Warning 'Existing installer metadata is not ACL-trusted; installer ownership claims will not be preserved.'
    }
}
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
$binaryDestinations = Get-BinaryDestinations -Directory $InstallDir
$wdDestination = $binaryDestinations['wd.exe']
$agentDestination = $binaryDestinations['wd-agent.exe']

if ($service) {
    if ($service.StartName -match '^(LocalSystem|LocalService|NetworkService|NT AUTHORITY\\(SYSTEM|LocalService|NetworkService))$') {
        throw "Refusing to upgrade service running as built-in identity $($service.StartName)"
    }
    $expectedAgent = '^(?:"' + [Regex]::Escape($agentDestination) + '"|' + [Regex]::Escape($agentDestination) + ')(?:\s|$)'
    if ($service.PathName -notmatch $expectedAgent) {
        throw "Existing service binary path is not $agentDestination; refusing to rewrite an unrelated service"
    }
    $localName = Get-LocalAccountName $service.StartName
    if (-not $localName) { throw "Installer-managed services must use a dedicated local account; got '$($service.StartName)'." }
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $localUser = Get-LocalUser -Name $localName -ErrorAction Stop
    Assert-StandardLocalAccount $localUser
    $accountSid = $localUser.SID.Value
    $managed = $false
    if ($metadataTrusted -and $metadata.service_account_sid -eq $accountSid) {
        $managed = [bool]$metadata.managed_service_account
    }

    if (-not $PSCmdlet.ShouldProcess("$InstallDir and service '$ServiceName'", "Upgrade WeDecent to $version")) { return }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Write-Host "Upgrading existing $ServiceName service; state and service account will be preserved."
    if ($service.State -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $attemptedBinaryNames = [System.Collections.Generic.List[string]]::new()
    $binaryOriginalState = @{}
    try {
        Install-Binaries -SourceDirectory $BundlePath -Destinations $binaryDestinations -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState
        Assert-InstalledBinaries -Destinations $binaryDestinations
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        Write-WeDecentMetadata -AccountSid $accountSid -ManagedAccount $managed -AccountName $localName -Version $version
    } catch {
        $failed = $_
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Invoke-RollbackStep 'restore installed binaries' {
            Rollback-Binaries -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState -Destinations $binaryDestinations
        }
        Invoke-RollbackStep 'restart previous agent service' {
            Start-Service -Name $ServiceName
            (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        }
        throw "Upgrade failed; rollback was attempted: $($failed.Exception.Message)"
    }
    Remove-BinaryBackups -Destinations $binaryDestinations
} else {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $localUser = Get-LocalUser -Name $ServiceAccountName -ErrorAction SilentlyContinue
    if ($localUser) { Assert-StandardLocalAccount $localUser }

    if (-not $PSCmdlet.ShouldProcess("$InstallDir and service '$ServiceName'", "Install WeDecent $version")) { return }

    $installDirExisted = Test-Path -LiteralPath $InstallDir -PathType Container
    $stateParent = Split-Path -Parent $StateDir
    $stateParentExisted = Test-Path -LiteralPath $stateParent -PathType Container
    $stateExisted = Test-Path -LiteralPath $StateDir -PathType Container
    $createdAccount = $false
    $hadLogonRight = $false
    $originalMachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $managed = $false
    $password = $null
    $attemptedBinaryNames = [System.Collections.Generic.List[string]]::new()
    $binaryOriginalState = @{}

    try {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        if ($localUser) {
            $metadataManaged = $metadataTrusted -and [bool]$metadata.managed_service_account -and $metadata.service_account_sid -eq $localUser.SID.Value
            if ($metadataManaged) {
                $plainGenerated = New-ServiceAccountPassword
                try {
                    $password = ConvertTo-SecureString $plainGenerated -AsPlainText -Force
                    Set-LocalUser -Name $ServiceAccountName -Password $password
                } finally {
                    $plainGenerated = $null
                }
                $managed = $true
            } elseif ($AdoptExistingServiceAccount) {
                if (-not $ServiceAccountCredential) {
                    throw '-AdoptExistingServiceAccount requires -ServiceAccountCredential for a pre-existing account.'
                }
                $password = $ServiceAccountCredential.Password
            } else {
                throw "Local account $ServiceAccountName already exists but is not recorded as trusted installer-managed. Use -AdoptExistingServiceAccount with an in-memory PSCredential, or choose another account name."
            }
        } else {
            if ($ServiceAccountCredential) {
                $password = $ServiceAccountCredential.Password
            } else {
                $plainGenerated = New-ServiceAccountPassword
                try {
                    $password = ConvertTo-SecureString $plainGenerated -AsPlainText -Force
                } finally {
                    $plainGenerated = $null
                }
            }
            $localUser = New-LocalUser -Name $ServiceAccountName -Password $password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description 'WeDecent dedicated terminal service account'
            $createdAccount = $true
            $managed = $true
        }

        Assert-StandardLocalAccount $localUser
        $hadLogonRight = Test-ServiceLogonRight -Sid $localUser.SID.Value
        if (-not $hadLogonRight) { Set-ServiceLogonRight -Sid $localUser.SID.Value -Present $true }

        Install-Binaries -SourceDirectory $BundlePath -Destinations $binaryDestinations -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState
        Assert-InstalledBinaries -Destinations $binaryDestinations
        Invoke-AgentServiceInstall -AgentPath $agentDestination -Password $password

        $finalService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        if (-not $finalService -or $finalService.State -ne 'Running') {
            throw "$ServiceName is not running after installation"
        }
        $finalSid = Resolve-AccountSid $finalService.StartName
        if ($finalSid -ne $localUser.SID.Value) {
            throw 'Installed service account SID does not match the expected local account.'
        }

        if ($AddToMachinePath) { Add-MachinePathEntry $InstallDir }
        Write-WeDecentMetadata -AccountSid $localUser.SID.Value -ManagedAccount $managed -AccountName $ServiceAccountName -Version $version
        Remove-BinaryBackups -Destinations $binaryDestinations
    } catch {
        $failed = $_
        Invoke-RollbackStep 'remove partially created service' {
            $createdService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($createdService) {
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                & sc.exe delete $ServiceName | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE" }
            }
        }
        Invoke-RollbackStep 'restore installed binaries' {
            Rollback-Binaries -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState -Destinations $binaryDestinations
        }
        if ($AddToMachinePath) {
            Invoke-RollbackStep 'restore machine PATH' {
                [Environment]::SetEnvironmentVariable('Path', $originalMachinePath, 'Machine')
            }
        }
        if (-not $stateExisted) {
            Invoke-RollbackStep 'remove installer-created state directory' {
                Remove-Item -LiteralPath $StateDir -Recurse -Force -ErrorAction Stop
            }
            if (-not $stateParentExisted) {
                Invoke-RollbackStep 'remove empty installer-created state parent' {
                    Remove-EmptyDirectory -Path $stateParent
                }
            }
        }
        if (-not $installDirExisted) {
            Invoke-RollbackStep 'remove empty installer-created install directory' {
                Remove-EmptyDirectory -Path $InstallDir
            }
        }
        if ($localUser -and -not $hadLogonRight) {
            Invoke-RollbackStep 'remove SeServiceLogonRight' {
                Set-ServiceLogonRight -Sid $localUser.SID.Value -Present $false
            }
        }
        if ($createdAccount) {
            Invoke-RollbackStep 'remove installer-created service account' {
                Remove-LocalUser -Name $ServiceAccountName -ErrorAction Stop
            }
        }
        throw "Fresh installation failed; rollback was attempted: $($failed.Exception.Message)"
    }
}

if ($service -and $AddToMachinePath) { Add-MachinePathEntry $InstallDir }

$finalService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if (-not $finalService -or $finalService.State -ne 'Running') { throw "$ServiceName is not running after installation" }

Write-Host "WeDecent $version installed successfully."
Write-Host "Client:    $wdDestination"
Write-Host "Agent:     $agentDestination"
Write-Host "RouterCtl: $($binaryDestinations['wd-routerctl.exe'])"
Write-Host "Core:      $($binaryDestinations['wd-core.exe'])"
Write-Host "UI:        $($binaryDestinations['wd-ui.exe'])"
Write-Host "State:     $StateDir"
Write-Host "Service:   $ServiceName ($($finalService.StartName))"
Write-Host 'wd-core.exe and wd-ui.exe are installed for same-user manual launch; they are not registered as services or autostart entries.'
