Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WeDecentMigrationPhases = @(
    'Prepared',
    'Copying',
    'Copied',
    'Verified',
    'StatePublished',
    'ServiceReconfigured',
    'Committed',
    'RollingBack',
    'RolledBack'
)

function Assert-WeDecentMigrationRealDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Migration path must be a real directory: $full"
    }
    return $full
}

function Get-WeDecentMigrationManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootFull = Assert-WeDecentMigrationRealDirectory -Path $Root
    $rootPrefix = $rootFull.TrimEnd('\') + '\'
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($rootFull)
    $entries = [Collections.Generic.List[object]]::new()

    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entryPath in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $item = Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Migration refuses reparse points: $entryPath"
            }
            $relative = $entryPath.Substring($rootPrefix.Length).Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($relative) -or
                $relative.StartsWith('/') -or
                $relative -match '(^|/)\.\.?(/|$)' -or
                $relative.Contains(':')) {
                throw "Migration encountered an ambiguous relative path: $relative"
            }

            if ($item.PSIsContainer) {
                $entries.Add([ordered]@{
                    path = $relative
                    kind = 'directory'
                    size = 0
                    sha256 = ''
                })
                $pending.Push($entryPath)
                continue
            }
            if (($item.Attributes -band [IO.FileAttributes]::Device) -ne 0) {
                throw "Migration refuses special filesystem objects: $entryPath"
            }
            $hash = Get-FileHash -LiteralPath $entryPath -Algorithm SHA256
            $entries.Add([ordered]@{
                path = $relative
                kind = 'file'
                size = [int64]$item.Length
                sha256 = $hash.Hash.ToLowerInvariant()
            })
        }
    }

    return @($entries | Sort-Object -Property path)
}

function Get-WeDecentMigrationManifestDigest {
    param([Parameter(Mandatory = $true)][object[]]$Manifest)

    $json = ConvertTo-Json -InputObject @($Manifest) -Depth 6 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($sha.ComputeHash($bytes))).ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-WeDecentMigrationSid {
    param([Parameter(Mandatory = $true)][string]$Sid)

    try { return [Security.Principal.SecurityIdentifier]::new($Sid) }
    catch { throw "Migration SID is invalid: $Sid" }
}

function Set-WeDecentMigrationDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceSid
    )

    $full = Assert-WeDecentMigrationRealDirectory -Path $Path
    $service = ConvertTo-WeDecentMigrationSid -Sid $ServiceSid
    $system = ConvertTo-WeDecentMigrationSid -Sid 'S-1-5-18'
    $admins = ConvertTo-WeDecentMigrationSid -Sid 'S-1-5-32-544'
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($service)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($service, $system, $admins)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $full -AclObject $acl -ErrorAction Stop
    Assert-WeDecentMigrationDirectoryAcl -Path $full -ServiceSid $ServiceSid
}

function Assert-WeDecentMigrationDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceSid
    )

    $full = Assert-WeDecentMigrationRealDirectory -Path $Path
    $service = ConvertTo-WeDecentMigrationSid -Sid $ServiceSid
    $allowed = @(
        $service.Value,
        'S-1-5-18',
        'S-1-5-32-544'
    )
    $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -cne $service.Value -or -not $acl.AreAccessRulesProtected) {
        throw "Migration directory owner or protected DACL is invalid: $full"
    }
    $rules = $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])
    $serviceFullControl = $false
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($sid -notin $allowed -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Migration directory contains an unexpected access rule for SID $sid"
        }
        if ($sid -ceq $service.Value) { $serviceFullControl = $true }
    }
    if (-not $serviceFullControl) {
        throw 'Migration directory does not grant full control to its service identity.'
    }
    return $true
}

function Invoke-WeDecentMigrationIdentityCheck {
    param(
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [Parameter(Mandatory = $true)][string]$StatePath
    )

    $agent = Get-Item -LiteralPath $AgentPath -Force -ErrorAction Stop
    if ($agent.PSIsContainer -or
        ($agent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Migration identity verifier must be a regular executable file.'
    }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $agent.FullName
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    [void]$psi.ArgumentList.Add('identity-check')
    [void]$psi.ArgumentList.Add("--state=$StatePath")
    $process = [Diagnostics.Process]::Start($psi)
    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Non-mutating identity verification failed: $($stderr.Trim())"
        }
        $fields = $stdout.Trim().Split([char]9)
        if ($fields.Count -ne 3 -or
            $fields[0] -notmatch '^wd_[a-z2-7]{16}

    $sourceFull = Assert-WeDecentMigrationRealDirectory -Path $Source
    $destinationFull = Assert-WeDecentMigrationRealDirectory -Path $Destination
    $identityFiles = @('identity.crt')
    $protectedKey = Join-Path $sourceFull 'identity.key.dpapi'
    $legacyKey = Join-Path $sourceFull 'identity.key'
    if (Test-Path -LiteralPath $protectedKey -PathType Leaf) {
        $identityFiles += 'identity.key.dpapi'
    }
    if (Test-Path -LiteralPath $legacyKey -PathType Leaf) {
        $identityFiles += 'identity.key'
    }
    if ($identityFiles.Count -lt 2) {
        throw 'Migration source does not contain both an identity certificate and a supported private-key file.'
    }

    $certificatePath = Join-Path $sourceFull 'identity.crt'
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($certificatePath)
    if ($certificate.PublicKey.Oid.Value -cne '1.3.101.112') {
        throw 'Migration identity certificate is not Ed25519.'
    }
    $fingerprints = @{
        'identity.crt.public_key_algorithm' = $certificate.PublicKey.Oid.Value
    }
    foreach ($name in $identityFiles) {
        $sourcePath = Join-Path $sourceFull $name
        $destinationPath = Join-Path $destinationFull $name
        foreach ($candidate in @($sourcePath, $destinationPath)) {
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
            if ($item.PSIsContainer -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Identity continuity refuses a non-regular identity file: $candidate"
            }
        }
        $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash
        if ($sourceHash -cne $destinationHash) {
            throw "Identity continuity check failed for $name."
        }
        $fingerprints[$name] = $sourceHash.ToLowerInvariant()
    }
    $sourceIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $AgentPath -StatePath $sourceFull
    $destinationIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $AgentPath -StatePath $destinationFull
    if ($sourceIdentity.DeviceId -cne $destinationIdentity.DeviceId -or
        $sourceIdentity.Fingerprint -cne $destinationIdentity.Fingerprint) {
        throw 'Cryptographic device identity changed during state migration.'
    }
    return [pscustomobject]@{
        SHA256 = $fingerprints
        DeviceId = $sourceIdentity.DeviceId
        Fingerprint = $sourceIdentity.Fingerprint
    }
}

function Copy-WeDecentMigrationTreeVerified {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Staging,
        [Parameter(Mandatory = $true)][string]$SourceServiceSid,
        [Parameter(Mandatory = $true)][string]$DestinationServiceSid,
        [Parameter(Mandatory = $true)][string]$AgentPath
    )

    $sourceFull = Assert-WeDecentMigrationRealDirectory -Path $Source
    [void](Assert-WeDecentMigrationDirectoryAcl -Path $sourceFull -ServiceSid $SourceServiceSid)
    $sourceManifest = @(Get-WeDecentMigrationManifest -Root $sourceFull)
    $stagingFull = [IO.Path]::GetFullPath($Staging)
    if (Test-Path -LiteralPath $stagingFull) {
        throw "Migration staging path already exists: $stagingFull"
    }

    [IO.Directory]::CreateDirectory($stagingFull) | Out-Null
    Set-WeDecentMigrationDirectoryAcl -Path $stagingFull -ServiceSid $DestinationServiceSid
    foreach ($entry in $sourceManifest) {
        $relative = $entry.path.Replace('/', '\')
        $destination = Join-Path $stagingFull $relative
        if ($entry.kind -eq 'directory') {
            [IO.Directory]::CreateDirectory($destination) | Out-Null
            continue
        }
        $parent = Split-Path -Parent $destination
        [IO.Directory]::CreateDirectory($parent) | Out-Null
        [IO.File]::Copy((Join-Path $sourceFull $relative), $destination, $false)
    }

    [void](Assert-WeDecentMigrationDirectoryAcl -Path $stagingFull -ServiceSid $DestinationServiceSid)
    $copiedManifest = @(Get-WeDecentMigrationManifest -Root $stagingFull)
    $sourceDigest = Get-WeDecentMigrationManifestDigest -Manifest $sourceManifest
    $copiedDigest = Get-WeDecentMigrationManifestDigest -Manifest $copiedManifest
    if ($sourceDigest -cne $copiedDigest) {
        throw 'Migration staging SHA-256 manifest does not match the source state tree.'
    }
    return [pscustomobject]@{
        SourceManifestSHA256 = $sourceDigest
        FileCount = @($sourceManifest | Where-Object kind -eq 'file').Count
        DirectoryCount = @($sourceManifest | Where-Object kind -eq 'directory').Count
        Identity = Assert-WeDecentMigrationIdentityContinuity -Source $sourceFull -Destination $stagingFull -AgentPath $AgentPath
    }
}

function Write-WeDecentMigrationJournal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][pscustomobject]$Journal
    )

    if ([int]$Journal.schema -ne 1 -or
        [string]$Journal.product -cne 'WeDecent' -or
        [string]$Journal.phase -notin $script:WeDecentMigrationPhases) {
        throw 'Migration journal schema, product, or phase is invalid.'
    }
    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    [void](Assert-WeDecentMigrationRealDirectory -Path $directory)
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Item -LiteralPath $Path -Force
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $existing.PSIsContainer) {
            throw 'Migration journal path is not a regular file.'
        }
    }

    $Journal.updated_utc = [DateTime]::UtcNow.ToString('o')
    $json = ConvertTo-Json -InputObject $Journal -Depth 10
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $temporary = Join-Path $directory ('.migration-journal-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $Path + '.previous'
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $temporary,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        if (Test-Path -LiteralPath $Path) {
            if (Test-Path -LiteralPath $backup) {
                Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
            }
            [IO.File]::Replace($temporary, $Path, $backup, $true)
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Read-WeDecentMigrationJournal {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Migration journal is not a regular file.'
    }
    $journal = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ([int]$journal.schema -ne 1 -or
        [string]$journal.product -cne 'WeDecent' -or
        [string]$journal.phase -notin $script:WeDecentMigrationPhases) {
        throw 'Migration journal is corrupt or has an unsupported schema/phase.'
    }
    $transactionId = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$journal.transaction_id, [ref]$transactionId)) {
        throw 'Migration journal transaction identifier is invalid.'
    }
    foreach ($field in @('source', 'destination', 'staging', 'original_service_path', 'updated_service_path')) {
        if ([string]::IsNullOrWhiteSpace([string]$journal.$field)) {
            throw "Migration journal field '$field' is missing."
        }
    }
    return $journal
}

Export-ModuleMember -Function @(
    'Get-WeDecentMigrationManifest',
    'Get-WeDecentMigrationManifestDigest',
    'Copy-WeDecentMigrationTreeVerified',
    'Set-WeDecentMigrationDirectoryAcl',
    'Assert-WeDecentMigrationDirectoryAcl',
    'Assert-WeDecentMigrationIdentityContinuity',
    'Invoke-WeDecentMigrationIdentityCheck',
    'Write-WeDecentMigrationJournal',
    'Read-WeDecentMigrationJournal'
)
 -or
            $fields[2] -notmatch '^SHA256:[A-F0-9]{64}

    $sourceFull = Assert-WeDecentMigrationRealDirectory -Path $Source
    $destinationFull = Assert-WeDecentMigrationRealDirectory -Path $Destination
    $identityFiles = @('identity.crt')
    $protectedKey = Join-Path $sourceFull 'identity.key.dpapi'
    $legacyKey = Join-Path $sourceFull 'identity.key'
    if (Test-Path -LiteralPath $protectedKey -PathType Leaf) {
        $identityFiles += 'identity.key.dpapi'
    }
    if (Test-Path -LiteralPath $legacyKey -PathType Leaf) {
        $identityFiles += 'identity.key'
    }
    if ($identityFiles.Count -lt 2) {
        throw 'Migration source does not contain both an identity certificate and a supported private-key file.'
    }

    $certificatePath = Join-Path $sourceFull 'identity.crt'
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($certificatePath)
    if ($certificate.PublicKey.Oid.Value -cne '1.3.101.112') {
        throw 'Migration identity certificate is not Ed25519.'
    }
    $fingerprints = @{
        'identity.crt.public_key_algorithm' = $certificate.PublicKey.Oid.Value
    }
    foreach ($name in $identityFiles) {
        $sourcePath = Join-Path $sourceFull $name
        $destinationPath = Join-Path $destinationFull $name
        foreach ($candidate in @($sourcePath, $destinationPath)) {
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
            if ($item.PSIsContainer -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Identity continuity refuses a non-regular identity file: $candidate"
            }
        }
        $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash
        if ($sourceHash -cne $destinationHash) {
            throw "Identity continuity check failed for $name."
        }
        $fingerprints[$name] = $sourceHash.ToLowerInvariant()
    }
    return [pscustomobject]@{ SHA256 = $fingerprints }
}

function Copy-WeDecentMigrationTreeVerified {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Staging,
        [Parameter(Mandatory = $true)][string]$SourceServiceSid,
        [Parameter(Mandatory = $true)][string]$DestinationServiceSid
    )

    $sourceFull = Assert-WeDecentMigrationRealDirectory -Path $Source
    [void](Assert-WeDecentMigrationDirectoryAcl -Path $sourceFull -ServiceSid $SourceServiceSid)
    $sourceManifest = @(Get-WeDecentMigrationManifest -Root $sourceFull)
    $stagingFull = [IO.Path]::GetFullPath($Staging)
    if (Test-Path -LiteralPath $stagingFull) {
        throw "Migration staging path already exists: $stagingFull"
    }

    [IO.Directory]::CreateDirectory($stagingFull) | Out-Null
    Set-WeDecentMigrationDirectoryAcl -Path $stagingFull -ServiceSid $DestinationServiceSid
    foreach ($entry in $sourceManifest) {
        $relative = $entry.path.Replace('/', '\')
        $destination = Join-Path $stagingFull $relative
        if ($entry.kind -eq 'directory') {
            [IO.Directory]::CreateDirectory($destination) | Out-Null
            continue
        }
        $parent = Split-Path -Parent $destination
        [IO.Directory]::CreateDirectory($parent) | Out-Null
        [IO.File]::Copy((Join-Path $sourceFull $relative), $destination, $false)
    }

    [void](Assert-WeDecentMigrationDirectoryAcl -Path $stagingFull -ServiceSid $DestinationServiceSid)
    $copiedManifest = @(Get-WeDecentMigrationManifest -Root $stagingFull)
    $sourceDigest = Get-WeDecentMigrationManifestDigest -Manifest $sourceManifest
    $copiedDigest = Get-WeDecentMigrationManifestDigest -Manifest $copiedManifest
    if ($sourceDigest -cne $copiedDigest) {
        throw 'Migration staging SHA-256 manifest does not match the source state tree.'
    }
    return [pscustomobject]@{
        SourceManifestSHA256 = $sourceDigest
        FileCount = @($sourceManifest | Where-Object kind -eq 'file').Count
        DirectoryCount = @($sourceManifest | Where-Object kind -eq 'directory').Count
        Identity = Assert-WeDecentMigrationIdentityContinuity -Source $sourceFull -Destination $stagingFull
    }
}

function Write-WeDecentMigrationJournal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][pscustomobject]$Journal
    )

    if ([int]$Journal.schema -ne 1 -or
        [string]$Journal.product -cne 'WeDecent' -or
        [string]$Journal.phase -notin $script:WeDecentMigrationPhases) {
        throw 'Migration journal schema, product, or phase is invalid.'
    }
    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    [void](Assert-WeDecentMigrationRealDirectory -Path $directory)
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Item -LiteralPath $Path -Force
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $existing.PSIsContainer) {
            throw 'Migration journal path is not a regular file.'
        }
    }

    $Journal.updated_utc = [DateTime]::UtcNow.ToString('o')
    $json = ConvertTo-Json -InputObject $Journal -Depth 10
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $temporary = Join-Path $directory ('.migration-journal-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $Path + '.previous'
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $temporary,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        if (Test-Path -LiteralPath $Path) {
            if (Test-Path -LiteralPath $backup) {
                Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
            }
            [IO.File]::Replace($temporary, $Path, $backup, $true)
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Read-WeDecentMigrationJournal {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Migration journal is not a regular file.'
    }
    $journal = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ([int]$journal.schema -ne 1 -or
        [string]$journal.product -cne 'WeDecent' -or
        [string]$journal.phase -notin $script:WeDecentMigrationPhases) {
        throw 'Migration journal is corrupt or has an unsupported schema/phase.'
    }
    $transactionId = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$journal.transaction_id, [ref]$transactionId)) {
        throw 'Migration journal transaction identifier is invalid.'
    }
    foreach ($field in @('source', 'destination', 'staging', 'original_service_path', 'updated_service_path')) {
        if ([string]::IsNullOrWhiteSpace([string]$journal.$field)) {
            throw "Migration journal field '$field' is missing."
        }
    }
    return $journal
}

Export-ModuleMember -Function @(
    'Get-WeDecentMigrationManifest',
    'Get-WeDecentMigrationManifestDigest',
    'Copy-WeDecentMigrationTreeVerified',
    'Set-WeDecentMigrationDirectoryAcl',
    'Assert-WeDecentMigrationDirectoryAcl',
    'Assert-WeDecentMigrationIdentityContinuity',
    'Write-WeDecentMigrationJournal',
    'Read-WeDecentMigrationJournal'
)
) {
            throw 'Non-mutating identity verifier returned malformed identity output.'
        }
        return [pscustomobject]@{
            DeviceId = $fields[0]
            Name = $fields[1]
            Fingerprint = $fields[2]
        }
    } finally {
        $process.Dispose()
    }
}

function Assert-WeDecentMigrationIdentityContinuity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$AgentPath
    )

    $sourceFull = Assert-WeDecentMigrationRealDirectory -Path $Source
    $destinationFull = Assert-WeDecentMigrationRealDirectory -Path $Destination
    $identityFiles = @('identity.crt')
    $protectedKey = Join-Path $sourceFull 'identity.key.dpapi'
    $legacyKey = Join-Path $sourceFull 'identity.key'
    if (Test-Path -LiteralPath $protectedKey -PathType Leaf) {
        $identityFiles += 'identity.key.dpapi'
    }
    if (Test-Path -LiteralPath $legacyKey -PathType Leaf) {
        $identityFiles += 'identity.key'
    }
    if ($identityFiles.Count -lt 2) {
        throw 'Migration source does not contain both an identity certificate and a supported private-key file.'
    }

    $certificatePath = Join-Path $sourceFull 'identity.crt'
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($certificatePath)
    if ($certificate.PublicKey.Oid.Value -cne '1.3.101.112') {
        throw 'Migration identity certificate is not Ed25519.'
    }
    $fingerprints = @{
        'identity.crt.public_key_algorithm' = $certificate.PublicKey.Oid.Value
    }
    foreach ($name in $identityFiles) {
        $sourcePath = Join-Path $sourceFull $name
        $destinationPath = Join-Path $destinationFull $name
        foreach ($candidate in @($sourcePath, $destinationPath)) {
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
            if ($item.PSIsContainer -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Identity continuity refuses a non-regular identity file: $candidate"
            }
        }
        $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash
        if ($sourceHash -cne $destinationHash) {
            throw "Identity continuity check failed for $name."
        }
        $fingerprints[$name] = $sourceHash.ToLowerInvariant()
    }
    return [pscustomobject]@{ SHA256 = $fingerprints }
}

function Copy-WeDecentMigrationTreeVerified {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Staging,
        [Parameter(Mandatory = $true)][string]$SourceServiceSid,
        [Parameter(Mandatory = $true)][string]$DestinationServiceSid
    )

    $sourceFull = Assert-WeDecentMigrationRealDirectory -Path $Source
    [void](Assert-WeDecentMigrationDirectoryAcl -Path $sourceFull -ServiceSid $SourceServiceSid)
    $sourceManifest = @(Get-WeDecentMigrationManifest -Root $sourceFull)
    $stagingFull = [IO.Path]::GetFullPath($Staging)
    if (Test-Path -LiteralPath $stagingFull) {
        throw "Migration staging path already exists: $stagingFull"
    }

    [IO.Directory]::CreateDirectory($stagingFull) | Out-Null
    Set-WeDecentMigrationDirectoryAcl -Path $stagingFull -ServiceSid $DestinationServiceSid
    foreach ($entry in $sourceManifest) {
        $relative = $entry.path.Replace('/', '\')
        $destination = Join-Path $stagingFull $relative
        if ($entry.kind -eq 'directory') {
            [IO.Directory]::CreateDirectory($destination) | Out-Null
            continue
        }
        $parent = Split-Path -Parent $destination
        [IO.Directory]::CreateDirectory($parent) | Out-Null
        [IO.File]::Copy((Join-Path $sourceFull $relative), $destination, $false)
    }

    [void](Assert-WeDecentMigrationDirectoryAcl -Path $stagingFull -ServiceSid $DestinationServiceSid)
    $copiedManifest = @(Get-WeDecentMigrationManifest -Root $stagingFull)
    $sourceDigest = Get-WeDecentMigrationManifestDigest -Manifest $sourceManifest
    $copiedDigest = Get-WeDecentMigrationManifestDigest -Manifest $copiedManifest
    if ($sourceDigest -cne $copiedDigest) {
        throw 'Migration staging SHA-256 manifest does not match the source state tree.'
    }
    return [pscustomobject]@{
        SourceManifestSHA256 = $sourceDigest
        FileCount = @($sourceManifest | Where-Object kind -eq 'file').Count
        DirectoryCount = @($sourceManifest | Where-Object kind -eq 'directory').Count
        Identity = Assert-WeDecentMigrationIdentityContinuity -Source $sourceFull -Destination $stagingFull
    }
}

function Write-WeDecentMigrationJournal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][pscustomobject]$Journal
    )

    if ([int]$Journal.schema -ne 1 -or
        [string]$Journal.product -cne 'WeDecent' -or
        [string]$Journal.phase -notin $script:WeDecentMigrationPhases) {
        throw 'Migration journal schema, product, or phase is invalid.'
    }
    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    [void](Assert-WeDecentMigrationRealDirectory -Path $directory)
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Item -LiteralPath $Path -Force
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $existing.PSIsContainer) {
            throw 'Migration journal path is not a regular file.'
        }
    }

    $Journal.updated_utc = [DateTime]::UtcNow.ToString('o')
    $json = ConvertTo-Json -InputObject $Journal -Depth 10
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $temporary = Join-Path $directory ('.migration-journal-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $Path + '.previous'
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $temporary,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        if (Test-Path -LiteralPath $Path) {
            if (Test-Path -LiteralPath $backup) {
                Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
            }
            [IO.File]::Replace($temporary, $Path, $backup, $true)
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Read-WeDecentMigrationJournal {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Migration journal is not a regular file.'
    }
    $journal = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ([int]$journal.schema -ne 1 -or
        [string]$journal.product -cne 'WeDecent' -or
        [string]$journal.phase -notin $script:WeDecentMigrationPhases) {
        throw 'Migration journal is corrupt or has an unsupported schema/phase.'
    }
    $transactionId = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$journal.transaction_id, [ref]$transactionId)) {
        throw 'Migration journal transaction identifier is invalid.'
    }
    foreach ($field in @('source', 'destination', 'staging', 'original_service_path', 'updated_service_path')) {
        if ([string]::IsNullOrWhiteSpace([string]$journal.$field)) {
            throw "Migration journal field '$field' is missing."
        }
    }
    return $journal
}

Export-ModuleMember -Function @(
    'Get-WeDecentMigrationManifest',
    'Get-WeDecentMigrationManifestDigest',
    'Copy-WeDecentMigrationTreeVerified',
    'Set-WeDecentMigrationDirectoryAcl',
    'Assert-WeDecentMigrationDirectoryAcl',
    'Assert-WeDecentMigrationIdentityContinuity',
    'Write-WeDecentMigrationJournal',
    'Read-WeDecentMigrationJournal'
)
