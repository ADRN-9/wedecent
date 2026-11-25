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

function Get-WeDecentMigrationStableManifestDigest {
    param([Parameter(Mandatory = $true)][object[]]$Manifest)

    $stable = @($Manifest | Where-Object { $_.path -notin @('identity.key', 'identity.key.dpapi') })
    return Get-WeDecentMigrationManifestDigest -Manifest $stable
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
    [void](Assert-WeDecentMigrationDirectoryAcl -Path $full -ServiceSid $ServiceSid)
}

function Assert-WeDecentMigrationDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceSid
    )

    $full = Assert-WeDecentMigrationRealDirectory -Path $Path
    $service = ConvertTo-WeDecentMigrationSid -Sid $ServiceSid
    $allowed = @($service.Value, 'S-1-5-18', 'S-1-5-32-544')
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

function Set-WeDecentMigrationTreeOwner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceSid
    )

    $full = Assert-WeDecentMigrationRealDirectory -Path $Path
    $sid = ConvertTo-WeDecentMigrationSid -Sid $ServiceSid
    $output = & icacls.exe $full '/setowner' ('*' + $sid.Value) '/T' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set migration tree ownership: $($output -join [Environment]::NewLine)"
    }
}

function Assert-WeDecentMigrationTreeAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceSid
    )

    $root = Assert-WeDecentMigrationRealDirectory -Path $Path
    $sid = ConvertTo-WeDecentMigrationSid -Sid $ServiceSid
    $allowed = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')
    $paths = @($root) + @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop | ForEach-Object FullName)
    foreach ($entryPath in $paths) {
        $item = Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Migration ACL validation refuses reparse points: $entryPath"
        }
        $acl = Get-Acl -LiteralPath $entryPath -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -cne $sid.Value) {
            throw "Migration tree object has an unexpected owner SID: $entryPath"
        }
        $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
        foreach ($rule in $rules) {
            if ($rule.IdentityReference.Value -notin $allowed -or
                $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
                throw "Migration tree object has an unexpected access rule: $entryPath"
            }
        }
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
            $fields[0] -notmatch '^wd_[a-z2-7]{16}$' -or
            $fields[2] -notmatch '^SHA256:[A-F0-9]{64}$') {
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

function Invoke-WeDecentMigrationIdentityProtect {
    param(
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [Parameter(Mandatory = $true)][string]$StatePath
    )

    $agent = Get-Item -LiteralPath $AgentPath -Force -ErrorAction Stop
    if ($agent.PSIsContainer -or ($agent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Identity protection verifier must be a regular executable file.'
    }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $agent.FullName
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    [void]$psi.ArgumentList.Add('identity-protect')
    [void]$psi.ArgumentList.Add("--state=$StatePath")
    $process = [Diagnostics.Process]::Start($psi)
    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Non-renewing identity protection failed: $($stderr.Trim())"
        }
        $fields = $stdout.Trim().Split([char]9)
        if ($fields.Count -ne 3 -or
            $fields[0] -notmatch '^wd_[a-z2-7]{16}$' -or
            $fields[2] -notmatch '^SHA256:[A-F0-9]{64}$') {
            throw 'Identity protection returned malformed identity output.'
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

function Assert-WeDecentMigrationProtectedIdentityContinuity {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$AgentPath
    )

    $sourceCert = (Get-FileHash -LiteralPath (Join-Path $Source 'identity.crt') -Algorithm SHA256).Hash
    $destinationCert = (Get-FileHash -LiteralPath (Join-Path $Destination 'identity.crt') -Algorithm SHA256).Hash
    if ($sourceCert -cne $destinationCert) {
        throw 'Migration changed the original Ed25519 identity certificate bytes.'
    }
    $sourceProtected = Join-Path $Source 'identity.key.dpapi'
    $sourceLegacy = Join-Path $Source 'identity.key'
    $destinationProtected = Join-Path $Destination 'identity.key.dpapi'
    $destinationLegacy = Join-Path $Destination 'identity.key'
    if (Test-Path -LiteralPath $sourceProtected -PathType Leaf) {
        if (-not (Test-Path -LiteralPath $destinationProtected -PathType Leaf) -or
            (Get-FileHash -LiteralPath $sourceProtected -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $destinationProtected -Algorithm SHA256).Hash) {
            throw 'Migration changed existing DPAPI-protected identity key material.'
        }
    } elseif (-not (Test-Path -LiteralPath $sourceLegacy -PathType Leaf) -or
        -not (Test-Path -LiteralPath $destinationProtected -PathType Leaf)) {
        throw 'Migration did not preserve the legacy key as protected DPAPI identity material.'
    }
    if (Test-Path -LiteralPath $destinationLegacy) {
        throw 'Migration left a plaintext legacy private key in the destination state.'
    }

    $sourceIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $AgentPath -StatePath $Source
    $destinationIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $AgentPath -StatePath $Destination
    if ($sourceIdentity.DeviceId -cne $destinationIdentity.DeviceId -or
        $sourceIdentity.Fingerprint -cne $destinationIdentity.Fingerprint) {
        throw 'Cryptographic device identity changed during protected-key migration.'
    }
    return [pscustomobject]@{
        DeviceId = $sourceIdentity.DeviceId
        Fingerprint = $sourceIdentity.Fingerprint
        CertificateSHA256 = $sourceCert.ToLowerInvariant()
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
    foreach ($name in @('identity.key.dpapi', 'identity.key')) {
        if (Test-Path -LiteralPath (Join-Path $sourceFull $name) -PathType Leaf) {
            $identityFiles += $name
        }
    }
    if ($identityFiles.Count -lt 2) {
        throw 'Migration source does not contain both an identity certificate and a supported private-key file.'
    }

    $fingerprints = @{}
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
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [string]$FaultAt
    )

    $sourceFull = Assert-WeDecentMigrationRealDirectory -Path $Source
    [void](Assert-WeDecentMigrationTreeAcl -Path $sourceFull -ServiceSid $SourceServiceSid)
    $sourceManifest = @(Get-WeDecentMigrationManifest -Root $sourceFull)
    $stagingFull = [IO.Path]::GetFullPath($Staging)
    if (Test-Path -LiteralPath $stagingFull) {
        throw "Migration staging path already exists: $stagingFull"
    }
    $stagingParent = Assert-WeDecentMigrationRealDirectory -Path (Split-Path -Parent $stagingFull)
    [void](Assert-WeDecentMigrationAdminDirectory -Path $stagingParent)

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
        Invoke-WeDecentMigrationFaultPoint -Name 'StagingEntryCopied' -FaultAt $FaultAt
    }

    Set-WeDecentMigrationTreeOwner -Path $stagingFull -ServiceSid $DestinationServiceSid
    [void](Assert-WeDecentMigrationTreeAcl -Path $stagingFull -ServiceSid $DestinationServiceSid)
    $copiedManifest = @(Get-WeDecentMigrationManifest -Root $stagingFull)
    $sourceDigest = Get-WeDecentMigrationManifestDigest -Manifest $sourceManifest
    $copiedDigest = Get-WeDecentMigrationManifestDigest -Manifest $copiedManifest
    if ($sourceDigest -cne $copiedDigest) {
        throw 'Migration staging SHA-256 manifest does not match the source state tree.'
    }
    return [pscustomobject]@{
        SourceManifestSHA256 = $sourceDigest
        SourceStableManifestSHA256 = Get-WeDecentMigrationStableManifestDigest -Manifest $sourceManifest
        FileCount = @($sourceManifest | Where-Object kind -eq 'file').Count
        DirectoryCount = @($sourceManifest | Where-Object kind -eq 'directory').Count
        Identity = Assert-WeDecentMigrationIdentityContinuity -Source $sourceFull -Destination $stagingFull -AgentPath $AgentPath
    }
}

function Set-WeDecentMigrationAdminFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $admins = ConvertTo-WeDecentMigrationSid -Sid 'S-1-5-32-544'
    $system = ConvertTo-WeDecentMigrationSid -Sid 'S-1-5-18'
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($admins)
    foreach ($sid in @($admins, $system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
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
    $fullPath = [IO.Path]::GetFullPath($Path)
    $directory = Split-Path -Parent $fullPath
    [void](Assert-WeDecentMigrationRealDirectory -Path $directory)
    if (Test-Path -LiteralPath $fullPath) {
        $existing = Get-Item -LiteralPath $fullPath -Force
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $existing.PSIsContainer) {
            throw 'Migration journal path is not a regular file.'
        }
    }

    $Journal.updated_utc = [DateTime]::UtcNow.ToString('o')
    $json = ConvertTo-Json -InputObject $Journal -Depth 10
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $temporary = Join-Path $directory ('.migration-journal-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $fullPath + '.previous'
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
        Set-WeDecentMigrationAdminFileAcl -Path $temporary

        if (Test-Path -LiteralPath $fullPath) {
            if (Test-Path -LiteralPath $backup) {
                Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
            }
            [IO.File]::Replace($temporary, $fullPath, $backup, $true)
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        } else {
            [IO.File]::Move($temporary, $fullPath)
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

    [void](Assert-WeDecentMigrationAdminDirectory -Path (Split-Path -Parent $Path))
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $allowedAclSids = @('S-1-5-18', 'S-1-5-32-544')
    if ($owner -notin $allowedAclSids -or -not $acl.AreAccessRulesProtected) {
        throw 'Migration journal owner or DACL is not trusted.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin $allowedAclSids -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw 'Migration journal contains an unexpected access rule.'
        }
    }
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Migration journal is not a regular file.'
    }

    $journal = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    if ([int]$journal.schema -ne 1 -or
        [string]$journal.product -cne 'WeDecent' -or
        [string]$journal.phase -notin $script:WeDecentMigrationPhases) {
        throw 'Migration journal is corrupt or has an unsupported schema/phase.'
    }
    $transactionId = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$journal.transaction_id, [ref]$transactionId)) {
        throw 'Migration journal transaction identifier is invalid.'
    }
    foreach ($field in @('source', 'destination', 'staging', 'metadata_path', 'journal_path',
        'service_name', 'service_sid', 'service_start_name', 'service_start_mode', 'agent_path', 'original_service_path',
        'updated_service_path', 'original_metadata_json', 'source_manifest_sha256', 'source_stable_manifest_sha256')) {
        if ([string]::IsNullOrWhiteSpace([string]$journal.$field)) {
            throw "Migration journal field '$field' is missing."
        }
    }
    foreach ($field in @('source', 'destination', 'staging', 'metadata_path', 'journal_path')) {
        if (-not [IO.Path]::IsPathRooted([string]$journal.$field)) {
            throw "Migration journal path '$field' is not absolute."
        }
        $journal.$field = Get-WeDecentMigrationCanonicalPath -Path ([string]$journal.$field)
    }
    if ([string]::Equals([string]$journal.source, [string]$journal.destination, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals((Split-Path -Parent ([string]$journal.destination)), (Split-Path -Parent ([string]$journal.staging)), [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName([string]$journal.staging)).StartsWith('.wedecent-migration-', [StringComparison]::Ordinal)) {
        throw 'Migration journal contains unsafe or inconsistent source, destination, or staging paths.'
    }
    if (-not [string]::Equals([string]$journal.journal_path, [IO.Path]::GetFullPath($Path), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Migration journal path does not match the protected journal file.'
    }
    [void](ConvertTo-WeDecentMigrationSid -Sid ([string]$journal.service_sid))
    $installerSid = $null
    if ($null -ne $journal.PSObject.Properties['installer_sid']) {
        $installerSid = [string]$journal.installer_sid
    }
    if (-not [string]::IsNullOrWhiteSpace($installerSid)) {
        [void](ConvertTo-WeDecentMigrationSid -Sid $installerSid)
    }
    if ([string]$journal.service_name -notmatch '^[A-Za-z0-9_.-]{1,128}$' -or
        [string]$journal.service_start_mode -notin @('Boot', 'System', 'Auto', 'Manual', 'Disabled')) {
        throw 'Migration journal contains an invalid SCM service configuration.'
    }
    $hasStagingMarker = $null -ne $journal.PSObject.Properties['staging_complete']
    $hasIdentity = $null -ne $journal.identity -and
        -not [string]::IsNullOrWhiteSpace([string]$journal.identity.DeviceId) -and
        -not [string]::IsNullOrWhiteSpace([string]$journal.identity.Fingerprint)
    if (-not $hasStagingMarker -or $journal.staging_complete -isnot [bool] -or -not $hasIdentity) {
        $identityJson = if ($null -eq $journal.identity) { '<null>' } else { ConvertTo-Json -InputObject $journal.identity -Compress -Depth 3 }
        $markerType = if ($null -eq $journal.staging_complete) { '<null>' } else { $journal.staging_complete.GetType().FullName }
        throw "Migration journal lacks its source identity snapshot or staging completion marker (marker=$hasStagingMarker; markerType=$markerType; identity=$identityJson)."
    }
    [void](Assert-WeDecentMigrationPathsDisjoint -Paths @(
        [string]$journal.source, [string]$journal.destination, [string]$journal.staging,
        [string]$journal.journal_path, [string]$journal.metadata_path
    ))
    foreach ($digestField in @('source_manifest_sha256', 'source_stable_manifest_sha256', 'destination_manifest_sha256')) {
        if (-not [string]::IsNullOrWhiteSpace([string]$journal.$digestField) -and
            [string]$journal.$digestField -notmatch '^[a-f0-9]{64}$') {
            throw "Migration journal digest '$digestField' is malformed."
        }
    }
    $originalMetadata = [string]$journal.original_metadata_json | ConvertFrom-Json
    if ([int]$originalMetadata.schema -ne 1 -or
        [string]$originalMetadata.product -cne 'WeDecent' -or
        -not [string]::Equals([IO.Path]::GetFullPath([string]$originalMetadata.state_dir),
            [string]$journal.source, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Migration journal original metadata does not authenticate its source state.'
    }
    return $journal
}

function Invoke-WeDecentMigrationStatePathCheck {
    param(
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [Parameter(Mandatory = $true)][string]$StatePath,
        [string]$ServiceSid,
        [switch]$PrepareParent,
        [switch]$MigrationSource
    )

    $agent = Get-Item -LiteralPath $AgentPath -Force -ErrorAction Stop
    if ($agent.PSIsContainer -or ($agent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'State path verifier must be a regular executable file.'
    }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $agent.FullName
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    [void]$psi.ArgumentList.Add('state-path-check')
    [void]$psi.ArgumentList.Add("--state=$StatePath")
    if ($PrepareParent -and $MigrationSource) {
        throw 'Prepare-parent and migration-source validation are mutually exclusive.'
    }
    if ($PrepareParent) {
        [void]$psi.ArgumentList.Add('--prepare-parent')
    }
    if (-not [string]::IsNullOrWhiteSpace($ServiceSid)) {
        [void]$psi.ArgumentList.Add("--service-sid=$ServiceSid")
    }
    if ($MigrationSource) {
        if ([string]::IsNullOrWhiteSpace($ServiceSid)) {
            throw 'Migration-source validation requires the dedicated service SID.'
        }
        [void]$psi.ArgumentList.Add('--migration-source')
    }
    $process = [Diagnostics.Process]::Start($psi)
    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Protected state path verification failed: $($stderr.Trim())"
        }
        return $true
    } finally {
        $process.Dispose()
    }
}

function Set-WeDecentMigrationAdminDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AgentPath
    )

    $full = Assert-WeDecentMigrationRealDirectory -Path $Path
    $parentProbe = Join-Path $full '.wedecent-migration-parent-probe'
    [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $AgentPath -StatePath $parentProbe -PrepareParent)
    $admins = ConvertTo-WeDecentMigrationSid -Sid 'S-1-5-32-544'
    $system = ConvertTo-WeDecentMigrationSid -Sid 'S-1-5-18'
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($admins)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($admins, $system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $full -AclObject $acl -ErrorAction Stop
    [void](Assert-WeDecentMigrationAdminDirectory -Path $full)
}

function Assert-WeDecentMigrationAdminDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Assert-WeDecentMigrationRealDirectory -Path $Path
    $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544') -or -not $acl.AreAccessRulesProtected) {
        throw "Migration parent is not protected by a trusted owner and DACL: $full"
    }
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin $allowed -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Migration parent contains an unexpected access rule: $full"
        }
    }
    return $true
}

function Assert-WeDecentMigrationMetadataAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer metadata must be a regular non-reparse file.'
    }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    if ($owner -notin $allowed -or -not $acl.AreAccessRulesProtected) {
        throw 'Installer metadata owner or DACL is not trusted.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin $allowed -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw 'Installer metadata contains an unexpected access rule.'
        }
    }
    return $acl
}

function Write-WeDecentMigrationMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$StatePath
    )

    $acl = Assert-WeDecentMigrationMetadataAcl -Path $Path
    $metadata = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    if ([int]$metadata.schema -ne 1 -or [string]$metadata.product -cne 'WeDecent') {
        throw 'Cannot migrate unauthenticated or unsupported installer metadata.'
    }
    $metadata.state_dir = [IO.Path]::GetFullPath($StatePath)
    $metadata.updated_at = [DateTime]::UtcNow.ToString('o')
    $json = ConvertTo-Json -InputObject $metadata -Depth 10
    $temp = Join-Path (Split-Path -Parent $Path) ('.installer-migration-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $Path + '.migration-previous'
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
        $stream = [IO.FileStream]::new($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        Set-Acl -LiteralPath $temp -AclObject $acl -ErrorAction Stop
        [IO.File]::Replace($temp, $Path, $backup, $true)
        Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        $verified = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
        if ([IO.Path]::GetFullPath([string]$verified.state_dir) -ine [IO.Path]::GetFullPath($StatePath)) {
            throw 'Authenticated installer metadata failed post-migration state-path verification.'
        }
        [void](Assert-WeDecentMigrationMetadataAcl -Path $Path)
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
}

function Restore-WeDecentMigrationMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OriginalJson
    )

    $acl = Assert-WeDecentMigrationMetadataAcl -Path $Path
    $temp = Join-Path (Split-Path -Parent $Path) ('.installer-restore-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $Path + '.migration-restore-previous'
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($OriginalJson)
        $stream = [IO.FileStream]::new($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        Set-Acl -LiteralPath $temp -AclObject $acl -ErrorAction Stop
        [IO.File]::Replace($temp, $Path, $backup, $true)
        Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
}

function Set-WeDecentMigrationServicePath {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$ServiceSid,
        [Parameter(Mandatory = $true)][string]$StartMode
    )

    $output = & sc.exe config $ServiceName "binPath= $BinaryPath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "SCM rejected the migration service path: $($output -join [Environment]::NewLine)"
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if (-not $service -or [string]$service.PathName -cne $BinaryPath) {
        throw 'SCM service path did not persist exactly as requested.'
    }
    $actualSid = ([Security.Principal.NTAccount]::new([string]$service.StartName)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($actualSid -cne $ServiceSid -or [string]$service.StartMode -cne $StartMode) {
        throw 'SCM service account or start mode changed during the state migration transition.'
    }
}

function Invoke-WeDecentMigrationFaultPoint {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$FaultAt
    )

    $selected = $FaultAt
    if ([string]::IsNullOrWhiteSpace($selected)) {
        $selected = [Environment]::GetEnvironmentVariable('WEDECENT_MIGRATION_FAULT_AT')
    }
    $selectedPoints = @($selected -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($selectedPoints -ccontains $Name) {
        throw "Injected WeDecent migration interruption at $Name."
    }
}

function Assert-WeDecentMigrationRollbackIdentityContinuity {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$AgentPath
    )

    $sourceCertificate = (Get-FileHash -LiteralPath (Join-Path $Source 'identity.crt') -Algorithm SHA256).Hash
    $candidateCertificate = (Get-FileHash -LiteralPath (Join-Path $Candidate 'identity.crt') -Algorithm SHA256).Hash
    if ($sourceCertificate -cne $candidateCertificate) {
        throw 'Rollback candidate certificate differs from the original device certificate.'
    }
    $sourceIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $AgentPath -StatePath $Source
    $candidateIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $AgentPath -StatePath $Candidate
    if ($sourceIdentity.DeviceId -cne $candidateIdentity.DeviceId -or
        $sourceIdentity.Fingerprint -cne $candidateIdentity.Fingerprint) {
        throw 'Rollback candidate does not preserve the original cryptographic device identity.'
    }
    return $true
}

function Assert-WeDecentMigrationPartialTreeSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceSid,
        [string]$InstallerSid
    )

    $root = Assert-WeDecentMigrationRealDirectory -Path $Path
    $service = ConvertTo-WeDecentMigrationSid -Sid $ServiceSid
    $allowed = @($service.Value, 'S-1-5-18', 'S-1-5-32-544')
    if (-not [string]::IsNullOrWhiteSpace($InstallerSid)) {
        $installer = ConvertTo-WeDecentMigrationSid -Sid $InstallerSid
        $allowed += $installer.Value
    }
    $paths = @($root) + @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop | ForEach-Object FullName)
    foreach ($entryPath in $paths) {
        $item = Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Interrupted migration staging contains a reparse point: $entryPath"
        }
        $acl = Get-Acl -LiteralPath $entryPath -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $allowed) {
            throw "Interrupted migration staging has an untrusted owner: $entryPath"
        }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.IdentityReference.Value -notin $allowed -or
                $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
                throw "Interrupted migration staging has an unexpected access rule: $entryPath"
            }
        }
    }
    return $true
}

function Restore-WeDecentMigrationTransaction {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Journal,
        [string]$FaultAt
    )

    $service = Get-Service -Name $Journal.service_name -ErrorAction Stop
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $Journal.service_name -Force -ErrorAction Stop
        (Get-Service -Name $Journal.service_name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Invoke-WeDecentMigrationFaultPoint -Name 'RollbackServiceStopped' -FaultAt $FaultAt
    Assert-WeDecentMigrationRecoverySource -Journal $Journal
    $Journal.phase = 'RollingBack'
    Write-WeDecentMigrationJournal -Path $Journal.journal_path -Journal $Journal
    Invoke-WeDecentMigrationFaultPoint -Name 'RollbackStarted' -FaultAt $FaultAt
    Set-WeDecentMigrationServicePath -ServiceName $Journal.service_name -BinaryPath $Journal.original_service_path -ServiceSid $Journal.service_sid -StartMode $Journal.service_start_mode
    Invoke-WeDecentMigrationFaultPoint -Name 'RollbackSCMRestored' -FaultAt $FaultAt
    Restore-WeDecentMigrationMetadata -Path $Journal.metadata_path -OriginalJson $Journal.original_metadata_json
    Invoke-WeDecentMigrationFaultPoint -Name 'RollbackMetadataRestored' -FaultAt $FaultAt
    if ([bool]$Journal.service_was_running) {
        Assert-WeDecentMigrationRecoverySource -Journal $Journal
        Start-Service -Name $Journal.service_name -ErrorAction Stop
        (Get-Service -Name $Journal.service_name).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
    Invoke-WeDecentMigrationFaultPoint -Name 'RollbackServiceRestarted' -FaultAt $FaultAt
    foreach ($candidate in @([string]$Journal.destination, [string]$Journal.staging)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
        $partialStaging = $candidate -ceq [string]$Journal.staging -and
            -not [bool]$Journal.staging_complete
        if (-not $partialStaging) {
            [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $Journal.agent_path -StatePath $candidate -ServiceSid $Journal.service_sid)
        }
        if ($partialStaging) {
            $installerSid = $null
            if ($null -ne $Journal.PSObject.Properties['installer_sid']) {
                $installerSid = [string]$Journal.installer_sid
            }
            [void](Assert-WeDecentMigrationPartialTreeSafe -Path $candidate -ServiceSid $Journal.service_sid -InstallerSid $installerSid)
        } else {
            $manifest = @(Get-WeDecentMigrationManifest -Root $candidate)
            $digest = Get-WeDecentMigrationStableManifestDigest -Manifest $manifest
            if ($digest -cne [string]$Journal.source_stable_manifest_sha256) {
                throw "Rollback refuses to remove changed migration copy: $candidate"
            }
            [void](Assert-WeDecentMigrationRollbackIdentityContinuity -Source $Journal.source -Candidate $candidate -AgentPath $Journal.agent_path)
        }
        Invoke-WeDecentMigrationFaultPoint -Name 'RollbackStagingValidated' -FaultAt $FaultAt
        Remove-Item -LiteralPath $candidate -Recurse -Force -ErrorAction Stop
    }
    $Journal.phase = 'RolledBack'
    Write-WeDecentMigrationJournal -Path $Journal.journal_path -Journal $Journal
    Invoke-WeDecentMigrationFaultPoint -Name 'RolledBack' -FaultAt $FaultAt
}

function Recover-WeDecentStateMigration {
    param(
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [Parameter(Mandatory = $true)][string]$MetadataPath,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [string]$FaultAt
    )

    if (-not (Test-Path -LiteralPath $JournalPath -PathType Leaf)) { return $false }
    $journal = Read-WeDecentMigrationJournal -Path $JournalPath
    if (-not [string]::Equals([string]$journal.metadata_path, [IO.Path]::GetFullPath($MetadataPath), [StringComparison]::OrdinalIgnoreCase) -or
        [string]$journal.service_name -cne $ServiceName) {
        throw 'Migration recovery journal does not match this installer metadata path and service.'
    }
    if ($journal.phase -in @('Committed', 'RolledBack')) { return $false }
    $journal | Add-Member -NotePropertyName journal_path -NotePropertyValue ([IO.Path]::GetFullPath($JournalPath)) -Force
    $journal | Add-Member -NotePropertyName agent_path -NotePropertyValue ([IO.Path]::GetFullPath($AgentPath)) -Force
    Restore-WeDecentMigrationTransaction -Journal $journal -FaultAt $FaultAt
    return $true
}

function Get-WeDecentMigrationUpdatedServicePath {
    param(
        [Parameter(Mandatory = $true)][string]$ServicePath,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $statePattern = '(?i)(?<!\S)"--state=([^"]+)"|(?<!\S)--state="([^"]+)"|(?<!\S)--state=([^\s"]+)'
    $matches = [regex]::Matches($ServicePath, $statePattern)
    if ($matches.Count -ne 1) {
        throw 'SCM command line must contain exactly one unambiguous --state argument.'
    }
    $match = $matches[0]
    $matchedState = if ($match.Groups[1].Success) {
        $match.Groups[1].Value
    } elseif ($match.Groups[2].Success) {
        $match.Groups[2].Value
    } else {
        $match.Groups[3].Value
    }
    if (-not [string]::Equals($matchedState, [IO.Path]::GetFullPath($Source), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'SCM command line does not reference the authenticated migration source.'
    }
    return [regex]::Replace(
        $ServicePath,
        $statePattern,
        [System.Text.RegularExpressions.MatchEvaluator]{
            param($entry)
            return '"--state=' + [IO.Path]::GetFullPath($Destination) + '"'
        },
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
}

function Get-WeDecentMigrationCanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\')) {
        throw 'Migration paths must be ordinary, absolute local filesystem paths.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root) -or $root.StartsWith('\\') -or $full -match '^[A-Za-z]:[^\\]') {
        throw 'Migration paths must use an absolute local drive path.'
    }
    if ([string]::Equals($full, $root, [StringComparison]::OrdinalIgnoreCase)) { return $root }
    $full = $full.TrimEnd('\')

    if (-not ('WeDecentMigrationPathApi' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class WeDecentMigrationPathApi {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetLongPathName(string shortPath, StringBuilder longPath, uint bufferLength);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetShortPathName(string longPath, StringBuilder shortPath, uint bufferLength);
}
'@ -ErrorAction Stop
    }

    $walk = $root
    $relativeParts = $full.Substring($root.Length).Split([char[]]@([char]92), [System.StringSplitOptions]::RemoveEmptyEntries)
    foreach ($part in $relativeParts) {
        $walk = Join-Path $walk $part
        if (Test-Path -LiteralPath $walk) {
            $component = Get-Item -LiteralPath $walk -Force -ErrorAction Stop
            if (($component.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Migration path traverses a reparse point: $walk"
            }
        }
    }

    $probe = $full
    $suffix = [Collections.Generic.Stack[string]]::new()
    while (-not (Test-Path -LiteralPath $probe)) {
        $leaf = [IO.Path]::GetFileName($probe)
        $parent = [IO.Path]::GetDirectoryName($probe)
        if ([string]::IsNullOrWhiteSpace($leaf) -or [string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $probe, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Migration path has no resolvable existing ancestor: $Path"
        }
        $suffix.Push($leaf)
        $probe = $parent
    }

    $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Migration path traverses a reparse point: $probe"
    }
    $buffer = [Text.StringBuilder]::new(32768)
    $length = [WeDecentMigrationPathApi]::GetLongPathName($probe, $buffer, [uint32]$buffer.Capacity)
    if ($length -eq 0 -or $length -ge $buffer.Capacity) {
        throw "Migration path could not be resolved to its filesystem long name: $probe"
    }
    $resolved = $buffer.ToString()
    while ($suffix.Count -gt 0) { $resolved = Join-Path $resolved $suffix.Pop() }
    return $resolved.TrimEnd('\')
}

function Assert-WeDecentMigrationPathsDisjoint {
    param([Parameter(Mandatory = $true)][string[]]$Paths)

    $canonical = @()
    foreach ($path in $Paths) {
        $value = Get-WeDecentMigrationCanonicalPath -Path $path
        foreach ($existing in $canonical) {
            $leftPrefix = $existing.TrimEnd('\') + '\'
            $rightPrefix = $value.TrimEnd('\') + '\'
            if ([string]::Equals($existing, $value, [StringComparison]::OrdinalIgnoreCase) -or
                $existing.StartsWith($rightPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                $value.StartsWith($leftPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Migration paths overlap or alias one another: '$existing' and '$value'."
            }
        }
        $canonical += $value
    }
    return $canonical
}

function Assert-WeDecentMigrationRecoverySource {
    param([Parameter(Mandatory = $true)][pscustomobject]$Journal)

    if ([string]::IsNullOrWhiteSpace([string]$Journal.source_manifest_sha256) -or
        [string]::IsNullOrWhiteSpace([string]$Journal.source_stable_manifest_sha256) -or
        $null -eq $Journal.identity -or
        [string]::IsNullOrWhiteSpace([string]$Journal.identity.DeviceId) -or
        [string]::IsNullOrWhiteSpace([string]$Journal.identity.Fingerprint)) {
        throw 'Migration journal lacks an authenticated original-source snapshot; refusing recovery.'
    }
    [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $Journal.agent_path -StatePath $Journal.source -ServiceSid $Journal.service_sid -MigrationSource)
    [void](Assert-WeDecentMigrationTreeAcl -Path $Journal.source -ServiceSid $Journal.service_sid)
    $manifest = @(Get-WeDecentMigrationManifest -Root $Journal.source)
    if ((Get-WeDecentMigrationManifestDigest -Manifest $manifest) -cne [string]$Journal.source_manifest_sha256 -or
        (Get-WeDecentMigrationStableManifestDigest -Manifest $manifest) -cne [string]$Journal.source_stable_manifest_sha256) {
        throw 'Original migration source manifest changed; refusing SCM restoration or service restart.'
    }
    $identity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $Journal.agent_path -StatePath $Journal.source
    if ($identity.DeviceId -cne [string]$Journal.identity.DeviceId -or
        $identity.Fingerprint -cne [string]$Journal.identity.Fingerprint) {
        throw 'Original migration source identity changed; refusing SCM restoration or service restart.'
    }
}

function Invoke-WeDecentStateMigration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$ServiceSid,
        [Parameter(Mandatory = $true)][string]$MetadataPath,
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [string]$FaultAt
    )

    $sourceFull = Get-WeDecentMigrationCanonicalPath -Path $Source
    $destinationFull = Get-WeDecentMigrationCanonicalPath -Path $Destination
    if (Test-Path -LiteralPath $destinationFull) {
        throw 'Migration destination already exists; refusing to merge or overwrite existing state.'
    }
    [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $AgentPath -StatePath $sourceFull -ServiceSid $ServiceSid -MigrationSource)
    $destinationParent = Assert-WeDecentMigrationRealDirectory -Path (Split-Path -Parent $destinationFull)
    $transactionId = [Guid]::NewGuid().ToString('D')
    $staging = Join-Path $destinationParent ('.wedecent-migration-' + $transactionId.Replace('-', ''))
    $staging = Get-WeDecentMigrationCanonicalPath -Path $staging
    $journalFull = Get-WeDecentMigrationCanonicalPath -Path $JournalPath
    $metadataFull = Get-WeDecentMigrationCanonicalPath -Path $MetadataPath
    [void](Assert-WeDecentMigrationPathsDisjoint -Paths @($sourceFull, $destinationFull, $staging, $journalFull, $metadataFull))
    [void](Set-WeDecentMigrationAdminDirectory -Path $destinationParent -AgentPath $AgentPath)
    [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $AgentPath -StatePath $destinationFull)

    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if (-not $service) { throw "Migration service '$ServiceName' does not exist." }
    $account = ([Security.Principal.NTAccount]::new([string]$service.StartName)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($account -cne $ServiceSid) { throw 'SCM service account SID differs from the migration target SID.' }
    $updatedPath = Get-WeDecentMigrationUpdatedServicePath -ServicePath ([string]$service.PathName) -Source $sourceFull -Destination $destinationFull
    if ($updatedPath -ceq [string]$service.PathName) { throw 'Could not construct an unambiguous destination SCM command line.' }

    [void](Set-WeDecentMigrationAdminDirectory -Path (Split-Path -Parent $JournalPath) -AgentPath $AgentPath)
    $metadataItem = Get-Item -LiteralPath $MetadataPath -Force -ErrorAction Stop
    if ($metadataItem.PSIsContainer -or ($metadataItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer metadata is not a regular file.'
    }
    $originalMetadataJson = Get-Content -LiteralPath $MetadataPath -Raw -ErrorAction Stop
    $metadata = $originalMetadataJson | ConvertFrom-Json
    if (-not [string]::Equals([IO.Path]::GetFullPath([string]$metadata.state_dir), $sourceFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Authenticated installer metadata does not match the migration source.'
    }

    $sourceManifest = @(Get-WeDecentMigrationManifest -Root $sourceFull)
    $sourceIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $AgentPath -StatePath $sourceFull
    $journal = [pscustomobject]@{
        schema = 1
        product = 'WeDecent'
        transaction_id = $transactionId
        phase = 'Prepared'
        source = $sourceFull
        destination = $destinationFull
        staging = $staging
        service_name = $ServiceName
        service_sid = $ServiceSid
        installer_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        service_start_name = [string]$service.StartName
        service_start_mode = [string]$service.StartMode
        agent_path = [IO.Path]::GetFullPath($AgentPath)
        service_was_running = ([string]$service.State -eq 'Running')
        original_service_path = [string]$service.PathName
        updated_service_path = $updatedPath
        metadata_path = [IO.Path]::GetFullPath($MetadataPath)
        original_metadata_json = $originalMetadataJson
        identity = $sourceIdentity
        staging_complete = $false
        source_manifest_sha256 = Get-WeDecentMigrationManifestDigest -Manifest $sourceManifest
        source_stable_manifest_sha256 = Get-WeDecentMigrationStableManifestDigest -Manifest $sourceManifest
        destination_manifest_sha256 = ''
        journal_path = [IO.Path]::GetFullPath($JournalPath)
        updated_utc = ''
    }
    Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
    try {
        Invoke-WeDecentMigrationFaultPoint -Name 'Prepared' -FaultAt $FaultAt
        if ($journal.service_was_running) {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        Invoke-WeDecentMigrationFaultPoint -Name 'ServiceStopped' -FaultAt $FaultAt
        $journal.phase = 'Copying'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        Invoke-WeDecentMigrationFaultPoint -Name 'Copying' -FaultAt $FaultAt
        $copy = Copy-WeDecentMigrationTreeVerified -Source $sourceFull -Staging $staging -SourceServiceSid $ServiceSid -DestinationServiceSid $ServiceSid -AgentPath $AgentPath -FaultAt $FaultAt
        if ($copy.SourceManifestSHA256 -cne [string]$journal.source_manifest_sha256 -or
            $copy.SourceStableManifestSHA256 -cne [string]$journal.source_stable_manifest_sha256 -or
            $copy.Identity.DeviceId -cne [string]$journal.identity.DeviceId -or
            $copy.Identity.Fingerprint -cne [string]$journal.identity.Fingerprint) {
            throw 'Original source changed after the authenticated migration snapshot; refusing to continue.'
        }
        $journal.phase = 'Copied'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        Invoke-WeDecentMigrationFaultPoint -Name 'Copied' -FaultAt $FaultAt
        Invoke-WeDecentMigrationFaultPoint -Name 'IdentityVerification' -FaultAt $FaultAt
        $protectedIdentity = Invoke-WeDecentMigrationIdentityProtect -AgentPath $AgentPath -StatePath $staging
        $journal.identity = Assert-WeDecentMigrationProtectedIdentityContinuity -Source $sourceFull -Destination $staging -AgentPath $AgentPath
        if ($journal.identity.DeviceId -cne $protectedIdentity.DeviceId -or
            $journal.identity.Fingerprint -cne $protectedIdentity.Fingerprint) {
            throw 'Protected identity result differs from the verified migration identity.'
        }
        $journal.destination_manifest_sha256 = Get-WeDecentMigrationManifestDigest -Manifest @(Get-WeDecentMigrationManifest -Root $staging)
        $journal.staging_complete = $true
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        Invoke-WeDecentMigrationFaultPoint -Name 'IdentityProtected' -FaultAt $FaultAt
        $journal.phase = 'Verified'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        Invoke-WeDecentMigrationFaultPoint -Name 'Verified' -FaultAt $FaultAt

        [IO.Directory]::Move($staging, $destinationFull)
        [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $AgentPath -StatePath $destinationFull -ServiceSid $ServiceSid)
        $journal.phase = 'StatePublished'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        Invoke-WeDecentMigrationFaultPoint -Name 'StatePublished' -FaultAt $FaultAt

        Assert-WeDecentMigrationRecoverySource -Journal $journal
        Invoke-WeDecentMigrationFaultPoint -Name 'SCMTransition' -FaultAt $FaultAt
        Set-WeDecentMigrationServicePath -ServiceName $ServiceName -BinaryPath $updatedPath -ServiceSid $ServiceSid -StartMode ([string]$service.StartMode)
        $journal.phase = 'ServiceReconfigured'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        Invoke-WeDecentMigrationFaultPoint -Name 'ServiceReconfigured' -FaultAt $FaultAt
        Write-WeDecentMigrationMetadata -Path $MetadataPath -StatePath $destinationFull
        Invoke-WeDecentMigrationFaultPoint -Name 'MetadataUpdated' -FaultAt $FaultAt
        if ($journal.service_was_running) {
            Assert-WeDecentMigrationRecoverySource -Journal $journal
            Start-Service -Name $ServiceName -ErrorAction Stop
            (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        }
        Invoke-WeDecentMigrationFaultPoint -Name 'ServiceRestarted' -FaultAt $FaultAt
        $destinationIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $AgentPath -StatePath $destinationFull
        if ($destinationIdentity.DeviceId -cne $copy.Identity.DeviceId -or
            $destinationIdentity.Fingerprint -cne $copy.Identity.Fingerprint) {
            throw 'Post-restart identity verification failed after state migration.'
        }
        $journal.phase = 'Committed'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        return $journal
    } catch {
        $failure = $_
        try {
            $journal | Add-Member -NotePropertyName journal_path -NotePropertyValue ([IO.Path]::GetFullPath($JournalPath)) -Force
            Restore-WeDecentMigrationTransaction -Journal $journal -FaultAt $FaultAt
        } catch {
            throw "Migration failed ($($failure.Exception.Message)); durable rollback is pending and original state was preserved: $($_.Exception.Message)"
        }
        throw "Migration failed and was rolled back; original state remains intact: $($failure.Exception.Message)"
    } finally {
        # Staging is transaction state, not scratch space. Rollback owns its
        # removal only after validating the tree and recording RolledBack.
        # Preserve it across any pending or interrupted recovery.
        if (Test-Path -LiteralPath $JournalPath -PathType Leaf) {
            $terminalJournal = $null
            try {
                $terminalJournal = Read-WeDecentMigrationJournal -Path $JournalPath
            } catch {
                # An unreadable journal cannot authorize destructive cleanup.
            }
            if ($null -ne $terminalJournal -and $terminalJournal.phase -in @('Committed', 'RolledBack') -and
                (Test-Path -LiteralPath $staging -PathType Container)) {
                [void](Assert-WeDecentMigrationPartialTreeSafe -Path $staging -ServiceSid $ServiceSid)
                throw 'Terminal migration journal unexpectedly retains staging; refusing implicit cleanup.'
            }
        }
    }
}

Export-ModuleMember -Function @(
    'Get-WeDecentMigrationManifest',
    'Get-WeDecentMigrationManifestDigest',
    'Get-WeDecentMigrationStableManifestDigest',
    'Copy-WeDecentMigrationTreeVerified',
    'Set-WeDecentMigrationDirectoryAcl',
    'Assert-WeDecentMigrationDirectoryAcl',
    'Set-WeDecentMigrationTreeOwner',
    'Assert-WeDecentMigrationTreeAcl',
    'Assert-WeDecentMigrationPartialTreeSafe',
    'Assert-WeDecentMigrationRollbackIdentityContinuity',
    'Assert-WeDecentMigrationIdentityContinuity',
    'Assert-WeDecentMigrationProtectedIdentityContinuity',
    'Invoke-WeDecentMigrationIdentityCheck',
    'Invoke-WeDecentMigrationIdentityProtect',
    'Write-WeDecentMigrationJournal',
    'Read-WeDecentMigrationJournal',
    'Invoke-WeDecentMigrationStatePathCheck',
    'Set-WeDecentMigrationAdminDirectory',
    'Assert-WeDecentMigrationAdminDirectory',
    'Set-WeDecentMigrationAdminFileAcl',
    'Assert-WeDecentMigrationMetadataAcl',
    'Recover-WeDecentStateMigration',
    'Invoke-WeDecentMigrationFaultPoint',
    'Get-WeDecentMigrationUpdatedServicePath',
    'Get-WeDecentMigrationCanonicalPath',
    'Assert-WeDecentMigrationPathsDisjoint',
    'Assert-WeDecentMigrationRecoverySource',
    'Invoke-WeDecentStateMigration'
)
