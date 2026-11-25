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

function Assert-WeDecentMigrationIdentityContinuity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$AgentPath
    )

    $sourceFull = Assert-WeDecentMigrationRealDirectory -Path $Source
    $destinationFull = Assert-WeDecentMigrationRealDirectory -Path $Destination
    # Go's identity.Load is the authoritative Ed25519 certificate, key-pair,
    # device-ID and fingerprint verifier. Never parse Ed25519 via .NET X509.
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
        [Parameter(Mandatory = $true)][string]$AgentPath
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


function Invoke-WeDecentMigrationStatePathCheck {
    param(
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [Parameter(Mandatory = $true)][string]$StatePath,
        [string]$ServiceSid
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
    if (-not [string]::IsNullOrWhiteSpace($ServiceSid)) {
        [void]$psi.ArgumentList.Add("--service-sid=$ServiceSid")
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
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Assert-WeDecentMigrationRealDirectory -Path $Path
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
    Assert-WeDecentMigrationAdminDirectory -Path $full
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

function Write-WeDecentMigrationMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$StatePath
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer metadata must be a regular non-reparse file.'
    }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
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
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
}

function Restore-WeDecentMigrationMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OriginalJson
    )

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
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
        [Parameter(Mandatory = $true)][string]$BinaryPath
    )

    $output = & sc.exe config $ServiceName "binPath= $BinaryPath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "SCM rejected the migration service path: $($output -join [Environment]::NewLine)"
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if (-not $service -or [string]$service.PathName -cne $BinaryPath) {
        throw 'SCM service path did not persist exactly as requested.'
    }
}

function Restore-WeDecentMigrationTransaction {
    param([Parameter(Mandatory = $true)][pscustomobject]$Journal)

    $Journal.phase = 'RollingBack'
    Write-WeDecentMigrationJournal -Path $Journal.journal_path -Journal $Journal
    $service = Get-Service -Name $Journal.service_name -ErrorAction Stop
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $Journal.service_name -Force -ErrorAction Stop
        (Get-Service -Name $Journal.service_name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Set-WeDecentMigrationServicePath -ServiceName $Journal.service_name -BinaryPath $Journal.original_service_path
    Restore-WeDecentMigrationMetadata -Path $Journal.metadata_path -OriginalJson $Journal.original_metadata_json
    if ([bool]$Journal.service_was_running) {
        Start-Service -Name $Journal.service_name -ErrorAction Stop
        (Get-Service -Name $Journal.service_name).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
    foreach ($candidate in @([string]$Journal.destination, [string]$Journal.staging)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
        [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $Journal.agent_path -StatePath $candidate -ServiceSid $Journal.service_sid)
        if ($candidate -ceq [string]$Journal.staging -and
            [string]::IsNullOrWhiteSpace([string]$Journal.source_manifest_sha256)) {
            [void](Assert-WeDecentMigrationTreeAcl -Path $candidate -ServiceSid $Journal.service_sid)
        } else {
            $manifest = @(Get-WeDecentMigrationManifest -Root $candidate)
            $digest = Get-WeDecentMigrationManifestDigest -Manifest $manifest
            if ($digest -cne [string]$Journal.source_manifest_sha256) {
                throw "Rollback refuses to remove changed migration copy: $candidate"
            }
        }
        Remove-Item -LiteralPath $candidate -Recurse -Force -ErrorAction Stop
    }
    $Journal.phase = 'RolledBack'
    Write-WeDecentMigrationJournal -Path $Journal.journal_path -Journal $Journal
}

function Recover-WeDecentStateMigration {
    param(
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [Parameter(Mandatory = $true)][string]$AgentPath
    )

    if (-not (Test-Path -LiteralPath $JournalPath -PathType Leaf)) { return $false }
    $journal = Read-WeDecentMigrationJournal -Path $JournalPath
    if ($journal.phase -in @('Committed', 'RolledBack')) { return $false }
    $journal | Add-Member -NotePropertyName journal_path -NotePropertyValue ([IO.Path]::GetFullPath($JournalPath)) -Force
    $journal | Add-Member -NotePropertyName agent_path -NotePropertyValue ([IO.Path]::GetFullPath($AgentPath)) -Force
    Restore-WeDecentMigrationTransaction -Journal $journal
    return $true
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
        [Parameter(Mandatory = $true)][string]$JournalPath
    )

    $sourceFull = [IO.Path]::GetFullPath($Source)
    $destinationFull = [IO.Path]::GetFullPath($Destination)
    if ([string]::Equals($sourceFull.TrimEnd('\'), $destinationFull.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Migration source and destination are identical.'
    }
    if (Test-Path -LiteralPath $destinationFull) {
        throw 'Migration destination already exists; refusing to merge or overwrite existing state.'
    }
    [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $AgentPath -StatePath $sourceFull -ServiceSid $ServiceSid)
    $destinationParent = Assert-WeDecentMigrationRealDirectory -Path (Split-Path -Parent $destinationFull)
    [void](Assert-WeDecentMigrationAdminDirectory -Path $destinationParent)
    [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $AgentPath -StatePath $destinationFull)

    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if (-not $service) { throw "Migration service '$ServiceName' does not exist." }
    $account = ([Security.Principal.NTAccount]::new([string]$service.StartName)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($account -cne $ServiceSid) { throw 'SCM service account SID differs from the migration target SID.' }
    $stateArg = [regex]::Escape($sourceFull)
    if ($service.PathName -notmatch ('(?i)(?:^|\s)--state=(?:"' + $stateArg + '"|' + $stateArg + ')(?:\s|$)')) {
        throw 'SCM command line does not reference the authenticated migration source.'
    }
    $updatedPath = [regex]::Replace(
        [string]$service.PathName,
        '(?i)(?<!\S)--state=(?:"[^"]+"|\S+)',
        ('--state="' + $destinationFull + '"'),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($updatedPath -ceq [string]$service.PathName) { throw 'Could not construct an unambiguous destination SCM command line.' }

    [void](Assert-WeDecentMigrationAdminDirectory -Path (Split-Path -Parent $JournalPath))
    $metadataItem = Get-Item -LiteralPath $MetadataPath -Force -ErrorAction Stop
    if ($metadataItem.PSIsContainer -or ($metadataItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer metadata is not a regular file.'
    }
    $originalMetadataJson = Get-Content -LiteralPath $MetadataPath -Raw -ErrorAction Stop
    $metadata = $originalMetadataJson | ConvertFrom-Json
    if ([IO.Path]::GetFullPath([string]$metadata.state_dir) -cne $sourceFull) {
        throw 'Authenticated installer metadata does not match the migration source.'
    }

    $transactionId = [Guid]::NewGuid().ToString('D')
    $staging = Join-Path $destinationParent ('.wedecent-migration-' + $transactionId.Replace('-', ''))
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
        agent_path = [IO.Path]::GetFullPath($AgentPath)
        service_was_running = ([string]$service.State -eq 'Running')
        original_service_path = [string]$service.PathName
        updated_service_path = $updatedPath
        metadata_path = [IO.Path]::GetFullPath($MetadataPath)
        original_metadata_json = $originalMetadataJson
        source_manifest_sha256 = ''
        journal_path = [IO.Path]::GetFullPath($JournalPath)
        updated_utc = ''
    }
    Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
    try {
        $journal.phase = 'Copying'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        $copy = Copy-WeDecentMigrationTreeVerified -Source $sourceFull -Staging $staging -SourceServiceSid $ServiceSid -DestinationServiceSid $ServiceSid -AgentPath $AgentPath
        $journal.source_manifest_sha256 = $copy.SourceManifestSHA256
        $journal.identity = $copy.Identity
        $journal.phase = 'Copied'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        [void](Assert-WeDecentMigrationIdentityContinuity -Source $sourceFull -Destination $staging -AgentPath $AgentPath)
        $journal.phase = 'Verified'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal

        if ($journal.service_was_running) {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        [IO.Directory]::Move($staging, $destinationFull)
        [void](Invoke-WeDecentMigrationStatePathCheck -AgentPath $AgentPath -StatePath $destinationFull -ServiceSid $ServiceSid)
        $journal.phase = 'StatePublished'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal

        Set-WeDecentMigrationServicePath -ServiceName $ServiceName -BinaryPath $updatedPath
        $journal.phase = 'ServiceReconfigured'
        Write-WeDecentMigrationJournal -Path $JournalPath -Journal $journal
        Write-WeDecentMigrationMetadata -Path $MetadataPath -StatePath $destinationFull
        if ($journal.service_was_running) {
            Start-Service -Name $ServiceName -ErrorAction Stop
            (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        }
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
            Restore-WeDecentMigrationTransaction -Journal $journal
        } catch {
            throw "Migration failed ($($failure.Exception.Message)); durable rollback is pending and original state was preserved: $($_.Exception.Message)"
        }
        throw "Migration failed and was rolled back; original state remains intact: $($failure.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $staging -PathType Container) {
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Export-ModuleMember -Function @(
    'Get-WeDecentMigrationManifest',
    'Get-WeDecentMigrationManifestDigest',
    'Copy-WeDecentMigrationTreeVerified',
    'Set-WeDecentMigrationDirectoryAcl',
    'Assert-WeDecentMigrationDirectoryAcl',
    'Set-WeDecentMigrationTreeOwner',
    'Assert-WeDecentMigrationTreeAcl',
    'Assert-WeDecentMigrationIdentityContinuity',
    'Invoke-WeDecentMigrationIdentityCheck',
    'Write-WeDecentMigrationJournal',
    'Read-WeDecentMigrationJournal',
    'Invoke-WeDecentMigrationStatePathCheck',
    'Set-WeDecentMigrationAdminDirectory',
    'Assert-WeDecentMigrationAdminDirectory',
    'Recover-WeDecentStateMigration',
    'Invoke-WeDecentStateMigration'
)
