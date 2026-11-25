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

function Copy-WeDecentMigrationTreeVerified {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Staging
    )

    $sourceFull = Assert-WeDecentMigrationRealDirectory -Path $Source
    $sourceManifest = @(Get-WeDecentMigrationManifest -Root $sourceFull)
    $stagingFull = [IO.Path]::GetFullPath($Staging)
    if (Test-Path -LiteralPath $stagingFull) {
        throw "Migration staging path already exists: $stagingFull"
    }

    [IO.Directory]::CreateDirectory($stagingFull) | Out-Null
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
    'Write-WeDecentMigrationJournal',
    'Read-WeDecentMigrationJournal'
)
