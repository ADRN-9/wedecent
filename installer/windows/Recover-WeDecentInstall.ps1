[CmdletBinding(DefaultParameterSetName = 'Recover')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [ValidatePattern('^[a-f0-9]{32}$')]
    [string]$TransactionId,
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [Parameter(Mandatory = $true)]
    [string]$StateDir,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')]
    [string]$ServiceName,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [string]$ExpectedManifestSHA256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [string]$ExpectedPackageSHA256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [UInt64]$Sequence,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [string]$PreviousVersion,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [string]$TargetVersion,
    [Parameter(Mandatory = $true, ParameterSetName = 'FinalizeCommitted')]
    [switch]$FinalizeCommitted,
    [Parameter(Mandatory = $true, ParameterSetName = 'FinalizeCommitted')]
    [UInt64]$ExpectedStableSequence,
    [Parameter(Mandatory = $true, ParameterSetName = 'FinalizeCommitted')]
    [string]$ExpectedInstalledVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$BinaryNames = @('wd.exe', 'wd-agent.exe', 'wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe')
$TrustedSids = @('S-1-5-18', 'S-1-5-32-544')

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Windows installer recovery requires an elevated administrator token.'
    }
}

function Get-Sha256FileHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Recovery input is not a regular file: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Set-TrustedAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sidText in $TrustedSids) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-TrustedAcl {
    param([Parameter(Mandatory = $true)][string]$Path, [string[]]$AdditionalTrustedSids = @())
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Recovery trust path must not be a reparse point: $Path"
    }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Recovery trust path has an inheriting DACL: $Path"
    }
    $ownerSid = (New-Object Security.Principal.NTAccount -ArgumentList $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedSids -notcontains $ownerSid -and $AdditionalTrustedSids -notcontains $ownerSid) {
        throw "Recovery trust path has an untrusted owner: $Path"
    }
    foreach ($rule in @($acl.Access)) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if (($TrustedSids -notcontains $sid -and $AdditionalTrustedSids -notcontains $sid) -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "Recovery trust path has an untrusted ACL entry: $Path"
        }
    }
}

function Write-TransactionJournal {
    param([Parameter(Mandatory = $true)]$Journal, [Parameter(Mandatory = $true)][string]$Path)
    $directory = Split-Path -Parent $Path
    $temp = Join-Path $directory ('.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $Journal.updated_at = [DateTime]::UtcNow.ToString('o')
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Journal | ConvertTo-Json -Depth 8 -Compress) + [Environment]::NewLine)
    $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    Set-TrustedAcl -Path $temp
    Assert-TrustedAcl -Path $temp
    $backup = Join-Path $directory ('.' + [Guid]::NewGuid().ToString('N') + '.previous')
    [IO.File]::Replace($temp, $Path, $backup, $true)
    Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    Assert-TrustedAcl -Path $Path
}

function Assert-NoRunningUserBinaries {
    $destinations = @{}
    foreach ($name in $BinaryNames) {
        $destinations[$name] = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
    }
    $processes = @(Get-CimInstance Win32_Process -Filter "Name='wd.exe' OR Name='wd-routerctl.exe' OR Name='wd-core.exe' OR Name='wd-ui.exe'" -ErrorAction Stop)
    foreach ($process in $processes) {
        if (@('wd.exe', 'wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe') -notcontains [string]$process.Name) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$process.ExecutablePath)) {
            throw "Cannot authenticate running $($process.Name) executable path; recovery will not terminate it."
        }
        $path = [IO.Path]::GetFullPath([string]$process.ExecutablePath)
        if ($path.Equals($destinations[[string]$process.Name], [StringComparison]::OrdinalIgnoreCase)) {
            throw "Close installed $($process.Name) (PID $($process.ProcessId)) before recovery."
        }
    }
}

Assert-Administrator
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$StateDir = [IO.Path]::GetFullPath($StateDir)
if (-not $InstallDir.StartsWith([IO.Path]::GetFullPath($env:ProgramFiles) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Recovery install directory is outside Program Files.'
}
if (-not $StateDir.StartsWith($InstallDir + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Recovery state directory is outside the install directory.'
}
$installItem = Get-Item -LiteralPath $InstallDir -Force
$stateDirectoryItem = Get-Item -LiteralPath $StateDir -Force
if (-not $installItem.PSIsContainer -or -not $stateDirectoryItem.PSIsContainer -or
    (($installItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    (($stateDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Install or state directory is unavailable or a reparse point.'
}
$journalRoot = Join-Path $env:ProgramData 'WeDecent\install-transactions'
if ($PSCmdlet.ParameterSetName -eq 'FinalizeCommitted') {
    if (-not (Test-Path -LiteralPath $journalRoot -PathType Container)) { return }
    Assert-TrustedAcl -Path $journalRoot
    $metadataPath = Join-Path $env:ProgramData 'WeDecent\installer.json'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw 'Authenticated installer metadata is unavailable; committed cleanup is unsafe.'
    }
    Assert-TrustedAcl -Path $metadataPath
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    if ([string]$metadata.install_dir -ine $InstallDir -or
        [string]$metadata.state_dir -ine $StateDir -or
        [string]$metadata.service_name -cne $ServiceName -or
        [string]$metadata.service_account_sid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') {
        throw 'Installer metadata does not authenticate committed cleanup paths.'
    }
    $installOwner = (Get-Acl -LiteralPath $InstallDir).Owner
    $installOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $installOwner).Translate([Security.Principal.SecurityIdentifier]).Value
    $stateOwner = (Get-Acl -LiteralPath $StateDir).Owner
    $stateOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $stateOwner).Translate([Security.Principal.SecurityIdentifier]).Value
    $statePath = Join-Path $StateDir 'update-state.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw 'Protected updater state is unavailable; committed cleanup is unsafe.'
    }
    $stateItem = Get-Item -LiteralPath $statePath -Force
    if ($stateItem.PSIsContainer -or ($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Updater state is not a regular file.'
    }
    Assert-TrustedAcl -Path $statePath -AdditionalTrustedSids @([string]$metadata.service_account_sid, $installOwnerSid, $stateOwnerSid)
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($null -ne $state.pending_install -or
        [UInt64]$state.stable_sequence -ne $ExpectedStableSequence -or
        [string]$state.installed_version -cne $ExpectedInstalledVersion) {
        throw 'Protected updater state changed before committed backup cleanup.'
    }

    $expectedNames = @($BinaryNames | Sort-Object -CaseSensitive)
    foreach ($file in @(Get-ChildItem -LiteralPath $journalRoot -Filter '*.json' -File)) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Committed cleanup journal is a reparse point: $($file.FullName)"
        }
        Assert-TrustedAcl -Path $file.FullName
        $journal = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        $journalSequence = [UInt64]$journal.sequence
        $managedJournal = -not [string]::IsNullOrWhiteSpace([string]$journal.package_sha256) -or $journalSequence -ne 0
        if ([int]$journal.schema -ne 1 -or
            [string]$journal.transaction_id -notmatch '^[a-f0-9]{32}$' -or
            [string]$file.BaseName -cne [string]$journal.transaction_id -or
            ($managedJournal -and ([string]$journal.package_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$journal.manifest_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$journal.previous_version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or $journalSequence -eq 0)) -or
            (-not $managedJournal -and (-not [string]::IsNullOrEmpty([string]$journal.manifest_sha256) -or
                -not [string]::IsNullOrEmpty([string]$journal.previous_version))) -or
            $journal.service_was_running -isnot [bool] -or
            [string]$journal.version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?
        if ($journal.phase -eq 'rolled-back') { continue }
        if ($journalSequence -gt $ExpectedStableSequence) {
            throw 'An unresolved transaction journal is ahead of protected updater sequence.'
        }

        $seen = @{}
        foreach ($entry in @($journal.entries)) {
            $name = [string]$entry.name
            if ($BinaryNames -notcontains $name -or $seen.ContainsKey($name)) {
                throw "Committed cleanup journal contains an unknown or duplicate binary: $name"
            }
            $seen[$name] = $true
            $destination = [IO.Path]::GetFullPath([string]$entry.destination)
            $expectedDestination = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
            $expectedBackup = "$expectedDestination.$($journal.transaction_id).bak"
            if (-not $destination.Equals($expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
                -not ([IO.Path]::GetFullPath([string]$entry.backup_path)).Equals($expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
                $entry.had_original -isnot [bool] -or
                [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced') -or
                [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$entry.original_sha256 -notmatch '^(?:[a-f0-9]{64})?$' -or
                ([bool]$entry.had_original -and [string]$entry.original_sha256 -notmatch '^[a-f0-9]{64}$')) {
                throw "Committed cleanup journal entry is invalid for $name"
            }
            $backup = [string]$entry.backup_path
            if ($journalSequence -lt $ExpectedStableSequence) {
                if ($journal.phase -ne 'committed' -or (Test-Path -LiteralPath $backup -PathType Leaf)) {
                    throw "Older transaction has incomplete or non-committed cleanup: $backup"
                }
                continue
            }
            if ([string]$journal.version -cne $ExpectedInstalledVersion -or
                $journal.phase -notin @('installed-awaiting-sequence-commit', 'committed')) {
                throw 'Current journal phase or version disagrees with protected updater state.'
            }
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Current committed binary failed verification: $destination"
            }
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                if (-not [bool]$entry.had_original -or
                    (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                    throw "Committed backup integrity failure: $backup"
                }
            } elseif ([bool]$entry.had_original -and $journal.phase -ne 'committed') {
                throw "Backup disappeared before durable committed journal publication: $backup"
            }
        }
        if ($seen.Count -ne $expectedNames.Count) {
            throw 'Committed cleanup journal does not cover all five approved binaries.'
        }
        if ($journalSequence -lt $ExpectedStableSequence) { continue }

        if ($journal.phase -ne 'committed') {
            $journal.phase = 'committed'
            Write-TransactionJournal -Journal $journal -Path $file.FullName
        }
        foreach ($entry in @($journal.entries)) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
            }
            Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
            $destination = [string]$entry.destination
            Remove-Item -LiteralPath "$destination.$($journal.transaction_id).new" -Force -ErrorAction SilentlyContinue
        }
        $metadataSnapshot = [string]$journal.metadata_backup_path
        if (Test-Path -LiteralPath $metadataSnapshot -PathType Leaf) {
            if ((Get-Sha256FileHash $metadataSnapshot) -ne [string]$journal.metadata_original_sha256) { throw "Refusing to clean corrupted committed metadata snapshot: $metadataSnapshot" }
            Remove-Item -LiteralPath $metadataSnapshot -Force -ErrorAction Stop
        }
    }
    Write-Output 'committed-backup-cleanup-complete'
    exit 0
}
$journalPath = Join-Path $journalRoot ($TransactionId + '.json')
if (-not (Test-Path -LiteralPath $journalRoot -PathType Container) -or
    -not (Test-Path -LiteralPath $journalPath -PathType Leaf)) {
    throw 'Transaction journal is unavailable; recovery outcome is unknown.'
}
Assert-TrustedAcl -Path $journalRoot
Assert-TrustedAcl -Path $journalPath
$journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
if ([int]$journal.schema -ne 1 -or [string]$journal.transaction_id -cne $TransactionId -or
    [string]$journal.manifest_sha256 -cne $ExpectedManifestSHA256 -or
    [string]$journal.manifest_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$journal.package_sha256 -cne $ExpectedPackageSHA256 -or
    [string]$journal.package_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [UInt64]$journal.sequence -ne $Sequence -or $Sequence -eq 0 -or
    [string]$journal.previous_version -cne $PreviousVersion -or
    [string]$journal.previous_version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
    [string]$journal.version -cne $TargetVersion -or
    [string]$journal.version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
    $journal.phase -notin @('prepared', 'backups-verified', 'replacing', 'installed-awaiting-sequence-commit', 'committed', 'rolled-back') -or
    $journal.service_was_running -isnot [bool] -or
    @($journal.entries).Count -ne $BinaryNames.Count) {
    throw 'Transaction journal does not match the authenticated Go transaction.'
}

$metadataPath = Join-Path $env:ProgramData 'WeDecent\installer.json'
if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
    throw 'Authenticated installer metadata is unavailable; recovery outcome is unknown.'
}
Assert-TrustedAcl -Path $metadataPath
$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
if ([string]$metadata.install_dir -ine $InstallDir -or
    [string]$metadata.state_dir -ine $StateDir -or
    [string]$metadata.service_name -cne $ServiceName -or
    [string]$metadata.service_account_sid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') {
    throw 'Installer metadata does not authenticate the requested service and state paths.'
}
$installOwner = (Get-Acl -LiteralPath $InstallDir).Owner
$installOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $installOwner).Translate([Security.Principal.SecurityIdentifier]).Value
$stateOwner = (Get-Acl -LiteralPath $StateDir).Owner
$stateOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $stateOwner).Translate([Security.Principal.SecurityIdentifier]).Value
$statePath = Join-Path $StateDir 'update-state.json'
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw 'Protected updater state is unavailable; recovery outcome is unknown.'
}
$stateItem = Get-Item -LiteralPath $statePath -Force
if ($stateItem.PSIsContainer -or ($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Updater state is not a regular file.'
}
Assert-TrustedAcl -Path $statePath -AdditionalTrustedSids @([string]$metadata.service_account_sid, $installOwnerSid, $stateOwnerSid)
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$committed = [UInt64]$state.stable_sequence -ge $Sequence -and
    $null -eq $state.pending_install -and [string]$state.installed_version -ceq $TargetVersion

$seen = @{}
foreach ($entry in @($journal.entries)) {
    $name = [string]$entry.name
    if ($BinaryNames -notcontains $name -or $seen.ContainsKey($name)) {
        throw "Transaction journal has an unknown or duplicate binary: $name"
    }
    $seen[$name] = $true
    $destination = [IO.Path]::GetFullPath([string]$entry.destination)
    $expectedDestination = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
    $expectedBackup = "$expectedDestination.$TransactionId.bak"
    if (-not $destination.Equals($expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$entry.backup_path)).Equals($expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
        $entry.had_original -isnot [bool] -or
        [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced') -or
        [string]$entry.original_sha256 -notmatch '^(?:[a-f0-9]{64})?$' -or
        [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$') {
        throw "Transaction journal entry is invalid for $name"
    }
    if ([bool]$entry.had_original) {
        if ([string]$entry.original_sha256 -notmatch '^[a-f0-9]{64}$') {
            throw "Original binary digest is missing for $name"
        }
        if (Test-Path -LiteralPath $expectedBackup -PathType Leaf) {
            if ((Get-Sha256FileHash $expectedBackup) -ne [string]$entry.original_sha256) {
                throw "Transaction backup integrity failure: $expectedBackup"
            }
        } elseif ($committed) {
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Committed transaction has neither its backup nor the verified replacement: $destination"
            }
        } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
            throw "Original binary and verified backup are both unavailable: $destination"
        }
    } elseif (-not [string]::IsNullOrEmpty([string]$entry.original_sha256)) {
        throw "Unexpected original digest for $name"
    }
}
if ($seen.Count -ne $BinaryNames.Count) {
    throw 'Transaction journal does not cover all five approved binaries.'
}

if ($journal.phase -eq 'committed' -and -not $committed) {
    throw 'Journal claims commit but protected updater state does not confirm it.'
}
if ($journal.phase -eq 'rolled-back' -and $committed) {
    throw 'Journal claims rollback but protected updater state confirms commit.'
}
if ($committed) {
    foreach ($entry in @($journal.entries)) {
        if ((Get-Sha256FileHash ([string]$entry.destination)) -ne [string]$entry.replacement_sha256) {
            throw "Committed sequence has a mismatched binary: $($entry.destination)"
        }
    }
    $journal.phase = 'committed'
    Write-TransactionJournal -Journal $journal -Path $journalPath
    foreach ($entry in @($journal.entries)) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ([bool]$entry.had_original -and
                (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Refusing to clean a corrupted committed backup: $backup"
            }
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        }
        Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
        $destination = [string]$entry.destination
        Remove-Item -LiteralPath "$destination.$TransactionId.new" -Force -ErrorAction SilentlyContinue
    }
    Write-Output 'applied'
    exit 0
}

$pending = $state.pending_install
if ($null -eq $pending -or [string]$pending.id -cne $TransactionId -or
    [UInt64]$pending.sequence -ne $Sequence -or
    [string]$pending.manifest_digest -cne $ExpectedManifestSHA256 -or
    [string]$pending.package_digest -cne $ExpectedPackageSHA256 -or
    [string]$pending.previous_version -cne $PreviousVersion -or
    [string]$pending.target_version -cne $TargetVersion) {
    throw 'Updater state does not contain the exact pending transaction; recovery is ambiguous.'
}

# Preflight every original and backup before stopping services or changing files.
foreach ($entry in @($journal.entries)) {
    $destination = [string]$entry.destination
    if ([bool]$entry.had_original) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ((Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Corrupted transaction backup: $backup"
            }
        } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
            throw "No verified original or backup is available: $destination"
        }
    } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
        if ((Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
            throw "Unexpected binary contents prevent safe rollback: $destination"
        }
    }
}
Assert-NoRunningUserBinaries

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$restartService = [bool]$journal.service_was_running
if ($service -and $service.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
try {
    for ($i = @($journal.entries).Count - 1; $i -ge 0; $i--) {
        $entry = @($journal.entries)[$i]
        $destination = [string]$entry.destination
        if ([bool]$entry.had_original) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                $restore = "$destination.$TransactionId.recover"
                Copy-Item -LiteralPath $backup -Destination $restore -Force
                if ((Get-Sha256FileHash $restore) -ne [string]$entry.original_sha256) {
                    Remove-Item -LiteralPath $restore -Force -ErrorAction SilentlyContinue
                    throw "Restored backup verification failed: $destination"
                }
                Move-Item -LiteralPath $restore -Destination $destination -Force
            }
            if ((Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                throw "Rollback verification failed: $destination"
            }
        } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
            Remove-Item -LiteralPath $destination -Force
        }
        Remove-Item -LiteralPath "$destination.$TransactionId.new" -Force -ErrorAction SilentlyContinue
    }
    if ($restartService -and $service) {
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
    $journal.phase = 'rolled-back'
    Write-TransactionJournal -Journal $journal -Path $journalPath
} catch {
    $failure = $_
    throw "Windows transaction recovery failed closed; pending authorization and backups were retained. Cause: $($failure.Exception.Message)"
}
Write-Output 'not-applied' -or
            [string]$journal.phase -notin @('prepared', 'backups-verified', 'replacing', 'installed-awaiting-sequence-commit', 'committed', 'rolled-back') -or
            $journal.metadata_had_original -isnot [bool] -or
            -not ([string]$journal.metadata_path).Equals($metadataPath, [StringComparison]::OrdinalIgnoreCase) -or
            -not ([string]$journal.metadata_backup_path).Equals("$metadataPath.$($journal.transaction_id).metadata.bak", [StringComparison]::OrdinalIgnoreCase) -or
            -not [regex]::IsMatch([string]$journal.metadata_original_sha256, '^[a-f0-9]{64}
        if ($journal.phase -eq 'rolled-back') { continue }
        if ($journalSequence -gt $ExpectedStableSequence) {
            throw 'An unresolved transaction journal is ahead of protected updater sequence.'
        }

        $seen = @{}
        foreach ($entry in @($journal.entries)) {
            $name = [string]$entry.name
            if ($BinaryNames -notcontains $name -or $seen.ContainsKey($name)) {
                throw "Committed cleanup journal contains an unknown or duplicate binary: $name"
            }
            $seen[$name] = $true
            $destination = [IO.Path]::GetFullPath([string]$entry.destination)
            $expectedDestination = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
            $expectedBackup = "$expectedDestination.$($journal.transaction_id).bak"
            if (-not $destination.Equals($expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
                -not ([IO.Path]::GetFullPath([string]$entry.backup_path)).Equals($expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
                $entry.had_original -isnot [bool] -or
                [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced') -or
                [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$entry.original_sha256 -notmatch '^(?:[a-f0-9]{64})?$' -or
                ([bool]$entry.had_original -and [string]$entry.original_sha256 -notmatch '^[a-f0-9]{64}$')) {
                throw "Committed cleanup journal entry is invalid for $name"
            }
            $backup = [string]$entry.backup_path
            if ($journalSequence -lt $ExpectedStableSequence) {
                if ($journal.phase -ne 'committed' -or (Test-Path -LiteralPath $backup -PathType Leaf)) {
                    throw "Older transaction has incomplete or non-committed cleanup: $backup"
                }
                continue
            }
            if ([string]$journal.version -cne $ExpectedInstalledVersion -or
                $journal.phase -notin @('installed-awaiting-sequence-commit', 'committed')) {
                throw 'Current journal phase or version disagrees with protected updater state.'
            }
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Current committed binary failed verification: $destination"
            }
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                if (-not [bool]$entry.had_original -or
                    (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                    throw "Committed backup integrity failure: $backup"
                }
            } elseif ([bool]$entry.had_original -and $journal.phase -ne 'committed') {
                throw "Backup disappeared before durable committed journal publication: $backup"
            }
        }
        if ($seen.Count -ne $expectedNames.Count) {
            throw 'Committed cleanup journal does not cover all five approved binaries.'
        }
        if ($journalSequence -lt $ExpectedStableSequence) { continue }

        if ($journal.phase -ne 'committed') {
            $journal.phase = 'committed'
            Write-TransactionJournal -Journal $journal -Path $file.FullName
        }
        foreach ($entry in @($journal.entries)) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
            }
            Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
            $destination = [string]$entry.destination
            Remove-Item -LiteralPath "$destination.$($journal.transaction_id).new" -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Output 'committed-backup-cleanup-complete'
    exit 0
}
$journalPath = Join-Path $journalRoot ($TransactionId + '.json')
if (-not (Test-Path -LiteralPath $journalRoot -PathType Container) -or
    -not (Test-Path -LiteralPath $journalPath -PathType Leaf)) {
    throw 'Transaction journal is unavailable; recovery outcome is unknown.'
}
Assert-TrustedAcl -Path $journalRoot
Assert-TrustedAcl -Path $journalPath
$journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
if ([int]$journal.schema -ne 1 -or [string]$journal.transaction_id -cne $TransactionId -or
    [string]$journal.manifest_sha256 -cne $ExpectedManifestSHA256 -or
    [string]$journal.manifest_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$journal.package_sha256 -cne $ExpectedPackageSHA256 -or
    [string]$journal.package_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [UInt64]$journal.sequence -ne $Sequence -or $Sequence -eq 0 -or
    [string]$journal.previous_version -cne $PreviousVersion -or
    [string]$journal.previous_version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
    [string]$journal.version -cne $TargetVersion -or
    [string]$journal.version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
    $journal.phase -notin @('prepared', 'backups-verified', 'replacing', 'installed-awaiting-sequence-commit', 'committed', 'rolled-back') -or
    $journal.service_was_running -isnot [bool] -or
    @($journal.entries).Count -ne $BinaryNames.Count) {
    throw 'Transaction journal does not match the authenticated Go transaction.'
}

$metadataPath = Join-Path $env:ProgramData 'WeDecent\installer.json'
if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
    throw 'Authenticated installer metadata is unavailable; recovery outcome is unknown.'
}
Assert-TrustedAcl -Path $metadataPath
$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
if ([string]$metadata.install_dir -ine $InstallDir -or
    [string]$metadata.state_dir -ine $StateDir -or
    [string]$metadata.service_name -cne $ServiceName -or
    [string]$metadata.service_account_sid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') {
    throw 'Installer metadata does not authenticate the requested service and state paths.'
}
$installOwner = (Get-Acl -LiteralPath $InstallDir).Owner
$installOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $installOwner).Translate([Security.Principal.SecurityIdentifier]).Value
$stateOwner = (Get-Acl -LiteralPath $StateDir).Owner
$stateOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $stateOwner).Translate([Security.Principal.SecurityIdentifier]).Value
$statePath = Join-Path $StateDir 'update-state.json'
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw 'Protected updater state is unavailable; recovery outcome is unknown.'
}
$stateItem = Get-Item -LiteralPath $statePath -Force
if ($stateItem.PSIsContainer -or ($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Updater state is not a regular file.'
}
Assert-TrustedAcl -Path $statePath -AdditionalTrustedSids @([string]$metadata.service_account_sid, $installOwnerSid, $stateOwnerSid)
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$committed = [UInt64]$state.stable_sequence -ge $Sequence -and
    $null -eq $state.pending_install -and [string]$state.installed_version -ceq $TargetVersion

$seen = @{}
foreach ($entry in @($journal.entries)) {
    $name = [string]$entry.name
    if ($BinaryNames -notcontains $name -or $seen.ContainsKey($name)) {
        throw "Transaction journal has an unknown or duplicate binary: $name"
    }
    $seen[$name] = $true
    $destination = [IO.Path]::GetFullPath([string]$entry.destination)
    $expectedDestination = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
    $expectedBackup = "$expectedDestination.$TransactionId.bak"
    if (-not $destination.Equals($expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$entry.backup_path)).Equals($expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
        $entry.had_original -isnot [bool] -or
        [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced') -or
        [string]$entry.original_sha256 -notmatch '^(?:[a-f0-9]{64})?$' -or
        [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$') {
        throw "Transaction journal entry is invalid for $name"
    }
    if ([bool]$entry.had_original) {
        if ([string]$entry.original_sha256 -notmatch '^[a-f0-9]{64}$') {
            throw "Original binary digest is missing for $name"
        }
        if (Test-Path -LiteralPath $expectedBackup -PathType Leaf) {
            if ((Get-Sha256FileHash $expectedBackup) -ne [string]$entry.original_sha256) {
                throw "Transaction backup integrity failure: $expectedBackup"
            }
        } elseif ($committed) {
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Committed transaction has neither its backup nor the verified replacement: $destination"
            }
        } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
            throw "Original binary and verified backup are both unavailable: $destination"
        }
    } elseif (-not [string]::IsNullOrEmpty([string]$entry.original_sha256)) {
        throw "Unexpected original digest for $name"
    }
}
if ($seen.Count -ne $BinaryNames.Count) {
    throw 'Transaction journal does not cover all five approved binaries.'
}

if ($journal.phase -eq 'committed' -and -not $committed) {
    throw 'Journal claims commit but protected updater state does not confirm it.'
}
if ($journal.phase -eq 'rolled-back' -and $committed) {
    throw 'Journal claims rollback but protected updater state confirms commit.'
}
if ($committed) {
    foreach ($entry in @($journal.entries)) {
        if ((Get-Sha256FileHash ([string]$entry.destination)) -ne [string]$entry.replacement_sha256) {
            throw "Committed sequence has a mismatched binary: $($entry.destination)"
        }
    }
    $journal.phase = 'committed'
    Write-TransactionJournal -Journal $journal -Path $journalPath
    foreach ($entry in @($journal.entries)) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ([bool]$entry.had_original -and
                (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Refusing to clean a corrupted committed backup: $backup"
            }
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        }
        Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
        $destination = [string]$entry.destination
        Remove-Item -LiteralPath "$destination.$TransactionId.new" -Force -ErrorAction SilentlyContinue
    }
    Write-Output 'applied'
    exit 0
}

$pending = $state.pending_install
if ($null -eq $pending -or [string]$pending.id -cne $TransactionId -or
    [UInt64]$pending.sequence -ne $Sequence -or
    [string]$pending.manifest_digest -cne $ExpectedManifestSHA256 -or
    [string]$pending.package_digest -cne $ExpectedPackageSHA256 -or
    [string]$pending.previous_version -cne $PreviousVersion -or
    [string]$pending.target_version -cne $TargetVersion) {
    throw 'Updater state does not contain the exact pending transaction; recovery is ambiguous.'
}

# Preflight every original and backup before stopping services or changing files.
foreach ($entry in @($journal.entries)) {
    $destination = [string]$entry.destination
    if ([bool]$entry.had_original) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ((Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Corrupted transaction backup: $backup"
            }
        } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
            throw "No verified original or backup is available: $destination"
        }
    } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
        if ((Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
            throw "Unexpected binary contents prevent safe rollback: $destination"
        }
    }
}
Assert-NoRunningUserBinaries

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$restartService = [bool]$journal.service_was_running
if ($service -and $service.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
try {
    for ($i = @($journal.entries).Count - 1; $i -ge 0; $i--) {
        $entry = @($journal.entries)[$i]
        $destination = [string]$entry.destination
        if ([bool]$entry.had_original) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                $restore = "$destination.$TransactionId.recover"
                Copy-Item -LiteralPath $backup -Destination $restore -Force
                if ((Get-Sha256FileHash $restore) -ne [string]$entry.original_sha256) {
                    Remove-Item -LiteralPath $restore -Force -ErrorAction SilentlyContinue
                    throw "Restored backup verification failed: $destination"
                }
                Move-Item -LiteralPath $restore -Destination $destination -Force
            }
            if ((Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                throw "Rollback verification failed: $destination"
            }
        } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
            Remove-Item -LiteralPath $destination -Force
        }
        Remove-Item -LiteralPath "$destination.$TransactionId.new" -Force -ErrorAction SilentlyContinue
    }
    if ($restartService -and $service) {
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
    $journal.phase = 'rolled-back'
    Write-TransactionJournal -Journal $journal -Path $journalPath
} catch {
    $failure = $_
    throw "Windows transaction recovery failed closed; pending authorization and backups were retained. Cause: $($failure.Exception.Message)"
}
Write-Output 'not-applied') -or
            @($journal.entries).Count -ne $BinaryNames.Count) {
            throw "Committed cleanup journal is malformed: $($file.FullName)"
        }
        $metadataSnapshot = [string]$journal.metadata_backup_path
        if (Test-Path -LiteralPath $metadataSnapshot -PathType Leaf) {
            if ((Get-Sha256FileHash $metadataSnapshot) -ne [string]$journal.metadata_original_sha256) { throw "Committed cleanup metadata snapshot is corrupted: $metadataSnapshot" }
        } elseif ($journal.phase -ne 'committed' -and $journal.phase -ne 'rolled-back') {
            throw "Committed cleanup metadata snapshot disappeared before durable commit: $metadataSnapshot"
        }
        if ($journal.phase -eq 'rolled-back') { continue }
        if ($journalSequence -gt $ExpectedStableSequence) {
            throw 'An unresolved transaction journal is ahead of protected updater sequence.'
        }

        $seen = @{}
        foreach ($entry in @($journal.entries)) {
            $name = [string]$entry.name
            if ($BinaryNames -notcontains $name -or $seen.ContainsKey($name)) {
                throw "Committed cleanup journal contains an unknown or duplicate binary: $name"
            }
            $seen[$name] = $true
            $destination = [IO.Path]::GetFullPath([string]$entry.destination)
            $expectedDestination = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
            $expectedBackup = "$expectedDestination.$($journal.transaction_id).bak"
            if (-not $destination.Equals($expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
                -not ([IO.Path]::GetFullPath([string]$entry.backup_path)).Equals($expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
                $entry.had_original -isnot [bool] -or
                [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced') -or
                [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$entry.original_sha256 -notmatch '^(?:[a-f0-9]{64})?$' -or
                ([bool]$entry.had_original -and [string]$entry.original_sha256 -notmatch '^[a-f0-9]{64}$')) {
                throw "Committed cleanup journal entry is invalid for $name"
            }
            $backup = [string]$entry.backup_path
            if ($journalSequence -lt $ExpectedStableSequence) {
                if ($journal.phase -ne 'committed' -or (Test-Path -LiteralPath $backup -PathType Leaf)) {
                    throw "Older transaction has incomplete or non-committed cleanup: $backup"
                }
                continue
            }
            if ([string]$journal.version -cne $ExpectedInstalledVersion -or
                $journal.phase -notin @('installed-awaiting-sequence-commit', 'committed')) {
                throw 'Current journal phase or version disagrees with protected updater state.'
            }
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Current committed binary failed verification: $destination"
            }
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                if (-not [bool]$entry.had_original -or
                    (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                    throw "Committed backup integrity failure: $backup"
                }
            } elseif ([bool]$entry.had_original -and $journal.phase -ne 'committed') {
                throw "Backup disappeared before durable committed journal publication: $backup"
            }
        }
        if ($seen.Count -ne $expectedNames.Count) {
            throw 'Committed cleanup journal does not cover all five approved binaries.'
        }
        if ($journalSequence -lt $ExpectedStableSequence) { continue }

        if ($journal.phase -ne 'committed') {
            $journal.phase = 'committed'
            Write-TransactionJournal -Journal $journal -Path $file.FullName
        }
        foreach ($entry in @($journal.entries)) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
            }
            Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
            $destination = [string]$entry.destination
            Remove-Item -LiteralPath "$destination.$($journal.transaction_id).new" -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Output 'committed-backup-cleanup-complete'
    exit 0
}
$journalPath = Join-Path $journalRoot ($TransactionId + '.json')
if (-not (Test-Path -LiteralPath $journalRoot -PathType Container) -or
    -not (Test-Path -LiteralPath $journalPath -PathType Leaf)) {
    throw 'Transaction journal is unavailable; recovery outcome is unknown.'
}
Assert-TrustedAcl -Path $journalRoot
Assert-TrustedAcl -Path $journalPath
$journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
if ([int]$journal.schema -ne 1 -or [string]$journal.transaction_id -cne $TransactionId -or
    [string]$journal.manifest_sha256 -cne $ExpectedManifestSHA256 -or
    [string]$journal.manifest_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$journal.package_sha256 -cne $ExpectedPackageSHA256 -or
    [string]$journal.package_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [UInt64]$journal.sequence -ne $Sequence -or $Sequence -eq 0 -or
    [string]$journal.previous_version -cne $PreviousVersion -or
    [string]$journal.previous_version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
    [string]$journal.version -cne $TargetVersion -or
    [string]$journal.version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
    $journal.phase -notin @('prepared', 'backups-verified', 'replacing', 'installed-awaiting-sequence-commit', 'committed', 'rolled-back') -or
    $journal.service_was_running -isnot [bool] -or
    @($journal.entries).Count -ne $BinaryNames.Count) {
    throw 'Transaction journal does not match the authenticated Go transaction.'
}

$metadataPath = Join-Path $env:ProgramData 'WeDecent\installer.json'
$metadataBackupPath = "$metadataPath.$TransactionId.metadata.bak"
$expectedMetadataBackup = "$metadataPath.$TransactionId.metadata.bak"
if (-not [IO.Path]::GetFullPath([string]$journal.metadata_path).Equals([IO.Path]::GetFullPath($metadataPath), [StringComparison]::OrdinalIgnoreCase) -or
    -not [IO.Path]::GetFullPath([string]$journal.metadata_backup_path).Equals([IO.Path]::GetFullPath($expectedMetadataBackup), [StringComparison]::OrdinalIgnoreCase) -or
    $journal.metadata_had_original -isnot [bool] -or -not [bool]$journal.metadata_had_original -or
    -not [regex]::IsMatch([string]$journal.metadata_original_sha256, '^[a-f0-9]{64}$')) {
    throw 'Transaction journal does not contain an authenticated prior installer metadata snapshot.'
}
$metadataSource = $null
if (Test-Path -LiteralPath $metadataBackupPath -PathType Leaf) {
    Assert-TrustedAcl -Path $metadataBackupPath
    if ((Get-Sha256FileHash $metadataBackupPath) -ne [string]$journal.metadata_original_sha256) { throw 'Previous installer metadata snapshot failed integrity verification.' }
    $metadataSource = $metadataBackupPath
} elseif (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
    Assert-TrustedAcl -Path $metadataPath
    if ((Get-Sha256FileHash $metadataPath) -eq [string]$journal.metadata_original_sha256) { $metadataSource = $metadataPath }
}
if (-not $metadataSource) { throw 'Previous installer metadata and its verified snapshot are both unavailable.' }
$metadata = Get-Content -LiteralPath $metadataSource -Raw | ConvertFrom-Json
if ([string]$metadata.install_dir -ine $InstallDir -or
    [string]$metadata.state_dir -ine $StateDir -or
    [string]$metadata.service_name -cne $ServiceName -or
    -not [regex]::IsMatch([string]$metadata.service_account_sid, '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$')) {
    throw 'Prior installer metadata does not authenticate the requested service and state paths.'
}
$installOwner = (Get-Acl -LiteralPath $InstallDir).Owner
$installOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $installOwner).Translate([Security.Principal.SecurityIdentifier]).Value
$stateOwner = (Get-Acl -LiteralPath $StateDir).Owner
$stateOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $stateOwner).Translate([Security.Principal.SecurityIdentifier]).Value
$statePath = Join-Path $StateDir 'update-state.json'
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw 'Protected updater state is unavailable; recovery outcome is unknown.'
}
$stateItem = Get-Item -LiteralPath $statePath -Force
if ($stateItem.PSIsContainer -or ($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Updater state is not a regular file.'
}
Assert-TrustedAcl -Path $statePath -AdditionalTrustedSids @([string]$metadata.service_account_sid, $installOwnerSid, $stateOwnerSid)
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$committed = [UInt64]$state.stable_sequence -ge $Sequence -and
    $null -eq $state.pending_install -and [string]$state.installed_version -ceq $TargetVersion

$seen = @{}
foreach ($entry in @($journal.entries)) {
    $name = [string]$entry.name
    if ($BinaryNames -notcontains $name -or $seen.ContainsKey($name)) {
        throw "Transaction journal has an unknown or duplicate binary: $name"
    }
    $seen[$name] = $true
    $destination = [IO.Path]::GetFullPath([string]$entry.destination)
    $expectedDestination = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
    $expectedBackup = "$expectedDestination.$TransactionId.bak"
    if (-not $destination.Equals($expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$entry.backup_path)).Equals($expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
        $entry.had_original -isnot [bool] -or
        [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced') -or
        [string]$entry.original_sha256 -notmatch '^(?:[a-f0-9]{64})?$' -or
        [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$') {
        throw "Transaction journal entry is invalid for $name"
    }
    if ([bool]$entry.had_original) {
        if ([string]$entry.original_sha256 -notmatch '^[a-f0-9]{64}$') {
            throw "Original binary digest is missing for $name"
        }
        if (Test-Path -LiteralPath $expectedBackup -PathType Leaf) {
            if ((Get-Sha256FileHash $expectedBackup) -ne [string]$entry.original_sha256) {
                throw "Transaction backup integrity failure: $expectedBackup"
            }
        } elseif ($committed) {
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Committed transaction has neither its backup nor the verified replacement: $destination"
            }
        } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
            throw "Original binary and verified backup are both unavailable: $destination"
        }
    } elseif (-not [string]::IsNullOrEmpty([string]$entry.original_sha256)) {
        throw "Unexpected original digest for $name"
    }
}
if ($seen.Count -ne $BinaryNames.Count) {
    throw 'Transaction journal does not cover all five approved binaries.'
}

if ($journal.phase -eq 'committed' -and -not $committed) {
    throw 'Journal claims commit but protected updater state does not confirm it.'
}
if ($journal.phase -eq 'rolled-back' -and $committed) {
    throw 'Journal claims rollback but protected updater state confirms commit.'
}
if ($committed) {
    foreach ($entry in @($journal.entries)) {
        if ((Get-Sha256FileHash ([string]$entry.destination)) -ne [string]$entry.replacement_sha256) {
            throw "Committed sequence has a mismatched binary: $($entry.destination)"
        }
    }
    $journal.phase = 'committed'
    Write-TransactionJournal -Journal $journal -Path $journalPath
    foreach ($entry in @($journal.entries)) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ([bool]$entry.had_original -and
                (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Refusing to clean a corrupted committed backup: $backup"
            }
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        }
        Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
        $destination = [string]$entry.destination
        Remove-Item -LiteralPath "$destination.$TransactionId.new" -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $metadataBackupPath -PathType Leaf) {
        if ((Get-Sha256FileHash $metadataBackupPath) -ne [string]$journal.metadata_original_sha256) { throw 'Refusing to clean a corrupted committed installer metadata snapshot.' }
        Remove-Item -LiteralPath $metadataBackupPath -Force -ErrorAction Stop
    }
    Write-Output 'applied'
    exit 0
}

$pending = $state.pending_install
if ($null -eq $pending -or [string]$pending.id -cne $TransactionId -or
    [UInt64]$pending.sequence -ne $Sequence -or
    [string]$pending.manifest_digest -cne $ExpectedManifestSHA256 -or
    [string]$pending.package_digest -cne $ExpectedPackageSHA256 -or
    [string]$pending.previous_version -cne $PreviousVersion -or
    [string]$pending.target_version -cne $TargetVersion) {
    throw 'Updater state does not contain the exact pending transaction; recovery is ambiguous.'
}

# Preflight every original and backup before stopping services or changing files.
foreach ($entry in @($journal.entries)) {
    $destination = [string]$entry.destination
    if ([bool]$entry.had_original) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ((Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Corrupted transaction backup: $backup"
            }
        } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
            throw "No verified original or backup is available: $destination"
        }
    } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
        if ((Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
            throw "Unexpected binary contents prevent safe rollback: $destination"
        }
    }
}
Assert-NoRunningUserBinaries

$service = Get-Service -Name $ServiceName -ErrorAction Stop
$serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
$expectedAgent = [IO.Path]::GetFullPath((Join-Path $InstallDir 'wd-agent.exe'))
$expectedServicePath = '"' + $expectedAgent + '"'
$stateArgumentPattern = '(?:^|\s)--state=(?:"' + [regex]::Escape([IO.Path]::GetFullPath($StateDir)) + '"|' + [regex]::Escape([IO.Path]::GetFullPath($StateDir)) + ')(?:\s|$)'
if ($null -eq $serviceConfig -or
    -not ([string]$serviceConfig.PathName).StartsWith($expectedServicePath, [StringComparison]::OrdinalIgnoreCase) -or
    -not [regex]::IsMatch([string]$serviceConfig.PathName, $stateArgumentPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
    throw 'SCM service identity does not match authenticated prior installer metadata.'
}
$restartService = [bool]$journal.service_was_running
if ($service.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force -ErrorAction Stop }
(Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
if ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne 'Stopped') { throw 'SCM did not confirm the service stopped before recovery.' }
try {
    for ($i = @($journal.entries).Count - 1; $i -ge 0; $i--) {
        $entry = @($journal.entries)[$i]
        $destination = [string]$entry.destination
        if ([bool]$entry.had_original) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                $restore = "$destination.$TransactionId.recover"
                Copy-Item -LiteralPath $backup -Destination $restore -Force
                if ((Get-Sha256FileHash $restore) -ne [string]$entry.original_sha256) {
                    Remove-Item -LiteralPath $restore -Force -ErrorAction SilentlyContinue
                    throw "Restored backup verification failed: $destination"
                }
                Move-Item -LiteralPath $restore -Destination $destination -Force
            }
            if ((Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                throw "Rollback verification failed: $destination"
            }
        } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
            Remove-Item -LiteralPath $destination -Force
        }
        Remove-Item -LiteralPath "$destination.$TransactionId.new" -Force -ErrorAction SilentlyContinue
    }
    $metadataTemp = "$metadataPath.$TransactionId.restore"
    Copy-Item -LiteralPath $metadataBackupPath -Destination $metadataTemp -Force
    if ((Get-Sha256FileHash $metadataTemp) -ne [string]$journal.metadata_original_sha256) {
        Remove-Item -LiteralPath $metadataTemp -Force -ErrorAction SilentlyContinue
        throw 'Restored installer metadata failed its original digest check.'
    }
    Set-TrustedAcl -Path $metadataTemp
    Move-Item -LiteralPath $metadataTemp -Destination $metadataPath -Force
    Set-TrustedAcl -Path $metadataPath
    if ((Get-Sha256FileHash $metadataPath) -ne [string]$journal.metadata_original_sha256) { throw 'Final restored installer metadata failed verification.' }
    $journal.phase = 'rolled-back'
    Write-TransactionJournal -Journal $journal -Path $journalPath
} catch {
    $failure = $_
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    throw "Windows transaction recovery failed closed; service was left stopped and pending authorization/backups were retained. Cause: $($failure.Exception.Message)"
}
try {
    if ($restartService) {
        Start-Service -Name $ServiceName -ErrorAction Stop
        (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        if ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne 'Running') { throw 'SCM did not confirm the previous service returned to Running.' }
    } elseif ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne 'Stopped') {
        throw 'SCM service was expected to remain stopped after recovery.'
    }
} catch {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    throw "Previous binaries and metadata were restored, but SCM restart/state verification failed; service was left stopped. Cause: $($_.Exception.Message)"
}
Write-Output 'not-applied'