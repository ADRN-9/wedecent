$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$recoveryScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'installer\windows\Recover-WeDecentInstall.ps1'
$binaryNames = @('wd.exe', 'wd-agent.exe', 'wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe')
$installerScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'installer\windows\Install-WeDecent.ps1'
$installerText = Get-Content -LiteralPath $installerScript -Raw
$backupStage = $installerText.IndexOf('All previous binaries are backed up and verified before any replacement.')
$replacementStage = $installerText.IndexOf('Install-Binary (Join-Path $SourceDirectory $name)')
if ($backupStage -lt 0 -or $replacementStage -lt 0 -or $backupStage -ge $replacementStage) {
    throw 'Installer must verify all five transaction backups before replacing the first binary.'
}
if (-not $installerText.Contains('$Destination.$($script:InstallTransactionId).bak') -or
    -not $installerText.Contains('installed-awaiting-sequence-commit') -or
    -not $installerText.Contains('$stream.Flush($true)')) {
    throw 'Installer transaction-specific backup, durable journal, or sequence-commit boundary is missing.'
}
$cleanupHelper = $installerText.IndexOf('function Remove-CommittedTransactionBackups')
$cleanupCommit = $installerText.IndexOf('Remove-CommittedTransactionBackups -Journal $journal')
$cleanupGate = $installerText.IndexOf('Cannot clean transaction backups before the exact transaction is durably committed.')
if ($cleanupHelper -lt 0 -or $cleanupCommit -lt 0 -or $cleanupGate -lt 0 -or
    $cleanupHelper -ge $cleanupGate -or $cleanupGate -ge $cleanupCommit) {
    throw 'Committed backup cleanup must be gated by durable updater state and invoked from committed recovery.'
}
if (-not $installerText.Contains('Committed installation remains valid; refusing another installation until backup cleanup completes.') -or
    -not $installerText.Contains('$superseded') -or
    -not $installerText.Contains('Superseded committed transaction has unfinished backup cleanup')) {
    throw 'Interrupted post-commit cleanup must fail closed and recognize only fully cleaned historical transactions.'
}
$recoveryText = Get-Content -LiteralPath $recoveryScript -Raw
if (-not $recoveryText.Contains('FinalizeCommitted') -or
    -not $recoveryText.Contains('Protected updater state changed before committed backup cleanup.') -or
    -not $recoveryText.Contains('Backup disappeared before durable committed journal publication')) {
    throw 'Committed backup finalization must require exact durable state, exact target hashes, and a durable journal marker.'
}
if (-not $installerText.Contains('$binariesRestored = Invoke-RollbackStep') -or
    -not $installerText.Contains('if ($binariesRestored)') -or
    -not $installerText.Contains('service is intentionally left stopped for recovery')) {
    throw 'Upgrade rollback must not restart the service when binary restoration fails.'
}
if ($installerText -match '(?s)\$journal\.phase = ''rolled-back''.*?finally\s*\{\s*if \(\$restartService\)') {
    throw 'Interrupted transaction recovery must not restart the service from a finally block after rollback failure.'
}
$publicationCalls = [regex]::Matches($installerText, 'Publish-WeDecentRecoveryScript').Count - 1
if ($publicationCalls -ne 1) {
    throw "Installer must publish its recovery script exactly once per upgrade; found $publicationCalls invocations."
}
$trustedSids = @('S-1-5-18', 'S-1-5-32-544')
$serviceSid = 'S-1-5-21-1-2-3-1000'
$originalProgramData = $env:ProgramData
$root = Join-Path ([IO.Path]::GetTempPath()) ('wedecent-recovery-' + [Guid]::NewGuid().ToString('N'))
$installDir = Join-Path $env:ProgramFiles ('WeDecent-Recovery-' + [Guid]::NewGuid().ToString('N'))
$stateDir = Join-Path $installDir 'data\agent'
$journalRoot = Join-Path $root 'WeDecent\install-transactions'
$serviceName = 'WeDecentRecoveryTestSvc' + [Guid]::NewGuid().ToString('N')

function Set-TestTrustedAcl {
    param([Parameter(Mandatory = $true)][string]$Path, [string[]]$ExtraSids = @())
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sidText in @($trustedSids + $ExtraSids | Sort-Object -Unique)) {
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

function Get-TestHash {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-TestJson {
    param([string]$Path, $Value, [string[]]$ExtraSids = @())
    $Value | ConvertTo-Json -Depth 10 -Compress | Set-Content -LiteralPath $Path -Encoding UTF8
    Set-TestTrustedAcl -Path $Path -ExtraSids $ExtraSids
}

function New-TransactionFixture {
    param(
        [string]$Id = ([Guid]::NewGuid().ToString('N')),
        [bool]$Committed = $false,
        [bool]$ServiceWasRunning = $false
    )
    $manifestDigest = 'a' * 64
    $packageDigest = 'b' * 64
    $sequence = [UInt64]42
    $previousVersion = 'v0.3.9'
    $targetVersion = 'v0.4.0'
    $entries = @()
    foreach ($name in $binaryNames) {
        $destination = Join-Path $installDir $name
        $backup = "$destination.$Id.bak"
        $originalBytes = [Text.Encoding]::UTF8.GetBytes("original:$name")
        $targetBytes = [Text.Encoding]::UTF8.GetBytes("target:$name")
        [IO.File]::WriteAllBytes($destination, $targetBytes)
        [IO.File]::WriteAllBytes($backup, $originalBytes)
        $entries += [ordered]@{
            name = $name
            destination = $destination
            had_original = $true
            original_sha256 = (Get-TestHash $backup)
            replacement_sha256 = (Get-TestHash $destination)
            backup_path = $backup
            state = 'replaced'
        }
    }
    $metadataPath = Join-Path $root 'WeDecent\installer.json'
    $metadataBackupPath = "$metadataPath.$Id.metadata.bak"
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { throw 'Recovery fixture prior metadata is missing.' }
    $metadataOriginalHash = Get-TestHash $metadataPath
    Copy-Item -LiteralPath $metadataPath -Destination $metadataBackupPath
    Set-TestTrustedAcl -Path $metadataBackupPath
    if ((Get-TestHash $metadataBackupPath) -ne $metadataOriginalHash) { throw 'Recovery fixture metadata snapshot failed integrity verification.' }
    $journal = [ordered]@{
        schema = 1
        transaction_id = $Id
        package_sha256 = $packageDigest
        manifest_sha256 = $manifestDigest
        previous_version = $previousVersion
        sequence = $sequence
        service_was_running = $ServiceWasRunning
        metadata_path = $metadataPath
        metadata_had_original = $true
        metadata_original_sha256 = $metadataOriginalHash
        metadata_backup_path = $metadataBackupPath
        version = $targetVersion
        phase = 'replacing'
        entries = $entries
        updated_at = [DateTime]::UtcNow.ToString('o')
    }
    $journalPath = Join-Path $journalRoot ($Id + '.json')
    Write-TestJson -Path $journalPath -Value $journal

    $pending = [ordered]@{
        id = $Id
        sequence = $sequence
        manifest_digest = $manifestDigest
        package_digest = $packageDigest
        previous_version = $previousVersion
        target_version = $targetVersion
        phase = 'recovery-required'
    }
    $state = [ordered]@{
        version = 3
        stable_sequence = if ($Committed) { $sequence } else { 41 }
        keyset_epoch = 1
        keyset_digest = ('c' * 64)
        installed_version = if ($Committed) { $targetVersion } else { $previousVersion }
        pending_install = if ($Committed) { $null } else { $pending }
    }
    $statePath = Join-Path $stateDir 'update-state.json'
    Write-TestJson -Path $statePath -Value $state -ExtraSids @($serviceSid)
    return [pscustomobject]@{
        id = $Id
        journal = $journal
        journalPath = $journalPath
        statePath = $statePath
        manifestDigest = $manifestDigest
        packageDigest = $packageDigest
        sequence = $sequence
        previousVersion = $previousVersion
        targetVersion = $targetVersion
        metadataPath = $metadataPath
        metadataBackupPath = $metadataBackupPath
        metadataOriginalHash = $metadataOriginalHash
    }
}

function Invoke-TestRecovery {
    param($Fixture)
    & $recoveryScript -TransactionId $Fixture.id -InstallDir $installDir -StateDir $stateDir -ServiceName $serviceName -ExpectedManifestSHA256 $Fixture.manifestDigest -ExpectedPackageSHA256 $Fixture.packageDigest -Sequence $Fixture.sequence -PreviousVersion $Fixture.previousVersion -TargetVersion $Fixture.targetVersion
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Synthetic recovery contract tests require an elevated Windows runner.'
    }
    if (-not (Test-Path -LiteralPath $recoveryScript -PathType Leaf)) {
        throw 'Windows recovery script is missing.'
    }
    New-Item -ItemType Directory -Force -Path $root, $installDir, $stateDir, $journalRoot | Out-Null
    Set-TestTrustedAcl -Path $root
    Set-TestTrustedAcl -Path (Join-Path $root 'WeDecent')
    Set-TestTrustedAcl -Path $journalRoot
    Set-TestTrustedAcl -Path $installDir
    Set-TestTrustedAcl -Path (Join-Path $installDir 'data')
    Set-TestTrustedAcl -Path $stateDir
    $env:ProgramData = $root

    $metadataPath = Join-Path $root 'WeDecent\installer.json'
    Write-TestJson -Path $metadataPath -Value ([ordered]@{
        schema = 1
        product = 'WeDecent'
        version = 'v0.3.9'
        service_name = $serviceName
        service_account_sid = $serviceSid
        install_dir = $installDir
        state_dir = $stateDir
    })
    $metadataOriginalBytes = [IO.File]::ReadAllBytes($metadataPath)

    $successful = New-TransactionFixture
    $agentPath = Join-Path $installDir 'wd-agent.exe'
    $serviceImage = '"' + $agentPath + '" --service --state="' + $stateDir + '"'
    & sc.exe create $serviceName binPath= $serviceImage start= demand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the isolated stopped SCM service fixture.' }
    $serviceCheck = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
    if ($null -eq $serviceCheck -or $serviceCheck.State -ne 'Stopped') { throw 'SCM service fixture was not created in the stopped state.' }
    $metadataBefore = Get-TestHash $successful.metadataBackupPath
    $targetMetadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    $targetMetadata.version = $successful.targetVersion
    Write-TestJson -Path $metadataPath -Value $targetMetadata
    [IO.File]::WriteAllText("$metadataPath.$($successful.id).restore", 'interrupted metadata restore')
    Invoke-TestRecovery -Fixture $successful | Out-Null
    if ((Get-TestHash $metadataPath) -ne $metadataBefore) { throw 'Recovery did not restore exact prior installer metadata bytes.' }
    $recovered = Get-Content -LiteralPath $successful.journalPath -Raw | ConvertFrom-Json
    if ($recovered.phase -ne 'rolled-back') { throw 'Recovery did not persist the rolled-back phase.' }
    foreach ($entry in $successful.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $entry.original_sha256) {
            throw "Rollback failed to restore the original binary: $($entry.name)"
        }
    }

    # Repeating the same recovery transaction must remain safe and idempotent.
    Invoke-TestRecovery -Fixture $successful | Out-Null
    $replayed = Get-Content -LiteralPath $successful.journalPath -Raw | ConvertFrom-Json
    if ($replayed.phase -ne 'rolled-back') { throw 'Repeated recovery changed the completed rollback phase.' }
    foreach ($entry in $successful.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $entry.original_sha256) {
            throw "Repeated recovery changed the restored original binary: $($entry.name)"
        }
    }

    $partialStage = New-TransactionFixture
    $partialJournal = Get-Content -LiteralPath $partialStage.journalPath -Raw | ConvertFrom-Json
    $partialJournal.phase = 'backups-verified'
    for ($i = 0; $i -lt $partialJournal.entries.Count; $i++) {
        $entry = $partialJournal.entries[$i]
        [IO.File]::WriteAllBytes([string]$entry.destination, [Text.Encoding]::UTF8.GetBytes("original:$($entry.name)"))
        if ($i -lt 2) {
            $entry.state = 'backup-verified'
        } else {
            $entry.state = 'planned'
            Remove-Item -LiteralPath $entry.backup_path -Force
        }
    }
    Write-TestJson -Path $partialStage.journalPath -Value $partialJournal
    Invoke-TestRecovery -Fixture $partialStage | Out-Null
    $partialRecovered = Get-Content -LiteralPath $partialStage.journalPath -Raw | ConvertFrom-Json
    if ($partialRecovered.phase -ne 'rolled-back') { throw 'Partial staging recovery did not persist the rolled-back phase.' }
    for ($i = 0; $i -lt $partialRecovered.entries.Count; $i++) {
        $entry = $partialRecovered.entries[$i]
        if ((Get-TestHash $entry.destination) -ne $entry.original_sha256) {
            throw "Partial staging recovery changed the original binary: $($entry.name)"
        }
        if ($i -lt 2) {
            if (-not (Test-Path -LiteralPath $entry.backup_path -PathType Leaf) -or
                (Get-TestHash $entry.backup_path) -ne $entry.original_sha256) {
                throw "Partial staging recovery lost a verified backup: $($entry.name)"
            }
        } elseif (Test-Path -LiteralPath $entry.backup_path) {
            throw "Partial staging fixture unexpectedly retained an uncreated backup: $($entry.name)"
        }
    }

    $corrupted = New-TransactionFixture
    $badBackup = [string]$corrupted.journal.entries[3].backup_path
    [IO.File]::WriteAllText($badBackup, 'corrupted backup')
    $before = @{}
    foreach ($entry in $corrupted.journal.entries) { $before[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $corrupted | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted a corrupted backup.' }
    foreach ($entry in $corrupted.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $before[$entry.name]) {
            throw "Corrupted-backup preflight mutated a binary before failing: $($entry.name)"
        }
    }

    $missing = New-TransactionFixture
    Remove-Item -LiteralPath $missing.journal.entries[2].backup_path -Force
    $before = @{}
    foreach ($entry in $missing.journal.entries) { $before[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $missing | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted a missing backup when the destination had changed.' }
    foreach ($entry in $missing.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $before[$entry.name]) {
            throw "Missing-backup preflight mutated a binary before failing: $($entry.name)"
        }
    }

    $rollbackFailure = New-TransactionFixture
    $blockedDestination = [string]$rollbackFailure.journal.entries[4].destination
    Remove-Item -LiteralPath $blockedDestination -Force
    New-Item -ItemType Directory -Path $blockedDestination | Out-Null
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $rollbackFailure | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery unexpectedly succeeded with a non-file destination blocking rollback.' }
    $failedJournal = Get-Content -LiteralPath $rollbackFailure.journalPath -Raw | ConvertFrom-Json
    if ($failedJournal.phase -ne 'replacing') { throw 'Failed rollback incorrectly advanced its durable journal phase.' }
    $failedState = Get-Content -LiteralPath $rollbackFailure.statePath -Raw | ConvertFrom-Json
    if ($null -eq $failedState.pending_install -or $failedState.stable_sequence -ne 41) {
        throw 'Failed rollback cleared pending authorization or advanced the stable sequence.'
    }
    foreach ($entry in $rollbackFailure.journal.entries) {
        if (-not (Test-Path -LiteralPath $entry.backup_path -PathType Leaf) -or
            (Get-TestHash $entry.backup_path) -ne $entry.original_sha256) {
            throw "Failed rollback did not retain the verified original backup: $($entry.name)"
        }
    }
    Remove-Item -LiteralPath $blockedDestination -Recurse -Force
    Invoke-TestRecovery -Fixture $rollbackFailure | Out-Null
    foreach ($entry in $rollbackFailure.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $entry.original_sha256) {
            throw "Recovery retry did not restore the original binary: $($entry.name)"
        }
    }

    $mismatched = New-TransactionFixture
    $forgedJournal = Get-Content -LiteralPath $mismatched.journalPath -Raw | ConvertFrom-Json
    $forgedJournal.package_sha256 = 'd' * 64
    Write-TestJson -Path $mismatched.journalPath -Value $forgedJournal
    $before = @{}
    foreach ($entry in $mismatched.journal.entries) { $before[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $mismatched | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted a journal bound to a different package digest.' }
    foreach ($entry in $mismatched.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $before[$entry.name]) {
            throw "Mismatched-journal rejection mutated a protected binary: $($entry.name)"
        }
    }

    $replaced = New-TransactionFixture
    $replacedBackup = [string]$replaced.journal.entries[1].backup_path
    Remove-Item -LiteralPath $replacedBackup -Force
    [IO.File]::WriteAllText($replacedBackup, 'replacement backup from another transaction')
    $before = @{}
    foreach ($entry in $replaced.journal.entries) { $before[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $replaced | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted a replaced transaction backup.' }
    foreach ($entry in $replaced.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $before[$entry.name]) {
            throw "Replaced-backup rejection mutated an installed binary: $($entry.name)"
        }
    }

    $wrongAssociation = New-TransactionFixture
    $forgedAssociation = Get-Content -LiteralPath $wrongAssociation.journalPath -Raw | ConvertFrom-Json
    $forgedAssociation.entries[0].backup_path = [string]$forgedAssociation.entries[1].backup_path
    Write-TestJson -Path $wrongAssociation.journalPath -Value $forgedAssociation
    $before = @{}
    foreach ($entry in $wrongAssociation.journal.entries) { $before[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $wrongAssociation | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted a backup associated with a different binary.' }
    foreach ($entry in $wrongAssociation.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $before[$entry.name]) {
            throw "Mismatched-backup association rejection mutated an installed binary: $($entry.name)"
        }
    }

    $committed = New-TransactionFixture -Committed $true
    # Simulate cleanup being interrupted after deleting only part of the backups.
    Remove-Item -LiteralPath $committed.journal.entries[0].backup_path -Force
    Remove-Item -LiteralPath $committed.journal.entries[2].backup_path -Force
    Invoke-TestRecovery -Fixture $committed | Out-Null
    $committedJournal = Get-Content -LiteralPath $committed.journalPath -Raw | ConvertFrom-Json
    if ($committedJournal.phase -ne 'committed') { throw 'Recovery did not recognize a committed sequence.' }
    foreach ($entry in $committed.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $entry.replacement_sha256) {
            throw "Committed recovery replaced a target binary: $($entry.name)"
        }
        if (Test-Path -LiteralPath $entry.backup_path) {
            throw "Committed backup cleanup left a stale backup: $($entry.name)"
        }
    }
    # Repeated recovery after complete cleanup must remain idempotent.
    Invoke-TestRecovery -Fixture $committed | Out-Null
    $replayedCommitted = Get-Content -LiteralPath $committed.journalPath -Raw | ConvertFrom-Json
    if ($replayedCommitted.phase -ne 'committed') { throw 'Repeated committed recovery changed the committed phase.' }

    $tamperedCommitted = New-TransactionFixture -Committed $true
    [IO.File]::WriteAllText([string]$tamperedCommitted.journal.entries[0].destination, 'tampered target')
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $tamperedCommitted | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Committed recovery accepted a changed installed binary.' }
    foreach ($entry in $tamperedCommitted.journal.entries) {
        if (-not (Test-Path -LiteralPath $entry.backup_path -PathType Leaf) -or
            (Get-TestHash $entry.backup_path) -ne $entry.original_sha256) {
            throw "Unverified committed target caused premature backup cleanup: $($entry.name)"
        }
    }

    # Exercise the dedicated post-commit finalizer in an isolated ProgramData/install root.
    $finalizeProgramData = Join-Path $root 'finalizer-programdata'
    $finalizeWeDecent = Join-Path $finalizeProgramData 'WeDecent'
    $finalizeJournalRoot = Join-Path $finalizeWeDecent 'install-transactions'
    $finalizeInstallDir = Join-Path $env:ProgramFiles ('WeDecent-C334-Finalizer-' + [Guid]::NewGuid().ToString('N'))
    $finalizeStateDir = Join-Path $finalizeInstallDir 'data\agent'
    New-Item -ItemType Directory -Force -Path $finalizeJournalRoot, $finalizeInstallDir, (Join-Path $finalizeInstallDir 'data'), $finalizeStateDir | Out-Null
    Set-TestTrustedAcl -Path $finalizeProgramData
    Set-TestTrustedAcl -Path $finalizeWeDecent
    Set-TestTrustedAcl -Path $finalizeJournalRoot
    Set-TestTrustedAcl -Path $finalizeInstallDir
    Set-TestTrustedAcl -Path (Join-Path $finalizeInstallDir 'data')
    Set-TestTrustedAcl -Path $finalizeStateDir

    $finalizeTransactionId = [Guid]::NewGuid().ToString('N')
    $finalizeEntries = @()
    foreach ($name in $binaryNames) {
        $destination = Join-Path $finalizeInstallDir $name
        $backup = "$destination.$finalizeTransactionId.bak"
        [IO.File]::WriteAllBytes($destination, [Text.Encoding]::UTF8.GetBytes("target:$name"))
        [IO.File]::WriteAllBytes($backup, [Text.Encoding]::UTF8.GetBytes("original:$name"))
        $finalizeEntries += [ordered]@{
            name = $name
            destination = $destination
            had_original = $true
            original_sha256 = Get-TestHash $backup
            replacement_sha256 = Get-TestHash $destination
            backup_path = $backup
            state = 'replaced'
        }
    }
    $finalizeMetadataPath = Join-Path $finalizeWeDecent 'installer.json'
    Write-TestJson -Path $finalizeMetadataPath -Value ([ordered]@{
        schema = 1
        product = 'WeDecent'
        version = 'v0.3.9'
        service_name = $serviceName
        service_account_sid = $serviceSid
        install_dir = $finalizeInstallDir
        state_dir = $finalizeStateDir
    })
    $finalizeMetadataBackup = "$finalizeMetadataPath.$finalizeTransactionId.metadata.bak"
    Copy-Item -LiteralPath $finalizeMetadataPath -Destination $finalizeMetadataBackup
    Set-TestTrustedAcl -Path $finalizeMetadataBackup
    $finalizeMetadataOriginalHash = Get-TestHash $finalizeMetadataBackup
    $finalizeJournalPath = Join-Path $finalizeJournalRoot ($finalizeTransactionId + '.json')
    $finalizeJournal = [ordered]@{
        schema = 1
        transaction_id = $finalizeTransactionId
        package_sha256 = 'b' * 64
        manifest_sha256 = 'a' * 64
        previous_version = 'v0.3.9'
        sequence = [UInt64]42
        service_was_running = $false
        metadata_path = $finalizeMetadataPath
        metadata_had_original = $true
        metadata_original_sha256 = $finalizeMetadataOriginalHash
        metadata_backup_path = $finalizeMetadataBackup
        version = 'v0.4.0'
        phase = 'installed-awaiting-sequence-commit'
        entries = $finalizeEntries
        updated_at = [DateTime]::UtcNow.ToString('o')
    }
    Write-TestJson -Path $finalizeJournalPath -Value $finalizeJournal
    $finalizeStatePath = Join-Path $finalizeStateDir 'update-state.json'
    Write-TestJson -Path $finalizeStatePath -Value ([ordered]@{
        version = 3
        stable_sequence = [UInt64]42
        keyset_epoch = 1
        keyset_digest = ('c' * 64)
        installed_version = 'v0.4.0'
        pending_install = $null
    }) -ExtraSids @($serviceSid)

    $env:ProgramData = $finalizeProgramData
    & $recoveryScript -FinalizeCommitted -InstallDir $finalizeInstallDir -StateDir $finalizeStateDir -ServiceName $serviceName -ExpectedStableSequence 42 -ExpectedInstalledVersion 'v0.4.0' | Out-Null
    $finalizedJournal = Get-Content -LiteralPath $finalizeJournalPath -Raw | ConvertFrom-Json
    if ($finalizedJournal.phase -ne 'committed') { throw 'Post-commit finalizer did not durably mark the journal committed.' }
    if (Test-Path -LiteralPath $finalizeMetadataBackup) { throw 'Post-commit finalizer did not remove the verified metadata snapshot.' }
    foreach ($entry in $finalizeEntries) {
        if (Test-Path -LiteralPath $entry.backup_path) {
            throw "Post-commit finalizer did not remove a verified backup: $($entry.name)"
        }
    }

    # A second pass simulates process termination after only some backups were deleted.
    foreach ($entry in $finalizeEntries) {
        [IO.File]::WriteAllBytes([string]$entry.backup_path, [Text.Encoding]::UTF8.GetBytes("original:$($entry.name)"))
    }
    Remove-Item -LiteralPath $finalizeEntries[0].backup_path -Force
    Remove-Item -LiteralPath $finalizeEntries[3].backup_path -Force
    & $recoveryScript -FinalizeCommitted -InstallDir $finalizeInstallDir -StateDir $finalizeStateDir -ServiceName $serviceName -ExpectedStableSequence 42 -ExpectedInstalledVersion 'v0.4.0' | Out-Null
    foreach ($entry in $finalizeEntries) {
        if (Test-Path -LiteralPath $entry.backup_path) {
            throw "Interrupted post-commit cleanup was not resumed: $($entry.name)"
        }
    }

    # Changed target bytes must prevent every remaining backup from being deleted.
    foreach ($entry in $finalizeEntries) {
        [IO.File]::WriteAllBytes([string]$entry.backup_path, [Text.Encoding]::UTF8.GetBytes("original:$($entry.name)"))
    }
    [IO.File]::WriteAllText([string]$finalizeEntries[2].destination, 'tampered committed target')
    $rejected = $false
    try {
        & $recoveryScript -FinalizeCommitted -InstallDir $finalizeInstallDir -StateDir $finalizeStateDir -ServiceName $serviceName -ExpectedStableSequence 42 -ExpectedInstalledVersion 'v0.4.0' | Out-Null
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'Post-commit finalizer accepted a changed target binary.' }
    foreach ($entry in $finalizeEntries) {
        if (-not (Test-Path -LiteralPath $entry.backup_path -PathType Leaf)) {
            throw "Changed target caused premature backup deletion: $($entry.name)"
        }
    }

    $metadataCorrupt = New-TransactionFixture
    $beforeCorrupt = @{}
    foreach ($entry in $metadataCorrupt.journal.entries) { $beforeCorrupt[$entry.name] = Get-TestHash $entry.destination }
    [IO.File]::WriteAllText($metadataCorrupt.metadataBackupPath, 'corrupt metadata snapshot')
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $metadataCorrupt | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted a corrupted prior metadata snapshot.' }
    foreach ($entry in $metadataCorrupt.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $beforeCorrupt[$entry.name]) { throw 'Corrupt metadata snapshot rejection mutated a binary.' }
    }

    $missingMetadata = New-TransactionFixture
    Remove-Item -LiteralPath $missingMetadata.metadataBackupPath -Force
    [IO.File]::WriteAllText($missingMetadata.metadataPath, 'incomplete target metadata')
    $beforeMissing = @{}
    foreach ($entry in $missingMetadata.journal.entries) { $beforeMissing[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $missingMetadata | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted missing prior metadata and corrupted current metadata.' }
    foreach ($entry in $missingMetadata.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $beforeMissing[$entry.name]) { throw 'Missing metadata rejection mutated a binary.' }
    }
    [IO.File]::WriteAllBytes($metadataPath, $metadataOriginalBytes)
    Set-TestTrustedAcl -Path $metadataPath

    $inconsistentMetadataJournal = New-TransactionFixture
    $inconsistentJournal = Get-Content -LiteralPath $inconsistentMetadataJournal.journalPath -Raw | ConvertFrom-Json
    $inconsistentJournal.metadata_path = (Join-Path $root 'forged-installer.json')
    Write-TestJson -Path $inconsistentMetadataJournal.journalPath -Value $inconsistentJournal
    $beforeInconsistent = @{}
    foreach ($entry in $inconsistentMetadataJournal.journal.entries) { $beforeInconsistent[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $inconsistentMetadataJournal | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted a journal with an inconsistent metadata path.' }
    foreach ($entry in $inconsistentMetadataJournal.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $beforeInconsistent[$entry.name]) { throw 'Inconsistent metadata journal rejection mutated a binary.' }
    }

    $missingScm = New-TransactionFixture
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
    $beforeMissingScm = @{}
    foreach ($entry in $missingScm.journal.entries) { $beforeMissingScm[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $missingScm | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted a missing SCM service.' }
    foreach ($entry in $missingScm.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $beforeMissingScm[$entry.name]) { throw 'Missing SCM service rejection mutated a binary.' }
    }
    & sc.exe create $serviceName binPath= $serviceImage start= demand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not recreate the isolated SCM service fixture.' }

    $badScm = New-TransactionFixture
    & sc.exe config $serviceName binPath= 'C:\Windows\System32\svchost.exe -k netsvcs' | Out-Null
    $beforeBadScm = @{}
    foreach ($entry in $badScm.journal.entries) { $beforeBadScm[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $badScm | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery accepted a service with a mismatched image path.' }
    foreach ($entry in $badScm.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $beforeBadScm[$entry.name]) { throw 'Mismatched SCM rejection mutated a binary.' }
    }
    & sc.exe config $serviceName binPath= $serviceImage | Out-Null

    $restartFailure = New-TransactionFixture -ServiceWasRunning $true
    $restartRejected = $false
    try { Invoke-TestRecovery -Fixture $restartFailure | Out-Null } catch { $restartRejected = $true }
    if (-not $restartRejected) { throw 'Recovery reported success when the previous running service could not restart.' }
    if ((Get-Service -Name $serviceName).Status -ne 'Stopped') { throw 'Failed SCM restart did not leave the service stopped.' }
    $restartJournal = Get-Content -LiteralPath $restartFailure.journalPath -Raw | ConvertFrom-Json
    if ($restartJournal.phase -ne 'rolled-back') { throw 'Completed binary/metadata rollback was not journaled before the failed restart.' }
    foreach ($entry in $restartFailure.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $entry.original_sha256) { throw "Restart failure lost the previous binary: $($entry.name)" }
    }

    Write-Host 'Windows transaction recovery and committed cleanup synthetic adversarial tests passed.'
} finally {
    $env:ProgramData = $originalProgramData
    & sc.exe delete $serviceName | Out-Null
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue
    $finalizePath = Get-Variable -Name finalizeInstallDir -ValueOnly -ErrorAction SilentlyContinue
    if ($finalizePath) {
        Remove-Item -LiteralPath $finalizePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}