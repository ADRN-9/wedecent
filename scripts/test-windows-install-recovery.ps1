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
    -not $installerText.Contains('param([Parameter(Mandatory = $true)]$Journal, [string]$Path, [switch]$CreateNew)') -or
    -not $installerText.Contains('Installer journal path must match its transaction ID inside the protected journal directory.') -or
    -not $installerText.Contains('Installer transaction journal already exists; exclusive transaction creation rejected replay.') -or
    -not $installerText.Contains('Publish-WeDecentBinaryBackup -Source $destination') -or
    -not $installerText.Contains('CopyTo($output); $output.Flush($true)') -or
    -not $installerText.Contains('Flush-WeDecentFileToDisk -Path $BackupPath') -or
    -not $installerText.Contains('Write($bytes, 0, $bytes.Length); $stream.Flush($true)') -or
    -not $installerText.Contains('FileShare]::None') -or
    -not $installerText.Contains('function Acquire-WeDecentInstallerLock')) {
    throw 'Installer must use exclusive transaction creation, durable verified backups, and an OS-released machine-wide lock.'
}
if (-not $installerText.Contains('service_existed = [bool]$script:InstallServiceExisted') -or
    -not $installerText.Contains('Fresh-install recovery expected no pre-existing SCM service') -or
    -not $installerText.Contains('if ($serviceExisted) {') -or
    -not $installerText.Contains('Publish-TransactionRecoveryScriptBackup')) {
    throw 'Interrupted fresh-install recovery must be independent of a service that has not yet been created.'
}
$lockCall = $installerText.IndexOf('Acquire-WeDecentInstallerLock', $installerText.IndexOf('Assert-Administrator'))
$recoveryCall = $installerText.IndexOf('Recover-InterruptedInstallerTransactions -Destinations')
if ($lockCall -lt 0 -or $recoveryCall -lt 0 -or $lockCall -ge $recoveryCall) {
    throw 'Installer-wide lock must be acquired before transaction recovery or any install-state mutation.'
}
$functionNames = @([regex]::Matches($installerText, '(?m)^function\s+([^\s{]+)') | ForEach-Object { $_.Groups[1].Value })
if (($functionNames | Sort-Object -Unique).Count -ne $functionNames.Count) {
    throw 'Installer contains duplicate top-level function definitions.'
}
if (-not $installerText.Contains("'removal-pending'") -or
    -not $installerText.Contains('Persist a valid removal identity before deleting the file.') -or
    -not $installerText.Contains("if (`$state -eq 'absent')")) {
    throw 'Fresh-install rollback must preserve an already-absent state and authenticate removal intent before deleting the published script.'
}
$installBinariesStart = $installerText.IndexOf('function Install-Binaries')
$firstServiceStop = $installerText.IndexOf('Stop-Service -Name $ServiceName -Force -ErrorAction Stop', $installBinariesStart)
$firstReplacement = $installerText.IndexOf('Install-Binary (Join-Path $SourceDirectory $name)', $installBinariesStart)
$lastDurableJournalBeforeStop = $installerText.LastIndexOf('Write-InstallJournal -Journal $script:InstallJournal', $firstServiceStop)
if ($installBinariesStart -lt 0 -or $firstServiceStop -lt 0 -or $firstReplacement -lt 0 -or
    $lastDurableJournalBeforeStop -lt $installBinariesStart -or
    $lastDurableJournalBeforeStop -ge $firstServiceStop -or $firstServiceStop -ge $firstReplacement) {
    throw 'Installer must durably journal the transaction and verify original backups before stopping SCM or replacing binaries.'
}
$upgradeStart = $installerText.IndexOf('Upgrading existing $ServiceName service')
$upgradeInstallCall = -1
$prematureUpgradeStop = -1
if ($upgradeStart -ge 0) {
    $upgradeInstallCall = $installerText.IndexOf('Install-Binaries -SourceDirectory $BundlePath', $upgradeStart)
    if ($upgradeInstallCall -ge $upgradeStart) {
        $prematureUpgradeStop = $installerText.IndexOf('Stop-Service -Name $ServiceName -Force', $upgradeStart, $upgradeInstallCall - $upgradeStart)
    }
}
if ($upgradeStart -lt 0 -or $upgradeInstallCall -lt 0 -or $prematureUpgradeStop -ge 0) {
    throw 'Managed upgrade must not stop the service before the durable installer transaction exists.'
}
$removalIntent = $installerText.IndexOf("recovery_script_state = 'removal-pending'")
$removalAction = $installerText.IndexOf('Remove-Item -LiteralPath $target -Force -ErrorAction Stop', $removalIntent)
$removalCommitted = $installerText.IndexOf("recovery_script_state = 'absent'", $removalAction)
if ($removalIntent -lt 0 -or $removalAction -lt 0 -or $removalCommitted -lt 0 -or
    $removalIntent -ge $removalAction -or $removalAction -ge $removalCommitted) {
    throw 'Fresh-install recovery-script removal intent, deletion, and completion journal ordering is invalid.'
}
if (-not $installerText.Contains('recovery_script_state = $recoveryScriptState') -or
    -not $installerText.Contains('Unexpected recovery script appeared after the initial-install transaction snapshot.') -or
    -not $installerText.Contains('Unexpected previous recovery-script backup exists for a new installation.')) {
    throw 'Fresh-install recovery-script publication must handle absent prior script state and reject unexpected files.'
}
$initialPublish = $installerText.LastIndexOf('Publish-WeDecentRecoveryScript')
$initialServiceInstall = $installerText.LastIndexOf('Invoke-AgentServiceInstall')
$initialRollback = $installerText.LastIndexOf('Restore-TransactionRecoveryScript -Journal $script:InstallJournal')
$freshFailure = $installerText.LastIndexOf('Fresh installation failed; rollback was attempted')
$initialCommit = $installerText.LastIndexOf('$script:InstallJournal.phase = ''committed''')
if ($initialPublish -lt 0 -or $initialPublish -gt $initialServiceInstall -or
    $initialRollback -lt 0 -or $initialRollback -gt $freshFailure -or
    $initialCommit -lt $freshFailure) {
    throw 'Fresh installation must publish and roll back its recovery script, and commit only after rollback handling has completed.'
}
$cleanupHelper = $installerText.IndexOf('function Remove-CommittedTransactionBackups')
$cleanupCommit = $installerText.IndexOf('Remove-CommittedTransactionBackups -Journal $journal')
$cleanupGate = $installerText.IndexOf('Cannot clean transaction backups before the exact transaction is durably committed.')
if ($cleanupHelper -lt 0 -or $cleanupCommit -lt 0 -or $cleanupGate -lt 0 -or
    $cleanupHelper -ge $cleanupGate -or $cleanupGate -ge $cleanupCommit) {
    throw 'Committed backup cleanup must be gated by durable updater state and invoked from committed recovery.'
}
$rolledBackBranch = $installerText.IndexOf("if (`$journal.phase -eq 'rolled-back') {")
$rolledBackContinue = -1
if ($rolledBackBranch -ge 0) { $rolledBackContinue = $installerText.IndexOf('continue', $rolledBackBranch) }
$rollbackServiceStart = $installerText.IndexOf('$serviceBefore = Get-Service')
if (-not $installerText.Contains('$historical = $superseded -or $journal.phase -eq ''rolled-back''') -or
    -not $installerText.Contains('$journal.phase -ne ''rolled-back'' -and') -or
    $rolledBackBranch -lt 0 -or $rolledBackContinue -lt 0 -or $rollbackServiceStart -lt 0 -or
    $rolledBackContinue -gt $rollbackServiceStart) {
    throw 'Installer must treat completed rollback journals as historical and never replay them over a later installation.'
}
if (-not $installerText.Contains('$stableSequence -gt [UInt64]$journal.sequence') -or
    -not $installerText.Contains('Superseded committed transaction has unfinished backup cleanup:')) {
    throw 'Installer must finish cleanup for the current committed journal and fail closed on superseded journals with retained backups.'
}
if (-not $installerText.Contains('Committed installation remains valid; refusing another installation until backup cleanup completes.') -or
    -not $installerText.Contains('$superseded') -or
    -not $installerText.Contains('Superseded committed transaction has unfinished backup cleanup')) {
    throw 'Interrupted post-commit cleanup must fail closed and recognize only fully cleaned historical transactions.'
}
$recoveryText = Get-Content -LiteralPath $recoveryScript -Raw
if (-not $recoveryText.Contains('FinalizeCommitted') -or
    -not $recoveryText.Contains('function Get-TransactionRecoveryScriptBackupForCleanup') -or
    -not $recoveryText.Contains('Recovery-script backup disappeared before durable committed journal publication.') -or
    -not $recoveryText.Contains('Transaction recovery-script backup failed its original digest check.') -or
    -not $recoveryText.Contains('Protected updater state changed before committed backup cleanup.') -or
    -not $recoveryText.Contains('Backup disappeared before durable committed journal publication') -or
    -not $recoveryText.Contains('Refusing to clean a corrupted committed metadata snapshot:') -or
    -not $recoveryText.Contains('metadata_backup_path') -or
    -not $recoveryText.Contains('SCM service identity does not match authenticated prior installer metadata.') -or
    -not $recoveryText.Contains('SCM service account SID does not match protected installer metadata') -or
    -not $recoveryText.Contains('$serviceConfig.StartName') -or
    -not $recoveryText.Contains('SCM did not confirm the service stopped before recovery.') -or
    -not $recoveryText.Contains('journalMetadataBackup') -or
    -not $recoveryText.Contains('Older transaction journal is not durably committed.') -or
    -not $recoveryText.Contains('Restored installer metadata failed its original digest check.')) {
    throw 'Committed cleanup and interrupted recovery must authenticate metadata and verify SCM before restart.'
}
if (-not $recoveryText.Contains('function Acquire-WeDecentRecoveryLock') -or
    -not $recoveryText.Contains('Join-Path $env:ProgramData ''WeDecent\install-transactions''') -or
    -not $recoveryText.Contains('[IO.FileShare]::None') -or
    -not $recoveryText.Contains('$recoveryLock.Dispose()')) {
    throw 'Updater recovery must share the installer-wide exclusive lock and release it on every exit.'
}
$recoveryMarker = $recoveryText.IndexOf('$journal.phase = ''rolled-back''')
$recoveryStart = $recoveryText.LastIndexOf('Start-Service -Name $ServiceName')
if ($recoveryMarker -lt 0 -or $recoveryStart -lt 0 -or $recoveryMarker -ge $recoveryStart) {
    throw 'Recovery must persist the rolled-back journal before attempting to restart the service.'
}
if (-not $installerText.Contains('$binariesRestored = Invoke-RollbackStep') -or
    -not $installerText.Contains('if ($binariesRestored -and $recoveryScriptRestored -and $metadataRestored -and $journalPersisted -and $script:InstallServiceStoppedForTransaction)') -or
    -not $installerText.Contains('if ($script:InstallServiceWasRunning)') -or
    -not $installerText.Contains('restore previous agent service state') -or
    -not $installerText.Contains('service is intentionally left stopped for recovery')) {
    throw 'Upgrade rollback must not restart unless binary, metadata and journal restoration all succeed.'
}
if (-not $installerText.Contains('metadata_original_sha256') -or
    -not $installerText.Contains('metadata_path = $metadataPath') -or
    -not $installerText.Contains('metadata_backup_path = $metadataBackupPath') -or
    -not $installerText.Contains('Assert-TransactionMetadataSnapshot -Journal $journal') -or
    -not $installerText.Contains('Restore-TransactionMetadata -Journal') -or
    -not $installerText.Contains('metadataBackup = [string]$Journal.metadata_backup_path') -or
    -not $installerText.Contains('persist completed rollback journal') -or
    -not $installerText.Contains('SCM service identity does not match the authenticated installer paths.') -or
    -not $installerText.Contains('SCM did not confirm the service stopped before interrupted-install recovery.')) {
    throw 'Installer recovery must preserve prior metadata and verify the expected SCM identity/state.'
}
if ($installerText -match '(?s)\$journal\.phase = ''rolled-back''.*?finally\s*\{\s*if \(\$restartService\)') {
    throw 'Interrupted transaction recovery must not restart the service from a finally block after rollback failure.'
}
if (-not $installerText.Contains('Legacy committed and rolled-back journals predate recovery-script transaction fields.') -or
    -not $installerText.Contains("@('committed', 'rolled-back')") -or
    -not $installerText.Contains('Legacy installer transaction cannot clean backups before durable commit.')) {
    throw 'Installer must accept only terminal legacy journals and fail closed for incomplete legacy transactions.'
}
if (-not $installerText.Contains('function Assert-TransactionRecoveryScript') -or
    -not $installerText.Contains('Assert-TransactionRecoveryScript -Journal $journal') -or
    -not $installerText.Contains('Previous recovery-script backup is unsafe, ACL-untrusted, or corrupted.') -or
    -not $installerText.Contains('Refusing committed cleanup because the installed recovery script identity or ACL is invalid.')) {
    throw 'Installer recovery must authenticate the recovery script and its backup before rollback or committed cleanup.'
}
$publicationCalls = [regex]::Matches($installerText, 'Publish-WeDecentRecoveryScript').Count - 1
if ($publicationCalls -ne 2) {
    throw "Installer must publish its recovery script once on upgrade and once on fresh install; found $publicationCalls invocations."
}
if (-not $installerText.Contains('recovery_script_backup_path') -or
    -not $installerText.Contains('Restore-TransactionRecoveryScript -Journal') -or
    -not $recoveryText.Contains('recovery_script_original_sha256') -or
    -not $recoveryText.Contains('Restore-TransactionRecoveryScript -Journal $journal') -or
    -not $recoveryText.Contains('Previous recovery script backup failed integrity verification.')) {
    throw 'Recovery-script preservation, integrity validation, and interrupted rollback restoration are required.'
}
$trustedSids = @('S-1-5-18', 'S-1-5-32-544')
$serviceSid = $null
$originalProgramData = $env:ProgramData
$root = Join-Path ([IO.Path]::GetTempPath()) ('wedecent-recovery-' + [Guid]::NewGuid().ToString('N'))
$installDir = Join-Path $env:ProgramFiles ('WeDecent-Recovery-' + [Guid]::NewGuid().ToString('N'))
$stateDir = Join-Path $installDir 'data\agent'
$journalRoot = Join-Path $root 'WeDecent\install-transactions'
$serviceName = 'WeDecentRecoveryTestSvc'

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
    $metadataPath = Join-Path $root 'WeDecent\installer.json'
    $metadataBackupPath = "$metadataPath.$Id.metadata.bak"
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { throw 'Recovery fixture prior metadata is missing.' }
    $metadataOriginalHash = Get-TestHash $metadataPath
    Copy-Item -LiteralPath $metadataPath -Destination $metadataBackupPath
    Set-TestTrustedAcl -Path $metadataBackupPath
    if ((Get-TestHash $metadataBackupPath) -ne $metadataOriginalHash) { throw 'Recovery fixture metadata snapshot failed integrity verification.' }
    $recoveryScriptPath = Join-Path $installDir 'Recover-WeDecentInstall.ps1'
    $recoveryScriptBackupPath = "$recoveryScriptPath.$Id.previous"
    [IO.File]::WriteAllText($recoveryScriptPath, "published recovery script:$Id")
    [IO.File]::WriteAllText($recoveryScriptBackupPath, "original recovery script:$Id")
    Set-TestTrustedAcl -Path $recoveryScriptPath
    Set-TestTrustedAcl -Path $recoveryScriptBackupPath
    $recoveryScriptOriginalHash = Get-TestHash $recoveryScriptBackupPath
    $recoveryScriptHash = Get-TestHash $recoveryScriptPath
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
        recovery_script_path = $recoveryScriptPath
        recovery_script_had_original = $true
        recovery_script_original_sha256 = $recoveryScriptOriginalHash
        recovery_script_backup_path = $recoveryScriptBackupPath
        recovery_script_sha256 = $recoveryScriptHash
        recovery_script_state = 'published'
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
        recoveryScriptPath = $recoveryScriptPath
        recoveryScriptBackupPath = $recoveryScriptBackupPath
        recoveryScriptOriginalHash = $recoveryScriptOriginalHash
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

    $serviceName = 'WeDecentRecoveryTestSvc' + [Guid]::NewGuid().ToString('N')
    $serviceAccountName = 'wdrec' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $servicePasswordPlain = ([Guid]::NewGuid().ToString('N')) + 'Aa1!'
    $servicePassword = ConvertTo-SecureString $servicePasswordPlain -AsPlainText -Force
    $serviceCredential = [pscredential]::new("$env:COMPUTERNAME\$serviceAccountName", $servicePassword)
    $serviceUser = New-LocalUser -Name $serviceAccountName -Password $servicePassword -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop
    $serviceSid = $serviceUser.SID.Value
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

    $agentPath = Join-Path $installDir 'wd-agent.exe'
    $serviceImage = '"' + $agentPath + '" --service --state="' + $stateDir + '"'
    New-Service -Name $serviceName -BinaryPathName $serviceImage -Credential $serviceCredential -StartupType Manual -ErrorAction Stop | Out-Null
    $serviceCheck = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
    if ($null -eq $serviceCheck -or $serviceCheck.State -ne 'Stopped') { throw 'SCM service fixture was not created stopped.' }
    $actualServiceStartName = ([string]$serviceCheck.StartName).Trim()
    if ($actualServiceStartName.StartsWith('.\', [StringComparison]::Ordinal)) {
        $actualServiceStartName = "$env:COMPUTERNAME\$($actualServiceStartName.Substring(2))"
    }
    $actualServiceSid = (New-Object Security.Principal.NTAccount -ArgumentList $actualServiceStartName).Translate([Security.Principal.SecurityIdentifier]).Value
    if (-not [string]::Equals($actualServiceSid, $serviceSid, [StringComparison]::OrdinalIgnoreCase)) {
        throw "SCM test service account SID does not match its provisioned local account ($actualServiceSid != $serviceSid)."
    }
    $successful = New-TransactionFixture
    $metadataBefore = Get-TestHash $successful.metadataBackupPath
    $targetMetadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    $targetMetadata.version = $successful.targetVersion
    Write-TestJson -Path $metadataPath -Value $targetMetadata
    [IO.File]::WriteAllText("$metadataPath.$($successful.id).restore", 'interrupted restore temp')
    Invoke-TestRecovery -Fixture $successful | Out-Null
    if ((Get-TestHash $metadataPath) -ne $metadataBefore) { throw 'Recovery did not restore exact prior installer metadata bytes.' }
    if ((Get-TestHash $successful.recoveryScriptPath) -ne $successful.recoveryScriptOriginalHash) {
        throw 'Interrupted recovery did not restore the exact previous privileged recovery script.'
    }
    if (Test-Path -LiteralPath $successful.recoveryScriptBackupPath) {
        throw 'Interrupted recovery did not clean its transaction-specific recovery-script backup after durable rollback.'
    }
    $recovered = Get-Content -LiteralPath $successful.journalPath -Raw | ConvertFrom-Json
    if ($recovered.phase -ne 'rolled-back') { throw 'Recovery did not persist the rolled-back phase.' }
    foreach ($entry in $successful.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $entry.original_sha256) {
            throw "Rollback failed to restore the original binary: $($entry.name)"
        }
    }

    # Repeating the same recovery transaction must remain safe and idempotent.
    Invoke-TestRecovery -Fixture $successful | Out-Null
    if (Test-Path -LiteralPath $successful.recoveryScriptBackupPath) {
        throw 'Repeated recovery recreated a previously cleaned recovery-script backup.'
    }
    $replayed = Get-Content -LiteralPath $successful.journalPath -Raw | ConvertFrom-Json
    if ($replayed.phase -ne 'rolled-back') { throw 'Repeated recovery changed the completed rollback phase.' }
    foreach ($entry in $successful.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $entry.original_sha256) {
            throw "Repeated recovery changed the restored original binary: $($entry.name)"
        }
    }
    $metadataOriginalBytes = [IO.File]::ReadAllBytes($metadataPath)

    # Simulate recovery interrupted after the original recovery-script state was journaled but before backup deletion.
    $interruptedCleanup = New-TransactionFixture
    $interruptedJournal = Get-Content -LiteralPath $interruptedCleanup.journalPath -Raw | ConvertFrom-Json
    [IO.File]::Copy($interruptedCleanup.recoveryScriptBackupPath, $interruptedCleanup.recoveryScriptPath, $true)
    Set-TestTrustedAcl -Path $interruptedCleanup.recoveryScriptPath
    $interruptedJournal.recovery_script_state = 'original'
    $interruptedJournal.recovery_script_sha256 = $interruptedJournal.recovery_script_original_sha256
    Write-TestJson -Path $interruptedCleanup.journalPath -Value $interruptedJournal
    Invoke-TestRecovery -Fixture $interruptedCleanup | Out-Null
    if (Test-Path -LiteralPath $interruptedCleanup.recoveryScriptBackupPath) {
        throw 'Interrupted recovery did not finish cleanup after the original recovery-script state was already durable.'
    }
    Invoke-TestRecovery -Fixture $interruptedCleanup | Out-Null
    if (Test-Path -LiteralPath $interruptedCleanup.recoveryScriptBackupPath) {
        throw 'Repeated interrupted recovery recreated a cleaned recovery-script backup.'
    }

    # A process death during recovery-script backup copy leaves only a staging file; recovery must retain the intact original.
    $interruptedRecoveryBackup = New-TransactionFixture
    $interruptedJournal = Get-Content -LiteralPath $interruptedRecoveryBackup.journalPath -Raw | ConvertFrom-Json
    [IO.File]::Copy($interruptedRecoveryBackup.recoveryScriptBackupPath, $interruptedRecoveryBackup.recoveryScriptPath, $true)
    Set-TestTrustedAcl -Path $interruptedRecoveryBackup.recoveryScriptPath
    Remove-Item -LiteralPath $interruptedRecoveryBackup.recoveryScriptBackupPath -Force
    $interruptedStaging = "$($interruptedRecoveryBackup.recoveryScriptBackupPath).staging"
    [IO.File]::WriteAllText($interruptedStaging, 'partial recovery backup bytes')
    Set-TestTrustedAcl -Path $interruptedStaging
    $interruptedJournal.recovery_script_state = 'original'
    $interruptedJournal.recovery_script_sha256 = $interruptedJournal.recovery_script_original_sha256
    Write-TestJson -Path $interruptedRecoveryBackup.journalPath -Value $interruptedJournal
    Invoke-TestRecovery -Fixture $interruptedRecoveryBackup | Out-Null
    if (Test-Path -LiteralPath $interruptedStaging) {
        throw 'Recovery did not remove the incomplete recovery-script staging file after authenticating the intact original.'
    }
    if ((Get-TestHash $interruptedRecoveryBackup.recoveryScriptPath) -ne $interruptedRecoveryBackup.recoveryScriptOriginalHash) {
        throw 'Recovery changed the intact original recovery script while cleaning an interrupted backup staging file.'
    }

    $corruptRecoveryScript = New-TransactionFixture
    $beforeCorruptRecovery = @{}
    foreach ($entry in $corruptRecoveryScript.journal.entries) { $beforeCorruptRecovery[$entry.name] = Get-TestHash $entry.destination }
    [IO.File]::WriteAllText($corruptRecoveryScript.recoveryScriptBackupPath, 'corrupt recovery-script backup')
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $corruptRecoveryScript | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery accepted a corrupted privileged recovery-script backup.' }
    foreach ($entry in $corruptRecoveryScript.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $beforeCorruptRecovery[$entry.name]) {
            throw 'Corrupted recovery-script backup rejection mutated an installed binary.'
        }
    }

    $corruptMetadata = New-TransactionFixture
    $beforeCorruptMetadata = @{}
    foreach ($entry in $corruptMetadata.journal.entries) { $beforeCorruptMetadata[$entry.name] = Get-TestHash $entry.destination }
    [IO.File]::WriteAllText($corruptMetadata.metadataBackupPath, 'corrupt metadata snapshot')
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $corruptMetadata | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery accepted a corrupted metadata snapshot.' }
    foreach ($entry in $corruptMetadata.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $beforeCorruptMetadata[$entry.name]) { throw 'Corrupt metadata rejection mutated a binary.' }
    }

    $missingMetadata = New-TransactionFixture
    Remove-Item -LiteralPath $missingMetadata.metadataBackupPath -Force
    [IO.File]::WriteAllText($metadataPath, 'incomplete current metadata')
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $missingMetadata | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery accepted missing snapshot plus corrupt current metadata.' }
    [IO.File]::WriteAllBytes($metadataPath, $metadataOriginalBytes)
    Set-TestTrustedAcl -Path $metadataPath

    $inconsistentMetadata = New-TransactionFixture
    $inconsistentJournal = Get-Content -LiteralPath $inconsistentMetadata.journalPath -Raw | ConvertFrom-Json
    $inconsistentJournal.metadata_path = (Join-Path $root 'forged-installer.json')
    Write-TestJson -Path $inconsistentMetadata.journalPath -Value $inconsistentJournal
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $inconsistentMetadata | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery accepted an inconsistent metadata journal path.' }

    $missingScm = New-TransactionFixture
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $missingScm | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery accepted a missing SCM service.' }
    New-Service -Name $serviceName -BinaryPathName $serviceImage -Credential $serviceCredential -StartupType Manual -ErrorAction Stop | Out-Null

    $mismatchedScm = New-TransactionFixture
    & sc.exe config $serviceName binPath= 'C:\Windows\System32\svchost.exe -k netsvcs' | Out-Null
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $mismatchedScm | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery accepted an SCM service with a mismatched image path.' }
    & sc.exe config $serviceName binPath= $serviceImage | Out-Null

    $localSystemSubstitution = New-TransactionFixture
    & sc.exe config $serviceName obj= LocalSystem | Out-Null
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $localSystemSubstitution | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery accepted LocalSystem in place of the protected service account.' }
    if ((Get-Service -Name $serviceName).Status -ne 'Stopped') { throw 'LocalSystem account mismatch changed the stopped service state.' }
    & sc.exe config $serviceName obj= "$env:COMPUTERNAME\$serviceAccountName" password= $servicePasswordPlain | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restore the isolated service account after LocalSystem mismatch test.' }

    $syntheticMetadataMismatch = New-TransactionFixture
    $mismatchMetadata = Get-Content -LiteralPath $syntheticMetadataMismatch.metadataBackupPath -Raw | ConvertFrom-Json
    $mismatchMetadata.service_account_sid = 'S-1-5-21-100-200-300-1001'
    Write-TestJson -Path $syntheticMetadataMismatch.metadataBackupPath -Value $mismatchMetadata
    $mismatchJournal = Get-Content -LiteralPath $syntheticMetadataMismatch.journalPath -Raw | ConvertFrom-Json
    $mismatchJournal.metadata_original_sha256 = Get-TestHash $syntheticMetadataMismatch.metadataBackupPath
    Write-TestJson -Path $syntheticMetadataMismatch.journalPath -Value $mismatchJournal
    $beforeSyntheticMismatch = @{}
    foreach ($entry in $syntheticMetadataMismatch.journal.entries) { $beforeSyntheticMismatch[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $syntheticMetadataMismatch | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery accepted a mismatched synthetic protected metadata SID.' }
    if ((Get-Service -Name $serviceName).Status -ne 'Stopped') { throw 'Metadata SID mismatch changed the stopped service state.' }
    foreach ($entry in $syntheticMetadataMismatch.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $beforeSyntheticMismatch[$entry.name]) { throw 'Metadata SID mismatch mutated a previous binary.' }
    }

    $malformedMetadata = New-TransactionFixture
    $malformedMetadataObject = Get-Content -LiteralPath $malformedMetadata.metadataBackupPath -Raw | ConvertFrom-Json
    $malformedMetadataObject.service_account_sid = 'not-a-sid'
    Write-TestJson -Path $malformedMetadata.metadataBackupPath -Value $malformedMetadataObject
    $malformedMetadataJournal = Get-Content -LiteralPath $malformedMetadata.journalPath -Raw | ConvertFrom-Json
    $malformedMetadataJournal.metadata_original_sha256 = Get-TestHash $malformedMetadata.metadataBackupPath
    Write-TestJson -Path $malformedMetadata.journalPath -Value $malformedMetadataJournal
    $beforeMalformedMetadata = @{}
    foreach ($entry in $malformedMetadata.journal.entries) { $beforeMalformedMetadata[$entry.name] = Get-TestHash $entry.destination }
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $malformedMetadata | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery accepted a malformed protected service account SID.' }
    if ((Get-Service -Name $serviceName).Status -ne 'Stopped') { throw 'Malformed metadata SID changed the stopped service state.' }
    foreach ($entry in $malformedMetadata.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $beforeMalformedMetadata[$entry.name]) { throw 'Malformed metadata SID mutated a previous binary.' }
    }

    $restartFailure = New-TransactionFixture -ServiceWasRunning $true
    $rejected = $false
    try { Invoke-TestRecovery -Fixture $restartFailure | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Updater recovery reported success when SCM could not restart the previous service.' }
    if ((Get-Service -Name $serviceName).Status -ne 'Stopped') { throw 'Failed SCM restart did not leave the service stopped.' }
    $restartJournal = Get-Content -LiteralPath $restartFailure.journalPath -Raw | ConvertFrom-Json
    if ($restartJournal.phase -ne 'rolled-back') { throw 'Rollback journal was not persisted before failed service restart.' }
    foreach ($entry in $restartFailure.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $entry.original_sha256) { throw "Restart failure lost previous binary $($entry.name)." }
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
    $finalizeJournalPath = Join-Path $finalizeJournalRoot ($finalizeTransactionId + '.json')
    $finalizeJournal = [ordered]@{
        schema = 1
        transaction_id = $finalizeTransactionId
        package_sha256 = 'b' * 64
        manifest_sha256 = 'a' * 64
        previous_version = 'v0.3.9'
        sequence = [UInt64]42
        service_was_running = $false
        version = 'v0.4.0'
        phase = 'installed-awaiting-sequence-commit'
        entries = $finalizeEntries
        updated_at = [DateTime]::UtcNow.ToString('o')
    }
    $finalizeRecoveryScriptPath = Join-Path $finalizeInstallDir 'Recover-WeDecentInstall.ps1'
    $finalizeRecoveryBackup = "$finalizeRecoveryScriptPath.$finalizeTransactionId.previous"
    [IO.File]::WriteAllText($finalizeRecoveryScriptPath, 'current published recovery script')
    [IO.File]::WriteAllText($finalizeRecoveryBackup, 'prior recovery script')
    Set-TestTrustedAcl -Path $finalizeRecoveryScriptPath
    Set-TestTrustedAcl -Path $finalizeRecoveryBackup
    $finalizeJournal.recovery_script_path = $finalizeRecoveryScriptPath
    $finalizeJournal.recovery_script_backup_path = $finalizeRecoveryBackup
    $finalizeJournal.recovery_script_had_original = $true
    $finalizeJournal.recovery_script_original_sha256 = Get-TestHash $finalizeRecoveryBackup
    $finalizeJournal.recovery_script_sha256 = Get-TestHash $finalizeRecoveryScriptPath
    $finalizeJournal.recovery_script_state = 'published'
    Write-TestJson -Path $finalizeJournalPath -Value $finalizeJournal
    $finalizeMetadataPath = Join-Path $finalizeWeDecent 'installer.json'
    Write-TestJson -Path $finalizeMetadataPath -Value ([ordered]@{
        schema = 1
        product = 'WeDecent'
        service_name = $serviceName
        service_account_sid = $serviceSid
        install_dir = $finalizeInstallDir
        state_dir = $finalizeStateDir
    })
    $finalizeMetadataBackup = "$finalizeMetadataPath.$finalizeTransactionId.metadata.bak"
    Copy-Item -LiteralPath $finalizeMetadataPath -Destination $finalizeMetadataBackup
    Set-TestTrustedAcl -Path $finalizeMetadataBackup
    $finalizeJournal.metadata_original_sha256 = Get-TestHash $finalizeMetadataBackup
    $finalizeJournal.metadata_path = $finalizeMetadataPath
    $finalizeJournal.metadata_had_original = $true
    $finalizeJournal.metadata_backup_path = $finalizeMetadataBackup
    Write-TestJson -Path $finalizeJournalPath -Value $finalizeJournal

    # A superseded committed journal may retain only its metadata snapshot after binary cleanup.
    $olderTransactionId = [Guid]::NewGuid().ToString('N')
    $olderEntries = @()
    foreach ($entry in $finalizeEntries) {
        $olderEntries += [ordered]@{
            name = $entry.name
            destination = $entry.destination
            had_original = $true
            original_sha256 = $entry.original_sha256
            replacement_sha256 = $entry.replacement_sha256
            backup_path = "$($entry.destination).$olderTransactionId.bak"
            state = 'replaced'
        }
    }
    $olderMetadataBackup = "$finalizeMetadataPath.$olderTransactionId.metadata.bak"
    Copy-Item -LiteralPath $finalizeMetadataPath -Destination $olderMetadataBackup
    Set-TestTrustedAcl -Path $olderMetadataBackup
    $olderJournal = [ordered]@{
        schema = 1
        transaction_id = $olderTransactionId
        package_sha256 = 'd' * 64
        manifest_sha256 = 'e' * 64
        previous_version = 'v0.3.8'
        sequence = [UInt64]41
        service_was_running = $false
        version = 'v0.3.9'
        phase = 'committed'
        entries = $olderEntries
        metadata_path = $finalizeMetadataPath
        metadata_had_original = $true
        metadata_original_sha256 = Get-TestHash $olderMetadataBackup
        metadata_backup_path = $olderMetadataBackup
        updated_at = [DateTime]::UtcNow.ToString('o')
    }
    $olderRecoveryBackup = "$finalizeRecoveryScriptPath.$olderTransactionId.previous"
    [IO.File]::WriteAllText($olderRecoveryBackup, 'older prior recovery script')
    Set-TestTrustedAcl -Path $olderRecoveryBackup
    $olderJournal.recovery_script_path = $finalizeRecoveryScriptPath
    $olderJournal.recovery_script_backup_path = $olderRecoveryBackup
    $olderJournal.recovery_script_had_original = $true
    $olderJournal.recovery_script_original_sha256 = Get-TestHash $olderRecoveryBackup
    $olderJournal.recovery_script_sha256 = Get-TestHash $olderRecoveryBackup
    $olderJournal.recovery_script_state = 'published'
    $olderJournalPath = Join-Path $finalizeJournalRoot ($olderTransactionId + '.json')
    Write-TestJson -Path $olderJournalPath -Value $olderJournal

    # A completed rollback is unrelated to this committed transaction; its binary backups must survive cleanup.
    $rolledBackTransactionId = [Guid]::NewGuid().ToString('N')
    $rolledBackEntries = @()
    $rolledBackBackupHashes = @{}
    foreach ($entry in $finalizeEntries) {
        $unrelatedBackup = "$($entry.destination).$rolledBackTransactionId.bak"
        [IO.File]::WriteAllBytes($unrelatedBackup, [Text.Encoding]::UTF8.GetBytes("unrelated:$($entry.name)"))
        Set-TestTrustedAcl -Path $unrelatedBackup
        $rolledBackBackupHashes[$entry.name] = Get-TestHash $unrelatedBackup
        $rolledBackEntries += [ordered]@{
            name = $entry.name
            destination = $entry.destination
            had_original = $true
            original_sha256 = $rolledBackBackupHashes[$entry.name]
            replacement_sha256 = $entry.replacement_sha256
            backup_path = $unrelatedBackup
            state = 'replaced'
        }
    }
    $rolledBackMetadataBackup = "$finalizeMetadataPath.$rolledBackTransactionId.metadata.bak"
    Copy-Item -LiteralPath $finalizeMetadataPath -Destination $rolledBackMetadataBackup
    Set-TestTrustedAcl -Path $rolledBackMetadataBackup
    $rolledBackJournal = [ordered]@{
        schema = 1
        transaction_id = $rolledBackTransactionId
        package_sha256 = 'f' * 64
        manifest_sha256 = '9' * 64
        previous_version = 'v0.3.7'
        sequence = [UInt64]40
        service_was_running = $false
        version = 'v0.3.8'
        phase = 'rolled-back'
        entries = $rolledBackEntries
        metadata_path = $finalizeMetadataPath
        metadata_had_original = $true
        metadata_original_sha256 = Get-TestHash $rolledBackMetadataBackup
        metadata_backup_path = $rolledBackMetadataBackup
        updated_at = [DateTime]::UtcNow.ToString('o')
    }
    $rolledBackJournalPath = Join-Path $finalizeJournalRoot ($rolledBackTransactionId + '.json')
    Write-TestJson -Path $rolledBackJournalPath -Value $rolledBackJournal
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
    $olderFinalizedJournal = Get-Content -LiteralPath $olderJournalPath -Raw | ConvertFrom-Json
    if ($olderFinalizedJournal.phase -ne 'committed' -or (Test-Path -LiteralPath $olderMetadataBackup)) {
        throw 'Multi-journal finalizer did not preserve the older committed journal and clean its associated metadata snapshot.'
    }
    if (Test-Path -LiteralPath $rolledBackMetadataBackup) { throw 'Rolled-back journal metadata snapshot was not cleaned.' }
    if (Test-Path -LiteralPath $finalizeRecoveryBackup) { throw 'Current committed recovery-script backup was not cleaned.' }
    if (Test-Path -LiteralPath $olderRecoveryBackup) { throw 'Superseded committed recovery-script backup was not cleaned.' }
    foreach ($entry in $rolledBackEntries) {
        if (-not (Test-Path -LiteralPath $entry.backup_path -PathType Leaf) -or
            (Get-TestHash $entry.backup_path) -ne $rolledBackBackupHashes[$entry.name]) {
            throw "Finalizer deleted or changed an unrelated rolled-back transaction backup: $($entry.name)"
        }
    }
    foreach ($entry in $finalizeEntries) {
        if (Test-Path -LiteralPath $entry.backup_path) {
            throw "Post-commit finalizer did not remove a verified backup: $($entry.name)"
        }
    }

    # Recreate only the superseded metadata snapshot to simulate interruption after binary cleanup.
    Copy-Item -LiteralPath $finalizeMetadataPath -Destination $olderMetadataBackup
    Set-TestTrustedAcl -Path $olderMetadataBackup
    [IO.File]::WriteAllText($finalizeRecoveryBackup, 'prior recovery script')
    [IO.File]::WriteAllText($olderRecoveryBackup, 'older prior recovery script')
    Set-TestTrustedAcl -Path $finalizeRecoveryBackup
    Set-TestTrustedAcl -Path $olderRecoveryBackup
    & $recoveryScript -FinalizeCommitted -InstallDir $finalizeInstallDir -StateDir $finalizeStateDir -ServiceName $serviceName -ExpectedStableSequence 42 -ExpectedInstalledVersion 'v0.4.0' | Out-Null
    if (Test-Path -LiteralPath $olderMetadataBackup) { throw 'Interrupted superseded metadata cleanup was not resumed.' }
    if (Test-Path -LiteralPath $finalizeRecoveryBackup) { throw 'Interrupted current recovery-script backup cleanup was not resumed.' }
    if (Test-Path -LiteralPath $olderRecoveryBackup) { throw 'Interrupted superseded recovery-script backup cleanup was not resumed.' }

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

    # A corrupted transaction-specific recovery-script backup must fail closed and remain for diagnosis.
    [IO.File]::WriteAllText($finalizeRecoveryBackup, 'corrupted prior recovery script')
    Set-TestTrustedAcl -Path $finalizeRecoveryBackup
    $rejectedRecoveryBackup = $false
    try {
        & $recoveryScript -FinalizeCommitted -InstallDir $finalizeInstallDir -StateDir $finalizeStateDir -ServiceName $serviceName -ExpectedStableSequence 42 -ExpectedInstalledVersion 'v0.4.0' | Out-Null
    } catch { $rejectedRecoveryBackup = $true }
    if (-not $rejectedRecoveryBackup -or -not (Test-Path -LiteralPath $finalizeRecoveryBackup)) {
        throw 'Committed cleanup did not fail closed and retain a corrupted recovery-script backup.'
    }
    Remove-Item -LiteralPath $finalizeRecoveryBackup -Force

    # Changed target bytes must prevent every remaining backup from being deleted.
    foreach ($entry in $finalizeEntries) {
        [IO.File]::WriteAllBytes([string]$entry.backup_path, [Text.Encoding]::UTF8.GetBytes("original:$($entry.name)"))
    }
    [IO.File]::WriteAllText([string]$finalizeEntries[2].destination, 'tampered committed target')
    [IO.File]::WriteAllText($finalizeRecoveryScriptPath, 'tampered committed recovery script')
    [IO.File]::WriteAllText($finalizeRecoveryBackup, 'prior recovery script')
    Set-TestTrustedAcl -Path $finalizeRecoveryBackup
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
    if (-not (Test-Path -LiteralPath $finalizeRecoveryBackup -PathType Leaf)) {
        throw 'Changed recovery-script target caused premature transaction backup deletion.'
    }

    # Execute the installer's metadata transaction helpers against an isolated ACL-protected fixture.
    $helperProgramData = Join-Path $root 'metadata-helper-programdata'
    $helperWeDecent = Join-Path $helperProgramData 'WeDecent'
    New-Item -ItemType Directory -Force -Path $helperWeDecent | Out-Null
    $helperMetadataPath = Join-Path $helperWeDecent 'installer.json'
    $helperTransactionId = [Guid]::NewGuid().ToString('N')
    $helperBackupPath = "$helperMetadataPath.$helperTransactionId.metadata.bak"
    $helperOriginalMetadata = [ordered]@{
        schema = 1
        product = 'WeDecent'
        version = 'v0.3.9'
        service_name = $serviceName
        service_account_sid = $serviceSid
        install_dir = $installDir
        state_dir = $stateDir
    }
    Write-TestJson -Path $helperMetadataPath -Value $helperOriginalMetadata
    Set-TestTrustedAcl -Path $helperMetadataPath
    $helperOriginalHash = Get-TestHash $helperMetadataPath
    Copy-Item -LiteralPath $helperMetadataPath -Destination $helperBackupPath
    Set-TestTrustedAcl -Path $helperBackupPath
    $helperJournal = [ordered]@{
        transaction_id = $helperTransactionId
        version = 'v0.4.0'
        metadata_path = $helperMetadataPath
        metadata_had_original = $true
        metadata_original_sha256 = $helperOriginalHash
        metadata_backup_path = $helperBackupPath
    }
    $tokens = $null
    $parseErrors = $null
    $installerAst = [System.Management.Automation.Language.Parser]::ParseFile($installerScript, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw 'Installer source did not parse for metadata helper tests.' }
    function Get-WeDecentMetadataPath { Join-Path $env:ProgramData 'WeDecent\installer.json' }
    function Get-Sha256FileHash { param([string]$Path) Get-TestHash $Path }
    function Protect-WeDecentMetadataAcl { param([string]$Path) Set-TestTrustedAcl -Path $Path }
    $writerFunction = $installerAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Write-InstallJournal'
    }, $true)
    if ($writerFunction.Count -ne 1) { throw 'Could not locate the production installer journal writer.' }
    Invoke-Expression $writerFunction[0].Extent.Text
    $metadataFunctions = $installerAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -in @('Assert-TransactionMetadataSnapshot', 'Restore-TransactionMetadata')
    }, $true)
    if ($metadataFunctions.Count -ne 2) { throw 'Could not locate both installer metadata transaction helpers.' }
    foreach ($functionAst in $metadataFunctions) { Invoke-Expression $functionAst.Extent.Text }
    $env:ProgramData = $helperProgramData
    $targetMetadata = [ordered]@{}
    foreach ($metadataKey in $helperOriginalMetadata.Keys) {
        $targetMetadata[$metadataKey] = $helperOriginalMetadata[$metadataKey]
    }
    $targetMetadata.version = 'v0.4.0'
    Write-TestJson -Path $helperMetadataPath -Value $targetMetadata
    Set-TestTrustedAcl -Path $helperMetadataPath
    [IO.File]::WriteAllText("$helperMetadataPath.$helperTransactionId.restore", 'interrupted restore temp')
    Restore-TransactionMetadata -Journal $helperJournal
    if ((Get-TestHash $helperMetadataPath) -ne $helperOriginalHash) { throw 'Installer metadata helper did not restore exact prior metadata bytes.' }
    Restore-TransactionMetadata -Journal $helperJournal
    if ((Get-TestHash $helperMetadataPath) -ne $helperOriginalHash) { throw 'Repeated installer metadata restoration was not idempotent.' }

    [IO.File]::WriteAllText($helperBackupPath, 'corrupted metadata backup')
    $rejected = $false
    try { Assert-TransactionMetadataSnapshot -Journal $helperJournal } catch { $rejected = $true }
    if (-not $rejected) { throw 'Installer metadata helper accepted a corrupted snapshot.' }
    Remove-Item -LiteralPath $helperBackupPath -Force
    [IO.File]::WriteAllText($helperMetadataPath, 'incomplete current metadata')
    $rejected = $false
    try { Assert-TransactionMetadataSnapshot -Journal $helperJournal } catch { $rejected = $true }
    if (-not $rejected) { throw 'Installer metadata helper accepted missing snapshot plus corrupted current metadata.' }
    $helperJournal.phase = 'rolled-back'
    Write-TestJson -Path $helperMetadataPath -Value $helperOriginalMetadata
    Set-TestTrustedAcl -Path $helperMetadataPath
    Remove-Item -LiteralPath $helperBackupPath -Force -ErrorAction SilentlyContinue
    $laterMetadata = [ordered]@{}
    foreach ($metadataKey in $helperOriginalMetadata.Keys) { $laterMetadata[$metadataKey] = $helperOriginalMetadata[$metadataKey] }
    $laterMetadata.version = 'v0.4.1'
    Write-TestJson -Path $helperMetadataPath -Value $laterMetadata
    Set-TestTrustedAcl -Path $helperMetadataPath
    Assert-TransactionMetadataSnapshot -Journal $helperJournal -Historical $true
    $rejected = $false
    try { Assert-TransactionMetadataSnapshot -Journal $helperJournal } catch { $rejected = $true }
    if (-not $rejected) { throw 'Historical metadata admission compared a rolled-back journal against a later installation.' }
    $env:ProgramData = $root

    # Exercise recovery-script admission for upgrades, fresh installs, and legacy journals.
    $recoveryFunction = $installerAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Assert-TransactionRecoveryScript'
    }, $true)
    if ($recoveryFunction.Count -ne 1) { throw 'Could not locate the installer recovery-script admission helper.' }
    $script:recoveryTestAclTrusted = $true
    function Test-WeDecentMetadataTrusted { param([string]$Path) return [bool]$script:recoveryTestAclTrusted }
    Invoke-Expression $recoveryFunction[0].Extent.Text
    $durableFunctionNames = @('Copy-WeDecentFileDurably', 'Flush-WeDecentFileToDisk', 'Write-WeDecentTextDurably', 'Publish-WeDecentBinaryBackup', 'Publish-TransactionRecoveryScriptBackup', 'Acquire-WeDecentInstallerLock')
    $durableFunctions = $installerAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $durableFunctionNames
    }, $true)
    if ($durableFunctions.Count -ne $durableFunctionNames.Count) { throw 'Could not locate every production durable-backup and installer-lock helper.' }
    foreach ($functionAst in $durableFunctions) { Invoke-Expression $functionAst.Extent.Text }

    # Exercise all five durable backup paths and reject corrupted existing backups.
    $durableTestDir = Join-Path $root 'durable-backup-tests'
    New-Item -ItemType Directory -Force -Path $durableTestDir | Out-Null
    Set-TestTrustedAcl -Path $durableTestDir
    foreach ($name in $binaryNames) {
        $source = Join-Path $durableTestDir ("source-" + $name)
        $backup = Join-Path $durableTestDir ("backup-" + $name)
        [IO.File]::WriteAllBytes($source, [Text.Encoding]::UTF8.GetBytes("durable-original:$name"))
        $expected = Get-TestHash $source
        Publish-WeDecentBinaryBackup -Source $source -BackupPath $backup -ExpectedSHA256 $expected
        if ((Get-TestHash $backup) -ne $expected -or (Get-Content -LiteralPath "$backup.sha256" -Raw).Trim() -cne $expected) {
            throw "Durable backup helper did not persist and verify both payload and sidecar: $name"
        }
    }
    $corruptDurableSource = Join-Path $durableTestDir 'corrupt-source'
    $corruptDurableBackup = Join-Path $durableTestDir 'corrupt-backup'
    [IO.File]::WriteAllText($corruptDurableSource, 'trusted source')
    [IO.File]::WriteAllText($corruptDurableBackup, 'corrupt backup')
    Set-TestTrustedAcl -Path $corruptDurableBackup
    $rejected = $false
    try { Publish-WeDecentBinaryBackup -Source $corruptDurableSource -BackupPath $corruptDurableBackup -ExpectedSHA256 (Get-TestHash $corruptDurableSource) } catch { $rejected = $true }
    if (-not $rejected) { throw 'Durable backup helper accepted a corrupted existing backup.' }

    # Kill child PowerShell processes at each durable backup boundary, then retry in a fresh process.
    $powerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $backupCrashPoints = @('after-backup-flush', 'after-backup-hash', 'after-backup-acl', 'after-sidecar-flush', 'after-sidecar-acl', 'after-sidecar-publish', 'after-backup-publish')
    foreach ($crashPoint in $backupCrashPoints) {
        $id = [Guid]::NewGuid().ToString('N')
        $source = Join-Path $durableTestDir ("crash-source-" + $id)
        $backup = Join-Path $durableTestDir ("crash-backup-" + $id)
        [IO.File]::WriteAllText($source, "crash-safe original:$id")
        $expected = Get-TestHash $source
        $marker = Join-Path $durableTestDir ("crash-marker-" + $id)
        $functionText = ($durableFunctions | Where-Object { $_.Name -in @('Copy-WeDecentFileDurably', 'Flush-WeDecentFileToDisk', 'Write-WeDecentTextDurably', 'Publish-WeDecentBinaryBackup') } | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
        $sourceQ = $source.Replace("'", "''"); $backupQ = $backup.Replace("'", "''")
        $markerQ = $marker.Replace("'", "''")
        $childCommand = @'
function Get-Sha256FileHash { param([string]$Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Protect-WeDecentMetadataAcl { param([string]$Path) }
function Test-WeDecentMetadataTrusted { param([string]$Path) return $true }
__FUNCTION_TEXT__
Publish-WeDecentBinaryBackup -Source '__SOURCE__' -BackupPath '__BACKUP__' -ExpectedSHA256 '__EXPECTED__' -CrashHook {
    param($point)
    if ($point -eq '__CRASH_POINT__') { [IO.File]::WriteAllText('__MARKER__', 'crash'); [Environment]::Exit(77) }
}
'@
        $childCommand = $childCommand.Replace('__FUNCTION_TEXT__', $functionText).Replace('__SOURCE__', $sourceQ).Replace('__BACKUP__', $backupQ).Replace('__EXPECTED__', $expected).Replace('__CRASH_POINT__', $crashPoint).Replace('__MARKER__', $markerQ)
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCommand))
        $child = Start-Process -FilePath $powerShellExe -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -PassThru -WindowStyle Hidden
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while (-not (Test-Path -LiteralPath $marker) -and -not $child.HasExited -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100; $child.Refresh() }
        if (-not (Test-Path -LiteralPath $marker)) {
            if (-not $child.HasExited) { Stop-Process -Id $child.Id -Force }
            throw "Child process did not reach durable backup crash point: $crashPoint"
        }
        $child.WaitForExit()
        if ($child.ExitCode -ne 77) { throw "Child process did not terminate at the expected crash point $crashPoint (exit $($child.ExitCode))." }
        $retryCommand = @'
function Get-Sha256FileHash { param([string]$Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Protect-WeDecentMetadataAcl { param([string]$Path) }
function Test-WeDecentMetadataTrusted { param([string]$Path) return $true }
__FUNCTION_TEXT__
Publish-WeDecentBinaryBackup -Source '__SOURCE__' -BackupPath '__BACKUP__' -ExpectedSHA256 '__EXPECTED__'
'@
        $retryCommand = $retryCommand.Replace('__FUNCTION_TEXT__', $functionText).Replace('__SOURCE__', $sourceQ).Replace('__BACKUP__', $backupQ).Replace('__EXPECTED__', $expected)
        $retryEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($retryCommand))
        $retry = Start-Process -FilePath $powerShellExe -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $retryEncoded) -PassThru -Wait -WindowStyle Hidden
        if ($retry.ExitCode -ne 0 -or (Get-TestHash $backup) -ne $expected -or (Get-Content -LiteralPath "$backup.sha256" -Raw).Trim() -cne $expected) {
            throw "Fresh-process recovery did not complete the durable backup after $crashPoint."
        }
    }

    # Recovery-script backup publication has the same process-death and fresh-process retry guarantees.
    $recoveryBackupFunctions = ($durableFunctions | Where-Object { $_.Name -in @('Copy-WeDecentFileDurably', 'Flush-WeDecentFileToDisk', 'Publish-TransactionRecoveryScriptBackup') } | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
    foreach ($crashPoint in @('after-backup-flush', 'after-backup-hash', 'after-backup-acl', 'after-backup-publish')) {
        $id = [Guid]::NewGuid().ToString('N')
        $target = Join-Path $durableTestDir ("recovery-target-" + $id)
        $backup = "$target.$id.previous"
        [IO.File]::WriteAllText($target, "prior recovery entrypoint:$id")
        $expected = Get-TestHash $target
        $marker = Join-Path $durableTestDir ("recovery-marker-" + $id)
        $targetQ = $target.Replace("'", "''"); $backupQ = $backup.Replace("'", "''")
        $markerQ = $marker.Replace("'", "''")
        $childCommand = @'
function Get-Sha256FileHash { param([string]$Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Protect-WeDecentMetadataAcl { param([string]$Path) }
function Test-WeDecentMetadataTrusted { param([string]$Path) return $true }
$RECOVERY_FUNCTIONS$
$script:InstallJournal = [ordered]@{
    recovery_script_had_original = $true
    recovery_script_path = '$TARGET$'
    recovery_script_backup_path = '$BACKUP$'
    recovery_script_original_sha256 = '$EXPECTED$'
}
Publish-TransactionRecoveryScriptBackup -CrashHook {
    param($point)
    if ($point -eq '$CRASH_POINT$') { [IO.File]::WriteAllText('$MARKER$', 'crash'); [Environment]::Exit(78) }
}
'@
        $childCommand = $childCommand.Replace('$RECOVERY_FUNCTIONS$', $recoveryBackupFunctions).Replace('$TARGET$', $targetQ).Replace('$BACKUP$', $backupQ).Replace('$EXPECTED$', $expected).Replace('$CRASH_POINT$', $crashPoint).Replace('$MARKER$', $markerQ)
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCommand))
        $child = Start-Process -FilePath $powerShellExe -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -PassThru -WindowStyle Hidden
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while (-not (Test-Path -LiteralPath $marker) -and -not $child.HasExited -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100; $child.Refresh() }
        if (-not (Test-Path -LiteralPath $marker)) {
            if (-not $child.HasExited) { Stop-Process -Id $child.Id -Force }
            throw "Recovery-script backup child did not reach crash point: $crashPoint"
        }
        $child.WaitForExit()
        if ($child.ExitCode -ne 78) { throw "Recovery-script backup child did not terminate at $crashPoint." }
        $retryCommand = @'
function Get-Sha256FileHash { param([string]$Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Protect-WeDecentMetadataAcl { param([string]$Path) }
function Test-WeDecentMetadataTrusted { param([string]$Path) return $true }
$RECOVERY_FUNCTIONS$
$script:InstallJournal = [ordered]@{
    recovery_script_had_original = $true
    recovery_script_path = '$TARGET$'
    recovery_script_backup_path = '$BACKUP$'
    recovery_script_original_sha256 = '$EXPECTED$'
}
Publish-TransactionRecoveryScriptBackup
'@
        $retryCommand = $retryCommand.Replace('$RECOVERY_FUNCTIONS$', $recoveryBackupFunctions).Replace('$TARGET$', $targetQ).Replace('$BACKUP$', $backupQ).Replace('$EXPECTED$', $expected)
        $retryEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($retryCommand))
        $retry = Start-Process -FilePath $powerShellExe -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $retryEncoded) -PassThru -Wait -WindowStyle Hidden
        if ($retry.ExitCode -ne 0 -or (Get-TestHash $backup) -ne $expected -or (Get-TestHash $target) -ne $expected) {
            throw "Fresh-process recovery did not complete recovery-script backup after $crashPoint."
        }
    }

    # The exclusive installer lock is held by a live process, then released automatically on process death.
    $lockRoot = Join-Path $env:ProgramData 'WeDecent\install-transactions'
    New-Item -ItemType Directory -Force -Path $lockRoot | Out-Null
    $lockPath = Join-Path $lockRoot 'installer.lock'
    if (Test-Path -LiteralPath $lockPath) { Remove-Item -LiteralPath $lockPath -Force }
    $lockFunction = ($durableFunctions | Where-Object Name -eq 'Acquire-WeDecentInstallerLock')[0].Extent.Text
    $lockMarker = Join-Path $durableTestDir 'lock-owned'
    $lockMarkerQ = $lockMarker.Replace("'", "''")
    $lockChildCommand = @'
function Protect-WeDecentMetadataAcl { param([string]$Path) }
function Test-WeDecentMetadataTrusted { param([string]$Path) return $true }
__LOCK_FUNCTION__
Acquire-WeDecentInstallerLock
[IO.File]::WriteAllText('__LOCK_MARKER__', 'owned')
Start-Sleep -Seconds 60
'@
    $lockChildCommand = $lockChildCommand.Replace('__LOCK_FUNCTION__', $lockFunction).Replace('__LOCK_MARKER__', $lockMarkerQ)
    $lockEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($lockChildCommand))
    $lockChild = Start-Process -FilePath $powerShellExe -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $lockEncoded) -PassThru -WindowStyle Hidden
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath $lockMarker) -and -not $lockChild.HasExited -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100; $lockChild.Refresh() }
    if (-not (Test-Path -LiteralPath $lockMarker)) { if (-not $lockChild.HasExited) { Stop-Process -Id $lockChild.Id -Force }; throw 'Installer lock child process did not acquire the lock.' }
    $lockRejected = $false
    try { Acquire-WeDecentInstallerLock } catch { $lockRejected = $true }
    if (-not $lockRejected) { throw 'Concurrent installer process acquired an already-owned machine-wide lock.' }
    Stop-Process -Id $lockChild.Id -Force
    $lockChild.WaitForExit()
    Acquire-WeDecentInstallerLock
    if ($null -eq $script:InstallerLockStream) { throw 'Installer lock was not reacquired after the owner process terminated.' }
    $script:InstallerLockStream.Dispose()
    $script:InstallerLockStream = $null
    $writerTransactionId = [Guid]::NewGuid().ToString('N')
    $writerJournal = [ordered]@{ transaction_id = $writerTransactionId; phase = 'prepared' }
    $writerJournalPath = Join-Path $journalRoot ($writerTransactionId + '.json')
    Write-InstallJournal -Journal $writerJournal -Path $writerJournalPath
    $writtenJournal = Get-Content -LiteralPath $writerJournalPath -Raw | ConvertFrom-Json
    if ($writtenJournal.transaction_id -ne $writerTransactionId -or $writtenJournal.phase -ne 'prepared') {
        throw 'Production installer journal writer did not persist the explicit transaction path.'
    }
    $defaultWriterId = [Guid]::NewGuid().ToString('N')
    $defaultWriterJournal = [ordered]@{ transaction_id = $defaultWriterId; phase = 'prepared' }
    Write-InstallJournal -Journal $defaultWriterJournal
    $defaultWriterPath = Join-Path $journalRoot ($defaultWriterId + '.json')
    if (-not (Test-Path -LiteralPath $defaultWriterPath -PathType Leaf)) {
        throw 'Production installer journal writer did not derive the canonical transaction path.'
    }
    $rejectedWriterPath = $false
    try { Write-InstallJournal -Journal $writerJournal -Path (Join-Path $root 'outside-transaction.json') } catch { $rejectedWriterPath = $true }
    if (-not $rejectedWriterPath) { throw 'Production installer journal writer accepted a path outside its transaction binding.' }
    $exclusiveWriterId = [Guid]::NewGuid().ToString('N')
    $exclusiveWriterJournal = [ordered]@{ transaction_id = $exclusiveWriterId; phase = 'prepared' }
    Write-InstallJournal -Journal $exclusiveWriterJournal -CreateNew
    $exclusiveReplayRejected = $false
    try { Write-InstallJournal -Journal $exclusiveWriterJournal -CreateNew } catch { $exclusiveReplayRejected = $true }
    if (-not $exclusiveReplayRejected) { throw 'Production journal writer replaced an existing transaction during exclusive creation.' }

    $currentIdentitySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([string]::Equals($currentIdentitySid, $serviceSid, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Isolation test service account must be a different authenticated Windows user from the installer process.'
    }
    $powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Set-TestTrustedAcl -Path $root -ExtraSids @($serviceSid)
    $identityProbeExe = Join-Path $root 'wd-agent-identity-probe.exe'
    & go test -c -o $identityProbeExe ./cmd/wd-agent
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $identityProbeExe -PathType Leaf)) {
        throw 'Could not build the wd-agent process identity probe test binary.'
    }
    Set-TestTrustedAcl -Path $identityProbeExe -ExtraSids @($serviceSid)
    if (-not ('WeDecentIdentityProcess' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class WeDecentIdentityProcess
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags, string applicationName,
        StringBuilder commandLine, uint creationFlags, IntPtr environment, string currentDirectory,
        ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessAsUserW")]
    private static extern bool CreateProcessAsUserW(IntPtr token, string applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
        IntPtr environment, string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
        uint bufferLength, IntPtr previousState, IntPtr returnLength);

    private static void EnablePrivilege(string name)
    {
        IntPtr processToken;
        if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, out processToken)) return;
        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, name, out luid)) return;
            TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES();
            privileges.PrivilegeCount = 1;
            privileges.Privileges.Luid = luid;
            privileges.Privileges.Attributes = 0x2;
            AdjustTokenPrivileges(processToken, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally { CloseHandle(processToken); }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    public static int Run(string user, string domain, string password, string executable, string arguments, string workingDirectory)
    {
        IntPtr token;
        if (!LogonUser(user, domain, password, 2, 0, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "LogonUser failed for the isolated test identity.");

        try
        {
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            PROCESS_INFORMATION process;
            StringBuilder commandLine = new StringBuilder("\"" + executable + "\" " + arguments);
            const uint CREATE_NO_WINDOW = 0x08000000;
            EnablePrivilege("SeImpersonatePrivilege");
            EnablePrivilege("SeIncreaseQuotaPrivilege");
            EnablePrivilege("SeAssignPrimaryTokenPrivilege");
            if (!CreateProcessWithTokenW(token, 0, executable, commandLine, CREATE_NO_WINDOW,
                IntPtr.Zero, workingDirectory, ref startup, out process))
            {
                int tokenError = Marshal.GetLastWin32Error();
                if (!CreateProcessAsUserW(token, executable, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                    CREATE_NO_WINDOW, IntPtr.Zero, workingDirectory, ref startup, out process))
                {
                    int userError = Marshal.GetLastWin32Error();
                    throw new Win32Exception(userError, "CreateProcessWithTokenW failed with " + tokenError +
                        " and CreateProcessAsUserW failed with " + userError + " for the isolated test identity.");
                }
            }

            try
            {
                uint wait = WaitForSingleObject(process.hProcess, 120000);
                if (wait != 0)
                {
                    TerminateProcess(process.hProcess, 124);
                    throw new TimeoutException("Isolated identity process did not exit within 120 seconds.");
                }
                uint exitCode;
                if (!GetExitCodeProcess(process.hProcess, out exitCode))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed for the isolated test identity.");
                return checked((int)exitCode);
            }
            finally
            {
                if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
            }
        }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    public static int RunDifferentSession(string user, string domain, string password,
        string targetExecutable, string targetArguments, string probeExecutable, string probeArguments,
        string workingDirectory, string evidencePath)
    {
        IntPtr firstToken = IntPtr.Zero, secondToken = IntPtr.Zero;
        PROCESS_INFORMATION target = new PROCESS_INFORMATION();
        PROCESS_INFORMATION probe = new PROCESS_INFORMATION();
        try
        {
            if (!LogonUser(user, domain, password, 2, 0, out firstToken))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "First service-account logon failed.");
            if (!LogonUser(user, domain, password, 2, 0, out secondToken))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Second service-account logon failed.");
            EnablePrivilege("SeImpersonatePrivilege");
            EnablePrivilege("SeIncreaseQuotaPrivilege");
            EnablePrivilege("SeAssignPrimaryTokenPrivilege");
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            StringBuilder targetCommand = new StringBuilder("\"" + targetExecutable + "\" " + targetArguments);
            if (!CreateProcessWithTokenW(firstToken, 0, targetExecutable, targetCommand, 0x08000000,
                IntPtr.Zero, workingDirectory, ref startup, out target))
            {
                int tokenError = Marshal.GetLastWin32Error();
                if (!CreateProcessAsUserW(firstToken, targetExecutable, targetCommand, IntPtr.Zero, IntPtr.Zero, false,
                    0x08000000, IntPtr.Zero, workingDirectory, ref startup, out target))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "First-session process creation failed; token error " + tokenError + ".");
            }
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE", "1");
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE_TARGET_PID", target.dwProcessId.ToString());
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE_EXPECTED_IMAGE", targetExecutable);
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE_EVIDENCE", evidencePath);
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE_BOUNDARY", "session");
            StringBuilder probeCommand = new StringBuilder("\"" + probeExecutable + "\" " + probeArguments);
            if (!CreateProcessWithTokenW(secondToken, 0, probeExecutable, probeCommand, 0x08000000,
                IntPtr.Zero, workingDirectory, ref startup, out probe))
            {
                int tokenError = Marshal.GetLastWin32Error();
                if (!CreateProcessAsUserW(secondToken, probeExecutable, probeCommand, IntPtr.Zero, IntPtr.Zero, false,
                    0x08000000, IntPtr.Zero, workingDirectory, ref startup, out probe))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Second-session validator creation failed; token error " + tokenError + ".");
            }
            uint wait = WaitForSingleObject(probe.hProcess, 120000);
            if (wait != 0) throw new TimeoutException("Second-session wd-agent validator timed out.");
            uint exitCode;
            if (!GetExitCodeProcess(probe.hProcess, out exitCode))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not read second-session validator exit code.");
            return checked((int)exitCode);
        }
        finally
        {
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE", null);
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE_TARGET_PID", null);
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE_EXPECTED_IMAGE", null);
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE_EVIDENCE", null);
            Environment.SetEnvironmentVariable("WEDECENT_IDENTITY_PROBE_BOUNDARY", null);
            if (target.hProcess != IntPtr.Zero) { TerminateProcess(target.hProcess, 0); CloseHandle(target.hProcess); }
            if (target.hThread != IntPtr.Zero) CloseHandle(target.hThread);
            if (probe.hProcess != IntPtr.Zero) CloseHandle(probe.hProcess);
            if (probe.hThread != IntPtr.Zero) CloseHandle(probe.hThread);
            if (firstToken != IntPtr.Zero) CloseHandle(firstToken);
            if (secondToken != IntPtr.Zero) CloseHandle(secondToken);
        }
    }
}
'@
    }
    function Invoke-ServiceIdentityIsolationProbe {
        param([string]$EvidencePath, [string]$JournalPath, [string]$ExpectedSid)
        [IO.File]::WriteAllText($EvidencePath, '')
        Set-TestTrustedAcl -Path $EvidencePath -ExtraSids @($ExpectedSid)
        $evidenceLiteral = $EvidencePath.Replace("'", "''")
        $journalLiteral = $JournalPath.Replace("'", "''")
        $sidLiteral = $ExpectedSid.Replace("'", "''")
        $probe = @(
            '$identity = [Security.Principal.WindowsIdentity]::GetCurrent()'
            '$sid = $identity.User.Value'
            '$logonSid = @($identity.Groups | ForEach-Object { $_.Value } | Where-Object { $_ -like ''S-1-5-5-*'' } | Select-Object -First 1)'
            "if (`$sid -ne '$sidLiteral' -or `$logonSid.Count -ne 1) { exit 20 }"
            "[IO.File]::WriteAllText('$evidenceLiteral', (`$sid + '|' + `$logonSid[0]))"
            'try {'
            "    [IO.File]::AppendAllText('$journalLiteral', 'unauthorized mutation')"
            '    exit 0'
            '} catch [UnauthorizedAccessException] {'
            '    exit 42'
            '} catch {'
            '    exit 43'
            '}'
        ) -join [Environment]::NewLine
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
        $processExitCode = [WeDecentIdentityProcess]::Run(
            $serviceAccountName,
            $env:COMPUTERNAME,
            $servicePasswordPlain,
            $powershellExe,
            "-NoProfile -NonInteractive -EncodedCommand $encoded",
            (Join-Path $env:SystemRoot 'System32')
        )
        if ($processExitCode -ne 42) {
            throw "Separate service-identity process did not receive the expected journal ACL denial (exit $processExitCode)."
        }
        $validatorEvidencePath = "$EvidencePath.wd-agent"
        [IO.File]::WriteAllText($validatorEvidencePath, '')
        Set-TestTrustedAcl -Path $validatorEvidencePath -ExtraSids @($serviceSid)
        $env:WEDECENT_IDENTITY_PROBE = '1'
        $env:WEDECENT_IDENTITY_PROBE_TARGET_PID = [string]$PID
        $env:WEDECENT_IDENTITY_PROBE_EXPECTED_IMAGE = (Get-Process -Id $PID).Path
        $env:WEDECENT_IDENTITY_PROBE_EVIDENCE = $validatorEvidencePath
        $env:WEDECENT_IDENTITY_PROBE_BOUNDARY = 'user'
        try {
            $validatorExit = [WeDecentIdentityProcess]::Run(
                $serviceAccountName, $env:COMPUTERNAME, $servicePasswordPlain,
                $identityProbeExe, '-test.run=^TestUpdateProcessIdentityRealProcessProbe$',
                (Join-Path $env:SystemRoot 'System32')
            )
        } finally {
            Remove-Item Env:WEDECENT_IDENTITY_PROBE -ErrorAction SilentlyContinue
            Remove-Item Env:WEDECENT_IDENTITY_PROBE_TARGET_PID -ErrorAction SilentlyContinue
            Remove-Item Env:WEDECENT_IDENTITY_PROBE_EXPECTED_IMAGE -ErrorAction SilentlyContinue
            Remove-Item Env:WEDECENT_IDENTITY_PROBE_EVIDENCE -ErrorAction SilentlyContinue
            Remove-Item Env:WEDECENT_IDENTITY_PROBE_BOUNDARY -ErrorAction SilentlyContinue
        }
        if ($validatorExit -ne 0) {
            throw "The real wd-agent process-identity validator failed (exit $validatorExit)."
        }
        $validatorEvidence = [IO.File]::ReadAllText($validatorEvidencePath)
        if ($validatorEvidence -notmatch '^user\|.*different Windows user or logon session') {
            throw 'The actual wd-agent process validator did not reject a different Windows user.'
        }
        $sessionEvidencePath = "$EvidencePath.session"
        [IO.File]::WriteAllText($sessionEvidencePath, '')
        Set-TestTrustedAcl -Path $sessionEvidencePath -ExtraSids @($serviceSid)
        $sessionExit = [WeDecentIdentityProcess]::RunDifferentSession(
            $serviceAccountName, $env:COMPUTERNAME, $servicePasswordPlain,
            $powershellExe, '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 90"',
            $identityProbeExe, '-test.run=^TestUpdateProcessIdentityRealProcessProbe$',
            (Join-Path $env:SystemRoot 'System32'), $sessionEvidencePath
        )
        if ($sessionExit -ne 0) {
            throw "The real wd-agent validator failed the same-user/different-logon-session probe (exit $sessionExit)."
        }
        $sessionEvidence = [IO.File]::ReadAllText($sessionEvidencePath)
        if ($sessionEvidence -notmatch '^session\|.*different Windows user or logon session') {
            throw 'The actual wd-agent process validator did not reject a distinct logon session for the same SID.'
        }
        $identityParts = [IO.File]::ReadAllText($EvidencePath) -split '\|'
        if ($identityParts.Count -ne 2 -or $identityParts[0] -ne $ExpectedSid -or $identityParts[1] -notmatch '^S-1-5-5-') {
            throw 'Separate process did not report its authenticated user SID and logon-session SID.'
        }
        return $identityParts[1]
    }
    $firstEvidencePath = Join-Path $root 'service-process-identity-1.txt'
    $secondEvidencePath = Join-Path $root 'service-process-identity-2.txt'
    $identityIsolationAvailable = $true
    try {
        $firstLogonSid = Invoke-ServiceIdentityIsolationProbe -EvidencePath $firstEvidencePath -JournalPath $writerJournalPath -ExpectedSid $serviceSid
        $secondLogonSid = Invoke-ServiceIdentityIsolationProbe -EvidencePath $secondEvidencePath -JournalPath $writerJournalPath -ExpectedSid $serviceSid
        if ([string]::Equals($firstLogonSid, $secondLogonSid, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Separate authenticated processes reused the same Windows logon session; cross-session isolation was not demonstrated.'
        }
    } catch [System.ComponentModel.Win32Exception] {
        if ($_.Exception.NativeErrorCode -ne 1314) { throw }
        $identityIsolationAvailable = $false
        Write-Warning 'Cross-user/session process isolation probe skipped: hosted Windows runner lacks the process-token privileges required to create a child under the authenticated service identity. Run this test on the persistent privileged Windows VM.'
    }
    $journalAfterIsolation = Get-Content -LiteralPath $writerJournalPath -Raw | ConvertFrom-Json
    if ($journalAfterIsolation.transaction_id -ne $writerTransactionId -or $journalAfterIsolation.phase -ne 'prepared') {
        throw 'Cross-session journal isolation probe changed the protected journal.'
    }
    if ($identityIsolationAvailable) {
        foreach ($evidencePath in @($firstEvidencePath, $secondEvidencePath)) {
            $identityParts = [IO.File]::ReadAllText($evidencePath) -split '\|'
            if ($identityParts.Count -ne 2 -or $identityParts[0] -ne $serviceSid -or
                $identityParts[1] -notmatch '^S-1-5-5-') {
                throw 'Separate process did not prove authenticated service identity and logon-session identity.'
            }
        }
    }
    $journalAfterIsolation = Get-Content -LiteralPath $writerJournalPath -Raw | ConvertFrom-Json
    if ($journalAfterIsolation.transaction_id -ne $writerTransactionId -or $journalAfterIsolation.phase -ne 'prepared') {
        throw 'Cross-session journal isolation probe changed the protected journal.'
    }

    $recoveryFixtureDir = Join-Path $root 'recovery-script-admission'
    New-Item -ItemType Directory -Force -Path $recoveryFixtureDir | Out-Null
    $savedInstallDir = $InstallDir
    $InstallDir = $recoveryFixtureDir
    $recoveryTarget = Join-Path $recoveryFixtureDir 'Recover-WeDecentInstall.ps1'
    $recoveryTransactionId = [Guid]::NewGuid().ToString('N')
    $recoveryBackup = "${recoveryTarget}.${recoveryTransactionId}.previous"
    $oldRecoveryContent = 'prior trusted recovery script'
    $newRecoveryContent = 'new trusted recovery script'
    [IO.File]::WriteAllText($recoveryTarget, $oldRecoveryContent)
    Copy-Item -LiteralPath $recoveryTarget -Destination $recoveryBackup
    $oldRecoveryHash = Get-TestHash $recoveryTarget
    $recoveryJournal = [ordered]@{
        transaction_id = $recoveryTransactionId
        phase = 'prepared'
        recovery_script_path = [IO.Path]::GetFullPath($recoveryTarget)
        recovery_script_backup_path = [IO.Path]::GetFullPath($recoveryBackup)
        recovery_script_had_original = $true
        recovery_script_original_sha256 = $oldRecoveryHash
        recovery_script_sha256 = $oldRecoveryHash
        recovery_script_state = 'original'
    }
    Assert-TransactionRecoveryScript -Journal $recoveryJournal
    $customJournal = [pscustomobject]$recoveryJournal
    Assert-TransactionRecoveryScript -Journal $customJournal
    $script:recoveryTestAclTrusted = $false
    $rejected = $false
    try { Assert-TransactionRecoveryScript -Journal $recoveryJournal } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery-script admission accepted a recovery file with an untrusted ACL.' }
    $script:recoveryTestAclTrusted = $true
    [IO.File]::WriteAllText($recoveryTarget, $newRecoveryContent)
    $newRecoveryHash = Get-TestHash $recoveryTarget
    $recoveryJournal.recovery_script_sha256 = $newRecoveryHash
    $recoveryJournal.recovery_script_state = 'publishing'
    Assert-TransactionRecoveryScript -Journal $recoveryJournal
    $recoveryJournal.recovery_script_state = 'published'
    Assert-TransactionRecoveryScript -Journal $recoveryJournal

    $recoveryJournal.phase = 'committed'
    [IO.File]::WriteAllText($recoveryTarget, 'later installed recovery script')
    Assert-TransactionRecoveryScript -Journal $recoveryJournal -Committed $true -Historical $true
    $rejected = $false
    try { Assert-TransactionRecoveryScript -Journal $recoveryJournal -Committed $true } catch { $rejected = $true }
    if (-not $rejected) { throw 'Current committed recovery admission accepted a later installation script.' }

    $recoveryJournal.phase = 'rolled-back'
    $recoveryJournal.recovery_script_state = 'original'
    $recoveryJournal.recovery_script_sha256 = $oldRecoveryHash
    Assert-TransactionRecoveryScript -Journal $recoveryJournal -Historical $true
    $rejected = $false
    try { Assert-TransactionRecoveryScript -Journal $recoveryJournal } catch { $rejected = $true }
    if (-not $rejected) { throw 'Rolled-back recovery admission accepted a later installation script as its original.' }
    $recoveryJournal.phase = 'prepared'
    $recoveryJournal.recovery_script_state = 'published'
    $recoveryJournal.recovery_script_sha256 = $newRecoveryHash
    [IO.File]::WriteAllText($recoveryTarget, $newRecoveryContent)
    Assert-TransactionRecoveryScript -Journal $recoveryJournal
    [IO.File]::WriteAllText($recoveryBackup, 'corrupted recovery backup')
    $rejected = $false
    try { Assert-TransactionRecoveryScript -Journal $recoveryJournal } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery-script admission accepted a corrupted transaction backup.' }

    Remove-Item -LiteralPath $recoveryTarget -Force
    Remove-Item -LiteralPath $recoveryBackup -Force
    $freshRecoveryTransactionId = [Guid]::NewGuid().ToString('N')
    $freshRecoveryJournal = [ordered]@{
        transaction_id = $freshRecoveryTransactionId
        phase = 'prepared'
        recovery_script_path = [IO.Path]::GetFullPath($recoveryTarget)
        recovery_script_backup_path = "${recoveryTarget}.${freshRecoveryTransactionId}.previous"
        recovery_script_had_original = $false
        recovery_script_original_sha256 = ''
        recovery_script_sha256 = ''
        recovery_script_state = 'absent'
    }
    Assert-TransactionRecoveryScript -Journal $freshRecoveryJournal
    $freshRecoveryJournal.recovery_script_sha256 = $newRecoveryHash
    $freshRecoveryJournal.recovery_script_state = 'publishing'
    Assert-TransactionRecoveryScript -Journal $freshRecoveryJournal
    [IO.File]::WriteAllText($recoveryTarget, $newRecoveryContent)
    Assert-TransactionRecoveryScript -Journal $freshRecoveryJournal
    $freshRecoveryJournal.recovery_script_state = 'published'
    Assert-TransactionRecoveryScript -Journal $freshRecoveryJournal
    $freshRecoveryJournal.phase = 'rolled-back'
    $freshRecoveryJournal.recovery_script_state = 'absent'
    $freshRecoveryJournal.recovery_script_sha256 = ''
    [IO.File]::WriteAllText($recoveryTarget, 'recovery script from a later install')
    Assert-TransactionRecoveryScript -Journal $freshRecoveryJournal -Historical $true
    $rejected = $false
    try { Assert-TransactionRecoveryScript -Journal $freshRecoveryJournal } catch { $rejected = $true }
    if (-not $rejected) { throw 'Rolled-back fresh-install journal rejected neither a later recovery script nor historical admission.' }
    Remove-Item -LiteralPath $recoveryTarget -Force
    $freshRecoveryJournal.phase = 'prepared'
    $freshRecoveryJournal.recovery_script_state = 'published'
    $freshRecoveryJournal.recovery_script_sha256 = $newRecoveryHash
    [IO.File]::WriteAllText($recoveryTarget, $newRecoveryContent)
    [IO.File]::WriteAllText($freshRecoveryJournal.recovery_script_backup_path, 'unexpected backup')
    $rejected = $false
    try { Assert-TransactionRecoveryScript -Journal $freshRecoveryJournal -Committed $true } catch { $rejected = $true }
    if (-not $rejected) { throw 'Fresh-install recovery-script admission accepted an unexpected backup.' }
    Remove-Item -LiteralPath $freshRecoveryJournal.recovery_script_backup_path -Force

    $legacyJournal = [ordered]@{ phase = 'committed' }
    Assert-TransactionRecoveryScript -Journal $legacyJournal -Committed $true
    $legacyJournal.phase = 'rolled-back'
    Assert-TransactionRecoveryScript -Journal $legacyJournal -Historical $true
    $legacyJournal.phase = 'prepared'
    $rejected = $false
    try { Assert-TransactionRecoveryScript -Journal $legacyJournal } catch { $rejected = $true }
    if (-not $rejected) { throw 'Recovery-script admission accepted an uncommitted legacy journal without authentication fields.' }
    $restoreFunction = $installerAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Restore-TransactionRecoveryScript'
    }, $true)
    if ($restoreFunction.Count -ne 1) { throw 'Could not locate the installer recovery-script rollback helper.' }
    Invoke-Expression $restoreFunction[0].Extent.Text
    $restoreJournalDir = Join-Path $env:ProgramData 'WeDecent\install-transactions'
    New-Item -ItemType Directory -Force -Path $restoreJournalDir | Out-Null
    $restoreTransactionId = [Guid]::NewGuid().ToString('N')
    $restoreOriginalContent = 'original recovery script bytes'
    $restorePublishedContent = 'published recovery script bytes'
    $restoreBackup = "${recoveryTarget}.${restoreTransactionId}.previous"
    [IO.File]::WriteAllText($recoveryTarget, $restorePublishedContent)
    [IO.File]::WriteAllText($restoreBackup, $restoreOriginalContent)
    $restoreJournal = [ordered]@{
        transaction_id = $restoreTransactionId
        phase = 'prepared'
        recovery_script_path = [IO.Path]::GetFullPath($recoveryTarget)
        recovery_script_backup_path = $restoreBackup
        recovery_script_had_original = $true
        recovery_script_original_sha256 = Get-TestHash $restoreBackup
        recovery_script_sha256 = Get-TestHash $recoveryTarget
        recovery_script_state = 'published'
    }
    Set-TestTrustedAcl -Path $restoreBackup
    Restore-TransactionRecoveryScript -Journal $restoreJournal
    $persistedRestoreJournal = Get-Content -LiteralPath (Join-Path $restoreJournalDir ($restoreTransactionId + '.json')) -Raw | ConvertFrom-Json
    if ((Get-TestHash $recoveryTarget) -ne $restoreJournal.recovery_script_original_sha256 -or
        $restoreJournal.recovery_script_state -ne 'original' -or
        $persistedRestoreJournal.recovery_script_state -ne 'original' -or
        (Test-Path -LiteralPath $restoreBackup)) {
        throw 'Installer rollback did not restore, durably journal, and clean the prior recovery script backup.'
    }
    Restore-TransactionRecoveryScript -Journal $restoreJournal
    if ((Get-TestHash $recoveryTarget) -ne $restoreJournal.recovery_script_original_sha256 -or
        (Test-Path -LiteralPath $restoreBackup)) {
        throw 'Repeated installer recovery was not idempotent after recovery-script backup cleanup.'
    }

    # Reconstruct the durable crash state after intent persistence but before deletion.
    $pendingFreshId = [Guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText($recoveryTarget, $restorePublishedContent)
    $pendingFreshJournal = [ordered]@{
        transaction_id = $pendingFreshId
        phase = 'replacing'
        recovery_script_path = [IO.Path]::GetFullPath($recoveryTarget)
        recovery_script_backup_path = ($recoveryTarget + '.' + $pendingFreshId + '.previous')
        recovery_script_had_original = $false
        recovery_script_original_sha256 = ''
        recovery_script_sha256 = Get-TestHash $recoveryTarget
        recovery_script_state = 'removal-pending'
    }
    $pendingFreshJournalPath = Join-Path $restoreJournalDir ($pendingFreshId + '.json')
    Write-InstallJournal -Journal $pendingFreshJournal -Path $pendingFreshJournalPath
    Assert-TransactionRecoveryScript -Journal $pendingFreshJournal
    Restore-TransactionRecoveryScript -Journal $pendingFreshJournal
    $pendingFreshPersisted = Get-Content -LiteralPath $pendingFreshJournalPath -Raw | ConvertFrom-Json
    if ((Test-Path -LiteralPath $recoveryTarget) -or $pendingFreshPersisted.recovery_script_state -ne 'absent') {
        throw 'Recovery did not finish removal after interruption between intent persistence and deletion.'
    }

    # Simulate interruption after the restored journal is durable but before its backup is deleted.
    $retryTransactionId = [Guid]::NewGuid().ToString('N')
    $retryBackup = "$recoveryTarget.$retryTransactionId.previous"
    [IO.File]::WriteAllText($recoveryTarget, $restoreOriginalContent)
    [IO.File]::WriteAllText($retryBackup, $restoreOriginalContent)
    Set-TestTrustedAcl -Path $retryBackup
    $retryJournal = [ordered]@{
        transaction_id = $retryTransactionId
        phase = 'replacing'
        recovery_script_path = [IO.Path]::GetFullPath($recoveryTarget)
        recovery_script_backup_path = $retryBackup
        recovery_script_had_original = $true
        recovery_script_original_sha256 = Get-TestHash $retryBackup
        recovery_script_sha256 = Get-TestHash $recoveryTarget
        recovery_script_state = 'original'
    }
    Write-InstallJournal -Journal $retryJournal -Path (Join-Path $restoreJournalDir ($retryTransactionId + '.json'))
    $retryCrashObserved = $false
    try {
        Restore-TransactionRecoveryScript -Journal $retryJournal -CrashHook {
            param($point)
            if ($point -eq 'after-terminal-journal') { throw 'injected crash after original-state journal publication' }
        }
    } catch { $retryCrashObserved = $true }
    if (-not $retryCrashObserved -or -not (Test-Path -LiteralPath $retryBackup) -or
        (Get-Content -LiteralPath (Join-Path $restoreJournalDir ($retryTransactionId + '.json')) -Raw | ConvertFrom-Json).recovery_script_state -ne 'original') {
        throw 'Crash injection did not preserve the original-state journal and verified backup before cleanup.'
    }
    Restore-TransactionRecoveryScript -Journal $retryJournal
    if ((Test-Path -LiteralPath $retryBackup) -or
        (Get-TestHash $recoveryTarget) -ne $retryJournal.recovery_script_original_sha256) {
        throw 'Interrupted recovery-script backup cleanup did not complete on retry.'
    }
    Restore-TransactionRecoveryScript -Journal $retryJournal
    if (Test-Path -LiteralPath $retryBackup) {
        throw 'Repeated recovery recreated or retained a cleaned transaction-specific backup.'
    }

    $freshRestoreTransactionId = [Guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText($recoveryTarget, $restorePublishedContent)
    $freshRestoreJournal = [ordered]@{
        transaction_id = $freshRestoreTransactionId
        phase = 'prepared'
        recovery_script_path = [IO.Path]::GetFullPath($recoveryTarget)
        recovery_script_backup_path = "${recoveryTarget}.${freshRestoreTransactionId}.previous"
        recovery_script_had_original = $false
        recovery_script_original_sha256 = ''
        recovery_script_sha256 = Get-TestHash $recoveryTarget
        recovery_script_state = 'published'
    }

    # Crash after durable removal intent but before deleting the script.
    $freshIntentCrash = $false
    try {
        Restore-TransactionRecoveryScript -Journal $freshRestoreJournal -CrashHook {
            param($point)
            if ($point -eq 'after-removal-intent') { throw 'injected crash after removal intent' }
        }
    } catch { $freshIntentCrash = $true }
    $freshIntentPersisted = Get-Content -LiteralPath (Join-Path $restoreJournalDir ($freshRestoreTransactionId + '.json')) -Raw | ConvertFrom-Json
    if (-not $freshIntentCrash -or -not (Test-Path -LiteralPath $recoveryTarget) -or
        $freshIntentPersisted.recovery_script_state -ne 'removal-pending' -or
        [string]$freshIntentPersisted.recovery_script_sha256 -notmatch '^[a-f0-9]{64}$') {
        throw 'Removal-intent crash did not preserve a valid published identity before script deletion.'
    }

    # Crash after deleting the script but before committing the absent journal state.
    $freshDeleteCrash = $false
    try {
        Restore-TransactionRecoveryScript -Journal $freshRestoreJournal -CrashHook {
            param($point)
            if ($point -eq 'after-script-delete') { throw 'injected crash after recovery-script deletion' }
        }
    } catch { $freshDeleteCrash = $true }
    $freshDeletePersisted = Get-Content -LiteralPath (Join-Path $restoreJournalDir ($freshRestoreTransactionId + '.json')) -Raw | ConvertFrom-Json
    if (-not $freshDeleteCrash -or (Test-Path -LiteralPath $recoveryTarget) -or
        $freshDeletePersisted.recovery_script_state -ne 'removal-pending' -or
        [string]$freshDeletePersisted.recovery_script_sha256 -notmatch '^[a-f0-9]{64}$') {
        throw 'Script-deletion crash did not preserve a valid retryable removal-pending journal.'
    }

    # Restart recovery must commit absent and remain idempotent on subsequent retries.
    Restore-TransactionRecoveryScript -Journal $freshRestoreJournal
    $persistedFreshRestore = Get-Content -LiteralPath (Join-Path $restoreJournalDir ($freshRestoreTransactionId + '.json')) -Raw | ConvertFrom-Json
    if ((Test-Path -LiteralPath $recoveryTarget) -or
        $freshRestoreJournal.recovery_script_state -ne 'absent' -or
        -not [string]::IsNullOrEmpty([string]$freshRestoreJournal.recovery_script_sha256) -or
        $persistedFreshRestore.recovery_script_state -ne 'absent') {
        throw 'Fresh-install rollback did not remove its script and persist the absent journal state.'
    }
    Restore-TransactionRecoveryScript -Journal $freshRestoreJournal
    $repeatedFreshRestore = Get-Content -LiteralPath (Join-Path $restoreJournalDir ($freshRestoreTransactionId + '.json')) -Raw | ConvertFrom-Json
    if ((Test-Path -LiteralPath $recoveryTarget) -or
        $repeatedFreshRestore.recovery_script_state -ne 'absent' -or
        -not [string]::IsNullOrEmpty([string]$repeatedFreshRestore.recovery_script_sha256)) {
        throw 'Repeated fresh-install recovery changed an already-absent transaction or published an invalid removal intent.'
    }

    # An invalid published digest must fail before any removal intent is written.
    $invalidFreshId = [Guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText($recoveryTarget, $restorePublishedContent)
    $invalidFreshJournal = [ordered]@{
        transaction_id = $invalidFreshId
        phase = 'replacing'
        recovery_script_path = [IO.Path]::GetFullPath($recoveryTarget)
        recovery_script_backup_path = ($recoveryTarget + '.' + $invalidFreshId + '.previous')
        recovery_script_had_original = $false
        recovery_script_original_sha256 = ''
        recovery_script_sha256 = 'invalid-digest'
        recovery_script_state = 'published'
    }
    $invalidFreshJournalPath = Join-Path $restoreJournalDir ($invalidFreshId + '.json')
    Write-InstallJournal -Journal $invalidFreshJournal -Path $invalidFreshJournalPath
    $invalidFreshRejected = $false
    try { Restore-TransactionRecoveryScript -Journal $invalidFreshJournal } catch { $invalidFreshRejected = $true }
    $invalidFreshPersisted = Get-Content -LiteralPath $invalidFreshJournalPath -Raw | ConvertFrom-Json
    if (-not $invalidFreshRejected -or -not (Test-Path -LiteralPath $recoveryTarget) -or
        $invalidFreshPersisted.recovery_script_state -ne 'published' -or
        $invalidFreshPersisted.recovery_script_sha256 -ne 'invalid-digest') {
        throw 'Invalid published digest was allowed to create a removal-pending journal or delete the recovery script.'
    }
    Remove-Item -LiteralPath $recoveryTarget -Force

    $InstallDir = $savedInstallDir

    Write-Host 'Windows transaction recovery and installer metadata helper adversarial tests passed.'
} finally {
    $env:ProgramData = $originalProgramData
    if ($serviceName) { & sc.exe delete $serviceName | Out-Null }
    if ($serviceAccountName) { Remove-LocalUser -Name $serviceAccountName -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue
    $finalizePath = Get-Variable -Name finalizeInstallDir -ValueOnly -ErrorAction SilentlyContinue
    if ($finalizePath) {
        Remove-Item -LiteralPath $finalizePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
