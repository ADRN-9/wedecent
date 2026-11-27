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
        [bool]$Committed = $false
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
    $journal = [ordered]@{
        schema = 1
        transaction_id = $Id
        package_sha256 = $packageDigest
        manifest_sha256 = $manifestDigest
        previous_version = $previousVersion
        sequence = $sequence
        service_was_running = $false
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
        service_name = $serviceName
        service_account_sid = $serviceSid
        install_dir = $installDir
        state_dir = $stateDir
    })

    $successful = New-TransactionFixture
    Invoke-TestRecovery -Fixture $successful | Out-Null
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

    $committed = New-TransactionFixture -Committed $true
    Invoke-TestRecovery -Fixture $committed | Out-Null
    $committedJournal = Get-Content -LiteralPath $committed.journalPath -Raw | ConvertFrom-Json
    if ($committedJournal.phase -ne 'committed') { throw 'Recovery did not recognize a committed sequence.' }
    foreach ($entry in $committed.journal.entries) {
        if ((Get-TestHash $entry.destination) -ne $entry.replacement_sha256) {
            throw "Committed recovery replaced a target binary: $($entry.name)"
        }
    }

    Write-Host 'Windows transaction recovery synthetic adversarial tests passed.'
} finally {
    $env:ProgramData = $originalProgramData
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue
}
