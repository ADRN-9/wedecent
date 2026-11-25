[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repoRoot 'installer/windows/StateMigration.psm1'
$installerPath = Join-Path $repoRoot 'installer/windows/Install-WeDecent.ps1'
$agentPath = Join-Path $repoRoot 'dist/wedecent-windows-amd64/wd-agent.exe'
if (-not (Test-Path -LiteralPath $agentPath -PathType Leaf)) { throw "Missing built Windows agent: $agentPath" }
$installerText = Get-Content -LiteralPath $installerPath -Raw
$migrationCall = $installerText.IndexOf('Invoke-WeDecentStateMigration -Source $recordedStateDir', [StringComparison]::Ordinal)
$binaryInstall = $installerText.IndexOf('Install-Binaries -SourceDirectory $BundlePath', [StringComparison]::Ordinal)
if ($migrationCall -lt 0 -or $binaryInstall -lt 0 -or $migrationCall -ge $binaryInstall) { throw 'Installer does not execute migration before binary replacement.' }
foreach ($required in @('Recover-WeDecentStateMigration','Test-WeDecentMetadataTrusted','Existing SCM command line does not match the authenticated state_dir metadata','Existing service state location is not authenticated by protected installer metadata','Legacy ProgramData service state exists; refusing to create a replacement identity')) {
    if (-not $installerText.Contains($required)) { throw "Installer migration integration is missing guard: $required" }
}
Import-Module $modulePath -Force
$global:WeDecentMigrationMockService = $null
$global:WeDecentMigrationMockStatus = 'Running'
function global:Get-CimInstance {
    [CmdletBinding()]
    param([string]$ClassName, [string]$Filter)
    if ($ClassName -ne 'Win32_Service' -or $null -eq $global:WeDecentMigrationMockService) { throw "Unexpected mocked CIM request: $ClassName" }
    return $global:WeDecentMigrationMockService
}
function global:Get-Service {
    [CmdletBinding()]
    param([string]$Name)
    if ($Name -cne $global:WeDecentMigrationMockService.Name) { throw "Unexpected service lookup: $Name" }
    $result = [pscustomobject]@{ Status = $global:WeDecentMigrationMockStatus }
    $result | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {
        param($Expected, $Timeout)
        if ($this.Status -cne $Expected) { throw "Mock service did not reach $Expected." }
    }
    return $result
}
function global:Stop-Service {
    [CmdletBinding()]
    param([string]$Name, [switch]$Force)
    if ($Name -cne $global:WeDecentMigrationMockService.Name) { throw "Unexpected service stop: $Name" }
    $global:WeDecentMigrationMockStatus = 'Stopped'
    $global:WeDecentMigrationMockService.State = 'Stopped'
}
function global:Start-Service {
    [CmdletBinding()]
    param([string]$Name)
    if ($Name -cne $global:WeDecentMigrationMockService.Name) { throw "Unexpected service start: $Name" }
    $global:WeDecentMigrationMockStatus = 'Running'
    $global:WeDecentMigrationMockService.State = 'Running'
}
function global:sc.exe {
    param([string]$Verb, [string]$Name, [string]$Config)
    if ($Verb -cne 'config' -or $Name -cne $global:WeDecentMigrationMockService.Name -or $Config -notmatch '^binPath= ') {
        $global:LASTEXITCODE = 1
        return 'Unexpected mocked SCM command.'
    }
    $global:WeDecentMigrationMockService.PathName = $Config.Substring('binPath= '.Length)
    $global:LASTEXITCODE = 0
    return 'SUCCESS'
}
function New-MigrationFixture {
    $root = Join-Path $env:ProgramFiles ('WeDecentMigrationCoordinator-' + [Guid]::NewGuid().ToString('N'))
    $source = Join-Path $root 'source-state'
    $destination = Join-Path $root 'destination-state'
    $journal = Join-Path $root 'migration.json'
    $metadataPath = Join-Path $root 'installer.json'
    $serviceName = 'WeDecentMigrationTest'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $serviceSid = $identity.User.Value
    $serviceAccount = $identity.Name
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    Set-WeDecentMigrationAdminDirectory -Path $root -AgentPath $agentPath
    New-Item -ItemType Directory -Path $source | Out-Null
    Set-WeDecentMigrationDirectoryAcl -Path $source -ServiceSid $serviceSid
    New-Item -ItemType Directory -Path (Join-Path $source 'nested') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $source 'empty') | Out-Null
    & $agentPath identity "--state=$source" --name=migration-coordinator-test | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create original migration identity fixture.' }
    [IO.File]::WriteAllText((Join-Path $source 'nested/recovery-authority.token'), 'synthetic-recovery-bytes')
    [IO.File]::WriteAllText((Join-Path $source 'nested/policy.json'), '{"schema":1,"policy":"fixture"}')
    Set-WeDecentMigrationTreeOwner -Path $source -ServiceSid $serviceSid
    $metadata = [ordered]@{ schema=1; product='WeDecent'; version='fixture'; service_name=$serviceName; service_account_name=$serviceAccount; service_account_sid=$serviceSid; managed_service_account=$false; install_dir=$root; state_dir=$source; updated_at=[DateTime]::UtcNow.ToString('o') }
    $originalMetadataJson = ConvertTo-Json -InputObject $metadata -Depth 10
    [IO.File]::WriteAllText($metadataPath, $originalMetadataJson)
    Set-WeDecentMigrationAdminFileAcl -Path $metadataPath
    $originalServicePath = '"' + $agentPath + '" serve "--state=' + $source + '"'
    $global:WeDecentMigrationMockService = [pscustomobject]@{ Name=$serviceName; StartName=$serviceAccount; StartMode='Manual'; State='Running'; PathName=$originalServicePath }
    $global:WeDecentMigrationMockStatus = 'Running'
    $manifest = Get-WeDecentMigrationManifest -Root $source
    return [pscustomobject]@{ Root=$root; Source=$source; Destination=$destination; Journal=$journal; MetadataPath=$metadataPath; ServiceName=$serviceName; ServiceSid=$serviceSid; OriginalServicePath=$originalServicePath; OriginalManifest=(Get-WeDecentMigrationManifestDigest -Manifest $manifest) }
}
function Assert-MigrationRolledBack {
    param([Parameter(Mandatory=$true)]$Fixture, [Parameter(Mandatory=$true)][string]$Fault)
    if (-not (Test-Path -LiteralPath $Fixture.Source -PathType Container)) { throw "Original state disappeared after $Fault." }
    if (Test-Path -LiteralPath $Fixture.Destination) { throw "Destination state remained after $Fault." }
    $manifest = Get-WeDecentMigrationManifest -Root $Fixture.Source
    if ((Get-WeDecentMigrationManifestDigest -Manifest $manifest) -cne $Fixture.OriginalManifest) { throw "Original state changed after $Fault." }
    $metadata = Get-Content -LiteralPath $Fixture.MetadataPath -Raw | ConvertFrom-Json
    if ([IO.Path]::GetFullPath([string]$metadata.state_dir) -ine [IO.Path]::GetFullPath($Fixture.Source)) { throw "Metadata not restored after $Fault." }
    if ($global:WeDecentMigrationMockService.PathName -cne $Fixture.OriginalServicePath) { throw "SCM path not restored after $Fault." }
    if ($global:WeDecentMigrationMockStatus -cne 'Running') { throw "Service not restarted after $Fault." }
    $journal = Read-WeDecentMigrationJournal -Path $Fixture.Journal
    if ($journal.phase -cne 'RolledBack') { throw "Rollback journal phase is $($journal.phase), not RolledBack." }
    if (Test-Path -LiteralPath $journal.staging) { throw "Terminal rollback retained staging after $Fault." }
}
$forwardFaults = @('Prepared','ServiceStopped','Copying','Copied','IdentityVerification','IdentityProtected','Verified','StatePublished','SCMTransition','ServiceReconfigured','MetadataUpdated','ServiceRestarted')
foreach ($fault in $forwardFaults) {
    $fixture = New-MigrationFixture
    try {
        $failed = $false
        try {
            Invoke-WeDecentStateMigration -Source $fixture.Source -Destination $fixture.Destination -AgentPath $agentPath -ServiceName $fixture.ServiceName -ServiceSid $fixture.ServiceSid -MetadataPath $fixture.MetadataPath -JournalPath $fixture.Journal -FaultAt $fault | Out-Null
        } catch {
            $failed = $_.Exception.Message -like "*$fault*"
            if (-not $failed) { throw }
        }
        if (-not $failed) { throw "Coordinator did not inject failure at $fault." }
        Assert-MigrationRolledBack -Fixture $fixture -Fault $fault
        Write-Host "Migration coordinator rollback PASS: $fault"
    } finally {
        Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
$success = New-MigrationFixture
try {
    $result = Invoke-WeDecentStateMigration -Source $success.Source -Destination $success.Destination -AgentPath $agentPath -ServiceName $success.ServiceName -ServiceSid $success.ServiceSid -MetadataPath $success.MetadataPath -JournalPath $success.Journal
    if ($result.phase -cne 'Committed') { throw 'Successful migration did not commit its journal.' }
    if (-not (Test-Path -LiteralPath $success.Source -PathType Container) -or -not (Test-Path -LiteralPath $success.Destination -PathType Container)) { throw 'Migration did not preserve source and publish destination.' }
    if (Test-Path -LiteralPath $result.staging) { throw 'Committed migration retained its staging directory.' }
    $metadata = Get-Content -LiteralPath $success.MetadataPath -Raw | ConvertFrom-Json
    if ([IO.Path]::GetFullPath([string]$metadata.state_dir) -ine [IO.Path]::GetFullPath($success.Destination)) { throw 'Metadata did not commit destination path.' }
    if ($global:WeDecentMigrationMockService.PathName -notlike "*$($success.Destination)*" -or $global:WeDecentMigrationMockStatus -cne 'Running') { throw 'SCM path or service state incorrect after migration.' }
    $sourceIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $agentPath -StatePath $success.Source
    $destinationIdentity = Invoke-WeDecentMigrationIdentityCheck -AgentPath $agentPath -StatePath $success.Destination
    if ($sourceIdentity.DeviceId -cne $destinationIdentity.DeviceId -or $sourceIdentity.Fingerprint -cne $destinationIdentity.Fingerprint) { throw 'Migration changed cryptographic device identity.' }
    Write-Host 'Migration coordinator commit PASS'
} finally {
    Remove-Item -LiteralPath $success.Root -Recurse -Force -ErrorAction SilentlyContinue
}
$recovery = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $recovery.Source -Destination $recovery.Destination -AgentPath $agentPath -ServiceName $recovery.ServiceName -ServiceSid $recovery.ServiceSid -MetadataPath $recovery.MetadataPath -JournalPath $recovery.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Injected rollback interruption did not leave a recoverable journal.' }
    $pending = Read-WeDecentMigrationJournal -Path $recovery.Journal
    if ($pending.phase -cne 'RollingBack' -or -not (Test-Path -LiteralPath $recovery.Destination)) { throw 'Interrupted rollback did not preserve journal and destination.' }
    $global:WeDecentMigrationMockService.State = 'Stopped'
    $global:WeDecentMigrationMockStatus = 'Stopped'
    if (-not (Recover-WeDecentStateMigration -JournalPath $recovery.Journal -AgentPath $agentPath -MetadataPath $recovery.MetadataPath -ServiceName $recovery.ServiceName)) { throw 'Installer recovery did not resume rollback.' }
    Assert-MigrationRolledBack -Fixture $recovery -Fault 'recovery'

$stagingRecovery = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $stagingRecovery.Source -Destination $stagingRecovery.Destination -AgentPath $agentPath -ServiceName $stagingRecovery.ServiceName -ServiceSid $stagingRecovery.ServiceSid -MetadataPath $stagingRecovery.MetadataPath -JournalPath $stagingRecovery.Journal -FaultAt 'Verified,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Interrupted staging rollback did not leave a recoverable journal.' }
    $pending = Read-WeDecentMigrationJournal -Path $stagingRecovery.Journal
    if ($pending.phase -cne 'RollingBack' -or -not (Test-Path -LiteralPath $pending.staging -PathType Container)) {
        throw 'Interrupted rollback did not preserve the staging tree and journal.'
    }
    [void](Assert-WeDecentMigrationPartialTreeSafe -Path $pending.staging -ServiceSid $stagingRecovery.ServiceSid)
    $global:WeDecentMigrationMockService.State = 'Stopped'
    $global:WeDecentMigrationMockStatus = 'Stopped'
    $recoveryInterrupted = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $stagingRecovery.Journal -AgentPath $agentPath -MetadataPath $stagingRecovery.MetadataPath -ServiceName $stagingRecovery.ServiceName -FaultAt 'RollbackStagingValidated')
    } catch {
        $recoveryInterrupted = $_.Exception.Message -like '*RollbackStagingValidated*'
        if (-not $recoveryInterrupted) { throw }
    }
    if (-not $recoveryInterrupted) { throw 'Fault injection did not interrupt rollback while staging existed.' }
    $pending = Read-WeDecentMigrationJournal -Path $stagingRecovery.Journal
    if ($pending.phase -cne 'RollingBack' -or -not (Test-Path -LiteralPath $pending.staging -PathType Container)) {
        throw 'Finally cleanup deleted staging after interrupted rollback.'
    }
    if (-not (Recover-WeDecentStateMigration -JournalPath $stagingRecovery.Journal -AgentPath $agentPath -MetadataPath $stagingRecovery.MetadataPath -ServiceName $stagingRecovery.ServiceName)) {
        throw 'Repeated recovery did not resume pending staging rollback.'
    }
    Assert-MigrationRolledBack -Fixture $stagingRecovery -Fault 'staging recovery'
    if (Recover-WeDecentStateMigration -JournalPath $stagingRecovery.Journal -AgentPath $agentPath -MetadataPath $stagingRecovery.MetadataPath -ServiceName $stagingRecovery.ServiceName) {
        throw 'Repeated recovery was not idempotent after terminal rollback.'
    }
    if (Test-Path -LiteralPath $pending.staging) { throw 'Validated terminal rollback left staging behind.' }
    Write-Host 'Migration coordinator interrupted staging rollback and repeated recovery PASS'
} finally {
    Remove-Item -LiteralPath $stagingRecovery.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$partialOwnerRoot = Join-Path $env:ProgramFiles ('WeDecentPartialOwner-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $partialOwnerRoot -Force | Out-Null
    Set-WeDecentMigrationAdminDirectory -Path $partialOwnerRoot -AgentPath $agentPath
    $partialOwnerTree = Join-Path $partialOwnerRoot '.wedecent-migration-owner-test'
    New-Item -ItemType Directory -Path $partialOwnerTree | Out-Null
    Set-WeDecentMigrationDirectoryAcl -Path $partialOwnerTree -ServiceSid 'S-1-5-19'
    $childDirectory = Join-Path $partialOwnerTree 'partial-child'
    New-Item -ItemType Directory -Path $childDirectory | Out-Null
    $installerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $childAcl = Get-Acl -LiteralPath $childDirectory
    $childAcl.SetOwner([Security.Principal.SecurityIdentifier]::new($installerSid))
    Set-Acl -LiteralPath $childDirectory -AclObject $childAcl
    [IO.File]::WriteAllText((Join-Path $childDirectory 'partial.bin'), 'partial')
    $fileAcl = Get-Acl -LiteralPath (Join-Path $childDirectory 'partial.bin')
    $fileAcl.SetOwner([Security.Principal.SecurityIdentifier]::new($installerSid))
    Set-Acl -LiteralPath (Join-Path $childDirectory 'partial.bin') -AclObject $fileAcl
    [void](Assert-WeDecentMigrationPartialTreeSafe -Path $partialOwnerTree -ServiceSid 'S-1-5-19' -InstallerSid $installerSid)
    $rejectedUnrecordedOwner = $false
    try {
        [void](Assert-WeDecentMigrationPartialTreeSafe -Path $partialOwnerTree -ServiceSid 'S-1-5-19')
    } catch {
        $rejectedUnrecordedOwner = $true
    }
    if (-not $rejectedUnrecordedOwner) { throw 'Partial-tree validator accepted an installer owner absent from its trusted owner set.' }
    Write-Host 'Migration coordinator authenticated installer-owner partial-tree validation PASS'
} finally {
    Remove-Item -LiteralPath $partialOwnerRoot -Recurse -Force -ErrorAction SilentlyContinue
}
$partialStagingRecovery = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $partialStagingRecovery.Source -Destination $partialStagingRecovery.Destination -AgentPath $agentPath -ServiceName $partialStagingRecovery.ServiceName -ServiceSid $partialStagingRecovery.ServiceSid -MetadataPath $partialStagingRecovery.MetadataPath -JournalPath $partialStagingRecovery.Journal -FaultAt 'StagingEntryCopied,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Partial-copy interruption did not leave a pending rollback.' }
    $pending = Read-WeDecentMigrationJournal -Path $partialStagingRecovery.Journal
    if ($pending.phase -cne 'RollingBack' -or -not (Test-Path -LiteralPath $pending.staging -PathType Container)) {
        throw 'Partial staging tree was not preserved with its recovery journal.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$pending.source_manifest_sha256) -or [bool]$pending.staging_complete) {
        throw 'Partial staging journal did not preserve the authenticated source snapshot and incomplete-staging marker.'
    }
    [void](Assert-WeDecentMigrationPartialTreeSafe -Path $pending.staging -ServiceSid $partialStagingRecovery.ServiceSid -InstallerSid $pending.installer_sid)
    $global:WeDecentMigrationMockService.State = 'Stopped'
    $global:WeDecentMigrationMockStatus = 'Stopped'
    $childScript = Join-Path $partialStagingRecovery.Root 'recover-in-new-process.ps1'
    $childBody = @'
[CmdletBinding()]
param([string]$ModulePath, [string]$JournalPath, [string]$AgentPath, [string]$MetadataPath, [string]$ServiceName)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
$journal = Read-WeDecentMigrationJournal -Path $JournalPath
$global:MigrationChildService = [pscustomobject]@{
    Name = $journal.service_name
    StartName = $journal.service_start_name
    StartMode = $journal.service_start_mode
    State = 'Stopped'
    PathName = $journal.original_service_path
}
$global:MigrationChildStatus = 'Stopped'
function global:Get-CimInstance {
    param([string]$ClassName, [string]$Filter)
    if ($ClassName -ne 'Win32_Service') { throw "Unexpected CIM class: $ClassName" }
    return $global:MigrationChildService
}
function global:Get-Service {
    param([string]$Name)
    if ($Name -cne $global:MigrationChildService.Name) { throw "Unexpected service: $Name" }
    $result = [pscustomobject]@{ Status = $global:MigrationChildStatus }
    $result | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {
        param($Expected, $Timeout)
        if ($global:MigrationChildStatus -cne $Expected) { throw "Mock service did not reach $Expected." }
        $this.Status = $Expected
    }
    return $result
}
function global:Stop-Service {
    param([string]$Name, [switch]$Force)
    $global:MigrationChildStatus = 'Stopped'
    $global:MigrationChildService.State = 'Stopped'
}
function global:Start-Service {
    param([string]$Name)
    $global:MigrationChildStatus = 'Running'
    $global:MigrationChildService.State = 'Running'
}
function global:sc.exe {
    param([string]$Verb, [string]$Name, [string]$Config)
    if ($Verb -cne 'config' -or $Name -cne $global:MigrationChildService.Name -or $Config -notmatch '^binPath= ') {
        $global:LASTEXITCODE = 1
        return 'Unexpected mocked SCM command.'
    }
    $global:MigrationChildService.PathName = $Config.Substring('binPath= '.Length)
    $global:LASTEXITCODE = 0
    return 'SUCCESS'
}
if (-not (Recover-WeDecentStateMigration -JournalPath $JournalPath -AgentPath $AgentPath -MetadataPath $MetadataPath -ServiceName $ServiceName)) {
    throw 'Fresh-process recovery did not resume the pending transaction.'
}
$terminal = Read-WeDecentMigrationJournal -Path $JournalPath
if ($terminal.phase -cne 'RolledBack') { throw "Fresh-process recovery ended in $($terminal.phase)." }
'@
    [IO.File]::WriteAllText($childScript, $childBody)
    $child = [Diagnostics.ProcessStartInfo]::new()
    $child.FileName = (Join-Path $PSHOME 'pwsh.exe')
    $child.UseShellExecute = $false
    $child.RedirectStandardOutput = $true
    $child.RedirectStandardError = $true
    foreach ($argument in @('-NoProfile','-File',$childScript,'-ModulePath',$modulePath,'-JournalPath',$partialStagingRecovery.Journal,'-AgentPath',$agentPath,'-MetadataPath',$partialStagingRecovery.MetadataPath,'-ServiceName',$partialStagingRecovery.ServiceName)) {
        [void]$child.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($child)
    try {
        $childOutput = $process.StandardOutput.ReadToEnd()
        $childError = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "Fresh-process migration recovery failed: $childError $childOutput" }
    } finally {
        $process.Dispose()
    }
    # Reflect the child process's successful mocked SCM transition in the parent assertions.
    $global:WeDecentMigrationMockStatus = 'Running'
    $global:WeDecentMigrationMockService.State = 'Running'
    Assert-MigrationRolledBack -Fixture $partialStagingRecovery -Fault 'partial staging recovery'
    if (Recover-WeDecentStateMigration -JournalPath $partialStagingRecovery.Journal -AgentPath $agentPath -MetadataPath $partialStagingRecovery.MetadataPath -ServiceName $partialStagingRecovery.ServiceName) {
        throw 'Recovery after fresh-process completion was not idempotent.'
    }
    Write-Host 'Migration coordinator partial-copy rollback recovery in fresh process PASS'
} finally {
    Remove-Item -LiteralPath $partialStagingRecovery.Root -Recurse -Force -ErrorAction SilentlyContinue
}
    Write-Host 'Migration coordinator durable recovery PASS'

$canonicalRoot = Get-WeDecentMigrationCanonicalPath -Path 'C:\'
if ($canonicalRoot -cne 'C:\') { throw "Drive-root canonicalization changed: $canonicalRoot" }
$normalized = Get-WeDecentMigrationCanonicalPath -Path 'C:\ProgramData\WeDecent\legacy\..\agent\'
if ($normalized -cne 'C:\ProgramData\WeDecent\agent') { throw "Windows dot-segment normalization failed: $normalized" }
foreach ($pair in @(
    @('C:\ProgramData\WeDecent', 'c:\programdata\wedecent\agent'),
    @('C:\ProgramData\WeDecent\agent', 'C:\ProgramData\WeDecent')
)) {
    $rejected = $false
    try { [void](Assert-WeDecentMigrationPathsDisjoint -Paths $pair) }
    catch { $rejected = $_.Exception.Message -like '*overlap or alias*'; if (-not $rejected) { throw } }
    if (-not $rejected) { throw "Migration path overlap was accepted: $($pair -join ' <> ')" }
}
[void](Assert-WeDecentMigrationPathsDisjoint -Paths @('C:\ProgramData\WeDecent\agent', 'C:\Program Files\WeDecent\data\agent'))
Write-Host 'Migration coordinator Windows path normalization and overlap validators PASS'

$pathFixture = New-MigrationFixture
try {
    $overlapDestination = Join-Path $pathFixture.Source 'nested/destination'
    $rejectedOverlap = $false
    try {
        Invoke-WeDecentStateMigration -Source $pathFixture.Source -Destination $overlapDestination -AgentPath $agentPath -ServiceName $pathFixture.ServiceName -ServiceSid $pathFixture.ServiceSid -MetadataPath $pathFixture.MetadataPath -JournalPath $pathFixture.Journal | Out-Null
    } catch {
        $rejectedOverlap = $_.Exception.Message -like '*overlap or alias*'
        if (-not $rejectedOverlap) { throw }
    }
    if (-not $rejectedOverlap) { throw 'Migration accepted a destination nested beneath its source.' }
    if (Test-Path -LiteralPath $pathFixture.Journal) { throw 'Path-overlap rejection created a migration journal.' }
    Write-Host 'Migration coordinator source/destination overlap rejection PASS'
} finally {
    Remove-Item -LiteralPath $pathFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$mutatedSource = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $mutatedSource.Source -Destination $mutatedSource.Destination -AgentPath $agentPath -ServiceName $mutatedSource.ServiceName -ServiceSid $mutatedSource.ServiceSid -MetadataPath $mutatedSource.MetadataPath -JournalPath $mutatedSource.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Source mutation fixture did not stop at the pending rollback boundary.' }
    [IO.File]::WriteAllText((Join-Path $mutatedSource.Source 'nested/policy.json'), '{"schema":1,"policy":"attacker-mutated"}')
    $rejectedMutation = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $mutatedSource.Journal -AgentPath $agentPath -MetadataPath $mutatedSource.MetadataPath -ServiceName $mutatedSource.ServiceName)
    } catch {
        $rejectedMutation = $_.Exception.Message -like '*source manifest changed*'
        if (-not $rejectedMutation) { throw }
    }
    if (-not $rejectedMutation) { throw 'Recovery accepted a mutated original source tree.' }
    if ($global:WeDecentMigrationMockService.PathName -cne $mutatedSource.OriginalServicePath) { throw 'Recovery changed SCM before authenticating the original source.' }
    if ($global:WeDecentMigrationMockStatus -cne 'Stopped') { throw 'Recovery restarted the service after source integrity failure.' }
    Write-Host 'Migration coordinator mutated-source recovery fail-closed PASS'
} finally {
    Remove-Item -LiteralPath $mutatedSource.Root -Recurse -Force -ErrorAction SilentlyContinue
}

} finally {
    Remove-Item -LiteralPath $recovery.Root -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'Windows state migration coordinator integration PASS'
