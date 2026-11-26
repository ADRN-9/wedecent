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
$namespaceFixture = New-MigrationFixture
try {
    $namespaceAcl = Get-Acl -LiteralPath $namespaceFixture.Root
    $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $usersWrite = [Security.AccessControl.FileSystemAccessRule]::new(
        $usersSid,
        [Security.AccessControl.FileSystemRights]::Modify,
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$namespaceAcl.AddAccessRule($usersWrite)
    Set-Acl -LiteralPath $namespaceFixture.Root -AclObject $namespaceAcl -ErrorAction Stop
    $rejected = $false
    try { [void](Assert-WeDecentMigrationPublicationNamespace -Path $namespaceFixture.Root) }
    catch {
        $rejected = $_.Exception.Message -like '*untrusted principal*'
        if (-not $rejected) { throw }
    }
    if (-not $rejected) { throw 'Migration publication namespace accepted untrusted Users write access.' }
    Write-Host 'Migration protected publication namespace rejects untrusted writer PASS'
} finally {
    Remove-Item -LiteralPath $namespaceFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not ('WeDecentMigrationTestLogon' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public static class WeDecentMigrationTestLogon {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="LogonUserW")]
    private static extern bool LogonUserNative(string user, string domain, string password, int logonType, int logonProvider, out SafeAccessTokenHandle token);
    public static void RunAs(string user, string domain, SecureString securePassword, Action action) {
        IntPtr passwordBuffer=Marshal.SecureStringToBSTR(securePassword);
        try {
            string password=Marshal.PtrToStringBSTR(passwordBuffer);
            SafeAccessTokenHandle token;
            if (!LogonUserNative(user,domain,password,2,0,out token))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"LogonUser failed for unprivileged migration test identity.");
            using (token) { WindowsIdentity.RunImpersonated(token,action); }
        } finally { Marshal.ZeroFreeBSTR(passwordBuffer); }
    }
}
'@
}

function Invoke-MigrationUntrustedMutationAttempt {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$BackupPath
    )
    $global:WeDecentMigrationAttackTarget = $TargetPath
    $global:WeDecentMigrationAttackBackup = $BackupPath
    $global:WeDecentMigrationAttackMoveError = 0
    $global:WeDecentMigrationAttackWriteError = 0
    $global:WeDecentMigrationAttackObservedSid = $null
    [WeDecentMigrationTestLogon]::RunAs(
        $global:WeDecentMigrationAttackerName,
        $env:COMPUTERNAME,
        $global:WeDecentMigrationAttackerPassword,
        [Action] {
            $global:WeDecentMigrationAttackObservedSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            try { [IO.File]::Move($global:WeDecentMigrationAttackTarget,$global:WeDecentMigrationAttackBackup) }
            catch { $global:WeDecentMigrationAttackMoveError = $_.Exception.HResult }
            try { [IO.File]::WriteAllText($global:WeDecentMigrationAttackTarget,'attacker') }
            catch { $global:WeDecentMigrationAttackWriteError = $_.Exception.HResult }
        }
    )
    if ($global:WeDecentMigrationAttackObservedSid -cne $global:WeDecentMigrationAttackerSid) {
        throw "Native publication attack did not execute under the distinct unprivileged account (observed=$global:WeDecentMigrationAttackObservedSid expected=$global:WeDecentMigrationAttackerSid)."
    }
    $denied = @(-2147024891, -2147024864)
    if ($global:WeDecentMigrationAttackMoveError -in $denied -and
        $global:WeDecentMigrationAttackWriteError -in $denied) { return $true }
    throw "Unprivileged publication mutation was not denied (move=$($global:WeDecentMigrationAttackMoveError), write=$($global:WeDecentMigrationAttackWriteError))."
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
$overlapCases = @(
    [pscustomobject]@{ Paths = @('C:\ProgramData\WeDecent', 'c:\programdata\wedecent\agent') },
    [pscustomobject]@{ Paths = @('C:\ProgramData\WeDecent\agent', 'C:\ProgramData\WeDecent') }
)
foreach ($case in $overlapCases) {
    $rejected = $false
    try { [void](Assert-WeDecentMigrationPathsDisjoint -Paths $case.Paths) }
    catch { $rejected = $_.Exception.Message -like '*overlap or alias*'; if (-not $rejected) { throw } }
    if (-not $rejected) { throw "Migration path overlap was accepted: $($case.Paths -join ' <> ')" }
}
[void](Assert-WeDecentMigrationPathsDisjoint -Paths @('C:\ProgramData\WeDecent\agent', 'C:\Program Files\WeDecent\data\agent'))
$aliasRoot = Join-Path $env:TEMP ('WeDecent Migration Alias Directory.extension-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $aliasRoot -Force | Out-Null
$shortBuffer = [Text.StringBuilder]::new(32768)
$shortLength = [WeDecentMigrationPathApi]::GetShortPathName($aliasRoot, $shortBuffer, [uint32]$shortBuffer.Capacity)
if ($shortLength -eq 0 -or $shortLength -ge $shortBuffer.Capacity) {
    throw 'Could not obtain an actual Windows 8.3 alias for the migration path regression.'
}
$shortAlias = $shortBuffer.ToString()
$shortLeaf = [IO.Path]::GetFileName($shortAlias)
if ($shortLeaf -notmatch '(?i)~[0-9]+\.[^\\]+$') {
    throw "Windows test volume did not produce the required extension-bearing 8.3 alias: $shortAlias"
}
$longCanonical = Get-WeDecentMigrationCanonicalPath -Path $aliasRoot
$shortCanonical = Get-WeDecentMigrationCanonicalPath -Path $shortAlias
if (-not [string]::Equals($longCanonical, $shortCanonical, [StringComparison]::OrdinalIgnoreCase)) {
    throw "8.3 alias did not resolve to the actual long filesystem path: '$shortAlias' => '$shortCanonical' (expected '$longCanonical')."
}
$aliasCollisionRejected = $false
try { [void](Assert-WeDecentMigrationPathsDisjoint -Paths @($shortAlias, $aliasRoot)) }
catch { $aliasCollisionRejected = $_.Exception.Message -like '*overlap or alias*'; if (-not $aliasCollisionRejected) { throw } }
if (-not $aliasCollisionRejected) { throw 'Migration accepted a short-name alias as a distinct path.' }
Remove-Item -LiteralPath $aliasRoot -Force -ErrorAction Stop

$substitutionRoot = Join-Path $env:TEMP ('WeDecent Migration Object Substitution-' + [Guid]::NewGuid().ToString('N'))
$substitutionPath = Join-Path $substitutionRoot 'anchor'
$renamedPath = Join-Path $substitutionRoot 'original-object'
try {
    New-Item -ItemType Directory -Path $substitutionPath -Force | Out-Null
    $substitutionSnapshot = Get-WeDecentMigrationIdentitySnapshot -Paths @($substitutionPath)
    [IO.Directory]::Move($substitutionPath, $renamedPath)
    [IO.Directory]::CreateDirectory($substitutionPath) | Out-Null
    $substitutionRejected = $false
    try {
        Assert-WeDecentMigrationIdentitySnapshot -Snapshot $substitutionSnapshot -Paths @($substitutionPath)
    } catch {
        $substitutionRejected = $_.Exception.Message -like '*filesystem object changed*'
        if (-not $substitutionRejected) { throw }
    }
    if (-not $substitutionRejected) { throw 'Migration identity snapshot accepted a substituted directory at the same pathname.' }
    Write-Host 'Migration coordinator native volume/file-ID substitution rejection PASS'
} finally {
    Remove-Item -LiteralPath $substitutionRoot -Recurse -Force -ErrorAction SilentlyContinue
}
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

$aclMutatedSource = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $aclMutatedSource.Source -Destination $aclMutatedSource.Destination -AgentPath $agentPath -ServiceName $aclMutatedSource.ServiceName -ServiceSid $aclMutatedSource.ServiceSid -MetadataPath $aclMutatedSource.MetadataPath -JournalPath $aclMutatedSource.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'ACL mutation fixture did not stop at the pending rollback boundary.' }
    $acl = Get-Acl -LiteralPath $aclMutatedSource.Source
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $users, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $aclMutatedSource.Source -AclObject $acl -ErrorAction Stop
    $rejectedAcl = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $aclMutatedSource.Journal -AgentPath $agentPath -MetadataPath $aclMutatedSource.MetadataPath -ServiceName $aclMutatedSource.ServiceName)
    } catch {
        $rejectedAcl = $_.Exception.Message -like '*Protected state path verification failed*' -or
            $_.Exception.Message -like '*DACL*'
        if (-not $rejectedAcl) { throw }
    }
    if (-not $rejectedAcl) { throw 'Recovery accepted an original source with a broadened DACL.' }
    if ($global:WeDecentMigrationMockService.PathName -cne $aclMutatedSource.OriginalServicePath) { throw 'Recovery changed SCM before authenticating the source ACL.' }
    if ($global:WeDecentMigrationMockStatus -cne 'Stopped') { throw 'Recovery restarted the service after source ACL failure.' }
    Write-Host 'Migration coordinator mutated-source ACL recovery fail-closed PASS'
} finally {
    Remove-Item -LiteralPath $aclMutatedSource.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$nestedFileAcl = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $nestedFileAcl.Source -Destination $nestedFileAcl.Destination -AgentPath $agentPath -ServiceName $nestedFileAcl.ServiceName -ServiceSid $nestedFileAcl.ServiceSid -MetadataPath $nestedFileAcl.MetadataPath -JournalPath $nestedFileAcl.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Nested ACL fixture did not stop at the pending rollback boundary.' }
    $nestedFile = Join-Path $nestedFileAcl.Source 'nested/policy.json'
    $output = & icacls.exe $nestedFile '/grant' '*S-1-5-32-545:(F)' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not broaden nested file ACL for regression: $($output -join ' ')" }
    $fileRules = (Get-Acl -LiteralPath $nestedFile).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $usersRules = @($fileRules | Where-Object {
        $_.IdentityReference.Value -ceq 'S-1-5-32-545' -and
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $_.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl
    })
    if ($usersRules.Count -eq 0) { throw 'Nested file ACL mutation did not create the expected Users FullControl ACE.' }
    $treePaths = @($nestedFileAcl.Source) + @(Get-ChildItem -LiteralPath $nestedFileAcl.Source -Force -Recurse | ForEach-Object FullName)
    if ($nestedFile -notin $treePaths) { throw 'Recursive ACL test enumeration omitted the nested file.' }
    $directFileAclRejected = $false
    try { [void](Assert-WeDecentMigrationTreeAcl -Path $nestedFileAcl.Source -ServiceSid $nestedFileAcl.ServiceSid) }
    catch { $directFileAclRejected = $_.Exception.Message -like '*unexpected access rule*'; if (-not $directFileAclRejected) { throw } }
    if (-not $directFileAclRejected) { throw 'Recursive ACL validator accepted the broadened nested file DACL.' }
    $rejectedNestedFileAcl = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $nestedFileAcl.Journal -AgentPath $agentPath -MetadataPath $nestedFileAcl.MetadataPath -ServiceName $nestedFileAcl.ServiceName)
    } catch {
        $rejectedNestedFileAcl = $_.Exception.Message -like '*unexpected access rule*'
        if (-not $rejectedNestedFileAcl) { throw }
    }
    if (-not $rejectedNestedFileAcl) { throw 'Recovery accepted a broadened nested file DACL.' }
    if ($global:WeDecentMigrationMockService.PathName -cne $nestedFileAcl.OriginalServicePath) { throw 'Nested file ACL rejection changed SCM configuration.' }
    if ($global:WeDecentMigrationMockStatus -cne 'Stopped') { throw 'Nested file ACL rejection did not leave the service stopped.' }
    Write-Host 'Migration coordinator nested file ACL recovery rejection PASS'
} finally {
    Remove-Item -LiteralPath $nestedFileAcl.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$nestedDirectoryAcl = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $nestedDirectoryAcl.Source -Destination $nestedDirectoryAcl.Destination -AgentPath $agentPath -ServiceName $nestedDirectoryAcl.ServiceName -ServiceSid $nestedDirectoryAcl.ServiceSid -MetadataPath $nestedDirectoryAcl.MetadataPath -JournalPath $nestedDirectoryAcl.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Nested ACL fixture did not stop at the pending rollback boundary.' }
    $nestedDirectory = Join-Path $nestedDirectoryAcl.Source 'nested'
    $output = & icacls.exe $nestedDirectory '/grant' '*S-1-5-32-545:(F)' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not broaden nested directory ACL for regression: $($output -join ' ')" }
    $directoryRules = (Get-Acl -LiteralPath $nestedDirectory).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $directoryUsersRules = @($directoryRules | Where-Object {
        $_.IdentityReference.Value -ceq 'S-1-5-32-545' -and
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $_.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl
    })
    if ($directoryUsersRules.Count -eq 0) { throw 'Nested directory ACL mutation did not create the expected Users FullControl ACE.' }
    $directDirectoryAclRejected = $false
    try { [void](Assert-WeDecentMigrationTreeAcl -Path $nestedDirectoryAcl.Source -ServiceSid $nestedDirectoryAcl.ServiceSid) }
    catch { $directDirectoryAclRejected = $_.Exception.Message -like '*unexpected access rule*'; if (-not $directDirectoryAclRejected) { throw } }
    if (-not $directDirectoryAclRejected) { throw 'Recursive ACL validator accepted the broadened nested directory DACL.' }
    $rejectedNestedDirectoryAcl = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $nestedDirectoryAcl.Journal -AgentPath $agentPath -MetadataPath $nestedDirectoryAcl.MetadataPath -ServiceName $nestedDirectoryAcl.ServiceName)
    } catch {
        $rejectedNestedDirectoryAcl = $_.Exception.Message -like '*unexpected access rule*'
        if (-not $rejectedNestedDirectoryAcl) { throw }
    }
    if (-not $rejectedNestedDirectoryAcl) { throw 'Recovery accepted a broadened nested directory DACL.' }
    if ($global:WeDecentMigrationMockService.PathName -cne $nestedDirectoryAcl.OriginalServicePath) { throw 'Nested directory ACL rejection changed SCM configuration.' }
    if ($global:WeDecentMigrationMockStatus -cne 'Stopped') { throw 'Nested directory ACL rejection did not leave the service stopped.' }
    Write-Host 'Migration coordinator nested directory ACL recovery rejection PASS'
} finally {
    Remove-Item -LiteralPath $nestedDirectoryAcl.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$nestedDirectoryOwner = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $nestedDirectoryOwner.Source -Destination $nestedDirectoryOwner.Destination -AgentPath $agentPath -ServiceName $nestedDirectoryOwner.ServiceName -ServiceSid $nestedDirectoryOwner.ServiceSid -MetadataPath $nestedDirectoryOwner.MetadataPath -JournalPath $nestedDirectoryOwner.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Nested ACL fixture did not stop at the pending rollback boundary.' }
    $nestedDirectory = Join-Path $nestedDirectoryOwner.Source 'nested'
    $output = & icacls.exe $nestedDirectory '/setowner' '*S-1-5-32-545' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not mutate nested directory owner for regression: $($output -join ' ')" }
    $nestedOwner = (Get-Acl -LiteralPath $nestedDirectory).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($nestedOwner -cne 'S-1-5-32-545') { throw "Nested directory owner mutation did not take effect: $nestedOwner" }
    $rejectedNestedOwner = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $nestedDirectoryOwner.Journal -AgentPath $agentPath -MetadataPath $nestedDirectoryOwner.MetadataPath -ServiceName $nestedDirectoryOwner.ServiceName)
    } catch {
        $rejectedNestedOwner = $_.Exception.Message -like '*unexpected owner SID*'
        if (-not $rejectedNestedOwner) { throw }
    }
    if (-not $rejectedNestedOwner) { throw 'Recovery accepted a nested directory owner substitution.' }
    if ($global:WeDecentMigrationMockService.PathName -cne $nestedDirectoryOwner.OriginalServicePath) { throw 'Nested directory owner rejection changed SCM configuration.' }
    if ($global:WeDecentMigrationMockStatus -cne 'Stopped') { throw 'Nested directory owner rejection did not leave the service stopped.' }
    Write-Host 'Migration coordinator nested directory owner recovery rejection PASS'
} finally {
    Remove-Item -LiteralPath $nestedDirectoryOwner.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$nestedFileOwner = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $nestedFileOwner.Source -Destination $nestedFileOwner.Destination -AgentPath $agentPath -ServiceName $nestedFileOwner.ServiceName -ServiceSid $nestedFileOwner.ServiceSid -MetadataPath $nestedFileOwner.MetadataPath -JournalPath $nestedFileOwner.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Nested file owner fixture did not stop at the pending rollback boundary.' }
    $nestedFile = Join-Path $nestedFileOwner.Source 'nested/policy.json'
    $output = & icacls.exe $nestedFile '/setowner' '*S-1-5-32-545' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not substitute nested file owner for regression: $($output -join ' ')" }
    $nestedOwner = (Get-Acl -LiteralPath $nestedFile).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($nestedOwner -cne 'S-1-5-32-545') { throw "Nested file owner substitution did not take effect: $nestedOwner" }
    $rejectedNestedFileOwner = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $nestedFileOwner.Journal -AgentPath $agentPath -MetadataPath $nestedFileOwner.MetadataPath -ServiceName $nestedFileOwner.ServiceName)
    } catch {
        $rejectedNestedFileOwner = $_.Exception.Message -like '*unexpected owner SID*'
        if (-not $rejectedNestedFileOwner) { throw }
    }
    if (-not $rejectedNestedFileOwner) { throw 'Recovery accepted a nested file owner substitution.' }
    if ($global:WeDecentMigrationMockService.PathName -cne $nestedFileOwner.OriginalServicePath) { throw 'Nested file owner rejection changed SCM configuration.' }
    if ($global:WeDecentMigrationMockStatus -cne 'Stopped') { throw 'Nested file owner rejection did not leave the service stopped.' }
    Write-Host 'Migration coordinator nested file owner recovery rejection PASS'
} finally {
    Remove-Item -LiteralPath $nestedFileOwner.Root -Recurse -Force -ErrorAction SilentlyContinue
}

} finally {
    Remove-Item -LiteralPath $recovery.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$nativeLeaseFixture = New-MigrationFixture
try {
    $lease = New-WeDecentMigrationMutationLease -Directories @($nativeLeaseFixture.Root)
    try {
        $renameBlocked = $false
        try {
            [IO.Directory]::Move($nativeLeaseFixture.Root, $nativeLeaseFixture.Root + '.renamed')
        } catch {
            $renameBlocked = $true
        }
        if (-not $renameBlocked) { throw 'Retained directory lease did not block parent rename/substitution.' }
        Assert-WeDecentMigrationMutationLease -Lease $lease -Paths @($nativeLeaseFixture.Source,$nativeLeaseFixture.Destination,$nativeLeaseFixture.Journal,$nativeLeaseFixture.MetadataPath)
        Write-Host 'Migration native retained parent handle blocks rename PASS'
    } finally { $lease.Dispose() }

    $createFailureRejected = $false
    $env:WEDECENT_MIGRATION_NATIVE_FAIL_CREATEFILE = '1'
    try { [void](New-WeDecentMigrationMutationLease -Directories @($nativeLeaseFixture.Root)) }
    catch { $createFailureRejected = $_.Exception.Message -like '*Injected native filesystem failure*' }
    finally { Remove-Item Env:WEDECENT_MIGRATION_NATIVE_FAIL_CREATEFILE -ErrorAction SilentlyContinue }
    if (-not $createFailureRejected) { throw 'Injected CreateFile failure was not rejected fail-closed.' }

    $infoFailureRejected = $false
    $env:WEDECENT_MIGRATION_NATIVE_FAIL_GETINFO = '1'
    try { [void](Get-WeDecentMigrationIdentitySnapshot -Paths @($nativeLeaseFixture.Source)) }
    catch { $infoFailureRejected = $_.Exception.Message -like '*Injected native filesystem failure*' }
    finally { Remove-Item Env:WEDECENT_MIGRATION_NATIVE_FAIL_GETINFO -ErrorAction SilentlyContinue }
    if (-not $infoFailureRejected) { throw 'Injected GetFileInformationByHandle failure was not rejected fail-closed.' }
    Write-Host 'Migration native CreateFile/GetFileInformationByHandle fail-closed injection PASS'
} finally {
    Remove-Item Env:WEDECENT_MIGRATION_NATIVE_FAIL_CREATEFILE -ErrorAction SilentlyContinue
    Remove-Item Env:WEDECENT_MIGRATION_NATIVE_FAIL_GETINFO -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $nativeLeaseFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$directoryRaceFixture = New-MigrationFixture
try {
    $raceSource = Join-Path $directoryRaceFixture.Root 'race-staging'
    $raceDisplaced = Join-Path $directoryRaceFixture.Root 'race-staging-original'
    $raceDestination = Join-Path $directoryRaceFixture.Root 'race-published'
    [IO.Directory]::CreateDirectory($raceSource) | Out-Null
    [IO.File]::WriteAllText((Join-Path $raceSource 'marker.txt'),'original-object')
    $global:WeDecentMigrationRaceSource = $raceSource
    $global:WeDecentMigrationRaceDisplaced = $raceDisplaced
    $global:WeDecentMigrationRaceInjection = {
        param($Name)
        if ($Name -ceq 'BeforeDirectoryAtomicPublish') {
            [IO.Directory]::Move($global:WeDecentMigrationRaceSource,$global:WeDecentMigrationRaceDisplaced)
            [IO.Directory]::CreateDirectory($global:WeDecentMigrationRaceSource) | Out-Null
            [IO.File]::WriteAllText((Join-Path $global:WeDecentMigrationRaceSource 'marker.txt'),'substituted-object')
        }
    }
    $rejected = $false
    try {
        [void](Publish-WeDecentMigrationObject -TemporaryPath $raceSource -ParentPath $directoryRaceFixture.Root -TargetName 'race-published' -RacePoint 'BeforeDirectoryAtomicPublish')
    } catch {
        $rejected = $_.Exception.Message -like '*source object changed*'
        if (-not $rejected) { throw }
    } finally { $global:WeDecentMigrationRaceInjection = $null }
    if (-not $rejected -or (Test-Path -LiteralPath $raceDestination)) {
        throw 'Directory substitution race was not rejected before publication.'
    }
    if ($global:WeDecentMigrationMockService.PathName -cne $directoryRaceFixture.OriginalServicePath -or $global:WeDecentMigrationMockStatus -cne 'Running') {
        throw 'Directory publication race changed SCM or service state.'
    }
    Write-Host 'Migration deterministic staging pathname substitution race rejection PASS'
} finally {
    $global:WeDecentMigrationRaceInjection = $null
    Remove-Item -LiteralPath $directoryRaceFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$metadataRaceFixture = New-MigrationFixture
try {
    $global:WeDecentMigrationRaceTarget = $metadataRaceFixture.MetadataPath
    $global:WeDecentMigrationRaceBackup = $metadataRaceFixture.MetadataPath + '.race-original'
    $global:WeDecentMigrationRaceInjection = {
        param($Name)
        if ($Name -ceq 'BeforeMetadataAtomicReplace') {
            [IO.File]::Move($global:WeDecentMigrationRaceTarget,$global:WeDecentMigrationRaceBackup)
            [IO.File]::WriteAllText($global:WeDecentMigrationRaceTarget,'{"attacker":"replacement"}')
        }
    }
    $rejected = $false
    try { Write-WeDecentMigrationMetadata -Path $metadataRaceFixture.MetadataPath -StatePath $metadataRaceFixture.Destination }
    catch {
        $rejected = $_.Exception.Message -like '*target object changed*'
        if (-not $rejected) { throw }
    } finally { $global:WeDecentMigrationRaceInjection = $null }
    if (-not $rejected) { throw 'Metadata target substitution was not rejected before atomic publication.' }
    if ((Get-Content -LiteralPath $metadataRaceFixture.MetadataPath -Raw) -cne '{"attacker":"replacement"}') {
        throw 'Metadata publication overwrote the substituted target after the identity mismatch.'
    }
    if ($global:WeDecentMigrationMockService.PathName -cne $metadataRaceFixture.OriginalServicePath -or $global:WeDecentMigrationMockStatus -cne 'Running') {
        throw 'Metadata target substitution changed SCM or service state.'
    }
    Write-Host 'Migration deterministic metadata target substitution race rejection PASS'
} finally {
    $global:WeDecentMigrationRaceInjection = $null
    Remove-Item -LiteralPath $metadataRaceFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$journalRaceFixture = New-MigrationFixture
try {
    # Match the production journal schema before the strict-mode writer refreshes its timestamp.
    $raceJournal = [pscustomobject]@{ schema=1; product='WeDecent'; phase='Prepared'; transaction_id=[Guid]::NewGuid().ToString('D'); updated_utc=[DateTime]::UtcNow.ToString('o') }
    Write-WeDecentMigrationJournal -Path $journalRaceFixture.Journal -Journal $raceJournal
    $global:WeDecentMigrationRaceTarget = $journalRaceFixture.Journal
    $global:WeDecentMigrationRaceBackup = $journalRaceFixture.Journal + '.race-original'
    $global:WeDecentMigrationRaceInjection = {
        param($Name)
        if ($Name -ceq 'BeforeJournalAtomicReplace') {
            [IO.File]::Move($global:WeDecentMigrationRaceTarget,$global:WeDecentMigrationRaceBackup)
            [IO.File]::WriteAllText($global:WeDecentMigrationRaceTarget,'{"attacker":"journal-substitution"}')
        }
    }
    $rejected = $false
    $raceJournal.phase = 'Copying'
    try { Write-WeDecentMigrationJournal -Path $journalRaceFixture.Journal -Journal $raceJournal }
    catch {
        $rejected = $_.Exception.Message -like '*target object changed*'
        if (-not $rejected) { throw }
    } finally { $global:WeDecentMigrationRaceInjection = $null }
    if (-not $rejected) { throw 'Journal target substitution was not rejected before atomic publication.' }
    if ((Get-Content -LiteralPath $journalRaceFixture.Journal -Raw) -cne '{"attacker":"journal-substitution"}') {
        throw 'Journal publication overwrote the substituted target after the identity mismatch.'
    }
    Write-Host 'Migration deterministic journal target substitution race rejection PASS'
} finally {
    $global:WeDecentMigrationRaceInjection = $null
    Remove-Item -LiteralPath $journalRaceFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}



$usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$metadataDaclFixture = New-MigrationFixture
try {
    $metadataAcl = Get-Acl -LiteralPath $metadataDaclFixture.MetadataPath
    $metadataAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $usersSid,[Security.AccessControl.FileSystemRights]::Modify,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    Set-Acl -LiteralPath $metadataDaclFixture.MetadataPath -AclObject $metadataAcl -ErrorAction Stop
    $rejected = $false
    try {
        Write-WeDecentMigrationMetadata -Path $metadataDaclFixture.MetadataPath -StatePath $metadataDaclFixture.Source
    } catch {
        $rejected = $_.Exception.Message -like '*unexpected access rule*'
        if (-not $rejected) { throw }
    }
    if (-not $rejected) { throw 'Metadata publication accepted a pre-existing destination DACL granting Users Modify.' }
    Write-Host 'Migration metadata pre-existing destination DACL rejection PASS'
} finally {
    Remove-Item -LiteralPath $metadataDaclFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$journalDaclFixture = New-MigrationFixture
try {
    $journalDacl = [pscustomobject]@{
        schema = 1
        product = 'WeDecent'
        phase = 'Prepared'
        transaction_id = [Guid]::NewGuid().ToString('D')
        updated_utc = [DateTime]::UtcNow.ToString('o')
    }
    Write-WeDecentMigrationJournal -Path $journalDaclFixture.Journal -Journal $journalDacl
    $journalAcl = Get-Acl -LiteralPath $journalDaclFixture.Journal
    $journalAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $usersSid,[Security.AccessControl.FileSystemRights]::Modify,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    Set-Acl -LiteralPath $journalDaclFixture.Journal -AclObject $journalAcl -ErrorAction Stop
    $journalDacl.phase = 'Copying'
    $rejected = $false
    try { Write-WeDecentMigrationJournal -Path $journalDaclFixture.Journal -Journal $journalDacl }
    catch {
        $rejected = $_.Exception.Message -like '*unexpected access rule*'
        if (-not $rejected) { throw }
    }
    if (-not $rejected) { throw 'Journal publication accepted a pre-existing destination DACL granting Users Modify.' }
    Write-Host 'Migration journal pre-existing destination DACL rejection PASS'
} finally {
    Remove-Item -LiteralPath $journalDaclFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$attackerName = 'WDA' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$attackerPassword = ConvertTo-SecureString -String ('WDecent-' + [Guid]::NewGuid().ToString('N') + 'aA1!') -AsPlainText -Force
try {
    New-LocalUser -Name $attackerName -Password $attackerPassword -PasswordNeverExpires -AccountNeverExpires | Out-Null
    $attackerSid = (Get-LocalUser -Name $attackerName).SID.Value
    if (-not (Get-LocalGroupMember -Group 'Users' | Where-Object { $_.SID.Value -eq $attackerSid })) {
        Add-LocalGroupMember -Group 'Users' -Member $attackerName
    }
    $global:WeDecentMigrationAttackerName = $attackerName
    $global:WeDecentMigrationAttackerPassword = $attackerPassword
    $global:WeDecentMigrationAttackerSid = $attackerSid
    $adminSids = @(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { $_.SID.Value })
    if ($attackerSid -in $adminSids) { throw 'Native publication attacker account unexpectedly belongs to Administrators.' }
    $userSids = @(Get-LocalGroupMember -Group 'Users' | ForEach-Object { $_.SID.Value })
    if ($attackerSid -notin $userSids) { throw 'Native publication attacker account is not a standard Users member.' }
foreach ($nativeRaceKind in @('metadata', 'journal')) {
    $nativeRaceFixture = New-MigrationFixture
    try {
        if ($nativeRaceKind -ceq 'metadata') {
            $nativeTarget = $nativeRaceFixture.MetadataPath
        } else {
            $nativeTarget = $nativeRaceFixture.Journal
            $nativeJournal = [pscustomobject]@{
                schema = 1
                product = 'WeDecent'
                phase = 'Prepared'
                transaction_id = [Guid]::NewGuid().ToString('D')
                updated_utc = [DateTime]::UtcNow.ToString('o')
            }
            Write-WeDecentMigrationJournal -Path $nativeTarget -Journal $nativeJournal
        }
        $global:WeDecentMigrationNativeRaceTarget = $nativeTarget
        $global:WeDecentMigrationNativeRaceBackup = $nativeTarget + '.native-race-original'
        $global:WeDecentMigrationNativeRaceBlocked = $false
        $global:WeDecentMigrationNativeRaceHookInvoked = $false
        $global:WeDecentMigrationNativeRaceError = $null
        [WeDecentMigrationFileIdentityApi]::PublicationHook = [System.Action[string]] {
            param($targetPath)
            if ([string]::Equals($targetPath, $global:WeDecentMigrationNativeRaceTarget, [StringComparison]::OrdinalIgnoreCase)) {
                $global:WeDecentMigrationNativeRaceHookInvoked = $true
                $global:WeDecentMigrationNativeRaceBlocked = Invoke-MigrationUntrustedMutationAttempt `
                    -TargetPath $global:WeDecentMigrationNativeRaceTarget `
                    -BackupPath $global:WeDecentMigrationNativeRaceBackup
            }
        }
        if ($nativeRaceKind -ceq 'metadata') {
            Write-WeDecentMigrationMetadata -Path $nativeTarget -StatePath $nativeRaceFixture.Destination
        } else {
            $nativeJournal.phase = 'Copying'
            Write-WeDecentMigrationJournal -Path $nativeTarget -Journal $nativeJournal
        }
        if (-not $global:WeDecentMigrationNativeRaceHookInvoked) {
            throw "Native $nativeRaceKind publication did not execute the final-boundary substitution hook."
        }
        if (-not $global:WeDecentMigrationNativeRaceBlocked) {
            throw "Native $nativeRaceKind publication did not prevent a delete/rename substitution at the syscall boundary (HRESULT=$global:WeDecentMigrationNativeRaceError)."
        }
        if (Test-Path -LiteralPath $global:WeDecentMigrationNativeRaceBackup) {
            throw "Native $nativeRaceKind publication allowed the original target to be renamed during its publication guard."
        }
        if ((Get-Content -LiteralPath $nativeTarget -Raw | ConvertFrom-Json).attacker) {
            throw "Native $nativeRaceKind publication exposed attacker-controlled replacement content."
        }
        if ($nativeRaceKind -ceq 'metadata') {
            $published = Get-Content -LiteralPath $nativeTarget -Raw | ConvertFrom-Json
            if ([IO.Path]::GetFullPath([string]$published.state_dir) -ine [IO.Path]::GetFullPath($nativeRaceFixture.Destination)) {
                throw 'Native metadata publication did not publish the intended state directory.'
            }
        } else {
            $published = Get-Content -LiteralPath $nativeTarget -Raw | ConvertFrom-Json
            if ([string]$published.phase -cne 'Copying') {
                throw 'Native journal publication did not publish the intended journal phase.'
            }
        }
        Write-Host "Migration native-boundary $nativeRaceKind substitution blocked by protected namespace and directory leases PASS"
    } finally {
        [WeDecentMigrationFileIdentityApi]::PublicationHook = $null
        $global:WeDecentMigrationNativeRaceTarget = $null
        $global:WeDecentMigrationNativeRaceBackup = $null
        $global:WeDecentMigrationNativeRaceBlocked = $false
        $global:WeDecentMigrationNativeRaceHookInvoked = $false
        $global:WeDecentMigrationNativeRaceError = $null
        Remove-Item -LiteralPath $nativeRaceFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}


foreach ($fallbackRaceKind in @('metadata', 'journal')) {
    $fallbackRaceFixture = New-MigrationFixture
    try {
        if ($fallbackRaceKind -ceq 'metadata') {
            $fallbackTarget = $fallbackRaceFixture.MetadataPath
        } else {
            $fallbackTarget = $fallbackRaceFixture.Journal
            $fallbackJournal = [pscustomobject]@{
                schema = 1
                product = 'WeDecent'
                phase = 'Prepared'
                transaction_id = [Guid]::NewGuid().ToString('D')
                updated_utc = [DateTime]::UtcNow.ToString('o')
            }
            Write-WeDecentMigrationJournal -Path $fallbackTarget -Journal $fallbackJournal
        }
        $global:WeDecentMigrationNativeRaceTarget = $fallbackTarget
        $global:WeDecentMigrationNativeRaceBackup = $fallbackTarget + '.absolute-race-original'
        $global:WeDecentMigrationNativeRaceBlocked = $false
        $global:WeDecentMigrationNativeRaceHookInvoked = $false
        [WeDecentMigrationFileIdentityApi]::PublicationHook = [System.Action[string]] {
            param($targetPath)
            if ([string]::Equals($targetPath, $global:WeDecentMigrationNativeRaceTarget, [StringComparison]::OrdinalIgnoreCase)) {
                $global:WeDecentMigrationNativeRaceHookInvoked = $true
                $global:WeDecentMigrationNativeRaceBlocked = Invoke-MigrationUntrustedMutationAttempt `
                    -TargetPath $global:WeDecentMigrationNativeRaceTarget `
                    -BackupPath $global:WeDecentMigrationNativeRaceBackup
            }
        }
        $env:WEDECENT_MIGRATION_TEST_FORCE_RENAME_UNSUPPORTED = '1'
        $failedClosed = $false
        try {
            if ($fallbackRaceKind -ceq 'metadata') {
                Write-WeDecentMigrationMetadata -Path $fallbackTarget -StatePath $fallbackRaceFixture.Destination
            } else {
                $fallbackJournal.phase = 'Copying'
                Write-WeDecentMigrationJournal -Path $fallbackTarget -Journal $fallbackJournal
            }
        } catch {
            $failedClosed = $_.Exception.Message -like '*Injected unsupported native rename*'
            if (-not $failedClosed) { throw }
        }
        if (-not $global:WeDecentMigrationNativeRaceHookInvoked -or -not $global:WeDecentMigrationNativeRaceBlocked -or -not $failedClosed) {
            throw "Protected $fallbackRaceKind publication did not fail closed after blocking unprivileged mutation."
        }
        if (Test-Path -LiteralPath $global:WeDecentMigrationNativeRaceBackup) {
            throw "Fail-closed $fallbackRaceKind publication allowed the original target to be renamed."
        }
        $unchanged = Get-Content -LiteralPath $fallbackTarget -Raw | ConvertFrom-Json
        if ($fallbackRaceKind -ceq 'metadata') {
            if ([IO.Path]::GetFullPath([string]$unchanged.state_dir) -ine [IO.Path]::GetFullPath($fallbackRaceFixture.Source)) {
                throw 'Fail-closed metadata publication changed the original state directory.'
            }
        } elseif ([string]$unchanged.phase -cne 'Prepared') {
            throw 'Fail-closed journal publication changed the original durable phase.'
        }
        Write-Host "Migration $fallbackRaceKind publication fails closed when native rename is unavailable PASS"
    } finally {
        [WeDecentMigrationFileIdentityApi]::PublicationHook = $null
        $global:WeDecentMigrationNativeRaceTarget = $null
        $global:WeDecentMigrationNativeRaceBackup = $null
        $global:WeDecentMigrationNativeRaceBlocked = $false
        $global:WeDecentMigrationNativeRaceHookInvoked = $false
        Remove-Item Env:WEDECENT_MIGRATION_TEST_FORCE_RENAME_UNSUPPORTED -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $fallbackRaceFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

} finally {
    $global:WeDecentMigrationAttackerName = $null
    if ($global:WeDecentMigrationAttackerPassword) { $global:WeDecentMigrationAttackerPassword.Dispose() }
    $global:WeDecentMigrationAttackerPassword = $null
    Remove-LocalUser -Name $attackerName -ErrorAction SilentlyContinue
}

$recoverySeparationFixture = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $recoverySeparationFixture.Source -Destination $recoverySeparationFixture.Destination -AgentPath $agentPath -ServiceName $recoverySeparationFixture.ServiceName -ServiceSid $recoverySeparationFixture.ServiceSid -MetadataPath $recoverySeparationFixture.MetadataPath -JournalPath $recoverySeparationFixture.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Recovery path-separation fixture did not reach the pending rollback boundary.' }
    $journal = Read-WeDecentMigrationJournal -Path $recoverySeparationFixture.Journal
    $journal.staging = Join-Path $recoverySeparationFixture.Source 'nested'
    Write-WeDecentMigrationJournal -Path $recoverySeparationFixture.Journal -Journal $journal
    $rejected = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $recoverySeparationFixture.Journal -AgentPath $agentPath -MetadataPath $recoverySeparationFixture.MetadataPath -ServiceName $recoverySeparationFixture.ServiceName)
    } catch {
        $rejected = $_.Exception.Message -like '*overlap or alias*' -or $_.Exception.Message -like '*unsafe or inconsistent source, destination, or staging paths*'
        if (-not $rejected) { throw }
    }
    if (-not $rejected) { throw 'Recovery accepted an overlapping source/staging path.' }
    if ($global:WeDecentMigrationMockService.PathName -cne $recoverySeparationFixture.OriginalServicePath) {
        throw 'Recovery path-separation rejection changed SCM configuration.'
    }
    if ($global:WeDecentMigrationMockStatus -cne 'Stopped') {
        throw 'Recovery path-separation rejection restarted or otherwise changed the stopped service.'
    }
    Write-Host 'Migration recovery full path-separation rejection before SCM/service mutation PASS'
} finally {
    Remove-Item -LiteralPath $recoverySeparationFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Windows state migration coordinator integration PASS'
