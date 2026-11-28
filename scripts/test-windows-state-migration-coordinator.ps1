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
$installerLockRoot = Join-Path $env:ProgramData 'WeDecent\install-transactions'
$installerLockRootCreated = -not (Test-Path -LiteralPath $installerLockRoot -PathType Container)
New-Item -ItemType Directory -Force -Path $installerLockRoot | Out-Null
if ($installerLockRootCreated) {
    Set-WeDecentMigrationAdminDirectory -Path $installerLockRoot -AgentPath $agentPath
} else {
    [void](Assert-WeDecentMigrationAdminDirectory -Path $installerLockRoot)
}
$installerLockPath = Join-Path $installerLockRoot 'installer.lock'
if (-not (Test-Path -LiteralPath $installerLockPath -PathType Leaf)) {
    $bootstrapLock = [IO.File]::Open($installerLockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $bootstrapLock.Dispose()
    Set-WeDecentMigrationAdminFileAcl -Path $installerLockPath
}
$global:WeDecentMigrationMockService = $null
$global:WeDecentMigrationMockStatus = 'Running'
$global:WeDecentMigrationStartCount = 0
$global:WeDecentMigrationStopCount = 0
$global:WeDecentMigrationScmConfigCount = 0
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
    $global:WeDecentMigrationStopCount++
    $global:WeDecentMigrationMockStatus = 'Stopped'
    $global:WeDecentMigrationMockService.State = 'Stopped'
}
function global:Start-Service {
    [CmdletBinding()]
    param([string]$Name)
    if ($Name -cne $global:WeDecentMigrationMockService.Name) { throw "Unexpected service start: $Name" }
    $global:WeDecentMigrationStartCount++
    $global:WeDecentMigrationMockStatus = 'Running'
    $global:WeDecentMigrationMockService.State = 'Running'
}
function global:sc.exe {
    param([string]$Verb, [string]$Name, [string]$Config)
    if ($Verb -cne 'config' -or $Name -cne $global:WeDecentMigrationMockService.Name -or $Config -notmatch '^binPath= ') {
        $global:LASTEXITCODE = 1
        return 'Unexpected mocked SCM command.'
    }
    $global:WeDecentMigrationScmConfigCount++
    $global:WeDecentMigrationMockService.PathName = $Config.Substring('binPath= '.Length)
    $global:LASTEXITCODE = 0
    return 'SUCCESS'
}
function Get-MigrationTreeSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return '<missing>' }
    $root = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $entries = [Collections.Generic.List[string]]::new()
    $items = @((Get-Item -LiteralPath $root -Force -ErrorAction Stop)) +
        @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop | Sort-Object -Property FullName)
    foreach ($item in $items) {
        $relative = if ([string]::Equals($item.FullName, $root, [StringComparison]::OrdinalIgnoreCase)) {
            '.'
        } else {
            $item.FullName.Substring($root.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        }
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $digest = $null
        if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
            $digest = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        $isReparsePoint = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        $kind = if ($isReparsePoint) { 'ReparsePoint' } elseif ($item.PSIsContainer) { 'Directory' } else { 'File' }
        $length = if ($item.PSIsContainer) { $null } else { [long]$item.Length }
        $linkType = $null
        $target = $null
        if ($isReparsePoint) {
            $linkType = [string]$item.LinkType
            $target = [string]$item.Target
        }
        $record = [ordered]@{
            Path = $relative
            Kind = $kind
            Length = $length
            Digest = $digest
            LinkType = $linkType
            Target = $target
            Attributes = [int]$item.Attributes
            Owner = [string]$acl.Owner
            Sddl = [string]$acl.Sddl
            CreationTimeUtcTicks = [long]$item.CreationTimeUtc.Ticks
            LastWriteTimeUtcTicks = [long]$item.LastWriteTimeUtc.Ticks
        }
        $entries.Add((ConvertTo-Json -InputObject $record -Compress -Depth 4))
    }
    return [string]::Join("`n", $entries.ToArray())
}
function Get-MigrationRecoverySideEffectSnapshot {
    param([Parameter(Mandatory = $true)]$Fixture, [Parameter(Mandatory = $true)]$Journal)
    $trees = [ordered]@{}
    foreach ($treePath in @($Journal.source, $Journal.destination, $Journal.staging) | Select-Object -Unique) {
        $fullPath = [IO.Path]::GetFullPath([string]$treePath)
        $trees[$fullPath] = Get-MigrationTreeSnapshot -Path $fullPath
    }
    return [pscustomobject]@{
        Trees = $trees
        PublicationParent = Get-MigrationTreeSnapshot -Path $Fixture.Root
        MetadataBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Fixture.MetadataPath))
        JournalBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Fixture.Journal))
        ServicePath = [string]$global:WeDecentMigrationMockService.PathName
        ServiceStartName = [string]$global:WeDecentMigrationMockService.StartName
        ServiceStartMode = [string]$global:WeDecentMigrationMockService.StartMode
        ServiceState = [string]$global:WeDecentMigrationMockService.State
        MockServiceStatus = [string]$global:WeDecentMigrationMockStatus
        ServiceStartCount = [int]$global:WeDecentMigrationStartCount
        ServiceStopCount = [int]$global:WeDecentMigrationStopCount
        ScmConfigCount = [int]$global:WeDecentMigrationScmConfigCount
    }
}
function Assert-MigrationRecoveryNoSideEffects {
    param([Parameter(Mandatory = $true)]$Fixture, [Parameter(Mandatory = $true)]$Journal, [Parameter(Mandatory = $true)]$Before, [Parameter(Mandatory = $true)][string]$Case)
    $after = Get-MigrationRecoverySideEffectSnapshot -Fixture $Fixture -Journal $Journal
    if ($after.MetadataBytes -cne $Before.MetadataBytes) { throw "Rejected $Case changed installer metadata bytes." }
    if ($after.JournalBytes -cne $Before.JournalBytes) { throw "Rejected $Case changed migration journal bytes." }
    if ($after.PublicationParent -cne $Before.PublicationParent) {
        throw "Rejected $Case changed publication-parent files, ACLs, ownership, or timestamps."
    }
    foreach ($treePath in $Before.Trees.Keys) {
        if ($after.Trees[$treePath] -cne $Before.Trees[$treePath]) { throw "Rejected $Case changed migration filesystem tree: $treePath" }
    }
    foreach ($field in @('ServicePath','ServiceStartName','ServiceStartMode','ServiceState','MockServiceStatus','ServiceStartCount','ServiceStopCount','ScmConfigCount')) {
        if ([string]$after.$field -cne [string]$Before.$field) { throw "Rejected $Case changed mocked SCM/service field $field." }
    }
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
function Set-MigrationJournalJsonForTest {
    param(
        [Parameter(Mandatory = $true)][string]$Json,
        [hashtable]$Fields = @{},
        [string[]]$RemoveFields = @()
    )
    $value = ConvertFrom-Json -InputObject $Json -AsHashtable -ErrorAction Stop
    foreach ($field in $RemoveFields) { [void]$value.Remove($field) }
    foreach ($field in $Fields.Keys) { $value[$field] = $Fields[$field] }
    return ConvertTo-Json -InputObject $value -Depth 10
}
function Assert-MigrationJournalRejected {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)][string]$Json,
        [Parameter(Mandatory = $true)][string]$Case
    )
    [IO.File]::WriteAllText($Fixture.Journal, $Json, [Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { [void](Read-WeDecentMigrationJournal -Path $Fixture.Journal) }
    catch { $rejected = $true }
    if (-not $rejected) { throw "Migration journal parser accepted $Case." }
    Write-Host "Migration journal parser rejects $Case PASS"
}

$journalParserFixture = New-MigrationFixture
try {
    $migrationFailed = $false
    try {
        Invoke-WeDecentStateMigration -Source $journalParserFixture.Source -Destination $journalParserFixture.Destination -AgentPath $agentPath -ServiceName $journalParserFixture.ServiceName -ServiceSid $journalParserFixture.ServiceSid -MetadataPath $journalParserFixture.MetadataPath -JournalPath $journalParserFixture.Journal -FaultAt 'Verified' | Out-Null
    } catch {
        $migrationFailed = $_.Exception.Message -like '*was rolled back*'
        if (-not $migrationFailed) { throw }
    }
    if (-not $migrationFailed) { throw 'Journal parser fixture did not reach a verified migration and rollback.' }
    $validJournalJson = Get-Content -LiteralPath $journalParserFixture.Journal -Raw -ErrorAction Stop
    $validJournal = Read-WeDecentMigrationJournal -Path $journalParserFixture.Journal
    if ($validJournal.phase -cne 'RolledBack' -or -not $validJournal.staging_complete) {
        throw 'Journal parser fixture is not a valid completed-staging rollback record.'
    }

    $duplicateJson = $validJournalJson -replace '^\s*\{', '{"phase":"RolledBack",'
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $duplicateJson -Case 'case-insensitive duplicate JSON properties'
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json ($validJournalJson.TrimEnd() + [Environment]::NewLine + '{}') -Case 'trailing JSON documents'
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json ($validJournalJson.TrimEnd() + ' unexpected') -Case 'unexpected trailing content'

    $caseJson = Set-MigrationJournalJsonForTest -Json $validJournalJson -RemoveFields @('source_manifest_sha256')
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $caseJson -Case 'missing source manifest digest'
    $caseJson = Set-MigrationJournalJsonForTest -Json $validJournalJson -RemoveFields @('source_stable_manifest_sha256')
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $caseJson -Case 'missing stable source manifest digest'
    $caseJson = Set-MigrationJournalJsonForTest -Json $validJournalJson -Fields @{ source_manifest_sha256 = 'not-a-sha256' }
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $caseJson -Case 'malformed source manifest digest'
    $caseJson = Set-MigrationJournalJsonForTest -Json $validJournalJson -Fields @{ source_stable_manifest_sha256 = ('a' * 63) }
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $caseJson -Case 'malformed stable source manifest digest'

    $caseJson = Set-MigrationJournalJsonForTest -Json $validJournalJson -Fields @{ phase = 'Verified' } -RemoveFields @('destination_manifest_sha256')
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $caseJson -Case 'missing destination digest after staging completion'
    $caseJson = Set-MigrationJournalJsonForTest -Json $validJournalJson -Fields @{ destination_manifest_sha256 = 'invalid' }
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $caseJson -Case 'malformed completed destination digest'
    $caseJson = Set-MigrationJournalJsonForTest -Json $validJournalJson -Fields @{ phase = 'Verified'; staging_complete = $false; destination_manifest_sha256 = '' }
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $caseJson -Case 'Verified phase without completed staging'
    $caseJson = Set-MigrationJournalJsonForTest -Json $validJournalJson -Fields @{ phase = 'Prepared' }
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $caseJson -Case 'Prepared phase with completed staging'
    $caseJson = Set-MigrationJournalJsonForTest -Json $validJournalJson -Fields @{ staging_complete = $false; destination_manifest_sha256 = ('a' * 64) }
    Assert-MigrationJournalRejected -Fixture $journalParserFixture -Json $caseJson -Case 'destination digest present before staging completion'
    Write-Host 'Migration journal strict JSON and phase/digest regression suite PASS'
} finally {
    Remove-Item -LiteralPath $journalParserFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$serviceBooleanFixture = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $serviceBooleanFixture.Source -Destination $serviceBooleanFixture.Destination -AgentPath $agentPath -ServiceName $serviceBooleanFixture.ServiceName -ServiceSid $serviceBooleanFixture.ServiceSid -MetadataPath $serviceBooleanFixture.MetadataPath -JournalPath $serviceBooleanFixture.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Service Boolean fixture did not leave an interrupted rollback journal.' }
    $pendingJson = Get-Content -LiteralPath $serviceBooleanFixture.Journal -Raw -ErrorAction Stop
    $pending = Read-WeDecentMigrationJournal -Path $serviceBooleanFixture.Journal
    if ($pending.phase -cne 'RollingBack' -or $pending.service_was_running -isnot [bool] -or -not $pending.service_was_running) {
        throw 'Running-service recovery fixture did not preserve a true JSON Boolean.'
    }
    $global:WeDecentMigrationMockStatus = 'Stopped'
    $global:WeDecentMigrationMockService.State = 'Stopped'

    $malformedServiceStates = @(
        @{ Name = 'string true'; Fields = @{ service_was_running = 'true' } },
        @{ Name = 'string false'; Fields = @{ service_was_running = 'false' } },
        @{ Name = 'numeric one'; Fields = @{ service_was_running = 1 } },
        @{ Name = 'numeric zero'; Fields = @{ service_was_running = 0 } },
        @{ Name = 'array'; Fields = @{ service_was_running = @($true) } },
        @{ Name = 'object'; Fields = @{ service_was_running = @{ value = $true } } },
        @{ Name = 'null'; Fields = @{ service_was_running = $null } },
        @{ Name = 'missing'; Fields = @{}; RemoveFields = @('service_was_running') }
    )
    foreach ($malformed in $malformedServiceStates) {
        $removeFields = @()
        if ($malformed.ContainsKey('RemoveFields')) { $removeFields = @($malformed['RemoveFields']) }
        $caseJson = Set-MigrationJournalJsonForTest -Json $pendingJson -Fields $malformed.Fields -RemoveFields $removeFields
        [IO.File]::WriteAllText($serviceBooleanFixture.Journal, $caseJson, [Text.UTF8Encoding]::new($false))
        $before = Get-MigrationRecoverySideEffectSnapshot -Fixture $serviceBooleanFixture -Journal $pending
        $rejected = $false
        try {
            [void](Recover-WeDecentStateMigration -JournalPath $serviceBooleanFixture.Journal -AgentPath $agentPath -MetadataPath $serviceBooleanFixture.MetadataPath -ServiceName $serviceBooleanFixture.ServiceName -ExpectedDestinationPath $serviceBooleanFixture.Destination)
        } catch { $rejected = $true }
        if (-not $rejected) { throw "Recovery accepted malformed service_was_running representation: $($malformed.Name)." }
        Assert-MigrationRecoveryNoSideEffects -Fixture $serviceBooleanFixture -Journal $pending -Before $before -Case "service_was_running $($malformed.Name)"
        Write-Host "Migration recovery rejects service_was_running $($malformed.Name) without SCM, metadata, journal or filesystem mutation PASS"
    }

    [IO.File]::WriteAllText($serviceBooleanFixture.Journal, $pendingJson, [Text.UTF8Encoding]::new($false))
    $validTrue = Read-WeDecentMigrationJournal -Path $serviceBooleanFixture.Journal
    if ($validTrue.service_was_running -isnot [bool] -or -not $validTrue.service_was_running) {
        throw 'Reader did not preserve service_was_running=true as a Boolean.'
    }
    $startCount = $global:WeDecentMigrationStartCount
    if (-not (Recover-WeDecentStateMigration -JournalPath $serviceBooleanFixture.Journal -AgentPath $agentPath -MetadataPath $serviceBooleanFixture.MetadataPath -ServiceName $serviceBooleanFixture.ServiceName -ExpectedDestinationPath $serviceBooleanFixture.Destination)) {
        throw 'Recovery did not resume valid true service_was_running journal.'
    }
    if ($global:WeDecentMigrationStartCount -ne ($startCount + 1) -or $global:WeDecentMigrationMockStatus -cne 'Running') {
        throw 'Valid true service_was_running did not restart the previously running service exactly once.'
    }
    Write-Host 'Migration recovery preserves true Boolean and restarts originally running service PASS'
} finally {
    Remove-Item -LiteralPath $serviceBooleanFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

$serviceStoppedBooleanFixture = New-MigrationFixture
try {
    $global:WeDecentMigrationMockStatus = 'Stopped'
    $global:WeDecentMigrationMockService.State = 'Stopped'
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $serviceStoppedBooleanFixture.Source -Destination $serviceStoppedBooleanFixture.Destination -AgentPath $agentPath -ServiceName $serviceStoppedBooleanFixture.ServiceName -ServiceSid $serviceStoppedBooleanFixture.ServiceSid -MetadataPath $serviceStoppedBooleanFixture.MetadataPath -JournalPath $serviceStoppedBooleanFixture.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch {
        $interrupted = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $interrupted) { throw }
    }
    if (-not $interrupted) { throw 'Stopped-service Boolean fixture did not leave an interrupted rollback journal.' }
    $pending = Read-WeDecentMigrationJournal -Path $serviceStoppedBooleanFixture.Journal
    if ($pending.service_was_running -isnot [bool] -or $pending.service_was_running) {
        throw 'Stopped-service journal did not preserve false as a JSON Boolean.'
    }
    $startCount = $global:WeDecentMigrationStartCount
    if (-not (Recover-WeDecentStateMigration -JournalPath $serviceStoppedBooleanFixture.Journal -AgentPath $agentPath -MetadataPath $serviceStoppedBooleanFixture.MetadataPath -ServiceName $serviceStoppedBooleanFixture.ServiceName -ExpectedDestinationPath $serviceStoppedBooleanFixture.Destination)) {
        throw 'Recovery did not resume valid false service_was_running journal.'
    }
    if ($global:WeDecentMigrationStartCount -ne $startCount -or $global:WeDecentMigrationMockStatus -cne 'Stopped') {
        throw 'Valid false service_was_running unexpectedly started the service.'
    }
    Write-Host 'Migration recovery preserves false Boolean and keeps originally stopped service stopped PASS'
} finally {
    Remove-Item -LiteralPath $serviceStoppedBooleanFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
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
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class WeDecentMigrationTestLogon {
    private const uint DELETE_ACCESS=0x00010000, FILE_READ_ATTRIBUTES=0x80;
    private const uint SHARE_READ_WRITE=3, OPEN_EXISTING=3;
    private const uint BACKUP_SEMANTICS=0x02000000, OPEN_REPARSE_POINT=0x00200000;
    private const int FILE_RENAME_INFO_EX_CLASS=22;
    private const uint FILE_RENAME_REPLACE_IF_EXISTS=0x1, FILE_RENAME_POSIX_SEMANTICS=0x2;

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct FILE_RENAME_INFO_EX {
        public uint Flags;
        public IntPtr RootDirectory;
        public uint FileNameLength;
        public char FileName;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_ELEVATION { public int TokenIsElevated; }
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="LogonUserW")]
    private static extern bool LogonUserNative(string user, string domain, IntPtr password, int logonType, int logonProvider, out SafeAccessTokenHandle token);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="CreateFileW")]
    private static extern SafeFileHandle CreateFileNative(string path, uint access, uint share, IntPtr security,
        uint creation, uint attributes, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true, EntryPoint="WriteFile")]
    private static extern bool WriteFileNative(SafeFileHandle handle, byte[] buffer, uint count, out uint written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, IntPtr info, uint size);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, uint size, out uint returned);
    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool LookupPrivilegeName(string systemName, ref LUID luid, StringBuilder name, ref uint length);

    public static int TryNativeReplace(string sourcePath, string targetPath) {
        using (SafeFileHandle source=CreateFileNative(sourcePath,DELETE_ACCESS|FILE_READ_ATTRIBUTES,
            SHARE_READ_WRITE,IntPtr.Zero,OPEN_EXISTING,BACKUP_SEMANTICS|OPEN_REPARSE_POINT,IntPtr.Zero)) {
            if (source==null || source.IsInvalid) return Marshal.GetLastWin32Error();
            int nameOffset=Marshal.OffsetOf(typeof(FILE_RENAME_INFO_EX),"FileName").ToInt32();
            byte[] absoluteName=Encoding.Unicode.GetBytes(System.IO.Path.GetFullPath(targetPath));
            int bufferSize=Marshal.SizeOf(typeof(FILE_RENAME_INFO_EX))+absoluteName.Length-2;
            IntPtr buffer=Marshal.AllocHGlobal(bufferSize);
            try {
                for (int n=0;n<bufferSize;n++) Marshal.WriteByte(buffer,n,0);
                uint flags=FILE_RENAME_REPLACE_IF_EXISTS|FILE_RENAME_POSIX_SEMANTICS;
                Marshal.WriteInt32(buffer,0,unchecked((int)flags));
                Marshal.WriteIntPtr(buffer,Marshal.OffsetOf(typeof(FILE_RENAME_INFO_EX),"RootDirectory").ToInt32(),IntPtr.Zero);
                Marshal.WriteInt32(buffer,Marshal.OffsetOf(typeof(FILE_RENAME_INFO_EX),"FileNameLength").ToInt32(),absoluteName.Length);
                Marshal.Copy(absoluteName,0,IntPtr.Add(buffer,nameOffset),absoluteName.Length);
                return SetFileInformationByHandle(source,FILE_RENAME_INFO_EX_CLASS,buffer,(uint)bufferSize)
                    ? 0 : Marshal.GetLastWin32Error();
            } finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    public static int TryWrite(string target) {
        using (SafeFileHandle handle=CreateFileNative(target,0x40000000,7,IntPtr.Zero,3,0x80,IntPtr.Zero)) {
            if (handle==null || handle.IsInvalid) return Marshal.GetLastWin32Error();
            byte[] payload=Encoding.UTF8.GetBytes("attacker");
            uint written;
            if (!WriteFileNative(handle,payload,(uint)payload.Length,out written,IntPtr.Zero))
                return Marshal.GetLastWin32Error();
            return written==(uint)payload.Length ? 0 : 29;
        }
    }

    private static IntPtr TokenBuffer(IntPtr token, int infoClass, out uint size) {
        size=0;
        GetTokenInformation(token,infoClass,IntPtr.Zero,0,out size);
        if (size==0) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr buffer=Marshal.AllocHGlobal((int)size);
        if (!GetTokenInformation(token,infoClass,buffer,size,out size)) {
            int error=Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw new Win32Exception(error);
        }
        return buffer;
    }

    public static string GetTokenEvidence() {
        using (WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
            IntPtr token=identity.Token;
            uint size;
            IntPtr integrity=TokenBuffer(token,25,out size);
            uint integrityRid;
            try {
                SID_AND_ATTRIBUTES label=(SID_AND_ATTRIBUTES)Marshal.PtrToStructure(integrity,typeof(SID_AND_ATTRIBUTES));
                byte count=Marshal.ReadByte(GetSidSubAuthorityCount(label.Sid));
                integrityRid=unchecked((uint)Marshal.ReadInt32(GetSidSubAuthority(label.Sid,(uint)(count-1))));
            } finally { Marshal.FreeHGlobal(integrity); }

            IntPtr elevationBuffer=TokenBuffer(token,20,out size);
            bool elevated;
            try {
                TOKEN_ELEVATION elevation=(TOKEN_ELEVATION)Marshal.PtrToStructure(elevationBuffer,typeof(TOKEN_ELEVATION));
                elevated=elevation.TokenIsElevated!=0;
            } finally { Marshal.FreeHGlobal(elevationBuffer); }

            IntPtr privileges=TokenBuffer(token,3,out size);
            List<string> enabled=new List<string>();
            try {
                uint count=unchecked((uint)Marshal.ReadInt32(privileges));
                int offset=4, entrySize=Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                for (uint i=0;i<count;i++) {
                    IntPtr entryPtr=IntPtr.Add(privileges,offset+checked((int)i)*entrySize);
                    LUID_AND_ATTRIBUTES entry=(LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(entryPtr,typeof(LUID_AND_ATTRIBUTES));
                    if ((entry.Attributes&0x2)==0) continue;
                    uint nameLength=256;
                    StringBuilder name=new StringBuilder((int)nameLength);
                    if (!LookupPrivilegeName(null,ref entry.Luid,name,ref nameLength))
                        throw new Win32Exception(Marshal.GetLastWin32Error(),"LookupPrivilegeName failed; refusing incomplete attacker-token evidence.");
                    enabled.Add(name.ToString());
                }
            } finally { Marshal.FreeHGlobal(privileges); }
            enabled.Sort(StringComparer.Ordinal);
            return "sid="+identity.User.Value+";integrityRid="+integrityRid.ToString("X")+";elevated="+elevated.ToString().ToLowerInvariant()+
                ";enabledPrivileges="+String.Join(",",enabled.ToArray());
        }
    }

    public static void RunAs(string user, string domain, SecureString securePassword, Action action) {
        IntPtr passwordBuffer=Marshal.SecureStringToGlobalAllocUnicode(securePassword);
        try {
            SafeAccessTokenHandle token;
            if (!LogonUserNative(user,domain,passwordBuffer,2,0,out token))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"LogonUser failed for unprivileged migration test identity.");
            using (token) { WindowsIdentity.RunImpersonated(token,action); }
        } finally { Marshal.ZeroFreeGlobalAllocUnicode(passwordBuffer); }
    }
}
'@
}

function Read-MigrationFileShared {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    )
    $reader = $null
    try {
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
        return $reader.ReadToEnd()
    } finally {
        if ($null -ne $reader) { $reader.Dispose() } else { $stream.Dispose() }
    }
}

function Assert-MigrationAttackerTokenEvidence {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Evidence,
        [Parameter(Mandatory=$true)][string]$ExpectedSid
    )
    # Fail closed unless the actual impersonated token is an ordinary medium-integrity,
    # non-elevated user token with only the explicitly permitted baseline privileges.
    $tokenFields = @{}
    $allowedTokenFields = @('sid','integrityRid','elevated','enabledPrivileges')
    foreach ($field in ($Evidence -split ';')) {
        $parts = $field -split '=', 2
        if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or $tokenFields.ContainsKey($parts[0])) {
            throw "Attacker token evidence is malformed or duplicated: $Evidence"
        }
        if ($parts[0] -notin $allowedTokenFields) {
            throw "Attacker token evidence contains an unexpected field '$($parts[0])'."
        }
        $tokenFields[$parts[0]] = $parts[1]
    }
    foreach ($requiredField in $allowedTokenFields) {
        if (-not $tokenFields.ContainsKey($requiredField)) {
            throw "Attacker token evidence is missing required field: $requiredField"
        }
    }
    if ($tokenFields.sid -cne $ExpectedSid) {
        throw "Attacker token SID mismatch (token=$($tokenFields.sid), expected=$ExpectedSid)."
    }
    if ($tokenFields.integrityRid -cne '2000') {
        throw "Attacker token must have medium integrity RID 0x2000 (observed=$($tokenFields.integrityRid))."
    }
    if ($tokenFields.elevated -cne 'false') {
        throw "Attacker token must not be elevated (observed=$($tokenFields.elevated))."
    }
    $enabledPrivileges = @()
    if (-not [string]::IsNullOrEmpty($tokenFields.enabledPrivileges)) {
        $enabledPrivileges = @($tokenFields.enabledPrivileges -split ',')
    }
    $allowedEnabledPrivileges = @('SeChangeNotifyPrivilege','SeIncreaseWorkingSetPrivilege','SeShutdownPrivilege','SeTimeZonePrivilege')
    $uniqueEnabledPrivileges = @($enabledPrivileges | Select-Object -Unique)
    if ($uniqueEnabledPrivileges.Count -ne $enabledPrivileges.Count) {
        throw 'Attacker token enabled privilege set contains duplicates.'
    }
    $unexpectedPrivileges = @($enabledPrivileges | Where-Object { $_ -notin $allowedEnabledPrivileges })
    if ($unexpectedPrivileges.Count -gt 0 -or 'SeChangeNotifyPrivilege' -notin $enabledPrivileges) {
        throw "Attacker token enabled privilege set violates standard-user policy (enabled=$($enabledPrivileges -join ','), unexpected=$($unexpectedPrivileges -join ','))."
    }
    return $true
}

function Test-MigrationAttackerTokenEvidenceValidator {
    $sid = 'S-1-5-21-111-222-333-1001'
    $valid = "sid=$sid;integrityRid=2000;elevated=false;enabledPrivileges=SeChangeNotifyPrivilege"
    if (-not (Assert-MigrationAttackerTokenEvidence -Evidence $valid -ExpectedSid $sid)) {
        throw 'Valid standard-user attacker token evidence was rejected.'
    }
    $invalid = @(
        @{ Name='missing field'; Evidence="sid=$sid;integrityRid=2000;elevated=false" },
        @{ Name='duplicate field'; Evidence="$valid;sid=$sid" },
        @{ Name='malformed field'; Evidence="sid=$sid;integrityRid; elevated=false;enabledPrivileges=SeChangeNotifyPrivilege" },
        @{ Name='unknown field'; Evidence="$valid;administrator=true" },
        @{ Name='incorrect SID'; Evidence="sid=S-1-5-21-9-8-7-1002;integrityRid=2000;elevated=false;enabledPrivileges=SeChangeNotifyPrivilege" },
        @{ Name='incorrect integrity'; Evidence="sid=$sid;integrityRid=3000;elevated=false;enabledPrivileges=SeChangeNotifyPrivilege" },
        @{ Name='elevated token'; Evidence="sid=$sid;integrityRid=2000;elevated=true;enabledPrivileges=SeChangeNotifyPrivilege" },
        @{ Name='unexpected privilege'; Evidence="sid=$sid;integrityRid=2000;elevated=false;enabledPrivileges=SeChangeNotifyPrivilege,SeDebugPrivilege" },
        @{ Name='missing required privilege'; Evidence="sid=$sid;integrityRid=2000;elevated=false;enabledPrivileges=SeIncreaseWorkingSetPrivilege" },
        @{ Name='duplicate privilege'; Evidence="sid=$sid;integrityRid=2000;elevated=false;enabledPrivileges=SeChangeNotifyPrivilege,SeChangeNotifyPrivilege" }
    )
    foreach ($test in $invalid) {
        $rejected = $false
        try { [void](Assert-MigrationAttackerTokenEvidence -Evidence $test.Evidence -ExpectedSid $sid) }
        catch { $rejected = $true }
        if (-not $rejected) { throw "Attacker token evidence validator accepted invalid case: $($test.Name)" }
    }
    Write-Host 'Migration attacker-token evidence validator positive and negative cases PASS'
}

function Invoke-MigrationUntrustedMutationAttempt {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$SourcePath
    )
    $beforeIdentity = [WeDecentMigrationFileIdentityApi]::GetIdentity($TargetPath)
    $beforeContent = Read-MigrationFileShared -Path $TargetPath
    $sourceIdentity = [WeDecentMigrationFileIdentityApi]::GetIdentity($SourcePath)
    $global:WeDecentMigrationAttackTarget = $TargetPath
    $global:WeDecentMigrationAttackSource = $SourcePath
    $global:WeDecentMigrationAttackMoveError = 0
    $global:WeDecentMigrationAttackWriteError = 0
    $global:WeDecentMigrationAttackObservedSid = $null
    $global:WeDecentMigrationAttackTokenEvidence = $null
    [WeDecentMigrationTestLogon]::RunAs(
        $global:WeDecentMigrationAttackerName,
        $env:COMPUTERNAME,
        $global:WeDecentMigrationAttackerPassword,
        [Action] {
            $global:WeDecentMigrationAttackObservedSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $global:WeDecentMigrationAttackTokenEvidence = [WeDecentMigrationTestLogon]::GetTokenEvidence()
            $global:WeDecentMigrationAttackMoveError = [WeDecentMigrationTestLogon]::TryNativeReplace(
                $global:WeDecentMigrationAttackSource,$global:WeDecentMigrationAttackTarget)
            $global:WeDecentMigrationAttackWriteError = [WeDecentMigrationTestLogon]::TryWrite(
                $global:WeDecentMigrationAttackTarget)
        }
    )
    if ($global:WeDecentMigrationAttackObservedSid -cne $global:WeDecentMigrationAttackerSid) {
        throw "Native publication attack did not execute under the distinct unprivileged account (observed=$global:WeDecentMigrationAttackObservedSid expected=$global:WeDecentMigrationAttackerSid)."
    }
    Assert-MigrationAttackerTokenEvidence -Evidence $global:WeDecentMigrationAttackTokenEvidence -ExpectedSid $global:WeDecentMigrationAttackerSid
    if ($global:WeDecentMigrationAttackMoveError -ne 5 -or $global:WeDecentMigrationAttackWriteError -ne 5) {
        throw "Unprivileged FILE_RENAME_INFO_EX POSIX replacement/write was not denied (rename=$global:WeDecentMigrationAttackMoveError, write=$global:WeDecentMigrationAttackWriteError)."
    }
    if ([WeDecentMigrationFileIdentityApi]::GetIdentity($TargetPath) -cne $beforeIdentity -or
        (Read-MigrationFileShared -Path $TargetPath) -cne $beforeContent) {
        throw 'Unprivileged native replacement changed the original destination identity or contents.'
    }
    if ([WeDecentMigrationFileIdentityApi]::GetIdentity($SourcePath) -cne $sourceIdentity) {
        throw 'Unprivileged native replacement changed the attacker source identity.'
    }
    return $true
}

Test-MigrationAttackerTokenEvidenceValidator

function New-MigrationAttackerWorkspace {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$AttackerSid
    )
    $path = Join-Path $RootPath 'attacker-workspace'
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $attacker = [Security.Principal.SecurityIdentifier]::new($AttackerSid)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($admins)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($admins, $system, $attacker)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
    return $path
}

$forwardFaults = @('Prepared','ServiceStopped','Copying','Copied','IdentityVerification','IdentityProtected','Verified','DestinationPublished','StatePublished','SCMTransition','ServiceReconfigured','MetadataUpdated','ServiceRestarted')
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
$unsupportedServiceStates = @('Paused', 'Start Pending', 'Stop Pending', 'Pause Pending', 'Continue Pending')
foreach ($unsupportedState in $unsupportedServiceStates) {
    $fixture = New-MigrationFixture
    try {
        $rootSddlBefore = (Get-Acl -LiteralPath $fixture.Root).Sddl
        $metadataBefore = [IO.File]::ReadAllText($fixture.MetadataPath)
        $sourceManifestBefore = Get-WeDecentMigrationManifestDigest -Manifest @(Get-WeDecentMigrationManifest -Root $fixture.Source)
        $global:WeDecentMigrationMockService.State = $unsupportedState
        $global:WeDecentMigrationMockStatus = $unsupportedState
        $rejected = $false
        try {
            Invoke-WeDecentStateMigration -Source $fixture.Source -Destination $fixture.Destination -AgentPath $agentPath -ServiceName $fixture.ServiceName -ServiceSid $fixture.ServiceSid -MetadataPath $fixture.MetadataPath -JournalPath $fixture.Journal | Out-Null
        } catch {
            $rejected = $_.Exception.Message -like "*requires SCM service to be Running or Stopped*"
            if (-not $rejected) { throw }
        }
        if (-not $rejected) { throw "Migration accepted unsupported SCM state '$unsupportedState'." }
        if (Test-Path -LiteralPath $fixture.Journal) { throw "Migration wrote a journal before rejecting SCM state '$unsupportedState'." }
        if (Test-Path -LiteralPath $fixture.Destination) { throw "Migration created a destination before rejecting SCM state '$unsupportedState'." }
        if (-not (Test-Path -LiteralPath $fixture.Source -PathType Container)) { throw "Migration changed the source while rejecting SCM state '$unsupportedState'." }
        if ((Get-Acl -LiteralPath $fixture.Root).Sddl -cne $rootSddlBefore) { throw "Migration changed parent ACLs before rejecting SCM state '$unsupportedState'." }
        if ([IO.File]::ReadAllText($fixture.MetadataPath) -cne $metadataBefore) { throw "Migration changed metadata before rejecting SCM state '$unsupportedState'." }
        if ((Get-WeDecentMigrationManifestDigest -Manifest @(Get-WeDecentMigrationManifest -Root $fixture.Source)) -cne $sourceManifestBefore) { throw "Migration changed source contents before rejecting SCM state '$unsupportedState'." }
        if ($global:WeDecentMigrationMockService.PathName -cne $fixture.OriginalServicePath -or
            $global:WeDecentMigrationMockService.State -cne $unsupportedState -or
            $global:WeDecentMigrationMockStatus -cne $unsupportedState) {
            throw "Migration mutated SCM or service state while rejecting '$unsupportedState'."
        }
        Write-Host "Migration rejects unsupported SCM state without mutation PASS: $unsupportedState"
    } finally {
        Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$serviceStateRaceFixture = New-MigrationFixture
try {
    $global:WeDecentMigrationMockService.State = 'Stopped'
    $global:WeDecentMigrationMockStatus = 'Stopped'
    $serviceStateRaceManifest = Get-WeDecentMigrationManifestDigest -Manifest @(Get-WeDecentMigrationManifest -Root $serviceStateRaceFixture.Source)
    $serviceStateRaceMetadata = [IO.File]::ReadAllText($serviceStateRaceFixture.MetadataPath)
    $global:WeDecentMigrationServiceStateRaceInjected = $false
    $global:WeDecentMigrationRaceInjection = {
        param($Name)
        if ($Name -ceq 'BeforeServiceStateRevalidation') {
            $global:WeDecentMigrationServiceStateRaceInjected = $true
            $global:WeDecentMigrationMockService.State = 'Running'
            $global:WeDecentMigrationMockStatus = 'Running'
        }
    }
    $rejected = $false
    try {
        Invoke-WeDecentStateMigration -Source $serviceStateRaceFixture.Source -Destination $serviceStateRaceFixture.Destination -AgentPath $agentPath -ServiceName $serviceStateRaceFixture.ServiceName -ServiceSid $serviceStateRaceFixture.ServiceSid -MetadataPath $serviceStateRaceFixture.MetadataPath -JournalPath $serviceStateRaceFixture.Journal | Out-Null
    } catch {
        $rejected = $_.Exception.Message -like '*changed after migration preflight*'
        if (-not $rejected) { throw }
    }
    if (-not $global:WeDecentMigrationServiceStateRaceInjected) { throw 'SCM state race injection point was not reached.' }
    if (-not $rejected) { throw 'Migration did not reject an SCM state change after preflight.' }
    if ($global:WeDecentMigrationMockService.State -cne 'Stopped' -or $global:WeDecentMigrationMockStatus -cne 'Stopped') {
        throw 'Migration did not restore the original stopped service state after an SCM race.'
    }
    if ($global:WeDecentMigrationMockService.PathName -cne $serviceStateRaceFixture.OriginalServicePath) {
        throw 'Migration changed the SCM command line after an SCM state race.'
    }
    if ([IO.File]::ReadAllText($serviceStateRaceFixture.MetadataPath) -cne $serviceStateRaceMetadata) {
        throw 'Migration changed metadata after an SCM state race.'
    }
    if ((Get-WeDecentMigrationManifestDigest -Manifest @(Get-WeDecentMigrationManifest -Root $serviceStateRaceFixture.Source)) -cne $serviceStateRaceManifest) {
        throw 'Migration changed source contents after an SCM state race.'
    }
    if (Test-Path -LiteralPath $serviceStateRaceFixture.Destination) {
        throw 'Migration published destination state after an SCM state race.'
    }
    $terminal = Read-WeDecentMigrationJournal -Path $serviceStateRaceFixture.Journal
    if ($terminal.phase -cne 'RolledBack') { throw "SCM state race journal phase is $($terminal.phase), not RolledBack." }
    Write-Host 'Migration revalidates SCM state before filesystem mutation and rolls back state races PASS'
} finally {
    $global:WeDecentMigrationRaceInjection = $null
    Remove-Item -LiteralPath $serviceStateRaceFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
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
$successStopped = New-MigrationFixture
try {
    $global:WeDecentMigrationMockStatus = 'Stopped'
    $global:WeDecentMigrationMockService.State = 'Stopped'
    $result = Invoke-WeDecentStateMigration -Source $successStopped.Source -Destination $successStopped.Destination -AgentPath $agentPath -ServiceName $successStopped.ServiceName -ServiceSid $successStopped.ServiceSid -MetadataPath $successStopped.MetadataPath -JournalPath $successStopped.Journal
    if ($result.phase -cne 'Committed') { throw 'Stopped-service migration did not commit.' }
    if ($global:WeDecentMigrationMockStatus -cne 'Stopped' -or $global:WeDecentMigrationMockService.State -cne 'Stopped') {
        throw 'Successful migration changed a service that was stopped before migration.'
    }
    if ($global:WeDecentMigrationMockService.PathName -notlike "*$($successStopped.Destination)*") {
        throw 'Successful stopped-service migration did not update the SCM state path.'
    }
    Write-Host 'Migration successful commit preserves originally stopped service state PASS'
} finally {
    Remove-Item -LiteralPath $successStopped.Root -Recurse -Force -ErrorAction SilentlyContinue
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
    if (-not (Recover-WeDecentStateMigration -JournalPath $recovery.Journal -AgentPath $agentPath -MetadataPath $recovery.MetadataPath -ServiceName $recovery.ServiceName -ExpectedDestinationPath $recovery.Destination)) { throw 'Installer recovery did not resume rollback.' }
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
        [void](Recover-WeDecentStateMigration -JournalPath $stagingRecovery.Journal -AgentPath $agentPath -MetadataPath $stagingRecovery.MetadataPath -ServiceName $stagingRecovery.ServiceName -ExpectedDestinationPath $stagingRecovery.Destination -FaultAt 'RollbackStagingValidated')
    } catch {
        $recoveryInterrupted = $_.Exception.Message -like '*RollbackStagingValidated*'
        if (-not $recoveryInterrupted) { throw }
    }
    if (-not $recoveryInterrupted) { throw 'Fault injection did not interrupt rollback while staging existed.' }
    $pending = Read-WeDecentMigrationJournal -Path $stagingRecovery.Journal
    if ($pending.phase -cne 'RollingBack' -or -not (Test-Path -LiteralPath $pending.staging -PathType Container)) {
        throw 'Finally cleanup deleted staging after interrupted rollback.'
    }
    if (-not (Recover-WeDecentStateMigration -JournalPath $stagingRecovery.Journal -AgentPath $agentPath -MetadataPath $stagingRecovery.MetadataPath -ServiceName $stagingRecovery.ServiceName -ExpectedDestinationPath $stagingRecovery.Destination)) {
        throw 'Repeated recovery did not resume pending staging rollback.'
    }
    Assert-MigrationRolledBack -Fixture $stagingRecovery -Fault 'staging recovery'
    if (Recover-WeDecentStateMigration -JournalPath $stagingRecovery.Journal -AgentPath $agentPath -MetadataPath $stagingRecovery.MetadataPath -ServiceName $stagingRecovery.ServiceName -ExpectedDestinationPath $stagingRecovery.Destination) {
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
param([string]$ModulePath, [string]$JournalPath, [string]$AgentPath, [string]$MetadataPath, [string]$ServiceName, [string]$ExpectedDestinationPath)
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
if (-not (Recover-WeDecentStateMigration -JournalPath $JournalPath -AgentPath $AgentPath -MetadataPath $MetadataPath -ServiceName $ServiceName -ExpectedDestinationPath $ExpectedDestinationPath)) {
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
    if (Recover-WeDecentStateMigration -JournalPath $partialStagingRecovery.Journal -AgentPath $agentPath -MetadataPath $partialStagingRecovery.MetadataPath -ServiceName $partialStagingRecovery.ServiceName -ExpectedDestinationPath $partialStagingRecovery.Destination) {
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
        [void](Recover-WeDecentStateMigration -JournalPath $mutatedSource.Journal -AgentPath $agentPath -MetadataPath $mutatedSource.MetadataPath -ServiceName $mutatedSource.ServiceName -ExpectedDestinationPath $mutatedSource.Destination)
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
        [void](Recover-WeDecentStateMigration -JournalPath $aclMutatedSource.Journal -AgentPath $agentPath -MetadataPath $aclMutatedSource.MetadataPath -ServiceName $aclMutatedSource.ServiceName -ExpectedDestinationPath $aclMutatedSource.Destination)
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
        [void](Recover-WeDecentStateMigration -JournalPath $nestedFileAcl.Journal -AgentPath $agentPath -MetadataPath $nestedFileAcl.MetadataPath -ServiceName $nestedFileAcl.ServiceName -ExpectedDestinationPath $nestedFileAcl.Destination)
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
        [void](Recover-WeDecentStateMigration -JournalPath $nestedDirectoryAcl.Journal -AgentPath $agentPath -MetadataPath $nestedDirectoryAcl.MetadataPath -ServiceName $nestedDirectoryAcl.ServiceName -ExpectedDestinationPath $nestedDirectoryAcl.Destination)
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
        [void](Recover-WeDecentStateMigration -JournalPath $nestedDirectoryOwner.Journal -AgentPath $agentPath -MetadataPath $nestedDirectoryOwner.MetadataPath -ServiceName $nestedDirectoryOwner.ServiceName -ExpectedDestinationPath $nestedDirectoryOwner.Destination)
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
        [void](Recover-WeDecentStateMigration -JournalPath $nestedFileOwner.Journal -AgentPath $agentPath -MetadataPath $nestedFileOwner.MetadataPath -ServiceName $nestedFileOwner.ServiceName -ExpectedDestinationPath $nestedFileOwner.Destination)
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
$attackerPassword = [Security.SecureString]::new()
$passwordBytes = New-Object byte[] 32
$passwordRandom = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $passwordRandom.GetBytes($passwordBytes)
    $attackerPassword.AppendChar([char](97 + ($passwordBytes[0] % 26)))
    $attackerPassword.AppendChar([char](65 + ($passwordBytes[1] % 26)))
    $attackerPassword.AppendChar([char](48 + ($passwordBytes[2] % 10)))
    $specialPasswordChars = '!@#$%^&*()-_=+[]{}:,.?'.ToCharArray()
    $attackerPassword.AppendChar($specialPasswordChars[$passwordBytes[3] % $specialPasswordChars.Length])
    $passwordAlphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}:,.?'.ToCharArray()
    for ($passwordIndex = 4; $passwordIndex -lt $passwordBytes.Length; $passwordIndex++) {
        $attackerPassword.AppendChar($passwordAlphabet[$passwordBytes[$passwordIndex] % $passwordAlphabet.Length])
    }
    $attackerPassword.MakeReadOnly()
} finally {
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    $passwordRandom.Dispose()
}
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
$mutationCases = @(
    [pscustomobject]@{ Name='FILE_ADD_FILE'; Rights=[Security.AccessControl.FileSystemRights]::CreateFiles },
    [pscustomobject]@{ Name='FILE_ADD_SUBDIRECTORY'; Rights=[Security.AccessControl.FileSystemRights]::CreateDirectories },
    [pscustomobject]@{ Name='DELETE_CHILD'; Rights=[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles },
    [pscustomobject]@{ Name='DELETE'; Rights=[Security.AccessControl.FileSystemRights]::Delete },
    [pscustomobject]@{ Name='WRITE_DAC'; Rights=[Security.AccessControl.FileSystemRights]::ChangePermissions },
    [pscustomobject]@{ Name='WRITE_OWNER'; Rights=[Security.AccessControl.FileSystemRights]::TakeOwnership }
)
foreach ($mutationCase in $mutationCases) {
    $aclFixture = New-MigrationFixture
    try {
        $ancestor = Join-Path $aclFixture.Root ('acl-ancestor-' + $mutationCase.Name)
        New-Item -ItemType Directory -Path $ancestor | Out-Null
        $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner($admins)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($sid in @($admins, $system)) {
            $trustedRule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
                [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow
            )
            [void]$acl.AddAccessRule($trustedRule)
        }
        $untrustedRule = [Security.AccessControl.FileSystemAccessRule]::new(
            $usersSid, $mutationCase.Rights, $inheritance,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($untrustedRule)
        Set-Acl -LiteralPath $ancestor -AclObject $acl -ErrorAction Stop

        $publication = Join-Path $ancestor 'publication'
        New-Item -ItemType Directory -Path $publication | Out-Null
        $publicationAcl = Get-Acl -LiteralPath $publication
        $publicationAcl.SetOwner($admins)
        Set-Acl -LiteralPath $publication -AclObject $publicationAcl -ErrorAction Stop
        $inheritedRule = @( (Get-Acl -LiteralPath $publication).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $usersSid.Value -and $_.IsInherited -and (($_.FileSystemRights -band $mutationCase.Rights) -ne 0) } )
        if ($inheritedRule.Count -eq 0) {
            throw "The $($mutationCase.Name) test fixture did not create an inherited effective ACE."
        }

        $metadataPath = Join-Path $publication 'installer.json'
        [IO.File]::WriteAllText($metadataPath, [IO.File]::ReadAllText($aclFixture.MetadataPath))
        Set-WeDecentMigrationAdminFileAcl -Path $metadataPath
        $journalPath = Join-Path $publication 'migration.json'
        $journal = [pscustomobject]@{
            schema = 1
            product = 'WeDecent'
            phase = 'Prepared'
            transaction_id = [Guid]::NewGuid().ToString('D')
            updated_utc = [DateTime]::UtcNow.ToString('o')
        }
        [IO.File]::WriteAllText($journalPath, (ConvertTo-Json -InputObject $journal -Depth 10))
        Set-WeDecentMigrationAdminFileAcl -Path $journalPath

        foreach ($writer in @('metadata', 'journal')) {
            $rejected = $false
            try {
                if ($writer -ceq 'metadata') {
                    Write-WeDecentMigrationMetadata -Path $metadataPath -StatePath $aclFixture.Source
                } else {
                    $journal.phase = 'Copying'
                    Write-WeDecentMigrationJournal -Path $journalPath -Journal $journal
                }
            } catch {
                $rejected = $_.Exception.Message -like '*effective or inherited mutation rights*'
                if (-not $rejected) { throw }
            }
            if (-not $rejected) {
                throw "$writer writer accepted inherited $($mutationCase.Name) access in its publication ancestor chain."
            }
        }
        Write-Host "Migration inherited $($mutationCase.Name) ACL rejected by metadata and journal writers PASS"
    } finally {
        Remove-Item -LiteralPath $aclFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$controlFixture = New-MigrationFixture
try {
    $controlWorkspace = New-MigrationAttackerWorkspace -RootPath $controlFixture.Root -AttackerSid $attackerSid
    $controlDirectory = Join-Path $controlWorkspace 'control'
    New-Item -ItemType Directory -Path $controlDirectory | Out-Null
    $controlDirectoryAcl = Get-Acl -LiteralPath $controlDirectory
    $controlDirectoryAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $controlDirectory -AclObject $controlDirectoryAcl -ErrorAction Stop
    $controlNamespaceRejected = $false
    try { [void](Assert-WeDecentMigrationPublicationNamespace -Path $controlDirectory) }
    catch {
        $controlNamespaceRejected = $_.Exception.Message -like '*effective or inherited mutation rights*'
        if (-not $controlNamespaceRejected) { throw }
    }
    if (-not $controlNamespaceRejected) { throw 'Native replacement control directory was unexpectedly accepted as a protected publication namespace.' }
    $controlTarget = Join-Path $controlDirectory 'target.json'
    $controlSource = Join-Path $controlDirectory 'source.tmp'
    [IO.File]::WriteAllText($controlTarget, '{"control":"original"}')
    [IO.File]::WriteAllText($controlSource, '{"attacker":true}')
    $controlOriginalIdentity = [WeDecentMigrationFileIdentityApi]::GetIdentity($controlTarget)
    $controlSourceIdentity = [WeDecentMigrationFileIdentityApi]::GetIdentity($controlSource)
    $global:WeDecentMigrationControlObservedSid = $null
    $global:WeDecentMigrationControlTokenEvidence = $null
    $global:WeDecentMigrationControlError = -1
    [WeDecentMigrationTestLogon]::RunAs(
        $attackerName, $env:COMPUTERNAME, $attackerPassword,
        [Action] {
            $global:WeDecentMigrationControlObservedSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $global:WeDecentMigrationControlTokenEvidence = [WeDecentMigrationTestLogon]::GetTokenEvidence()
            $global:WeDecentMigrationControlError = [WeDecentMigrationTestLogon]::TryNativeReplace($controlSource, $controlTarget)
        }
    )
    if ($global:WeDecentMigrationControlObservedSid -cne $attackerSid) {
        throw 'Native replacement control did not execute under the distinct standard-user token.'
    }
    if ($global:WeDecentMigrationControlError -ne 0) {
        throw "Native FILE_RENAME_INFO_EX POSIX replacement control failed (Win32=$global:WeDecentMigrationControlError)."
    }
    if ([WeDecentMigrationFileIdentityApi]::GetIdentity($controlTarget) -cne $controlSourceIdentity -or
        [IO.File]::ReadAllText($controlTarget) -cne '{"attacker":true}' -or
        (Test-Path -LiteralPath $controlSource)) {
        throw 'Native replacement control did not replace the original object with the source object.'
    }
    if ([WeDecentMigrationFileIdentityApi]::GetIdentity($controlTarget) -ceq $controlOriginalIdentity) {
        throw 'Native replacement control unexpectedly retained the original destination identity.'
    }
    Write-Host "Migration unprotected namespace native POSIX replacement control PASS: $global:WeDecentMigrationControlTokenEvidence"
} finally {
    Remove-Item -LiteralPath $controlFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}

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
        $nativeWorkspace = New-MigrationAttackerWorkspace -RootPath $nativeRaceFixture.Root -AttackerSid $attackerSid
        $nativeSource = Join-Path $nativeWorkspace ("native-" + $nativeRaceKind + ".tmp")
        [IO.File]::WriteAllText($nativeSource, '{"attacker":true}')
        $global:WeDecentMigrationNativeRaceTarget = $nativeTarget
        $global:WeDecentMigrationNativeRaceSource = $nativeSource
        $global:WeDecentMigrationNativeRaceBlocked = $false
        $global:WeDecentMigrationNativeRaceHookInvoked = $false
        [WeDecentMigrationFileIdentityApi]::PublicationHook = [System.Action[string]] {
            param($targetPath)
            if ([string]::Equals($targetPath, $global:WeDecentMigrationNativeRaceTarget, [StringComparison]::OrdinalIgnoreCase)) {
                $global:WeDecentMigrationNativeRaceHookInvoked = $true
                $global:WeDecentMigrationNativeRaceBlocked = Invoke-MigrationUntrustedMutationAttempt -TargetPath $global:WeDecentMigrationNativeRaceTarget -SourcePath $global:WeDecentMigrationNativeRaceSource
            }
        }
        if ($nativeRaceKind -ceq 'metadata') {
            Write-WeDecentMigrationMetadata -Path $nativeTarget -StatePath $nativeRaceFixture.Destination
        } else {
            $nativeJournal.phase = 'Copying'
            Write-WeDecentMigrationJournal -Path $nativeTarget -Journal $nativeJournal
        }
        if (-not $global:WeDecentMigrationNativeRaceHookInvoked -or -not $global:WeDecentMigrationNativeRaceBlocked) {
            throw "Native $nativeRaceKind publication did not block a standard-user FILE_RENAME_INFO_EX POSIX replacement."
        }
        if (-not (Test-Path -LiteralPath $nativeSource)) {
            throw "Native $nativeRaceKind attack unexpectedly consumed its source file."
        }
        $nativePublishedContent = Get-Content -LiteralPath $nativeTarget -Raw | ConvertFrom-Json
        if ($null -ne $nativePublishedContent.PSObject.Properties['attacker']) {
            throw "Native $nativeRaceKind publication exposed attacker-controlled replacement content."
        }
        if ($nativeRaceKind -ceq 'metadata') {
            if ([IO.Path]::GetFullPath([string]$nativePublishedContent.state_dir) -ine [IO.Path]::GetFullPath($nativeRaceFixture.Destination)) {
                throw 'Native metadata publication did not publish the intended state directory.'
            }
        } elseif ([string]$nativePublishedContent.phase -cne 'Copying') {
            throw 'Native journal publication did not publish the intended journal phase.'
        }
        Write-Host "Migration native-boundary $nativeRaceKind FILE_RENAME_INFO_EX POSIX substitution blocked PASS: $global:WeDecentMigrationAttackTokenEvidence"
    } finally {
        [WeDecentMigrationFileIdentityApi]::PublicationHook = $null
        $global:WeDecentMigrationNativeRaceTarget = $null
        $global:WeDecentMigrationNativeRaceSource = $null
        $global:WeDecentMigrationNativeRaceBlocked = $false
        $global:WeDecentMigrationNativeRaceHookInvoked = $false
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
        $fallbackWorkspace = New-MigrationAttackerWorkspace -RootPath $fallbackRaceFixture.Root -AttackerSid $attackerSid
        $fallbackSource = Join-Path $fallbackWorkspace ("fallback-" + $fallbackRaceKind + ".tmp")
        [IO.File]::WriteAllText($fallbackSource, '{"attacker":true}')
        $fallbackOriginalIdentity = [WeDecentMigrationFileIdentityApi]::GetIdentity($fallbackTarget)
        $fallbackOriginalContent = [IO.File]::ReadAllText($fallbackTarget)
        $global:WeDecentMigrationNativeRaceTarget = $fallbackTarget
        $global:WeDecentMigrationNativeRaceSource = $fallbackSource
        $global:WeDecentMigrationNativeRaceBlocked = $false
        $global:WeDecentMigrationNativeRaceHookInvoked = $false
        [WeDecentMigrationFileIdentityApi]::PublicationHook = [System.Action[string]] {
            param($targetPath)
            if ([string]::Equals($targetPath, $global:WeDecentMigrationNativeRaceTarget, [StringComparison]::OrdinalIgnoreCase)) {
                $global:WeDecentMigrationNativeRaceHookInvoked = $true
                $global:WeDecentMigrationNativeRaceBlocked = Invoke-MigrationUntrustedMutationAttempt -TargetPath $global:WeDecentMigrationNativeRaceTarget -SourcePath $global:WeDecentMigrationNativeRaceSource
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
        if (-not $global:WeDecentMigrationNativeRaceHookInvoked -or
            -not $global:WeDecentMigrationNativeRaceBlocked -or -not $failedClosed) {
            throw "Protected $fallbackRaceKind publication did not fail closed after blocking native unprivileged replacement."
        }
        if ([WeDecentMigrationFileIdentityApi]::GetIdentity($fallbackTarget) -cne $fallbackOriginalIdentity -or
            [IO.File]::ReadAllText($fallbackTarget) -cne $fallbackOriginalContent -or
            -not (Test-Path -LiteralPath $fallbackSource)) {
            throw "Fail-closed $fallbackRaceKind publication changed the original destination or consumed the attack source."
        }
        Write-Host "Migration $fallbackRaceKind publication fails closed after native POSIX attack rejection PASS"
    } finally {
        [WeDecentMigrationFileIdentityApi]::PublicationHook = $null
        $global:WeDecentMigrationNativeRaceTarget = $null
        $global:WeDecentMigrationNativeRaceSource = $null
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
    $before = Get-MigrationRecoverySideEffectSnapshot -Fixture $recoverySeparationFixture -Journal $journal
    $rejected = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $recoverySeparationFixture.Journal -AgentPath $agentPath -MetadataPath $recoverySeparationFixture.MetadataPath -ServiceName $recoverySeparationFixture.ServiceName -ExpectedDestinationPath $recoverySeparationFixture.Destination)
    } catch {
        $rejected = $_.Exception.Message -like '*overlap or alias*' -or $_.Exception.Message -like '*unsafe or inconsistent source, destination, or staging paths*'
        if (-not $rejected) { throw }
    }
    if (-not $rejected) { throw 'Recovery accepted an overlapping source/staging path.' }
    Assert-MigrationRecoveryNoSideEffects -Fixture $recoverySeparationFixture -Journal $journal -Before $before -Case 'overlapping source/staging path'
    Write-Host 'Migration recovery full path-separation rejection before any side effect PASS'
} finally {
    Remove-Item -LiteralPath $recoverySeparationFixture.Root -Recurse -Force -ErrorAction SilentlyContinue
}


function Invoke-MigrationRecoveryInFreshPowerShell {
    param([Parameter(Mandatory = $true)]$Fixture)
    $childScript = Join-Path $Fixture.Root 'recover-in-independent-process.ps1'
    $childBody = @'
[CmdletBinding()]
param([string]$ModulePath, [string]$JournalPath, [string]$AgentPath, [string]$MetadataPath, [string]$ServiceName, [string]$ExpectedDestinationPath)
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
if (-not (Recover-WeDecentStateMigration -JournalPath $JournalPath -AgentPath $AgentPath -MetadataPath $MetadataPath -ServiceName $ServiceName -ExpectedDestinationPath $ExpectedDestinationPath)) {
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
    foreach ($argument in @('-NoProfile','-File',$childScript,'-ModulePath',$modulePath,'-JournalPath',$Fixture.Journal,'-AgentPath',$agentPath,'-MetadataPath',$Fixture.MetadataPath,'-ServiceName',$Fixture.ServiceName)) {
        [void]$child.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($child)
    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "Fresh-process recovery failed: $stderr $stdout" }
    } finally {
        $process.Dispose()
    }
}

# Reject malformed but well-formed JSON recovery records without changing any transaction resource.
$recoveryRejectedCases = @(
    [pscustomobject]@{
        Name = 'overlapping source/staging paths'
        ExpectedError = '*unsafe or inconsistent source, destination, or staging paths*'
        Mutate = { param($journal, $fixture) $journal.staging = Join-Path $fixture.Source 'nested' }
    },
    [pscustomobject]@{
        Name = 'Verified phase without completed staging'
        ExpectedError = '*requires completed, authenticated staging*'
        Mutate = { param($journal, $fixture) $journal.phase = 'Verified'; $journal.staging_complete = $false; $journal.destination_manifest_sha256 = '' }
    },
    [pscustomobject]@{
        Name = 'string true service_was_running marker'
        ExpectedError = '*required Boolean state markers*'
        Mutate = { param($journal, $fixture) $journal.service_was_running = 'true' }
    },
    [pscustomobject]@{
        Name = 'string false service_was_running marker'
        ExpectedError = '*required Boolean state markers*'
        Mutate = { param($journal, $fixture) $journal.service_was_running = 'false' }
    },
    [pscustomobject]@{
        Name = 'numeric service_was_running marker'
        ExpectedError = '*required Boolean state markers*'
        Mutate = { param($journal, $fixture) $journal.service_was_running = 1 }
    },
    [pscustomobject]@{
        Name = 'null service_was_running marker'
        ExpectedError = '*required Boolean state markers*'
        Mutate = { param($journal, $fixture) $journal.service_was_running = $null }
    },
    [pscustomobject]@{
        Name = 'missing service_was_running marker'
        ExpectedError = '*required Boolean state markers*'
        Mutate = { param($journal, $fixture) [void]$journal.PSObject.Properties.Remove('service_was_running') }
    },
    [pscustomobject]@{
        Name = 'original metadata bound to a different source'
        ExpectedError = '*original metadata does not authenticate its source state*'
        Mutate = {
            param($journal, $fixture)
            $metadata = ConvertFrom-Json -InputObject $journal.original_metadata_json
            $metadata.state_dir = $fixture.Destination
            $journal.original_metadata_json = ConvertTo-Json -InputObject $metadata -Depth 10
        }
    }
    [pscustomobject]@{
        Name = 'missing protected service-account SID'
        ExpectedError = '*Migration SID is invalid*'
        Mutate = {
            param($journal, $fixture)
            $metadata = Get-Content -LiteralPath $fixture.MetadataPath -Raw | ConvertFrom-Json
            $metadata.service_account_sid = ''
            [IO.File]::WriteAllText($fixture.MetadataPath, (ConvertTo-Json -InputObject $metadata -Depth 10))
        }
    },
    [pscustomobject]@{
        Name = 'malformed protected service-account SID'
        ExpectedError = '*Migration SID is invalid*'
        Mutate = {
            param($journal, $fixture)
            $metadata = Get-Content -LiteralPath $fixture.MetadataPath -Raw | ConvertFrom-Json
            $metadata.service_account_sid = 'not-a-sid'
            [IO.File]::WriteAllText($fixture.MetadataPath, (ConvertTo-Json -InputObject $metadata -Depth 10))
        }
    },
    [pscustomobject]@{
        Name = 'mismatched protected service-account SID'
        ExpectedError = '*disagree on service identity*'
        Mutate = {
            param($journal, $fixture)
            $metadata = Get-Content -LiteralPath $fixture.MetadataPath -Raw | ConvertFrom-Json
            $metadata.service_account_sid = 'S-1-5-18'
            [IO.File]::WriteAllText($fixture.MetadataPath, (ConvertTo-Json -InputObject $metadata -Depth 10))
        }
    },
    [pscustomobject]@{
        Name = 'unresolved live SCM service account'
        ExpectedError = '*cannot resolve SCM service account*'
        Mutate = {
            param($journal, $fixture)
            $global:WeDecentMigrationMockService.StartName = 'WEDECENT-NO-SUCH-DOMAIN\NO-SUCH-ACCOUNT'
        }
    },
    [pscustomobject]@{
        Name = 'mismatched live SCM service account'
        ExpectedError = '*Live SCM service-account SID*'
        Mutate = {
            param($journal, $fixture)
            $global:WeDecentMigrationMockService.StartName = 'NT AUTHORITY\SYSTEM'
        }
    }
)
$installerLockContentionFixture = New-MigrationFixture
try {
    $pendingRollback = $false
    try {
        Invoke-WeDecentStateMigration -Source $installerLockContentionFixture.Source -Destination $installerLockContentionFixture.Destination -AgentPath $agentPath -ServiceName $installerLockContentionFixture.ServiceName -ServiceSid $installerLockContentionFixture.ServiceSid -MetadataPath $installerLockContentionFixture.MetadataPath -JournalPath $installerLockContentionFixture.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch { $pendingRollback = $_.Exception.Message -like '*durable rollback is pending*'; if (-not $pendingRollback) { throw } }
    if (-not $pendingRollback) { throw 'Installer-lock contention fixture did not reach pending rollback.' }
    $journal = Read-WeDecentMigrationJournal -Path $installerLockContentionFixture.Journal
    $before = Get-MigrationRecoverySideEffectSnapshot -Fixture $installerLockContentionFixture -Journal $journal
    $installerOwnedLock = [IO.File]::Open($installerLockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $rejected = $false
        try {
            [void](Recover-WeDecentStateMigration -JournalPath $installerLockContentionFixture.Journal -AgentPath $agentPath -MetadataPath $installerLockContentionFixture.MetadataPath -ServiceName $installerLockContentionFixture.ServiceName -ExpectedDestinationPath $installerLockContentionFixture.Destination)
        } catch {
            $rejected = $_.Exception.Message -like '*owns the machine-wide installation lock*'
            if (-not $rejected) { throw }
        }
        if (-not $rejected) { throw 'Migration recovery entered while the installer held the shared machine-wide lock.' }
        Assert-MigrationRecoveryNoSideEffects -Fixture $installerLockContentionFixture -Journal $journal -Before $before -Case 'installer/recovery lock contention'
    } finally { $installerOwnedLock.Dispose() }
    $installerText = Get-Content -LiteralPath $installerPath -Raw
    $installerLockAcquire = $installerText.IndexOf('Acquire-WeDecentInstallerLock', [StringComparison]::Ordinal)
    $installerMigrationRecovery = $installerText.IndexOf('Recover-WeDecentStateMigration -JournalPath', [StringComparison]::Ordinal)
    if ($installerLockAcquire -lt 0 -or $installerMigrationRecovery -lt 0 -or $installerLockAcquire -ge $installerMigrationRecovery) {
        throw 'Production installer does not acquire the shared installer lock before migration recovery.'
    }
    Write-Host 'Installer and standalone migration recovery serialize on the same exclusive machine lock PASS'
} finally { Remove-Item -LiteralPath $installerLockContentionFixture.Root -Recurse -Force -ErrorAction SilentlyContinue }

$expectedDestinationFixture = New-MigrationFixture
try {
    $interrupted = $false
    try {
        Invoke-WeDecentStateMigration -Source $expectedDestinationFixture.Source -Destination $expectedDestinationFixture.Destination -AgentPath $agentPath -ServiceName $expectedDestinationFixture.ServiceName -ServiceSid $expectedDestinationFixture.ServiceSid -MetadataPath $expectedDestinationFixture.MetadataPath -JournalPath $expectedDestinationFixture.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
    } catch { $interrupted = $_.Exception.Message -like '*durable rollback is pending*'; if (-not $interrupted) { throw } }
    if (-not $interrupted) { throw 'Expected-destination fixture did not reach pending rollback.' }
    $journal = Read-WeDecentMigrationJournal -Path $expectedDestinationFixture.Journal
    $before = Get-MigrationRecoverySideEffectSnapshot -Fixture $expectedDestinationFixture -Journal $journal
    $rejected = $false
    try {
        [void](Recover-WeDecentStateMigration -JournalPath $expectedDestinationFixture.Journal -AgentPath $agentPath -MetadataPath $expectedDestinationFixture.MetadataPath -ServiceName $expectedDestinationFixture.ServiceName -ExpectedDestinationPath (Join-Path $expectedDestinationFixture.Root 'unexpected-state'))
    } catch { $rejected = $_.Exception.Message -like '*does not match this installer metadata path*' -or $_.Exception.Message -like '*expected state destination*'; if (-not $rejected) { throw } }
    if (-not $rejected) { throw 'Recovery accepted a destination outside the installer-requested state path.' }
    Assert-MigrationRecoveryNoSideEffects -Fixture $expectedDestinationFixture -Journal $journal -Before $before -Case 'unexpected destination path'
    Write-Host 'Migration recovery rejects destination outside installer-requested state path without side effects PASS'
} finally { Remove-Item -LiteralPath $expectedDestinationFixture.Root -Recurse -Force -ErrorAction SilentlyContinue }

foreach ($case in $recoveryRejectedCases) {
    $fixture = New-MigrationFixture
    try {
        $pendingRollback = $false
        try {
            Invoke-WeDecentStateMigration -Source $fixture.Source -Destination $fixture.Destination -AgentPath $agentPath -ServiceName $fixture.ServiceName -ServiceSid $fixture.ServiceSid -MetadataPath $fixture.MetadataPath -JournalPath $fixture.Journal -FaultAt 'StatePublished,RollbackStarted' | Out-Null
        } catch {
            $pendingRollback = $_.Exception.Message -like '*durable rollback is pending*'
            if (-not $pendingRollback) { throw }
        }
        if (-not $pendingRollback) { throw "Fixture did not reach pending rollback for $($case.Name)." }
        $journal = Read-WeDecentMigrationJournal -Path $fixture.Journal
        & $case.Mutate $journal $fixture
        Write-WeDecentMigrationJournal -Path $fixture.Journal -Journal $journal
        $before = Get-MigrationRecoverySideEffectSnapshot -Fixture $fixture -Journal $journal
        $rejected = $false
        try {
            [void](Recover-WeDecentStateMigration -JournalPath $fixture.Journal -AgentPath $agentPath -MetadataPath $fixture.MetadataPath -ServiceName $fixture.ServiceName -ExpectedDestinationPath $fixture.Destination)
        } catch {
            $rejected = $_.Exception.Message -like $case.ExpectedError
            if (-not $rejected) { throw }
        }
        if (-not $rejected) { throw "Recovery accepted $($case.Name)." }
        Assert-MigrationRecoveryNoSideEffects -Fixture $fixture -Journal $journal -Before $before -Case $case.Name
        Write-Host "Migration recovery rejects $($case.Name) without filesystem, metadata, journal, or SCM mutation PASS"
    } finally {
        Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Model the crash window after same-parent destination rename but before StatePublished is journaled.
$publishedCrashRecovery = New-MigrationFixture
try {
    $pendingRollback = $false
    try {
        Invoke-WeDecentStateMigration -Source $publishedCrashRecovery.Source -Destination $publishedCrashRecovery.Destination -AgentPath $agentPath -ServiceName $publishedCrashRecovery.ServiceName -ServiceSid $publishedCrashRecovery.ServiceSid -MetadataPath $publishedCrashRecovery.MetadataPath -JournalPath $publishedCrashRecovery.Journal -FaultAt 'Verified,RollbackServiceStopped' | Out-Null
    } catch {
        $pendingRollback = $_.Exception.Message -like '*durable rollback is pending*'
        if (-not $pendingRollback) { throw }
    }
    if (-not $pendingRollback) { throw 'Did not preserve the Verified journal boundary for destination-publication recovery.' }
    $pending = Read-WeDecentMigrationJournal -Path $publishedCrashRecovery.Journal
    if ($pending.phase -cne 'Verified' -or -not $pending.staging_complete -or -not (Test-Path -LiteralPath $pending.staging -PathType Container)) {
        throw 'Fixture did not retain the verified staging tree and pre-publication journal phase.'
    }
    [IO.Directory]::Move([string]$pending.staging, [string]$publishedCrashRecovery.Destination)
    if ((Test-Path -LiteralPath $pending.staging) -or -not (Test-Path -LiteralPath $publishedCrashRecovery.Destination -PathType Container)) {
        throw 'Could not model atomic destination publication before the StatePublished journal write.'
    }
    $afterRename = Read-WeDecentMigrationJournal -Path $publishedCrashRecovery.Journal
    if ($afterRename.phase -cne 'Verified') { throw 'Synthetic crash-state unexpectedly advanced the durable journal phase.' }
    Invoke-MigrationRecoveryInFreshPowerShell -Fixture $publishedCrashRecovery
    $global:WeDecentMigrationMockStatus = 'Running'
    $global:WeDecentMigrationMockService.State = 'Running'
    $global:WeDecentMigrationMockService.PathName = $publishedCrashRecovery.OriginalServicePath
    Assert-MigrationRolledBack -Fixture $publishedCrashRecovery -Fault 'fresh-process destination-publication recovery'
    Write-Host 'Migration coordinator recovers destination publication before StatePublished journal write in fresh process PASS (synthetic crash-state; SCM mocked)'
} finally {
    Remove-Item -LiteralPath $publishedCrashRecovery.Root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Windows state migration coordinator integration PASS'
