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
    param([string]$Name, [switch]$ErrorAction)
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
    param([string]$Name, [switch]$Force, [string]$ErrorAction)
    if ($Name -cne $global:WeDecentMigrationMockService.Name) { throw "Unexpected service stop: $Name" }
    $global:WeDecentMigrationMockStatus = 'Stopped'
    $global:WeDecentMigrationMockService.State = 'Stopped'
}
function global:Start-Service {
    [CmdletBinding()]
    param([string]$Name, [string]$ErrorAction)
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
}
$forwardFaults = @('Prepared','ServiceStopped','Copying','Copied','IdentityProtected','Verified','StatePublished','ServiceReconfigured','MetadataUpdated','ServiceRestarted')
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
    Write-Host 'Migration coordinator durable recovery PASS'
} finally {
    Remove-Item -LiteralPath $recovery.Root -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'Windows state migration coordinator integration PASS'
