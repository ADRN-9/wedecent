[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$installerPath = Join-Path $root 'installer/windows/Install-WeDecent.ps1'
$validationPath = Join-Path $root 'installer/windows/Test-WeDecentInstall.ps1'
$installer = Get-Content -LiteralPath $installerPath -Raw
$validation = Get-Content -LiteralPath $validationPath -Raw
$uninstallerPath = Join-Path $root 'installer/windows/Uninstall-WeDecent.ps1'
$uninstaller = Get-Content -LiteralPath $uninstallerPath -Raw

function Assert-Contains([string]$Text, [string]$Needle, [string]$Message) {
    if (-not $Text.Contains($Needle)) { throw $Message }
}

foreach ($argument in @(
    '--pairing-recovery-authority-url=$RecoveryAuthorityUrl',
    '--pairing-recovery-authority-spki-sha256=$RecoveryAuthoritySPKISHA256',
    '--pairing-recovery-trust=$RecoveryAuthorityTrustFile',
    '--pairing-recovery-authority-token-stdin'
)) {
    Assert-Contains $installer $argument "Installer does not forward required service argument: $argument"
}

$passwordWrite = $installer.IndexOf('Write-SecureStringLine -Writer $process.StandardInput -SecureString $Password')
$bearerWrite = $installer.IndexOf('Write-SecureStringLine -Writer $process.StandardInput -SecureString $RecoveryBearerToken')
if ($passwordWrite -lt 0 -or $bearerWrite -le $passwordWrite) {
    throw 'Installer must stream the service password first and the recovery bearer second.'
}
if ($installer -match '--pairing-recovery-authority-token=') {
    throw 'Recovery bearer must never appear as a service command-line argument.'
}
Assert-Contains $installer '[Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pointer)' 'Secure credential unmanaged buffers are not zeroed.'
Assert-Contains $installer '[Array]::Clear($characters, 0, $characters.Length)' 'Secure credential character buffers are not zeroed.'
Assert-Contains $installer 'Remove-EmptyDirectory -Path $StateDir' 'Interrupted install rollback must remove only an empty state directory.'
if ($installer -match 'Remove-Item -LiteralPath \$StateDir -Recurse') {
    throw 'Interrupted install rollback must never recursively delete service identity/trust state.'
}

foreach ($argument in @(
    '--pairing-recovery-authority-url=',
    '--pairing-recovery-authority-spki-sha256=',
    '--pairing-recovery-trust=',
    '--pairing-recovery-authority-token-file='
)) {
    Assert-Contains $validation $argument "Installed-service validation does not check $argument"
}
Assert-Contains $validation 'recovery-authority.token' 'Installed-service validation does not inspect the protected bearer file.'
Assert-Contains $validation 'recovery-authority-trust.json' 'Installed-service validation does not inspect the protected trust copy.'


Assert-Contains $installer "[string]`$StateDir = (Join-Path `$InstallDir 'data\agent')" 'Fresh service state must default beneath the protected Program Files install root.'
Assert-Contains $installer "-Root `$InstallDir -Label 'StateDir'" 'Installer must reject service state outside the selected protected install root.'
Assert-Contains $installer 'Authenticated installer metadata exists but the service is absent' 'Fresh install must not regenerate identity when a previously managed service is missing.'
Assert-Contains $installer 'Legacy ProgramData service state exists; refusing to create a replacement identity' 'Fresh install must fail closed when legacy ProgramData state remains, regardless of metadata state.'
Assert-Contains $installer 'Existing service state location is not authenticated by protected installer metadata' 'Upgrade must fail closed when existing state location metadata is unavailable.'
Assert-Contains $installer 'Refusing to redirect or overwrite identity state' 'Upgrade must not silently redirect existing cryptographic state.'
Assert-Contains $installer 'Existing SCM command line does not match the authenticated state_dir metadata' 'Upgrade must verify the SCM state path matches authenticated metadata.'
Assert-Contains $uninstaller "[string]`$StateDir = (Join-Path `$InstallDir 'data\agent')" 'Uninstaller default must match the fresh-install state location.'
Assert-Contains $uninstaller '$StateDir = $metadataStateDir' 'Uninstaller must resolve existing state from authenticated metadata.'
Assert-Contains $uninstaller 'function Test-DirectoryExistsStrict' 'Purge must distinguish a missing state path from an inaccessible or ambiguous path.'
Assert-Contains $validation '$StateDir = $metadataStateDir' 'Installed-service validation must resolve the authenticated state path.'
Assert-Contains $validation 'Requested validation state path does not match authenticated installer metadata' 'Installed-service validation must reject a mismatched state path.'
Assert-Contains $uninstaller 'SCM state path does not match authenticated installer metadata' 'Uninstaller must verify service state path before removal.'
Assert-Contains $uninstaller '$stateFull.StartsWith' 'Uninstaller must preserve install subtrees containing protected state.'
if ($uninstaller -match 'Remove-Item -LiteralPath \$InstallDir -Recurse') {
    throw 'Uninstaller must not recursively delete the install directory containing service state.'
}
Assert-Contains $installer 'function Test-DirectoryExistsStrict' 'Installer must distinguish a missing state path from an inaccessible or ambiguous path.'
Assert-Contains $installer 'function Test-ServiceStateSafeForAccountRemoval' 'Installer must centralize fail-closed account-removal checks.'
Assert-Contains $installer '$stateExisted = Test-DirectoryExistsStrict -Path $StateDir' 'Installer state existence must fail on ambiguous paths.'
Assert-Contains $installer 'Test-ServiceStateSafeForAccountRemoval -Path $StateDir' 'Account cleanup does not use the fail-closed state inspection helper.'

# Execute the actual helper function definitions extracted from installer source.
$parseTokens = $null
$parseErrors = $null
$installerAst = [System.Management.Automation.Language.Parser]::ParseInput($installer, [ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Installer AST parse failed during state-path helper tests.' }
foreach ($functionName in @('Test-DirectoryExistsStrict', 'Test-ServiceStateSafeForAccountRemoval')) {
    $functionAst = $installerAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
    }, $true)
    if (-not $functionAst) { throw "Installer helper not found: $functionName" }
    . ([scriptblock]::Create($functionAst.Extent.Text))
}

$script:mockItemMode = 'directory'
$script:mockEntries = @()
$script:mockEnumerationFails = $false
function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force)
    switch ($script:mockItemMode) {
        'missing' {
            $exception = [System.Management.Automation.ItemNotFoundException]::new('injected missing path')
            $record = [System.Management.Automation.ErrorRecord]::new(
                $exception, 'PathNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $LiteralPath
            )
            $PSCmdlet.ThrowTerminatingError($record)
        }
        'ambiguous' { throw [System.UnauthorizedAccessException]::new('injected ambiguous state-path access') }
        'file' { return [pscustomobject]@{ PSIsContainer = $false; Attributes = [System.IO.FileAttributes]::Normal } }
        'reparse' { return [pscustomobject]@{ PSIsContainer = $true; Attributes = [System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReparsePoint } }
        default { return [pscustomobject]@{ PSIsContainer = $true; Attributes = [System.IO.FileAttributes]::Directory } }
    }
}
function Get-ChildItem {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force)
    if ($script:mockEnumerationFails) { throw 'injected state enumeration failure' }
    return $script:mockEntries
}

$script:mockItemMode = 'directory'
if (-not (Test-DirectoryExistsStrict -Path 'C:\mock\WeDecent\Agent')) {
    throw 'Existing state directory was reported absent.'
}
$script:mockItemMode = 'missing'
if (Test-DirectoryExistsStrict -Path 'C:\mock\WeDecent\Agent') {
    throw 'Missing state directory was reported present.'
}
$script:mockItemMode = 'reparse'
$reparseRejected = $false
try { [void](Test-DirectoryExistsStrict -Path 'C:\mock\WeDecent\Agent') } catch { $reparseRejected = $true }
if (-not $reparseRejected) { throw 'Reparse state directory was accepted as a normal directory.' }
$script:mockItemMode = 'ambiguous'
$ambiguousRejected = $false
try { [void](Test-DirectoryExistsStrict -Path 'C:\mock\WeDecent\Agent') } catch { $ambiguousRejected = $true }
if (-not $ambiguousRejected) { throw 'Ambiguous state-path existence was treated as absence.' }

$script:mockItemMode = 'directory'
$script:mockEntries = @('identity.key.dpapi')
if (Test-ServiceStateSafeForAccountRemoval -Path 'C:\mock\WeDecent\Agent') {
    throw 'Non-empty protected state was considered safe for account removal.'
}
$script:mockEntries = @()
if (-not (Test-ServiceStateSafeForAccountRemoval -Path 'C:\mock\WeDecent\Agent')) {
    throw 'Confirmed empty state directory was not considered safe for account removal.'
}
$script:mockEnumerationFails = $true
if (Test-ServiceStateSafeForAccountRemoval -Path 'C:\mock\WeDecent\Agent') {
    throw 'State enumeration failure was considered safe for account removal.'
}
$script:mockEnumerationFails = $false
$script:mockItemMode = 'ambiguous'
if (Test-ServiceStateSafeForAccountRemoval -Path 'C:\mock\WeDecent\Agent') {
    throw 'Ambiguous state-path existence was considered safe for account removal.'
}
$script:mockItemMode = 'reparse'
if (Test-ServiceStateSafeForAccountRemoval -Path 'C:\mock\WeDecent\Agent') {
    throw 'Reparse state directory was considered safe for account removal.'
}
$script:mockItemMode = 'file'
if (Test-ServiceStateSafeForAccountRemoval -Path 'C:\mock\WeDecent\Agent') {
    throw 'Non-directory state path was considered safe for account removal.'
}
$script:mockItemMode = 'missing'
if (-not (Test-ServiceStateSafeForAccountRemoval -Path 'C:\mock\WeDecent\Agent')) {
    throw 'Confirmed absent state path was not considered safe for account removal.'
}


# Exercise durable migration journal and complete-tree SHA-256 copy primitives.
$migrationModule = Join-Path (Split-Path -Parent $installerPath) 'StateMigration.psm1'
Import-Module $migrationModule -Force
$migrationRoot = Join-Path ([IO.Path]::GetTempPath()) ('wedecent-migration-' + [Guid]::NewGuid().ToString('N'))
$sourceState = Join-Path $migrationRoot 'source'
$stageState = Join-Path $migrationRoot 'stage'
$journalPath = Join-Path $migrationRoot 'migration.json'
New-Item -ItemType Directory -Path (Join-Path $sourceState 'nested') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $sourceState 'empty') -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $sourceState 'identity.key.dpapi'), 'synthetic-identity-bytes')
[IO.File]::WriteAllText((Join-Path $sourceState 'identity.crt'), 'synthetic-ed25519-certificate-bytes')
$serviceSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Set-WeDecentMigrationDirectoryAcl -Path $sourceState -ServiceSid $serviceSid
[IO.File]::WriteAllText((Join-Path $sourceState 'nested/recovery-authority.token'), 'synthetic-recovery-bytes')
try {
    $copy = Copy-WeDecentMigrationTreeVerified -Source $sourceState -Staging $stageState -SourceServiceSid $serviceSid -DestinationServiceSid $serviceSid
    if ($copy.FileCount -ne 3 -or $copy.DirectoryCount -ne 2 -or
        [string]::IsNullOrWhiteSpace($copy.SourceManifestSHA256)) {
        throw 'Verified state-tree copy returned an invalid manifest.'
    }

    $journal = [pscustomobject]@{
        schema = 1
        product = 'WeDecent'
        transaction_id = [Guid]::NewGuid().ToString('D')
        phase = 'Prepared'
        source = $sourceState
        destination = (Join-Path $migrationRoot 'destination')
        staging = $stageState
        original_service_path = 'synthetic-original-service-command'
        updated_service_path = 'synthetic-updated-service-command'
        source_manifest_sha256 = $copy.SourceManifestSHA256
        updated_utc = ''
    }
    foreach ($phase in @(
        'Prepared', 'Copying', 'Copied', 'Verified', 'StatePublished',
        'ServiceReconfigured', 'Committed', 'RollingBack', 'RolledBack'
    )) {
        $journal.phase = $phase
        Write-WeDecentMigrationJournal -Path $journalPath -Journal $journal
        $recovered = Read-WeDecentMigrationJournal -Path $journalPath
        if ($recovered.phase -cne $phase -or
            $recovered.transaction_id -cne $journal.transaction_id) {
            throw "Migration journal did not durably round-trip phase $phase."
        }
    }

    $invalidPhaseRejected = $false
    $journal.phase = 'Unknown'
    try { Write-WeDecentMigrationJournal -Path $journalPath -Journal $journal } catch { $invalidPhaseRejected = $true }
    if (-not $invalidPhaseRejected) { throw 'Migration journal accepted an unknown phase.' }

    $corruptJournalRejected = $false
    [IO.File]::WriteAllText($journalPath, '{"schema":99,"product":"WeDecent","phase":"Prepared"}')
    try { [void](Read-WeDecentMigrationJournal -Path $journalPath) } catch { $corruptJournalRejected = $true }
    if (-not $corruptJournalRejected) { throw 'Migration journal accepted an unsupported schema.' }

    $manifest = @(Get-WeDecentMigrationManifest -Root $stageState)
    [IO.File]::WriteAllText((Join-Path $stageState 'identity.key.dpapi'), 'tampered-identity-bytes')
    $tamperedManifest = @(Get-WeDecentMigrationManifest -Root $stageState)
    if ((Get-WeDecentMigrationManifestDigest -Manifest $manifest) -ceq
        (Get-WeDecentMigrationManifestDigest -Manifest $tamperedManifest)) {
        throw 'Migration manifest failed to detect changed identity bytes.'
    }

    $junctionRejected = $false
    $junction = Join-Path $sourceState 'junction'
    try {
        New-Item -ItemType Junction -Path $junction -Target $stageState -ErrorAction Stop | Out-Null
        try { [void](Get-WeDecentMigrationManifest -Root $sourceState) } catch { $junctionRejected = $true }
    } catch {
        Write-Warning "Junction fixture unavailable; reparse rejection was not exercised: $($_.Exception.Message)"
    }
    if ((Test-Path -LiteralPath $junction) -and -not $junctionRejected) {
        throw 'Migration manifest accepted a directory junction.'
    }
} finally {
    Remove-Item -LiteralPath $migrationRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Windows service installer contract PASS'
