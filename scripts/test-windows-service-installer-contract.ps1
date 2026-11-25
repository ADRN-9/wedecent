[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$installerPath = Join-Path $root 'installer/windows/Install-WeDecent.ps1'
$validationPath = Join-Path $root 'installer/windows/Test-WeDecentInstall.ps1'
$installer = Get-Content -LiteralPath $installerPath -Raw
$validation = Get-Content -LiteralPath $validationPath -Raw

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


Assert-Contains $installer 'function Test-DirectoryExistsStrict' 'Installer must distinguish a missing state path from an inaccessible or ambiguous path.'
Assert-Contains $installer 'function Test-ServiceStateSafeForAccountRemoval' 'Installer must centralize fail-closed account-removal checks.'
Assert-Contains $installer '$stateExisted = Test-DirectoryExistsStrict -Path $StateDir' 'Installer state existence must fail on ambiguous paths.'
Assert-Contains $installer 'Test-ServiceStateSafeForAccountRemoval -Path $StateDir' 'Account cleanup does not use the fail-closed state inspection helper.'

# Execute the actual helper function definitions extracted from installer source.
$installerAst = [System.Management.Automation.Language.Parser]::ParseInput($installer, [ref]$null, [ref]$null)
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
    param([string]$LiteralPath, [switch]$Force, [string]$ErrorAction)
    switch ($script:mockItemMode) {
        'missing' {
            $exception = [System.Management.Automation.ItemNotFoundException]::new('injected missing path')
            $record = [System.Management.Automation.ErrorRecord]::new(
                $exception, 'PathNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $LiteralPath
            )
            $PSCmdlet.ThrowTerminatingError($record)
        }
        'ambiguous' { throw [System.UnauthorizedAccessException]::new('injected ambiguous state-path access') }
        'file' { return [pscustomobject]@{ PSIsContainer = $false } }
        default { return [pscustomobject]@{ PSIsContainer = $true } }
    }
}
function Get-ChildItem {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force, [string]$ErrorAction)
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
$script:mockItemMode = 'file'
if (Test-ServiceStateSafeForAccountRemoval -Path 'C:\mock\WeDecent\Agent') {
    throw 'Non-directory state path was considered safe for account removal.'
}
$script:mockItemMode = 'missing'
if (-not (Test-ServiceStateSafeForAccountRemoval -Path 'C:\mock\WeDecent\Agent')) {
    throw 'Confirmed absent state path was not considered safe for account removal.'
}

Write-Host 'Windows service installer contract PASS'
