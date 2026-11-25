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


$rollbackAccountStart = $installer.IndexOf('if ($createdAccount)')
$rollbackFailureEnd = $installer.IndexOf('throw "Fresh installation failed;', $rollbackAccountStart)
if ($rollbackAccountStart -lt 0 -or $rollbackFailureEnd -le $rollbackAccountStart) {
    throw 'Cannot locate fresh-install rollback account cleanup block.'
}
$rollbackAccountBlock = $installer.Substring($rollbackAccountStart, $rollbackFailureEnd - $rollbackAccountStart)
$stateGuard = $rollbackAccountBlock.IndexOf('if ($stateContainsProtectedMaterial)')
$accountRemoval = $rollbackAccountBlock.IndexOf('Remove-LocalUser -Name $ServiceAccountName')
if ($stateGuard -lt 0 -or $accountRemoval -le $stateGuard) {
    throw 'Rollback can remove the service account before checking surviving protected state.'
}
Assert-Contains $rollbackAccountBlock '$remainingState.Count -gt 0' 'Rollback does not detect non-empty protected state.'
Assert-Contains $rollbackAccountBlock '$stateContainsProtectedMaterial = $true' 'Rollback must fail closed when state enumeration fails.'
Assert-Contains $rollbackAccountBlock 'Retaining installer-created service account' 'Rollback must retain the service account when state survives.'
$elseStart = $rollbackAccountBlock.IndexOf('} else {', $stateGuard)
if ($elseStart -lt 0 -or $accountRemoval -lt $elseStart) {
    throw 'Service account removal is not confined to the empty-state branch.'
}


# Fault-inject the cleanup contract after structural checks bind it to installer source.
function Invoke-RollbackAccountCleanup {
    $stateContainsProtectedMaterial = $false
    if (Test-Path -LiteralPath $StateDir) {
        try {
            $remainingState = @(Get-ChildItem -LiteralPath $StateDir -Force -ErrorAction Stop)
            $stateContainsProtectedMaterial = $remainingState.Count -gt 0
        } catch {
            $stateContainsProtectedMaterial = $true
        }
    }
    if ($stateContainsProtectedMaterial) {
        Write-Warning "Retaining installer-created service account '$ServiceAccountName'."
    } else {
        Remove-LocalUser -Name $ServiceAccountName -ErrorAction Stop
    }
}

$script:mockStateExists = $true
$script:mockStateReadFails = $false
$script:mockStateEntries = @()
$script:removedAccounts = @()
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath)
    return $script:mockStateExists
}
function Get-ChildItem {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force)
    if ($script:mockStateReadFails) { throw 'injected state enumeration failure' }
    return $script:mockStateEntries
}
function Remove-LocalUser {
    [CmdletBinding()]
    param([string]$Name)
    $script:removedAccounts += $Name
}
function Write-Warning {
    [CmdletBinding()]
    param([string]$Message)
}

$StateDir = 'C:\mock\WeDecent\Agent'
$ServiceAccountName = 'WeDecentSvc'
$script:mockStateEntries = @('identity.key.dpapi')
Invoke-RollbackAccountCleanup
if ($script:removedAccounts.Count -ne 0) {
    throw 'Rollback deleted the service account while protected state remained.'
}

$script:mockStateReadFails = $true
Invoke-RollbackAccountCleanup
if ($script:removedAccounts.Count -ne 0) {
    throw 'Rollback deleted the service account when protected state could not be inspected.'
}

$script:mockStateReadFails = $false
$script:mockStateEntries = @()
Invoke-RollbackAccountCleanup
if ($script:removedAccounts.Count -ne 1 -or $script:removedAccounts[0] -ne $ServiceAccountName) {
    throw 'Rollback did not remove the service account after proving state empty.'
}

$script:mockStateExists = $false
Invoke-RollbackAccountCleanup
if ($script:removedAccounts.Count -ne 2) {
    throw 'Rollback did not remove the service account when no state directory existed.'
}

Write-Host 'Windows service installer contract PASS'
