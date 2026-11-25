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


$rollbackAccountStart = $installer.IndexOf("if ($createdAccount)")
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

Write-Host 'Windows service installer contract PASS'
