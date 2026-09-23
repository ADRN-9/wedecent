[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'WeDecent'),
    [string]$StateDir = (Join-Path $env:ProgramData 'WeDecent\agent'),
    [ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')]
    [string]$ServiceName = 'WeDecentAgent',
    [string]$WebRelay = 'https://relay.wedecent.com',
    [switch]$RequireManagedServiceAccount
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$binaryNames = @('wd.exe', 'wd-agent.exe', 'wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe')

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Assert-True $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'Validation must run from an elevated PowerShell session.'
}

function Get-LocalAccountName {
    param([Parameter(Mandatory = $true)][string]$Account)
    $value = $Account.Trim()
    $localPrefix = "$env:COMPUTERNAME\"
    if ($value.StartsWith('.\', [StringComparison]::OrdinalIgnoreCase)) { return $value.Substring(2) }
    if ($value.StartsWith($localPrefix, [StringComparison]::OrdinalIgnoreCase)) { return $value.Substring($localPrefix.Length) }
    return $null
}

function Test-MetadataTrusted {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { return $false }
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    try {
        $ownerSid = (New-Object Security.Principal.NTAccount -ArgumentList $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $false
    }
    if ($trusted -notcontains $ownerSid) { return $false }
    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            return $false
        }
        if ($trusted -notcontains $sid) { return $false }
    }
    return $true
}

function Test-ServiceLogonRight {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][string]$AccountName
    )
    $work = Join-Path $env:TEMP ("wedecent-secedit-check-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $export = Join-Path $work 'export.inf'
    try {
        & secedit.exe /export /cfg $export /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit export failed with exit code $LASTEXITCODE" }
        $line = Get-Content -LiteralPath $export | Where-Object { $_ -match '^SeServiceLogonRight\s*=' } | Select-Object -First 1
        if (-not $line) { return $false }
        $needle = "*$Sid"
        $accountForms = @(
            $AccountName,
            ".\$AccountName",
            "$env:COMPUTERNAME\$AccountName"
        )
        foreach ($entry in ((($line -split '=', 2)[1]) -split ',')) {
            $trimmed = $entry.Trim()
            if ($trimmed -eq $needle -or $trimmed -eq $Sid -or $accountForms -contains $trimmed) { return $true }
        }
        return $false
    } finally {
        Remove-Item -LiteralPath $work -Force -Recurse -ErrorAction SilentlyContinue
    }
}

Assert-Administrator
$binaryPaths = @{}
foreach ($name in $binaryNames) {
    $path = Join-Path $InstallDir $name
    $binaryPaths[$name] = $path
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "Missing $path"
}
$wd = $binaryPaths['wd.exe']
$agent = $binaryPaths['wd-agent.exe']
$metadataPath = Join-Path (Join-Path $env:ProgramData 'WeDecent') 'installer.json'
Assert-True (Test-Path -LiteralPath $StateDir -PathType Container) "Missing state directory $StateDir"
Assert-True (Test-Path -LiteralPath $metadataPath -PathType Leaf) "Missing installer metadata $metadataPath"
Assert-True (Test-MetadataTrusted $metadataPath) 'Installer metadata ACL/owner is not trusted'

foreach ($name in $binaryNames) {
    & $binaryPaths[$name] version
    if ($LASTEXITCODE -ne 0) { throw "$name version failed" }
}

$services = @(Get-CimInstance Win32_Service)
$service = $services | Where-Object { $_.Name -ceq $ServiceName } | Select-Object -First 1
Assert-True ($null -ne $service) "Service $ServiceName is missing"
Assert-True ($service.State -eq 'Running') "Service $ServiceName is not running"
Assert-True ($service.StartMode -eq 'Auto') "Service $ServiceName is not automatic"
Assert-True ($service.StartName -notmatch '^(LocalSystem|LocalService|NetworkService|NT AUTHORITY\\(SYSTEM|LocalService|NetworkService))$') 'Service uses a forbidden built-in identity'
$expectedAgent = '^(?:"' + [Regex]::Escape($agent) + '"|' + [Regex]::Escape($agent) + ')(?:\s|$)'
Assert-True ($service.PathName -match $expectedAgent) 'Service binary path does not point at the installed wd-agent.exe'
Assert-True ($service.PathName -match [Regex]::Escape('--listen=')) 'Service is missing explicit outbound-only --listen= configuration'
Assert-True ($service.PathName -match [Regex]::Escape("--web-relay=$WebRelay")) "Service is not configured for expected web relay $WebRelay"

foreach ($name in @('wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe')) {
    $pathPattern = '^(?:"' + [Regex]::Escape($binaryPaths[$name]) + '"|' + [Regex]::Escape($binaryPaths[$name]) + ')(?:\s|$)'
    $unexpected = @($services | Where-Object { $_.PathName -match $pathPattern })
    Assert-True ($unexpected.Count -eq 0) "$name must not be registered as a Windows service"
}

$localName = Get-LocalAccountName $service.StartName
Assert-True (-not [string]::IsNullOrWhiteSpace($localName)) 'Service does not run as a dedicated local account'
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
$localUser = Get-LocalUser -Name $localName -ErrorAction Stop
$adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
$isAdmin = [bool]($adminMembers | Where-Object { $_.SID -and $_.SID.Value -eq $localUser.SID.Value })
Assert-True (-not $isAdmin) 'Service account is a member of the local Administrators group'
Assert-True (Test-ServiceLogonRight -Sid $localUser.SID.Value -AccountName $localName) 'Service account is missing SeServiceLogonRight'

$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
Assert-True ([int]$metadata.schema -eq 1) 'Installer metadata schema is not supported'
Assert-True ([string]$metadata.product -eq 'WeDecent') 'Installer metadata product is invalid'
Assert-True ([string]$metadata.service_name -ceq $ServiceName) 'Installer metadata service name does not match'
Assert-True ([string]$metadata.service_account_sid -eq $localUser.SID.Value) 'Installer metadata account SID does not match the running service account'
if ($RequireManagedServiceAccount) {
    Assert-True ([bool]$metadata.managed_service_account) 'Fresh-install validation expected an installer-managed service account'
}

$acl = Get-Acl -LiteralPath $StateDir
$bad = @($acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Value -match '(^|\\)(Everyone|Users|Authenticated Users)$'
})
Assert-True ($bad.Count -eq 0) 'State directory grants broad access to a user group'

& $agent service status "--service-name=$ServiceName"
if ($LASTEXITCODE -ne 0) { throw 'wd-agent service status failed' }

Write-Host 'WeDecent Windows installation validation PASS'
