[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'WeDecent'),
    [string]$StateDir = (Join-Path $env:ProgramData 'WeDecent\agent'),
    [ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')]
    [string]$ServiceName = 'WeDecentAgent',
    [switch]$Purge,
    [switch]$RemoveServiceAccount,
    [bool]$RemoveFromMachinePath = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Uninstall-WeDecent.ps1 must be run from an elevated PowerShell session.'
    }
}

function Assert-SafeChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path)).TrimEnd('\', '/')
    $rootFull = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Root)).TrimEnd('\', '/')
    if ($full -ieq $rootFull -or -not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be a child of $rootFull; got $full"
    }
    $cursor = $full
    while ($cursor.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label crosses a reparse point at $cursor"
            }
        }
        if ($cursor -ieq $rootFull) { break }
        $cursor = Split-Path -Parent $cursor
    }
    return $full
}

function Get-MetadataPath { Join-Path (Join-Path $env:ProgramData 'WeDecent') 'installer.json' }

function Assert-MetadataShape {
    param([Parameter(Mandatory = $true)]$Metadata)
    if ([int]$Metadata.schema -ne 1 -or [string]$Metadata.product -ne 'WeDecent') {
        throw 'Installer metadata has an unsupported schema or product.'
    }
    if ([string]$Metadata.service_name -notmatch '^[A-Za-z0-9_.-]{1,128}$') {
        throw 'Installer metadata contains an invalid service name.'
    }
    if ([string]$Metadata.service_account_name -notmatch '^[A-Za-z0-9_.-]{1,64}$') {
        throw 'Installer metadata contains an invalid service account name.'
    }
    try {
        $null = [Security.Principal.SecurityIdentifier]::new([string]$Metadata.service_account_sid)
    } catch {
        throw 'Installer metadata contains an invalid service account SID.'
    }
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

function Read-Metadata {
    $path = Get-MetadataPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $metadata = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        Assert-MetadataShape $metadata
        return $metadata
    } catch {
        throw "Cannot read installer metadata at $path : $($_.Exception.Message)"
    }
}

function Assert-StandardLocalAccount {
    param([Parameter(Mandatory = $true)]$LocalUser)
    $adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    if ($adminMembers | Where-Object { $_.SID -and $_.SID.Value -eq $LocalUser.SID.Value }) {
        throw "Refusing to remove installer ownership metadata for local administrator $($LocalUser.Name)."
    }
}

function Remove-MachinePathEntry {
    param([string]$PathEntry)
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($machine -split ';' | Where-Object {
        $_ -and $_.TrimEnd('\') -ine $PathEntry.TrimEnd('\')
    })
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'Machine')
}

function Set-ServiceLogonRight {
    param([string]$Sid, [bool]$Present)
    $work = Join-Path $env:TEMP ("wedecent-secedit-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $export = Join-Path $work 'export.inf'
    $apply = Join-Path $work 'apply.inf'
    $db = Join-Path $work 'rights.sdb'
    try {
        & secedit.exe /export /cfg $export /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit export failed with exit code $LASTEXITCODE" }
        $entries = New-Object System.Collections.Generic.List[string]
        $line = Get-Content -LiteralPath $export | Where-Object { $_ -match '^SeServiceLogonRight\s*=' } | Select-Object -First 1
        if ($line) {
            foreach ($entry in ((($line -split '=', 2)[1]) -split ',')) {
                $trimmed = $entry.Trim()
                if ($trimmed) { $entries.Add($trimmed) }
            }
        }
        $needle = "*$Sid"
        for ($i = $entries.Count - 1; $i -ge 0; $i--) {
            if ($entries[$i] -eq $needle -or $entries[$i] -eq $Sid) { $entries.RemoveAt($i) }
        }
        if ($Present) { $entries.Add($needle) }
        $rights = ($entries | Sort-Object -Unique) -join ','
        $content = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeServiceLogonRight = {0}
'@ -f $rights
        Set-Content -LiteralPath $apply -Value $content -Encoding Unicode
        & secedit.exe /configure /db $db /cfg $apply /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit configure failed with exit code $LASTEXITCODE" }
    } finally {
        Remove-Item -LiteralPath $work -Force -Recurse -ErrorAction SilentlyContinue
    }
}

Assert-Administrator
if ($RemoveServiceAccount -and -not $Purge) {
    throw '-RemoveServiceAccount requires -Purge so identity/state removal is explicit.'
}

$InstallDir = Assert-SafeChildPath -Path $InstallDir -Root $env:ProgramFiles -Label 'InstallDir'
$StateDir = Assert-SafeChildPath -Path $StateDir -Root (Join-Path $env:ProgramData 'WeDecent') -Label 'StateDir'
$metadataPath = Get-MetadataPath
$metadata = $null
if ($RemoveServiceAccount) { $metadata = Read-Metadata }
$accountToRemove = $null

# Destructive-account authorization is completed before stopping services or deleting files/state.
if ($RemoveServiceAccount) {
    if (-not $metadata) {
        throw 'Refusing service-account removal because installer metadata is missing.'
    }
    if (-not (Test-MetadataTrusted $metadataPath)) {
        throw 'Refusing service-account removal because installer metadata is not protected by a trusted ACL.'
    }
    if (-not [bool]$metadata.managed_service_account) {
        throw 'Refusing to remove a service account that is not recorded as installer-managed.'
    }
    if ([string]$metadata.service_name -cne $ServiceName) {
        throw 'Installer metadata service name does not match the requested service.'
    }
    $metadataInstallDir = [IO.Path]::GetFullPath([string]$metadata.install_dir).TrimEnd('\', '/')
    $metadataStateDir = [IO.Path]::GetFullPath([string]$metadata.state_dir).TrimEnd('\', '/')
    if ($metadataInstallDir -ine $InstallDir -or $metadataStateDir -ine $StateDir) {
        throw 'Installer metadata paths do not match the requested install/state paths.'
    }
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $accountToRemove = Get-LocalUser -Name ([string]$metadata.service_account_name) -ErrorAction SilentlyContinue
    if ($accountToRemove) {
        if ($accountToRemove.SID.Value -ne [string]$metadata.service_account_sid) {
            throw 'Service account SID no longer matches installer metadata; refusing account deletion.'
        }
        Assert-StandardLocalAccount $accountToRemove
    }
}

$agent = Join-Path $InstallDir 'wd-agent.exe'
$serviceInfo = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if ($serviceInfo) {
    $expectedAgent = '^(?:"' + [Regex]::Escape($agent) + '"|' + [Regex]::Escape($agent) + ')(?:\s|$)'
    if ($serviceInfo.PathName -notmatch $expectedAgent) {
        throw "Existing service binary path is not $agent; refusing to delete an unrelated service."
    }
}

$action = if ($Purge) { 'Uninstall WeDecent and purge device identity/state' } else { 'Uninstall WeDecent and preserve device identity/state' }
if ($RemoveServiceAccount) { $action += ' and remove the installer-managed service account' }
if (-not $PSCmdlet.ShouldProcess("$InstallDir and service '$ServiceName'", $action)) { return }

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    if (Test-Path -LiteralPath $agent -PathType Leaf) {
        & $agent service uninstall "--service-name=$ServiceName"
        if ($LASTEXITCODE -ne 0) { throw "wd-agent service uninstall failed with exit code $LASTEXITCODE" }
    } else {
        & sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE" }
    }
}

Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
if ($RemoveFromMachinePath) { Remove-MachinePathEntry $InstallDir }

if ($Purge) {
    Remove-Item -LiteralPath $StateDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($RemoveServiceAccount) {
    if ($accountToRemove) {
        Set-ServiceLogonRight -Sid $accountToRemove.SID.Value -Present $false
        Remove-LocalUser -Name $accountToRemove.Name
    }
    Remove-Item -LiteralPath $metadataPath -Force -ErrorAction SilentlyContinue
}

Write-Host 'WeDecent binaries and service removed.'
if (-not $Purge) {
    Write-Host "Preserved agent state: $StateDir"
}
if (-not $RemoveServiceAccount) {
    Write-Host 'Preserved service account. Use -Purge -RemoveServiceAccount only when permanent identity removal is intended.'
}
