[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$BundlePath,
    [string]$TransactionId,
    [string]$ExpectedPackageSHA256,
    [string]$ExpectedManifestSHA256,
    [string]$PreviousVersion,
    [UInt64]$TransactionSequence = 0,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'WeDecent'),
    [string]$StateDir = (Join-Path $InstallDir 'data\agent'),
    [ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')]
    [string]$ServiceName = 'WeDecentAgent',
    [string]$DisplayName = 'WeDecent Agent',
    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$ServiceAccountName = 'WeDecentSvc',
    [string]$WebRelay = 'https://relay.wedecent.com',
    [string]$RecoveryAuthorityUrl = $env:WEDECENT_PAIRING_RECOVERY_AUTHORITY_URL,
    [string]$RecoveryAuthoritySPKISHA256 = $env:WEDECENT_PAIRING_RECOVERY_AUTHORITY_SPKI_SHA256,
    [string]$RecoveryAuthorityTrustFile,
    [Security.SecureString]$RecoveryAuthorityBearerToken,
    [ValidateRange(1, 32)]
    [int]$RelaySlots = 4,
    [string]$DeviceName = $env:COMPUTERNAME,
    [string]$Shell = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),
    [bool]$AddToMachinePath = $true,
    [System.Management.Automation.PSCredential]$ServiceAccountCredential,
    [switch]$AdoptExistingServiceAccount
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:BinaryNames = @('wd.exe', 'wd-agent.exe', 'wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe')
$script:VerifiedBinaryHashes = @{}
if ($TransactionId -and ($TransactionId -notmatch '^[a-f0-9]{32}$' -or $ExpectedPackageSHA256 -notmatch '^[a-f0-9]{64}$' -or $ExpectedManifestSHA256 -notmatch '^[a-f0-9]{64}$' -or $PreviousVersion -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or $TransactionSequence -eq 0)) {
    throw 'The installer transaction ID, package digest and sequence are invalid or incomplete.'
}
if (-not $TransactionId -and ($ExpectedPackageSHA256 -or $ExpectedManifestSHA256 -or $PreviousVersion -or $TransactionSequence -ne 0)) {
    throw 'Installer transaction parameters must be supplied together.'
}
$script:IsManagedUpdate = -not [string]::IsNullOrWhiteSpace($TransactionId)
if (-not $TransactionId) { $TransactionId = [Guid]::NewGuid().ToString('N') }
$script:InstallTransactionId = $TransactionId
$script:InstallTransactionSequence = $TransactionSequence
$script:InstallJournal = $null

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Install-WeDecent.ps1 must be run from an elevated PowerShell session.'
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

function Get-WeDecentMetadataPath {
    $root = Join-Path $env:ProgramData 'WeDecent'
    return Join-Path $root 'installer.json'
}

function Protect-WeDecentMetadataAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-WeDecentMetadataTrusted {
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

function Assert-WeDecentMetadataShape {
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

function Set-WeDecentUpdateStateAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$TrustedSids,
        [bool]$Directory = $false
    )
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sidText in @($TrustedSids | Sort-Object -Unique)) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
        if ($Directory) {
            $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
                [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow
            )
        } else {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow
            )
        }
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Initialize-WeDecentUpdateState {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ServiceSid
    )
    if ($script:IsManagedUpdate) { return }
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $installOwner = (Get-Acl -LiteralPath $InstallDir).Owner
    $installOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $installOwner).Translate([Security.Principal.SecurityIdentifier]).Value
    $stateDirectorySids = @('S-1-5-18', 'S-1-5-32-544', $ServiceSid, $installOwnerSid)
    Set-WeDecentUpdateStateAcl -Path $StateDir -TrustedSids $stateDirectorySids -Directory $true

    $path = Join-Path $StateDir 'update-state.json'
    $state = $null
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Existing update state must be a regular non-reparse file.'
        }
        $state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($null -ne $state.pending_install) {
            throw 'An interrupted verified update must be recovered before installer state initialization.'
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$state.installed_version) -and
            [string]$state.installed_version -ne $Version) {
            throw 'Installed-version authority does not match the requested installer; use the verified updater path.'
        }
        if ([string]::IsNullOrWhiteSpace([string]$state.installed_version)) {
            $state | Add-Member -NotePropertyName installed_version -NotePropertyValue $Version
        }
    } else {
        $state = [ordered]@{
            version = 1
            stable_sequence = 0
            installed_version = $Version
        }
    }

    $temp = Join-Path $StateDir ('.update-state-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $json = ($state | ConvertTo-Json -Depth 8 -Compress) + "`n"
    [IO.File]::WriteAllText($temp, $json, (New-Object Text.UTF8Encoding($false)))
    $stateOwner = (Get-Acl -LiteralPath $StateDir).Owner
    $stateOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $stateOwner).Translate([Security.Principal.SecurityIdentifier]).Value
    Set-WeDecentUpdateStateAcl -Path $temp -TrustedSids @('S-1-5-18', 'S-1-5-32-544', $ServiceSid, $stateOwnerSid)
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $backup = Join-Path $StateDir ('.update-state-' + [Guid]::NewGuid().ToString('N') + '.previous')
        [IO.File]::Replace($temp, $path, $backup, $true)
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    } else {
        [IO.File]::Move($temp, $path)
    }
    Set-WeDecentUpdateStateAcl -Path $path -TrustedSids @('S-1-5-18', 'S-1-5-32-544', $ServiceSid, $stateOwnerSid)
}

function Read-WeDecentMetadata {
    $path = Get-WeDecentMetadataPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $metadata = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        Assert-WeDecentMetadataShape $metadata
        return $metadata
    } catch {
        throw "Cannot read existing installer metadata at $path : $($_.Exception.Message)"
    }
}

function Write-WeDecentMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$AccountSid,
        [Parameter(Mandatory = $true)][bool]$ManagedAccount,
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][string]$Version
    )
    $path = Get-WeDecentMetadataPath
    $parent = Split-Path -Parent $path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $payload = [ordered]@{
        schema                  = 1
        product                 = 'WeDecent'
        version                 = $Version
        service_name            = $ServiceName
        service_account_name    = $AccountName
        service_account_sid     = $AccountSid
        managed_service_account = $ManagedAccount
        install_dir             = $InstallDir
        state_dir               = $StateDir
        updated_at              = [DateTime]::UtcNow.ToString('o')
    }
    $temp = Join-Path $parent ('.installer-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $null
    try {
        $payload | ConvertTo-Json | Set-Content -LiteralPath $temp -Encoding UTF8
        Protect-WeDecentMetadataAcl $temp
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $backup = Join-Path $parent ('.installer-' + [Guid]::NewGuid().ToString('N') + '.bak')
            [IO.File]::Replace($temp, $path, $backup, $true)
        } else {
            Move-Item -LiteralPath $temp -Destination $path
        }
        Protect-WeDecentMetadataAcl $path
    } finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        if ($backup) { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
    }
}

function Get-LocalAccountName {
    param([Parameter(Mandatory = $true)][string]$Account)
    $value = $Account.Trim()
    $localPrefix = "$env:COMPUTERNAME\"
    if ($value.StartsWith('.\', [StringComparison]::OrdinalIgnoreCase)) { return $value.Substring(2) }
    if ($value.StartsWith($localPrefix, [StringComparison]::OrdinalIgnoreCase)) { return $value.Substring($localPrefix.Length) }
    return $null
}

function Assert-StandardLocalAccount {
    param([Parameter(Mandatory = $true)]$LocalUser)
    $adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    if ($adminMembers | Where-Object { $_.SID -and $_.SID.Value -eq $LocalUser.SID.Value }) {
        throw "Refusing to run the terminal service as local administrator $($LocalUser.Name)."
    }
}

function Get-ManifestHashes {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)
    $result = @{}
    foreach ($line in Get-Content -LiteralPath $ManifestPath) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^(?<hash>[0-9A-Fa-f]{64})\s+\*?(?<name>.+)$') {
            throw "Malformed checksum line in $ManifestPath : $line"
        }
        $name = [IO.Path]::GetFileName($Matches['name'].Trim())
        if ($result.ContainsKey($name)) {
            throw "Duplicate checksum entry for $name"
        }
        $result[$name] = $Matches['hash'].ToLowerInvariant()
    }
    return $result
}

function Get-Sha256FileHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($stream)
        return ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Assert-ReleaseBundle {
    $required = @($script:BinaryNames + @('VERSION.txt', 'SHA256SUMS.txt'))
    foreach ($name in $required) {
        $path = Join-Path $BundlePath $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Release bundle is missing $name at $path"
        }
    }

    $hashes = Get-ManifestHashes (Join-Path $BundlePath 'SHA256SUMS.txt')
    $verifiedHashes = @{}
    foreach ($name in $script:BinaryNames) {
        if (-not $hashes.ContainsKey($name)) {
            throw "SHA256SUMS.txt has no entry for $name"
        }
        $actual = Get-Sha256FileHash (Join-Path $BundlePath $name)
        if ($actual -ne $hashes[$name]) {
            throw "Checksum mismatch for $name"
        }
        $verifiedHashes[$name] = $hashes[$name]
    }
    $script:VerifiedBinaryHashes = $verifiedHashes

    $versionLine = Get-Content -LiteralPath (Join-Path $BundlePath 'VERSION.txt') |
        Where-Object { $_ -like 'version=*' } |
        Select-Object -First 1
    if (-not $versionLine) {
        throw 'VERSION.txt is missing version= metadata'
    }
    return $versionLine.Substring('version='.Length).Trim()
}

function Get-CryptoInt {
    param([Parameter(Mandatory = $true)][int]$UpperExclusive)
    if ($UpperExclusive -lt 1) { throw 'UpperExclusive must be positive' }
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] 4
        $range = [uint64]4294967296
        $limit = $range - ($range % [uint64]$UpperExclusive)
        do {
            $rng.GetBytes($bytes)
            $value = [BitConverter]::ToUInt32($bytes, 0)
        } while ([uint64]$value -ge $limit)
        return [int]([uint64]$value % [uint64]$UpperExclusive)
    } finally {
        $rng.Dispose()
    }
}

function New-ServiceAccountPassword {
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower = 'abcdefghijkmnopqrstuvwxyz'
    $digit = '23456789'
    $symbol = '!@#$%_-+='
    $all = $upper + $lower + $digit + $symbol
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($set in @($upper, $lower, $digit, $symbol)) {
        $chars.Add($set[(Get-CryptoInt $set.Length)])
    }
    while ($chars.Count -lt 32) {
        $chars.Add($all[(Get-CryptoInt $all.Length)])
    }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-CryptoInt ($i + 1)
        $tmp = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $tmp
    }
    return -join $chars
}

function Assert-SecureStringLine {
    param(
        [Parameter(Mandatory = $true)][Security.SecureString]$SecureString,
        [Parameter(Mandatory = $true)][int]$MinimumLength,
        [Parameter(Mandatory = $true)][int]$MaximumLength,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$RejectEdgeWhitespace
    )
    if ($SecureString.Length -lt $MinimumLength -or $SecureString.Length -gt $MaximumLength) {
        throw "$Label length must be between $MinimumLength and $MaximumLength characters."
    }
    $pointer = [IntPtr]::Zero
    $characters = $null
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
        $characters = New-Object char[] $SecureString.Length
        for ($i = 0; $i -lt $characters.Length; $i++) {
            $characters[$i] = [char][Runtime.InteropServices.Marshal]::ReadInt16($pointer, $i * 2)
            if ($characters[$i] -eq [char]10 -or $characters[$i] -eq [char]13) {
                throw "$Label must not contain newline characters."
            }
        }
        if ($RejectEdgeWhitespace -and
            ([char]::IsWhiteSpace($characters[0]) -or [char]::IsWhiteSpace($characters[$characters.Length - 1]))) {
            throw "$Label must not contain leading or trailing whitespace."
        }
    } finally {
        if ($characters) { [Array]::Clear($characters, 0, $characters.Length) }
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pointer)
        }
    }
}

function Write-SecureStringLine {
    param(
        [Parameter(Mandatory = $true)][IO.StreamWriter]$Writer,
        [Parameter(Mandatory = $true)][Security.SecureString]$SecureString
    )
    $pointer = [IntPtr]::Zero
    $characters = $null
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
        $characters = New-Object char[] $SecureString.Length
        for ($i = 0; $i -lt $characters.Length; $i++) {
            $characters[$i] = [char][Runtime.InteropServices.Marshal]::ReadInt16($pointer, $i * 2)
        }
        $Writer.Write($characters)
        $Writer.WriteLine()
    } finally {
        if ($characters) { [Array]::Clear($characters, 0, $characters.Length) }
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pointer)
        }
    }
}

function Resolve-AccountSid {
    param([Parameter(Mandatory = $true)][string]$Account)
    $localName = Get-LocalAccountName $Account
    if (-not $localName) {
        throw "Installer-managed services must use a dedicated local account; got '$Account'."
    }
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $localUser = Get-LocalUser -Name $localName -ErrorAction Stop
    Assert-StandardLocalAccount $localUser
    return $localUser.SID.Value
}

function Test-ServiceLogonRight {
    param([Parameter(Mandatory = $true)][string]$Sid)
    $work = Join-Path $env:TEMP ("wedecent-secedit-check-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $export = Join-Path $work 'export.inf'
    try {
        & secedit.exe /export /cfg $export /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit export failed with exit code $LASTEXITCODE" }
        $line = Get-Content -LiteralPath $export |
            Where-Object { $_ -match '^SeServiceLogonRight\s*=' } |
            Select-Object -First 1
        if (-not $line) { return $false }
        $needle = "*$Sid"
        foreach ($entry in ((($line -split '=', 2)[1]) -split ',')) {
            $trimmed = $entry.Trim()
            if ($trimmed -eq $needle -or $trimmed -eq $Sid) { return $true }
        }
        return $false
    } finally {
        Remove-Item -LiteralPath $work -Force -Recurse -ErrorAction SilentlyContinue
    }
}

function Set-ServiceLogonRight {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][bool]$Present
    )
    $work = Join-Path $env:TEMP ("wedecent-secedit-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $export = Join-Path $work 'export.inf'
    $apply = Join-Path $work 'apply.inf'
    $db = Join-Path $work 'rights.sdb'
    try {
        & secedit.exe /export /cfg $export /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit export failed with exit code $LASTEXITCODE" }

        $entries = New-Object System.Collections.Generic.List[string]
        $line = Get-Content -LiteralPath $export |
            Where-Object { $_ -match '^SeServiceLogonRight\s*=' } |
            Select-Object -First 1
        if ($line) {
            $rhs = ($line -split '=', 2)[1]
            foreach ($entry in ($rhs -split ',')) {
                $trimmed = $entry.Trim()
                if ($trimmed) { $entries.Add($trimmed) }
            }
        }

        $needle = "*$Sid"
        for ($i = $entries.Count - 1; $i -ge 0; $i--) {
            if ($entries[$i] -eq $needle -or $entries[$i] -eq $Sid) {
                $entries.RemoveAt($i)
            }
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

function Quote-WindowsArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') {
            $slashes++
            continue
        }
        if ($ch -eq '"') {
            [void]$builder.Append(('\' * (($slashes * 2) + 1)))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append(('\' * $slashes))
            $slashes = 0
        }
        [void]$builder.Append($ch)
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * ($slashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-AgentServiceInstall {
    param(
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [Parameter(Mandatory = $true)][Security.SecureString]$Password,
        [Parameter(Mandatory = $true)][Security.SecureString]$RecoveryBearerToken
    )
    $arguments = @(
        'service', 'install',
        "--service-name=$ServiceName",
        "--display-name=$DisplayName",
        "--account=.\$ServiceAccountName",
        '--account-password-stdin',
        "--state=$StateDir",
        "--name=$DeviceName",
        '--listen=',
        "--web-relay=$WebRelay",
        "--relay-slots=$RelaySlots",
        "--shell=$Shell",
        "--pairing-recovery-authority-url=$RecoveryAuthorityUrl",
        "--pairing-recovery-authority-spki-sha256=$RecoveryAuthoritySPKISHA256",
        "--pairing-recovery-trust=$RecoveryAuthorityTrustFile",
        '--pairing-recovery-authority-token-stdin',
        '--automatic=true',
        '--start=true'
    )
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $AgentPath
    $psi.Arguments = (($arguments | ForEach-Object { Quote-WindowsArgument $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'Failed to start wd-agent.exe service installer' }
    try {
        Write-SecureStringLine -Writer $process.StandardInput -SecureString $Password
        Write-SecureStringLine -Writer $process.StandardInput -SecureString $RecoveryBearerToken
        $process.StandardInput.Close()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
    } finally {
        if (-not $process.HasExited) {
            try { $process.StandardInput.Close() } catch {}
            try { $process.Kill() } catch {}
            $process.WaitForExit()
        }
        $process.Dispose()
    }
    if ($exitCode -ne 0) {
        throw "wd-agent.exe service install failed with exit code $exitCode"
    }
}

function Install-Binary {
    param([string]$Source, [string]$Destination, [bool]$HadOriginal)
    $newPath = "$Destination.$($script:InstallTransactionId).new"
    $backupPath = "$Destination.$($script:InstallTransactionId).bak"
    Remove-Item -LiteralPath $newPath -Force -ErrorAction SilentlyContinue
    $entry = @($script:InstallJournal.entries | Where-Object { $_.destination -eq [IO.Path]::GetFullPath($Destination) })[0]
    if ($HadOriginal -and (-not (Test-Path -LiteralPath $backupPath -PathType Leaf) -or
        (Get-Sha256FileHash $backupPath) -ne [string]$entry.original_sha256)) {
        throw "Verified transaction backup is unavailable before replacement: $Destination"
    }
    Copy-Item -LiteralPath $Source -Destination $newPath -Force
    $sourceHash = Get-Sha256FileHash $Source
    if ((Get-Sha256FileHash $newPath) -ne $sourceHash -or $sourceHash -ne [string]$entry.replacement_sha256) {
        throw "Staged replacement hash mismatch for $Destination"
    }
    $entry.state = 'replacing'
    $script:InstallJournal.phase = 'replacing'
    Write-InstallJournal -Journal $script:InstallJournal
    Move-Item -LiteralPath $newPath -Destination $Destination -Force
    if ((Get-Sha256FileHash $Destination) -ne $sourceHash) {
        throw "Replacement verification failed for $Destination"
    }
    $entry.state = 'replaced'
    Write-InstallJournal -Journal $script:InstallJournal
}

function Rollback-Binary {
    param(
        [string]$Destination,
        [bool]$HadOriginal
    )
    $backupPath = "$Destination.$($script:InstallTransactionId).bak"
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
        $entry = @($script:InstallJournal.entries | Where-Object { $_.destination -eq [IO.Path]::GetFullPath($Destination) })[0]
        $expectedHash = [string]$entry.original_sha256
        if ($expectedHash -notmatch '^[a-f0-9]{64}$' -or (Get-Sha256FileHash $backupPath) -ne $expectedHash) {
            throw "Backup integrity verification failed; refusing rollback for $Destination"
        }
        $restorePath = "$Destination.$($script:InstallTransactionId).restore"
        Copy-Item -LiteralPath $backupPath -Destination $restorePath -Force
        if ((Get-Sha256FileHash $restorePath) -ne $expectedHash) {
            Remove-Item -LiteralPath $restorePath -Force -ErrorAction SilentlyContinue
            throw "Restore verification failed for $Destination"
        }
        Move-Item -LiteralPath $restorePath -Destination $Destination -Force
        if ((Get-Sha256FileHash $Destination) -ne $expectedHash) {
            throw "Restored binary verification failed for $Destination"
        }
    } elseif (-not $HadOriginal) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
    } else {
        $entry = @($script:InstallJournal.entries | Where-Object { $_.destination -eq [IO.Path]::GetFullPath($Destination) })[0]
        if (-not (Test-Path -LiteralPath $Destination -PathType Leaf) -or
            (Get-Sha256FileHash $Destination) -ne [string]$entry.original_sha256) {
            throw "Required transaction backup is missing for changed binary $Destination"
        }
    }
    Remove-Item -LiteralPath "$Destination.$($script:InstallTransactionId).new" -Force -ErrorAction SilentlyContinue
}

function Remove-BinaryBackup {
    param([string]$Destination)
    Remove-Item -LiteralPath "$Destination.$($script:InstallTransactionId).bak" -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$Destination.$($script:InstallTransactionId).bak.sha256" -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$Destination.$($script:InstallTransactionId).new" -Force -ErrorAction SilentlyContinue
}

function Get-BinaryDestinations {
    param([Parameter(Mandatory = $true)][string]$Directory)
    $destinations = @{}
    foreach ($name in $script:BinaryNames) {
        $destinations[$name] = Join-Path $Directory $name
    }
    return $destinations
}

function Assert-InstalledUserBinariesStopped {
    param([Parameter(Mandatory = $true)][hashtable]$Destinations)

    $targetNames = @('wd-core.exe', 'wd-ui.exe')
    $targets = @{}
    foreach ($name in $targetNames) {
        $path = [IO.Path]::GetFullPath([string]$Destinations[$name])
        $targets[$name] = $path
    }

    $conflicts = New-Object System.Collections.Generic.List[string]
    $processes = @(Get-CimInstance Win32_Process -Filter "Name='wd-core.exe' OR Name='wd-ui.exe'" -ErrorAction Stop)
    foreach ($process in $processes) {
        $name = [string]$process.Name
        if ($targetNames -notcontains $name) { continue }
        $pidText = [string]$process.ProcessId
        $image = [string]$process.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($image)) {
            $conflicts.Add("$name (PID $pidText; executable path unavailable)")
            continue
        }
        try {
            $fullImage = [IO.Path]::GetFullPath($image)
        } catch {
            $conflicts.Add("$name (PID $pidText; executable path invalid)")
            continue
        }
        if ($fullImage.Equals($targets[$name], [StringComparison]::OrdinalIgnoreCase)) {
            $conflicts.Add("$name (PID $pidText)")
        }
    }

    if ($conflicts.Count -ne 0) {
        $running = ($conflicts | Sort-Object -Unique) -join ', '
        throw "Close installed WeDecent user processes before install/upgrade and retry. The installer will not terminate interactive processes. Running: $running"
    }
}

function Write-InstallJournal {
    param([Parameter(Mandatory = $true)]$Journal)
    $root = Join-Path $env:ProgramData 'WeDecent\install-transactions'
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    Protect-WeDecentMetadataAcl $root
    $path = Join-Path $root ([string]$Journal.transaction_id + '.json')
    $temp = Join-Path $root ('.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $Journal.updated_at = [DateTime]::UtcNow.ToString('o')
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Journal | ConvertTo-Json -Depth 8 -Compress) + "`n")
    $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Protect-WeDecentMetadataAcl $temp
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $backup = Join-Path $root ('.' + [Guid]::NewGuid().ToString('N') + '.previous')
        [IO.File]::Replace($temp, $path, $backup, $true)
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    } else {
        [IO.File]::Move($temp, $path)
    }
    Protect-WeDecentMetadataAcl $path
}

function Assert-TransactionMetadataSnapshot {
    param([Parameter(Mandatory = $true)]$Journal, [bool]$Committed = $false)
    $expectedPath = [IO.Path]::GetFullPath((Get-WeDecentMetadataPath))
    $expectedBackup = "$expectedPath.$($Journal.transaction_id).metadata.bak"
    if (-not [IO.Path]::GetFullPath([string]$Journal.metadata_path).Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath([string]$Journal.metadata_backup_path).Equals($expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
        $Journal.metadata_had_original -isnot [bool]) { throw 'Installer metadata snapshot journal fields are invalid.' }
    $backupExists = Test-Path -LiteralPath $expectedBackup -PathType Leaf
    if ([bool]$Journal.metadata_had_original) {
        if ([string]$Journal.metadata_original_sha256 -notmatch '^[a-f0-9]{64}
    param([Parameter(Mandatory = $true)]$Journal)

    $statePath = Join-Path $StateDir 'update-state.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw 'Cannot clean transaction backups without durable updater state.'
    }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ([UInt64]$state.stable_sequence -lt [UInt64]$Journal.sequence -or
        $null -ne $state.pending_install -or
        [string]$state.installed_version -cne [string]$Journal.version) {
        throw 'Cannot clean transaction backups before the exact transaction is durably committed.'
    }
    foreach ($entry in @($Journal.entries)) {
        $destination = [string]$entry.destination
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
            throw "Cannot clean transaction backups while an installed binary is unverified: $destination"
        }
    }

    # The durable committed journal is the retry marker if cleanup is interrupted.
    foreach ($entry in @($Journal.entries)) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ([bool]$entry.had_original -and
                (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Refusing to clean a corrupted transaction backup: $backup"
            }
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        }
        Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
        $destination = [string]$entry.destination
        Remove-Item -LiteralPath "$destination.$($Journal.transaction_id).new" -Force -ErrorAction SilentlyContinue
    }
    $metadataBackup = [string]$Journal.metadata_backup_path
    if (Test-Path -LiteralPath $metadataBackup -PathType Leaf) {
        if ([bool]$Journal.metadata_had_original -and (Get-Sha256FileHash $metadataBackup) -ne [string]$Journal.metadata_original_sha256) { throw 'Refusing to clean a corrupted installer metadata snapshot.' }
        Remove-Item -LiteralPath $metadataBackup -Force -ErrorAction Stop
    }
}

function Recover-InterruptedInstallerTransactions {
    param([Parameter(Mandatory = $true)][hashtable]$Destinations)
    $root = Join-Path $env:ProgramData 'WeDecent\install-transactions'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return }

    $expectedNames = @($script:BinaryNames | Sort-Object -CaseSensitive)
    foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter '*.json' -File)) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Installer transaction journal must not be a reparse point: $($file.FullName)"
        }
        $journal = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        $journalSequence = [UInt64]$journal.sequence
        $managedJournal = -not [string]::IsNullOrWhiteSpace([string]$journal.package_sha256) -or $journalSequence -ne 0
        if ([int]$journal.schema -ne 1 -or
            [string]$journal.transaction_id -notmatch '^[a-f0-9]{32}$' -or
            [string]$file.BaseName -cne [string]$journal.transaction_id -or
            ($managedJournal -and ([string]$journal.package_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$journal.manifest_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$journal.previous_version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or $journalSequence -eq 0)) -or
            (-not $managedJournal -and (-not [string]::IsNullOrEmpty([string]$journal.manifest_sha256) -or
                -not [string]::IsNullOrEmpty([string]$journal.previous_version))) -or
            $journal.service_was_running -isnot [bool] -or
            [string]$journal.version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
            @($journal.entries).Count -ne $script:BinaryNames.Count -or
            [string]$journal.phase -notin @('prepared', 'backups-verified', 'replacing', 'installed-awaiting-sequence-commit', 'committed', 'rolled-back')) {
            throw "Installer transaction journal is malformed: $($file.FullName)"
        }
        Assert-TransactionMetadataSnapshot -Journal $journal -Committed ($journal.phase -eq 'committed')

        $statePath = Join-Path $StateDir 'update-state.json'
        $committed = $false
        $stableSequence = [UInt64]0
        $installedVersion = ''
        $state = $null
        if (Test-Path -LiteralPath $statePath -PathType Leaf) {
            $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            $stableSequence = [UInt64]$state.stable_sequence
            $installedVersion = [string]$state.installed_version
            $committed = $stableSequence -ge [UInt64]$journal.sequence -and
                $null -eq $state.pending_install -and $installedVersion -ceq [string]$journal.version
        }
        $superseded = $journal.phase -eq 'committed' -and
            $stableSequence -ge [UInt64]$journal.sequence -and
            $null -ne $state -and
            ($null -eq $state.pending_install -or [UInt64]$state.pending_install.sequence -gt [UInt64]$journal.sequence)
        $seenNames = @{}
        foreach ($entry in @($journal.entries)) {
            $name = [string]$entry.name
            if ($script:BinaryNames -notcontains $name -or $seenNames.ContainsKey($name)) {
                throw "Installer transaction journal contains an unknown or duplicate binary: $name"
            }
            $seenNames[$name] = $true
            $destination = [IO.Path]::GetFullPath([string]$entry.destination)
            $expectedDestination = [IO.Path]::GetFullPath([string]$Destinations[$name])
            $expectedBackup = "$expectedDestination.$($journal.transaction_id).bak"
            if (-not [string]::Equals($destination, $expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$entry.backup_path), $expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
                $entry.had_original -isnot [bool] -or
                [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced')) {
                throw "Installer transaction journal entry is invalid for $name"
            }
            if ([bool]$entry.had_original) {
                $expectedOriginal = [string]$entry.original_sha256
                if ($expectedOriginal -notmatch '^[a-f0-9]{64}$') {
                    throw "Installer transaction original digest is invalid for $name"
                }
                if (Test-Path -LiteralPath $expectedBackup -PathType Leaf) {
                    if ((Get-Sha256FileHash $expectedBackup) -ne $expectedOriginal) {
                        throw "Interrupted-install backup integrity failure: $expectedBackup"
                    }
                } elseif ($committed) {
                    if (-not (Test-Path -LiteralPath $expectedDestination -PathType Leaf) -or
                        (Get-Sha256FileHash $expectedDestination) -ne [string]$entry.replacement_sha256) {
                        throw "Committed transaction has neither its backup nor the verified replacement: $expectedDestination"
                    }
                } elseif (-not $superseded -and (-not (Test-Path -LiteralPath $expectedDestination -PathType Leaf) -or
                    (Get-Sha256FileHash $expectedDestination) -ne $expectedOriginal)) {
                    throw "Original binary and verified transaction backup are both unavailable: $expectedDestination"
                }
            } elseif (-not [string]::IsNullOrEmpty([string]$entry.original_sha256)) {
                throw "Unexpected original digest for new binary $name"
            }
        }
        if ($seenNames.Count -ne $expectedNames.Count) {
            throw "Installer transaction journal does not cover the exact five approved binaries: $($file.FullName)"
        }
        if ($superseded) {
            foreach ($entry in @($journal.entries)) {
                if (Test-Path -LiteralPath ([string]$entry.backup_path) -PathType Leaf) {
                    throw "Superseded committed transaction has unfinished backup cleanup: $($entry.backup_path)"
                }
            }
        }

        if ($superseded) {
            continue
        }
        if ($journal.phase -eq 'committed' -and -not $committed) {
            throw 'Installer journal claims commit but protected updater state does not confirm it.'
        }
        if ($journal.phase -eq 'rolled-back' -and $committed) {
            throw 'Installer journal claims rollback but protected updater state confirms commit.'
        }
        if ($committed) {
            foreach ($entry in @($journal.entries)) {
                $destination = [string]$entry.destination
                if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                    (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                    throw "Sequence is committed but installed binary does not match the transaction: $destination"
                }
            }
        }
        if ($committed) {
            $journal.phase = 'committed'
            Write-InstallJournal -Journal $journal
            try {
                Remove-CommittedTransactionBackups -Journal $journal
            } catch {
                throw "Committed installation remains valid; refusing another installation until backup cleanup completes. Cause: $($_.Exception.Message)"
            }
            continue
        }

        $serviceBefore = Get-Service -Name $ServiceName -ErrorAction Stop
        $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        $expectedAgent = [IO.Path]::GetFullPath((Join-Path $InstallDir 'wd-agent.exe'))
        if ($null -eq $serviceConfig -or
            -not ([string]$serviceConfig.PathName).Contains($expectedAgent, [StringComparison]::OrdinalIgnoreCase) -or
            -not ([string]$serviceConfig.PathName).Contains('--state=', [StringComparison]::OrdinalIgnoreCase) -or
            -not ([string]$serviceConfig.PathName).Contains([IO.Path]::GetFullPath($StateDir), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'SCM service identity does not match the authenticated installer paths.'
        }
        $restartService = [bool]$journal.service_was_running
        if ($serviceBefore.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force -ErrorAction Stop }
        (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        if ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne 'Stopped') { throw 'SCM did not confirm the service stopped before interrupted-install recovery.' }
        try {
            for ($i = @($journal.entries).Count - 1; $i -ge 0; $i--) {
                $entry = @($journal.entries)[$i]
                $destination = [IO.Path]::GetFullPath([string]$entry.destination)
                if ([bool]$entry.had_original) {
                    $backup = [string]$entry.backup_path
                    if (Test-Path -LiteralPath $backup -PathType Leaf) {
                        $expected = [string]$entry.original_sha256
                        $restore = "$destination.$($journal.transaction_id).recover"
                        Copy-Item -LiteralPath $backup -Destination $restore -Force
                        if ((Get-Sha256FileHash $restore) -ne $expected) {
                            Remove-Item -LiteralPath $restore -Force -ErrorAction SilentlyContinue
                            throw "Interrupted-install restore verification failure: $destination"
                        }
                        Move-Item -LiteralPath $restore -Destination $destination -Force
                    }
                    if ((Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                        throw "Interrupted-install rollback verification failure: $destination"
                    }
                } else {
                    if (Test-Path -LiteralPath $destination -PathType Leaf) {
                        if ((Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                            throw "Unexpected binary contents prevent safe rollback: $destination"
                        }
                        Remove-Item -LiteralPath $destination -Force
                    }
                }
                Remove-Item -LiteralPath "$destination.$($journal.transaction_id).new" -Force -ErrorAction SilentlyContinue
            }
            Restore-TransactionMetadata -Journal $journal
            $journal.phase = 'rolled-back'
            Write-InstallJournal -Journal $journal
        } catch {
            throw "Interrupted installer rollback failed closed; service remains stopped and backups are retained. Cause: $($_.Exception.Message)"
        }
        try {
            if ($restartService) {
                Start-Service -Name $ServiceName -ErrorAction Stop
                (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                if ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne 'Running') { throw 'SCM did not confirm the previous service returned to Running.' }
            } elseif ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne 'Stopped') {
                throw 'SCM service was expected to remain stopped after recovery.'
            }
        } catch {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            throw "Previous binaries and metadata were restored, but SCM restart/state verification failed; service was left stopped. Cause: $($_.Exception.Message)"
        }
    }
}

function Install-Binaries {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][hashtable]$Destinations,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$AttemptedNames,
        [Parameter(Mandatory = $true)][hashtable]$OriginalState
    )
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($name in $script:BinaryNames) {
        if (-not $script:VerifiedBinaryHashes.ContainsKey($name)) {
            throw "No pinned verified hash for $name"
        }
        $source = Join-Path $SourceDirectory $name
        $sourceHash = Get-Sha256FileHash $source
        if ($sourceHash -ne $script:VerifiedBinaryHashes[$name]) {
            throw "Release bundle changed after verification: $name"
        }
        $destination = [IO.Path]::GetFullPath([string]$Destinations[$name])
        $hadOriginal = Test-Path -LiteralPath $destination -PathType Leaf
        $OriginalState[$name] = $hadOriginal
        $originalHash = ''
        if ($hadOriginal) { $originalHash = Get-Sha256FileHash $destination }
        $entries.Add([ordered]@{
            name = $name
            destination = $destination
            had_original = [bool]$hadOriginal
            original_sha256 = $originalHash
            replacement_sha256 = $sourceHash
            backup_path = "$destination.$($script:InstallTransactionId).bak"
            state = 'planned'
        })
    }

    $journalPath = Join-Path (Join-Path $env:ProgramData 'WeDecent\install-transactions') ($script:InstallTransactionId + '.json')
    if (Test-Path -LiteralPath $journalPath) { throw 'Installer transaction ID has already been used; refusing replay.' }
    $metadataPath = [IO.Path]::GetFullPath((Get-WeDecentMetadataPath))
    $metadataHadOriginal = Test-Path -LiteralPath $metadataPath -PathType Leaf
    $metadataBackupPath = "$metadataPath.$($script:InstallTransactionId).metadata.bak"
    $metadataOriginalHash = ''
    if ($metadataHadOriginal) {
        if ((Get-Item -LiteralPath $metadataPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installer metadata cannot be snapshotted from a reparse point.' }
        if (Test-Path -LiteralPath $metadataBackupPath) { throw 'Transaction-specific installer metadata snapshot path already exists.' }
        $metadataOriginalHash = Get-Sha256FileHash $metadataPath
        Copy-Item -LiteralPath $metadataPath -Destination $metadataBackupPath
        if ((Get-Sha256FileHash $metadataBackupPath) -ne $metadataOriginalHash) { throw 'Installer metadata snapshot failed integrity verification.' }
        Protect-WeDecentMetadataAcl $metadataBackupPath
    }
    $script:InstallJournal = [ordered]@{
        schema = 1
        transaction_id = $script:InstallTransactionId
        package_sha256 = $ExpectedPackageSHA256
        manifest_sha256 = $ExpectedManifestSHA256
        previous_version = $PreviousVersion
        sequence = [UInt64]$script:InstallTransactionSequence
        service_was_running = [bool]$script:InstallServiceWasRunning
        metadata_path = $metadataPath
        metadata_had_original = [bool]$metadataHadOriginal
        metadata_original_sha256 = $metadataOriginalHash
        metadata_backup_path = $metadataBackupPath
        version = $script:InstallTargetVersion
        phase = 'prepared'
        entries = @($entries.ToArray())
        updated_at = [DateTime]::UtcNow.ToString('o')
    }
    Write-InstallJournal -Journal $script:InstallJournal

    # All previous binaries are backed up and verified before any replacement.
    foreach ($entry in $script:InstallJournal.entries) {
        $name = [string]$entry.name
        $destination = [string]$entry.destination
        $backupPath = [string]$entry.backup_path
        if ([bool]$entry.had_original) {
            if (Test-Path -LiteralPath $backupPath) {
                throw "Transaction-specific backup path already exists: $backupPath"
            }
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                throw "Original binary changed before backup: $destination"
            }
            Copy-Item -LiteralPath $destination -Destination $backupPath
            if ((Get-Sha256FileHash $backupPath) -ne [string]$entry.original_sha256) {
                throw "Backup integrity verification failed for $destination"
            }
            Set-Content -LiteralPath "$backupPath.sha256" -Value $entry.original_sha256 -NoNewline -Encoding ASCII
            Protect-WeDecentMetadataAcl "$backupPath.sha256"
        }
        $entry.state = 'backup-verified'
        $script:InstallJournal.phase = 'backups-verified'
        Write-InstallJournal -Journal $script:InstallJournal
    }

    foreach ($entry in $script:InstallJournal.entries) {
        $AttemptedNames.Add([string]$entry.name)
    }
    foreach ($entry in $script:InstallJournal.entries) {
        $name = [string]$entry.name
        Install-Binary (Join-Path $SourceDirectory $name) ([string]$entry.destination) ([bool]$entry.had_original)
    }
    $script:InstallJournal.phase = 'installed-awaiting-sequence-commit'
    Write-InstallJournal -Journal $script:InstallJournal
}

function Assert-InstalledBinaries {
    param([Parameter(Mandatory = $true)][hashtable]$Destinations)
    foreach ($name in $script:BinaryNames) {
        if (-not $script:VerifiedBinaryHashes.ContainsKey($name)) {
            throw "No pinned verified hash for $name"
        }
        $destination = $Destinations[$name]
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            throw "Installed binary is missing: $destination"
        }
        $actual = Get-Sha256FileHash $destination
        if ($actual -ne $script:VerifiedBinaryHashes[$name]) {
            throw "Installed checksum mismatch for $name"
        }
    }
}

function Rollback-Binaries {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$AttemptedNames,
        [Parameter(Mandatory = $true)][hashtable]$OriginalState,
        [Parameter(Mandatory = $true)][hashtable]$Destinations
    )
    foreach ($name in $AttemptedNames) {
        $entry = @($script:InstallJournal.entries | Where-Object { $_.name -eq $name })[0]
        if ($null -eq $entry) { throw "Rollback journal entry is missing for $name" }
        $destination = [IO.Path]::GetFullPath([string]$Destinations[$name])
        if ([bool]$OriginalState[$name]) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                if ((Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                    throw "Rollback preflight found a corrupted backup: $backup"
                }
            } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                throw "Rollback preflight cannot find a verified original or backup: $destination"
            }
        } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
            if ((Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Rollback preflight found unexpected contents at $destination"
            }
        }
    }
    for ($i = $AttemptedNames.Count - 1; $i -ge 0; $i--) {
        $name = $AttemptedNames[$i]
        Rollback-Binary -Destination $Destinations[$name] -HadOriginal ([bool]$OriginalState[$name])
    }
}

function Remove-BinaryBackups {
    param([Parameter(Mandatory = $true)][hashtable]$Destinations)
    foreach ($name in $script:BinaryNames) {
        Remove-BinaryBackup $Destinations[$name]
    }
}

function Add-MachinePathEntry {
    param([string]$PathEntry)
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($machine -split ';' | Where-Object { $_ })
    if ($parts | Where-Object { $_.TrimEnd('\') -ieq $PathEntry.TrimEnd('\') }) { return }
    [Environment]::SetEnvironmentVariable('Path', (($parts + $PathEntry) -join ';'), 'Machine')
}

function Remove-EmptyDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    $child = Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop |
        Select-Object -First 1
    if (-not $child) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
}

function Test-DirectoryExistsStrict {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Expected a real, non-reparse directory at '$Path'."
        }
        return $true
    } catch {
        if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound -and
            $_.FullyQualifiedErrorId -match 'PathNotFound|ItemNotFound') {
            return $false
        }
        throw
    }
}

function Test-ServiceStateSafeForAccountRemoval {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch {
        if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound -and
            $_.FullyQualifiedErrorId -match 'PathNotFound|ItemNotFound') {
            return $true
        }
        return $false
    }
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $false
    }

    try {
        $remainingState = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        return $remainingState.Count -eq 0
    } catch {
        return $false
    }
}

function Publish-WeDecentRecoveryScript {
    $source = Join-Path $BundlePath 'Recover-WeDecentInstall.ps1'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw 'Verified installer recovery script is missing from the package.'
    }
    $target = Join-Path $InstallDir 'Recover-WeDecentInstall.ps1'
    $temp = "$target.$($script:InstallTransactionId).new"
    Copy-Item -LiteralPath $source -Destination $temp -Force
    if ((Get-Sha256FileHash $temp) -ne (Get-Sha256FileHash $source)) {
        throw 'Persisted installer recovery script failed integrity verification.'
    }
    Protect-WeDecentMetadataAcl $temp
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        $backup = Join-Path $InstallDir ('.recovery-script-' + [Guid]::NewGuid().ToString('N') + '.previous')
        [IO.File]::Replace($temp, $target, $backup, $true)
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    } else {
        [IO.File]::Move($temp, $target)
    }
    Protect-WeDecentMetadataAcl $target
}

function Invoke-RollbackStep {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    try {
        $null = & $Action
        return $true
    } catch {
        Write-Warning "Rollback step failed ($Description): $($_.Exception.Message)"
        return $false
    }
}

Assert-Administrator
if ([string]::IsNullOrWhiteSpace($BundlePath)) { $BundlePath = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($BundlePath)) { throw 'Cannot determine installer bundle path.' }
$BundlePath = (Resolve-Path -LiteralPath $BundlePath).Path
$InstallDir = Assert-SafeChildPath -Path $InstallDir -Root $env:ProgramFiles -Label 'InstallDir'
$StateDir = Assert-SafeChildPath -Path $StateDir -Root $InstallDir -Label 'StateDir'
$version = Assert-ReleaseBundle
$script:InstallTargetVersion = $version
$metadataPath = Get-WeDecentMetadataPath
$migrationModule = Join-Path $PSScriptRoot 'StateMigration.psm1'
Import-Module $migrationModule -Force -ErrorAction Stop
$migrationJournalPath = Join-Path $InstallDir 'migration\state-migration.json'
$migrationAgentPath = Join-Path $BundlePath 'wd-agent.exe'
$metadata = Read-WeDecentMetadata
$metadataTrusted = $false
if ($metadata) {
    $metadataTrusted = Test-WeDecentMetadataTrusted $metadataPath
    if (-not $metadataTrusted) {
        throw 'Existing installer metadata is not ACL-trusted; refusing migration recovery or installer state changes.'
    }
}
if (Test-Path -LiteralPath $migrationJournalPath -PathType Leaf) {
    [void](Set-WeDecentMigrationAdminDirectory -Path (Split-Path -Parent $migrationJournalPath) -AgentPath $migrationAgentPath)
    [void](Recover-WeDecentStateMigration -JournalPath $migrationJournalPath -AgentPath $migrationAgentPath -MetadataPath $metadataPath -ServiceName $ServiceName)
}
$metadata = Read-WeDecentMetadata
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
$script:InstallServiceWasRunning = $null -ne $service -and $service.State -eq 'Running'
if (-not $service) {
    if ($metadata) {
        if (-not $metadataTrusted) {
            throw 'Installer metadata exists but is not ACL-authenticated; refusing a fresh identity over potentially existing state.'
        }
        throw 'Authenticated installer metadata exists but the service is absent; refusing fresh identity creation until the existing installation state is recovered or explicitly retired.'
    }
    $legacyDefaultStateDir = Join-Path $env:ProgramData 'WeDecent\agent'
    if (Test-DirectoryExistsStrict -Path $legacyDefaultStateDir) {
        throw 'Legacy ProgramData service state exists; refusing to create a replacement identity at the Program Files location.'
    }
}
$binaryDestinations = Get-BinaryDestinations -Directory $InstallDir
Recover-InterruptedInstallerTransactions -Destinations $binaryDestinations
Assert-InstalledUserBinariesStopped -Destinations $binaryDestinations
$wdDestination = $binaryDestinations['wd.exe']
$agentDestination = $binaryDestinations['wd-agent.exe']

if ($service) {
    if (-not $metadataTrusted -or [string]::IsNullOrWhiteSpace([string]$metadata.state_dir)) {
        throw 'Existing service state location is not authenticated by protected installer metadata; refusing upgrade until an operator performs an identity-preserving offline migration.'
    }
    $recordedStateDir = [IO.Path]::GetFullPath([string]$metadata.state_dir)
    $requestedStateDir = [IO.Path]::GetFullPath($StateDir)
    $needsStateMigration = -not [string]::Equals($recordedStateDir.TrimEnd('\'), $requestedStateDir.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
    $stateArg = [regex]::Escape('--state=' + $recordedStateDir)
    if ($service.PathName -notmatch ('(?i)(?:^|\s)"?' + $stateArg + '"?(?:\s|$)')) {
        throw 'Existing SCM command line does not match the authenticated state_dir metadata; refusing upgrade.'
    }
    if ($service.StartName -match '^(LocalSystem|LocalService|NetworkService|NT AUTHORITY\\(SYSTEM|LocalService|NetworkService))$') {
        throw "Refusing to upgrade service running as built-in identity $($service.StartName)"
    }
    $expectedAgent = '^(?:"' + [Regex]::Escape($agentDestination) + '"|' + [Regex]::Escape($agentDestination) + ')(?:\s|$)'
    if ($service.PathName -notmatch $expectedAgent) {
        throw "Existing service binary path is not $agentDestination; refusing to rewrite an unrelated service"
    }
    $localName = Get-LocalAccountName $service.StartName
    if (-not $localName) { throw "Installer-managed services must use a dedicated local account; got '$($service.StartName)'." }
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $localUser = Get-LocalUser -Name $localName -ErrorAction Stop
    Assert-StandardLocalAccount $localUser
    $accountSid = $localUser.SID.Value
    $managed = $false
    if ($metadataTrusted -and $metadata.service_account_sid -eq $accountSid) {
        $managed = [bool]$metadata.managed_service_account
    }

    if (-not $PSCmdlet.ShouldProcess("$InstallDir and service '$ServiceName'", "Upgrade WeDecent to $version")) { return }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    if ($needsStateMigration) {
        $journalParent = Split-Path -Parent $migrationJournalPath
        if (-not (Test-Path -LiteralPath $journalParent -PathType Container)) {
            New-Item -ItemType Directory -Path $journalParent -Force | Out-Null
        }
        [void](Set-WeDecentMigrationAdminDirectory -Path $journalParent -AgentPath $migrationAgentPath)
        $destinationParent = Split-Path -Parent $requestedStateDir
        if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
            New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
            Set-WeDecentMigrationAdminDirectory -Path $destinationParent -AgentPath $migrationAgentPath
        } else {
            [void](Set-WeDecentMigrationAdminDirectory -Path $destinationParent -AgentPath $migrationAgentPath)
        }
        Write-Host "Migrating authenticated service state from '$recordedStateDir' to '$requestedStateDir'."
        [void](Invoke-WeDecentStateMigration -Source $recordedStateDir -Destination $requestedStateDir -AgentPath $migrationAgentPath -ServiceName $ServiceName -ServiceSid $accountSid -MetadataPath $metadataPath -JournalPath $migrationJournalPath)
        $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        $metadata = Read-WeDecentMetadata
        if ([IO.Path]::GetFullPath([string]$metadata.state_dir) -ine $requestedStateDir) {
            throw 'Authenticated installer metadata did not commit the migrated state path.'
        }
    }
    Write-Host "Upgrading existing $ServiceName service; state and service account will be preserved."
    if ($service.State -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $attemptedBinaryNames = [System.Collections.Generic.List[string]]::new()
    $binaryOriginalState = @{}
    try {
        Install-Binaries -SourceDirectory $BundlePath -Destinations $binaryDestinations -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState
        Publish-WeDecentRecoveryScript

        Assert-InstalledBinaries -Destinations $binaryDestinations
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        Write-WeDecentMetadata -AccountSid $accountSid -ManagedAccount $managed -AccountName $localName -Version $version
        Initialize-WeDecentUpdateState -Version $version -ServiceSid $accountSid
    } catch {
        $failed = $_
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $binariesRestored = Invoke-RollbackStep 'restore installed binaries' {
            Rollback-Binaries -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState -Destinations $binaryDestinations
        }
        $metadataRestored = $true
        if ($script:InstallJournal) {
            $metadataRestored = Invoke-RollbackStep 'restore previous installer metadata' { Restore-TransactionMetadata -Journal $script:InstallJournal }
        }
        $journalPersisted = $true
        if ($binariesRestored -and $metadataRestored -and $script:InstallJournal) {
            $script:InstallJournal.phase = 'rolled-back'
            $journalPersisted = Invoke-RollbackStep 'persist completed rollback journal' { Write-InstallJournal -Journal $script:InstallJournal }
        }
        if ($binariesRestored -and $metadataRestored -and $journalPersisted) {
            Invoke-RollbackStep 'restart previous agent service' {
                Start-Service -Name $ServiceName -ErrorAction Stop
                (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                if ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne 'Running') { throw 'SCM did not confirm the previous agent service is running.' }
            } | Out-Null
        } else {
            Write-Warning 'Previous binaries, metadata, or rollback journal could not be fully restored; the agent service is intentionally left stopped for recovery.'
        }
        throw "Upgrade failed; rollback was attempted: $($failed.Exception.Message)"
    }
    if (-not $script:IsManagedUpdate -and $script:InstallJournal) {
        $script:InstallJournal.phase = 'committed'
        Write-InstallJournal -Journal $script:InstallJournal
        Remove-CommittedTransactionBackups -Journal $script:InstallJournal
    }
} else {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $localUser = Get-LocalUser -Name $ServiceAccountName -ErrorAction SilentlyContinue
    if ($localUser) { Assert-StandardLocalAccount $localUser }

    if (-not $PSCmdlet.ShouldProcess("$InstallDir and service '$ServiceName'", "Install WeDecent $version")) { return }

    if ([string]::IsNullOrWhiteSpace($RecoveryAuthorityUrl)) {
        throw 'A recovery-authority HTTPS origin is required through -RecoveryAuthorityUrl or WEDECENT_PAIRING_RECOVERY_AUTHORITY_URL.'
    }
    $authorityUri = $null
    if (-not [Uri]::TryCreate($RecoveryAuthorityUrl, [UriKind]::Absolute, [ref]$authorityUri) -or
        $authorityUri.Scheme -ne 'https' -or [string]::IsNullOrEmpty($authorityUri.Host) -or
        $authorityUri.UserInfo -or $authorityUri.Query -or $authorityUri.Fragment -or
        ($authorityUri.AbsolutePath -ne '' -and $authorityUri.AbsolutePath -ne '/')) {
        throw 'RecoveryAuthorityUrl must be an origin-only HTTPS URL.'
    }
    if ($RecoveryAuthoritySPKISHA256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw 'RecoveryAuthoritySPKISHA256 must contain exactly 64 hexadecimal characters.'
    }
    if ([string]::IsNullOrWhiteSpace($RecoveryAuthorityTrustFile)) {
        throw 'RecoveryAuthorityTrustFile is required.'
    }
    $trustItem = Get-Item -LiteralPath $RecoveryAuthorityTrustFile -Force -ErrorAction Stop
    if ($trustItem.PSIsContainer -or
        ($trustItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'RecoveryAuthorityTrustFile must be a regular, non-reparse file.'
    }
    $RecoveryAuthorityTrustFile = $trustItem.FullName
    if ($null -eq $RecoveryAuthorityBearerToken) {
        $RecoveryAuthorityBearerToken = Read-Host -Prompt 'Short-lived recovery-authority bearer token' -AsSecureString
    }
    if ($null -eq $RecoveryAuthorityBearerToken -or $RecoveryAuthorityBearerToken.Length -lt 32 -or
        $RecoveryAuthorityBearerToken.Length -gt 4096) {
        throw 'RecoveryAuthorityBearerToken must contain 32 to 4096 characters.'
    }
    Assert-SecureStringLine -SecureString $RecoveryAuthorityBearerToken -MinimumLength 32 -MaximumLength 4096 -Label 'RecoveryAuthorityBearerToken' -RejectEdgeWhitespace

    $installDirExisted = Test-Path -LiteralPath $InstallDir -PathType Container
    $stateParent = Split-Path -Parent $StateDir
    $stateParentExisted = Test-DirectoryExistsStrict -Path $stateParent
    $stateExisted = Test-DirectoryExistsStrict -Path $StateDir
    $createdAccount = $false
    $hadLogonRight = $false
    $originalMachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $managed = $false
    $password = $null
    $attemptedBinaryNames = [System.Collections.Generic.List[string]]::new()
    $binaryOriginalState = @{}

    try {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        if ($localUser) {
            $metadataManaged = $metadataTrusted -and [bool]$metadata.managed_service_account -and $metadata.service_account_sid -eq $localUser.SID.Value
            if ($metadataManaged) {
                $plainGenerated = New-ServiceAccountPassword
                try {
                    $password = ConvertTo-SecureString $plainGenerated -AsPlainText -Force
                    Set-LocalUser -Name $ServiceAccountName -Password $password
                } finally {
                    $plainGenerated = $null
                }
                $managed = $true
            } elseif ($AdoptExistingServiceAccount) {
                if (-not $ServiceAccountCredential) {
                    throw '-AdoptExistingServiceAccount requires -ServiceAccountCredential for a pre-existing account.'
                }
                $password = $ServiceAccountCredential.Password
            } else {
                throw "Local account $ServiceAccountName already exists but is not recorded as trusted installer-managed. Use -AdoptExistingServiceAccount with an in-memory PSCredential, or choose another account name."
            }
        } else {
            if ($ServiceAccountCredential) {
                $password = $ServiceAccountCredential.Password
            } else {
                $plainGenerated = New-ServiceAccountPassword
                try {
                    $password = ConvertTo-SecureString $plainGenerated -AsPlainText -Force
                } finally {
                    $plainGenerated = $null
                }
            }
            $localUser = New-LocalUser -Name $ServiceAccountName -Password $password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description 'WeDecent dedicated terminal service account'
            $createdAccount = $true
            $managed = $true
        }

        Assert-StandardLocalAccount $localUser
        Assert-SecureStringLine -SecureString $password -MinimumLength 1 -MaximumLength 4096 -Label 'Service account password'
        $hadLogonRight = Test-ServiceLogonRight -Sid $localUser.SID.Value
        if (-not $hadLogonRight) { Set-ServiceLogonRight -Sid $localUser.SID.Value -Present $true }

        Install-Binaries -SourceDirectory $BundlePath -Destinations $binaryDestinations -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState
        Assert-InstalledBinaries -Destinations $binaryDestinations
        Invoke-AgentServiceInstall -AgentPath $agentDestination -Password $password -RecoveryBearerToken $RecoveryAuthorityBearerToken

        $finalService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        if (-not $finalService -or $finalService.State -ne 'Running') {
            throw "$ServiceName is not running after installation"
        }
        $finalSid = Resolve-AccountSid $finalService.StartName
        if ($finalSid -ne $localUser.SID.Value) {
            throw 'Installed service account SID does not match the expected local account.'
        }

        if ($AddToMachinePath) { Add-MachinePathEntry $InstallDir }
        Write-WeDecentMetadata -AccountSid $localUser.SID.Value -ManagedAccount $managed -AccountName $ServiceAccountName -Version $version
        Initialize-WeDecentUpdateState -Version $version -ServiceSid $localUser.SID.Value
        if (-not $script:IsManagedUpdate -and $script:InstallJournal) {
        $script:InstallJournal.phase = 'committed'
        Write-InstallJournal -Journal $script:InstallJournal
        Remove-CommittedTransactionBackups -Journal $script:InstallJournal
    }
    } catch {
        $failed = $_
        Invoke-RollbackStep 'remove partially created service' {
            $createdService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($createdService) {
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                & sc.exe delete $ServiceName | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE" }
            }
        }
        Invoke-RollbackStep 'restore installed binaries' {
            Rollback-Binaries -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState -Destinations $binaryDestinations
        }
        if ($AddToMachinePath) {
            Invoke-RollbackStep 'restore machine PATH' {
                [Environment]::SetEnvironmentVariable('Path', $originalMachinePath, 'Machine')
            }
        }
        if (-not $stateExisted) {
            Invoke-RollbackStep 'remove only an empty installer-created state directory' {
                Remove-EmptyDirectory -Path $StateDir
            }
            if (-not $stateParentExisted) {
                Invoke-RollbackStep 'remove empty installer-created state parent' {
                    Remove-EmptyDirectory -Path $stateParent
                }
            }
            if (Test-Path -LiteralPath $StateDir -PathType Container) {
                $remainingState = @(Get-ChildItem -LiteralPath $StateDir -Force -ErrorAction Stop)
                if ($remainingState.Count -gt 0) {
                    Write-Warning "Preserving non-empty protected service state after interrupted installation. Do not delete or repair identity/trust material; use the documented offline recovery and re-enrollment procedure. State: $StateDir"
                }
            }
        }
        if (-not $installDirExisted) {
            Invoke-RollbackStep 'remove empty installer-created install directory' {
                Remove-EmptyDirectory -Path $InstallDir
            }
        }
        if ($localUser -and -not $hadLogonRight) {
            Invoke-RollbackStep 'remove SeServiceLogonRight' {
                Set-ServiceLogonRight -Sid $localUser.SID.Value -Present $false
            }
        }
        if ($createdAccount) {
            Invoke-RollbackStep 'remove installer-created service account only when protected state is empty' {
                if (Test-ServiceStateSafeForAccountRemoval -Path $StateDir) {
                    Remove-LocalUser -Name $ServiceAccountName -ErrorAction Stop
                } else {
                    Write-Warning "Retaining installer-created service account '$ServiceAccountName': protected state is non-empty, non-directory, or could not be inspected. Preserve the account for offline recovery."
                }
            }
        }
        throw "Fresh installation failed; rollback was attempted: $($failed.Exception.Message)"
    }
}

if ($service -and $AddToMachinePath) { Add-MachinePathEntry $InstallDir }

$finalService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if (-not $finalService -or $finalService.State -ne 'Running') { throw "$ServiceName is not running after installation" }

Write-Host "WeDecent $version installed successfully."
Write-Host "Client:    $wdDestination"
Write-Host "Agent:     $agentDestination"
Write-Host "RouterCtl: $($binaryDestinations['wd-routerctl.exe'])"
Write-Host "Core:      $($binaryDestinations['wd-core.exe'])"
Write-Host "UI:        $($binaryDestinations['wd-ui.exe'])"
Write-Host "State:     $StateDir"
Write-Host "Service:   $ServiceName ($($finalService.StartName))"
Write-Host 'wd-core.exe and wd-ui.exe are installed for same-user launch; the installer does not register them as services or autostart entries.') { throw 'Installer metadata snapshot digest is invalid.' }
        if ($backupExists) {
            if ((Get-Sha256FileHash $expectedBackup) -ne [string]$Journal.metadata_original_sha256) { throw 'Installer metadata snapshot backup is corrupted.' }
        } elseif (-not $Committed -and (-not (Test-Path -LiteralPath $expectedPath -PathType Leaf) -or (Get-Sha256FileHash $expectedPath) -ne [string]$Journal.metadata_original_sha256)) {
            throw 'Previous installer metadata and its verified snapshot are both unavailable.'
        } elseif ($Committed -and $Journal.phase -ne 'committed') { throw 'Committed metadata snapshot disappeared before the durable commit marker.' }
    } elseif (-not [string]::IsNullOrEmpty([string]$Journal.metadata_original_sha256) -or $backupExists) {
        throw 'Unexpected installer metadata snapshot for a transaction without prior metadata.'
    }
}
function Restore-TransactionMetadata {
    param([Parameter(Mandatory = $true)]$Journal)
    Assert-TransactionMetadataSnapshot -Journal $Journal
    $path = [IO.Path]::GetFullPath([string]$Journal.metadata_path)
    if ([bool]$Journal.metadata_had_original) {
        $backup = [string]$Journal.metadata_backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            $temp = "$path.$($Journal.transaction_id).restore"
            Copy-Item -LiteralPath $backup -Destination $temp -Force
            if ((Get-Sha256FileHash $temp) -ne [string]$Journal.metadata_original_sha256) {
                Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
                throw 'Restored installer metadata failed its original digest check.'
            }
            Protect-WeDecentMetadataAcl $temp
            Move-Item -LiteralPath $temp -Destination $path -Force
            Protect-WeDecentMetadataAcl $path
        } elseif ((Get-Sha256FileHash $path) -ne [string]$Journal.metadata_original_sha256) {
            throw 'Installer metadata snapshot is missing and current metadata is not the original.'
        }
    } elseif (Test-Path -LiteralPath $path -PathType Leaf) {
        $current = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ([string]$current.product -cne 'WeDecent' -or [string]$current.version -cne [string]$Journal.version -or
            [string]$current.install_dir -ine $InstallDir -or [string]$current.state_dir -ine $StateDir -or
            [string]$current.service_name -cne $ServiceName) { throw 'Refusing to remove installer metadata not created by this transaction.' }
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
    }
}

function Remove-CommittedTransactionBackups {
    param([Parameter(Mandatory = $true)]$Journal)

    $statePath = Join-Path $StateDir 'update-state.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw 'Cannot clean transaction backups without durable updater state.'
    }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ([UInt64]$state.stable_sequence -lt [UInt64]$Journal.sequence -or
        $null -ne $state.pending_install -or
        [string]$state.installed_version -cne [string]$Journal.version) {
        throw 'Cannot clean transaction backups before the exact transaction is durably committed.'
    }
    foreach ($entry in @($Journal.entries)) {
        $destination = [string]$entry.destination
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
            throw "Cannot clean transaction backups while an installed binary is unverified: $destination"
        }
    }

    # The durable committed journal is the retry marker if cleanup is interrupted.
    foreach ($entry in @($Journal.entries)) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ([bool]$entry.had_original -and
                (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Refusing to clean a corrupted transaction backup: $backup"
            }
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        }
        Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
        $destination = [string]$entry.destination
        Remove-Item -LiteralPath "$destination.$($Journal.transaction_id).new" -Force -ErrorAction SilentlyContinue
    }
}

function Recover-InterruptedInstallerTransactions {
    param([Parameter(Mandatory = $true)][hashtable]$Destinations)
    $root = Join-Path $env:ProgramData 'WeDecent\install-transactions'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return }

    $expectedNames = @($script:BinaryNames | Sort-Object -CaseSensitive)
    foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter '*.json' -File)) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Installer transaction journal must not be a reparse point: $($file.FullName)"
        }
        $journal = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        $journalSequence = [UInt64]$journal.sequence
        $managedJournal = -not [string]::IsNullOrWhiteSpace([string]$journal.package_sha256) -or $journalSequence -ne 0
        if ([int]$journal.schema -ne 1 -or
            [string]$journal.transaction_id -notmatch '^[a-f0-9]{32}$' -or
            [string]$file.BaseName -cne [string]$journal.transaction_id -or
            ($managedJournal -and ([string]$journal.package_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$journal.manifest_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$journal.previous_version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or $journalSequence -eq 0)) -or
            (-not $managedJournal -and (-not [string]::IsNullOrEmpty([string]$journal.manifest_sha256) -or
                -not [string]::IsNullOrEmpty([string]$journal.previous_version))) -or
            $journal.service_was_running -isnot [bool] -or
            [string]$journal.version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
            @($journal.entries).Count -ne $script:BinaryNames.Count -or
            [string]$journal.phase -notin @('prepared', 'backups-verified', 'replacing', 'installed-awaiting-sequence-commit', 'committed', 'rolled-back')) {
            throw "Installer transaction journal is malformed: $($file.FullName)"
        }

        $statePath = Join-Path $StateDir 'update-state.json'
        $committed = $false
        $stableSequence = [UInt64]0
        $installedVersion = ''
        $state = $null
        if (Test-Path -LiteralPath $statePath -PathType Leaf) {
            $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            $stableSequence = [UInt64]$state.stable_sequence
            $installedVersion = [string]$state.installed_version
            $committed = $stableSequence -ge [UInt64]$journal.sequence -and
                $null -eq $state.pending_install -and $installedVersion -ceq [string]$journal.version
        }
        $superseded = $journal.phase -eq 'committed' -and
            $stableSequence -ge [UInt64]$journal.sequence -and
            $null -ne $state -and
            ($null -eq $state.pending_install -or [UInt64]$state.pending_install.sequence -gt [UInt64]$journal.sequence)
        $seenNames = @{}
        foreach ($entry in @($journal.entries)) {
            $name = [string]$entry.name
            if ($script:BinaryNames -notcontains $name -or $seenNames.ContainsKey($name)) {
                throw "Installer transaction journal contains an unknown or duplicate binary: $name"
            }
            $seenNames[$name] = $true
            $destination = [IO.Path]::GetFullPath([string]$entry.destination)
            $expectedDestination = [IO.Path]::GetFullPath([string]$Destinations[$name])
            $expectedBackup = "$expectedDestination.$($journal.transaction_id).bak"
            if (-not [string]::Equals($destination, $expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals([IO.Path]::GetFullPath([string]$entry.backup_path), $expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
                $entry.had_original -isnot [bool] -or
                [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced')) {
                throw "Installer transaction journal entry is invalid for $name"
            }
            if ([bool]$entry.had_original) {
                $expectedOriginal = [string]$entry.original_sha256
                if ($expectedOriginal -notmatch '^[a-f0-9]{64}$') {
                    throw "Installer transaction original digest is invalid for $name"
                }
                if (Test-Path -LiteralPath $expectedBackup -PathType Leaf) {
                    if ((Get-Sha256FileHash $expectedBackup) -ne $expectedOriginal) {
                        throw "Interrupted-install backup integrity failure: $expectedBackup"
                    }
                } elseif ($committed) {
                    if (-not (Test-Path -LiteralPath $expectedDestination -PathType Leaf) -or
                        (Get-Sha256FileHash $expectedDestination) -ne [string]$entry.replacement_sha256) {
                        throw "Committed transaction has neither its backup nor the verified replacement: $expectedDestination"
                    }
                } elseif (-not $superseded -and (-not (Test-Path -LiteralPath $expectedDestination -PathType Leaf) -or
                    (Get-Sha256FileHash $expectedDestination) -ne $expectedOriginal)) {
                    throw "Original binary and verified transaction backup are both unavailable: $expectedDestination"
                }
            } elseif (-not [string]::IsNullOrEmpty([string]$entry.original_sha256)) {
                throw "Unexpected original digest for new binary $name"
            }
        }
        if ($seenNames.Count -ne $expectedNames.Count) {
            throw "Installer transaction journal does not cover the exact five approved binaries: $($file.FullName)"
        }
        if ($superseded) {
            foreach ($entry in @($journal.entries)) {
                if (Test-Path -LiteralPath ([string]$entry.backup_path) -PathType Leaf) {
                    throw "Superseded committed transaction has unfinished backup cleanup: $($entry.backup_path)"
                }
            }
        }

        if ($superseded) {
            continue
        }
        if ($journal.phase -eq 'committed' -and -not $committed) {
            throw 'Installer journal claims commit but protected updater state does not confirm it.'
        }
        if ($journal.phase -eq 'rolled-back' -and $committed) {
            throw 'Installer journal claims rollback but protected updater state confirms commit.'
        }
        if ($committed) {
            foreach ($entry in @($journal.entries)) {
                $destination = [string]$entry.destination
                if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                    (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                    throw "Sequence is committed but installed binary does not match the transaction: $destination"
                }
            }
        }
        if ($committed) {
            $journal.phase = 'committed'
            Write-InstallJournal -Journal $journal
            try {
                Remove-CommittedTransactionBackups -Journal $journal
            } catch {
                throw "Committed installation remains valid; refusing another installation until backup cleanup completes. Cause: $($_.Exception.Message)"
            }
            continue
        }

        $serviceBefore = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $restartService = $null -ne $serviceBefore -and $serviceBefore.Status -eq 'Running'
        if ($restartService) {
            & (Get-Command -Name Stop-Service -CommandType Cmdlet) -Name $ServiceName -Force
            (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        try {
            for ($i = @($journal.entries).Count - 1; $i -ge 0; $i--) {
                $entry = @($journal.entries)[$i]
                $destination = [IO.Path]::GetFullPath([string]$entry.destination)
                if ([bool]$entry.had_original) {
                    $backup = [string]$entry.backup_path
                    if (Test-Path -LiteralPath $backup -PathType Leaf) {
                        $expected = [string]$entry.original_sha256
                        $restore = "$destination.$($journal.transaction_id).recover"
                        Copy-Item -LiteralPath $backup -Destination $restore -Force
                        if ((Get-Sha256FileHash $restore) -ne $expected) {
                            Remove-Item -LiteralPath $restore -Force -ErrorAction SilentlyContinue
                            throw "Interrupted-install restore verification failure: $destination"
                        }
                        Move-Item -LiteralPath $restore -Destination $destination -Force
                    }
                    if ((Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                        throw "Interrupted-install rollback verification failure: $destination"
                    }
                } else {
                    if (Test-Path -LiteralPath $destination -PathType Leaf) {
                        if ((Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                            throw "Unexpected binary contents prevent safe rollback: $destination"
                        }
                        Remove-Item -LiteralPath $destination -Force
                    }
                }
                Remove-Item -LiteralPath "$destination.$($journal.transaction_id).new" -Force -ErrorAction SilentlyContinue
            }
            $journal.phase = 'rolled-back'
            Write-InstallJournal -Journal $journal
        } catch {
            throw "Interrupted installer rollback failed closed; service remains stopped and backups are retained. Cause: $($_.Exception.Message)"
        }
        if ($restartService) {
            Start-Service -Name $ServiceName
            (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        }
    }
}

function Install-Binaries {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][hashtable]$Destinations,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$AttemptedNames,
        [Parameter(Mandatory = $true)][hashtable]$OriginalState
    )
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($name in $script:BinaryNames) {
        if (-not $script:VerifiedBinaryHashes.ContainsKey($name)) {
            throw "No pinned verified hash for $name"
        }
        $source = Join-Path $SourceDirectory $name
        $sourceHash = Get-Sha256FileHash $source
        if ($sourceHash -ne $script:VerifiedBinaryHashes[$name]) {
            throw "Release bundle changed after verification: $name"
        }
        $destination = [IO.Path]::GetFullPath([string]$Destinations[$name])
        $hadOriginal = Test-Path -LiteralPath $destination -PathType Leaf
        $OriginalState[$name] = $hadOriginal
        $originalHash = ''
        if ($hadOriginal) { $originalHash = Get-Sha256FileHash $destination }
        $entries.Add([ordered]@{
            name = $name
            destination = $destination
            had_original = [bool]$hadOriginal
            original_sha256 = $originalHash
            replacement_sha256 = $sourceHash
            backup_path = "$destination.$($script:InstallTransactionId).bak"
            state = 'planned'
        })
    }

    $journalPath = Join-Path (Join-Path $env:ProgramData 'WeDecent\install-transactions') ($script:InstallTransactionId + '.json')
    if (Test-Path -LiteralPath $journalPath) {
        throw 'Installer transaction ID has already been used; refusing replay.'
    }
    $script:InstallJournal = [ordered]@{
        schema = 1
        transaction_id = $script:InstallTransactionId
        package_sha256 = $ExpectedPackageSHA256
        manifest_sha256 = $ExpectedManifestSHA256
        previous_version = $PreviousVersion
        sequence = [UInt64]$script:InstallTransactionSequence
        service_was_running = [bool]$script:InstallServiceWasRunning
        version = $script:InstallTargetVersion
        phase = 'prepared'
        entries = @($entries.ToArray())
        updated_at = [DateTime]::UtcNow.ToString('o')
    }
    Write-InstallJournal -Journal $script:InstallJournal

    # All previous binaries are backed up and verified before any replacement.
    foreach ($entry in $script:InstallJournal.entries) {
        $name = [string]$entry.name
        $destination = [string]$entry.destination
        $backupPath = [string]$entry.backup_path
        if ([bool]$entry.had_original) {
            if (Test-Path -LiteralPath $backupPath) {
                throw "Transaction-specific backup path already exists: $backupPath"
            }
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                throw "Original binary changed before backup: $destination"
            }
            Copy-Item -LiteralPath $destination -Destination $backupPath
            if ((Get-Sha256FileHash $backupPath) -ne [string]$entry.original_sha256) {
                throw "Backup integrity verification failed for $destination"
            }
            Set-Content -LiteralPath "$backupPath.sha256" -Value $entry.original_sha256 -NoNewline -Encoding ASCII
            Protect-WeDecentMetadataAcl "$backupPath.sha256"
        }
        $entry.state = 'backup-verified'
        $script:InstallJournal.phase = 'backups-verified'
        Write-InstallJournal -Journal $script:InstallJournal
    }

    foreach ($entry in $script:InstallJournal.entries) {
        $AttemptedNames.Add([string]$entry.name)
    }
    foreach ($entry in $script:InstallJournal.entries) {
        $name = [string]$entry.name
        Install-Binary (Join-Path $SourceDirectory $name) ([string]$entry.destination) ([bool]$entry.had_original)
    }
    $script:InstallJournal.phase = 'installed-awaiting-sequence-commit'
    Write-InstallJournal -Journal $script:InstallJournal
}

function Assert-InstalledBinaries {
    param([Parameter(Mandatory = $true)][hashtable]$Destinations)
    foreach ($name in $script:BinaryNames) {
        if (-not $script:VerifiedBinaryHashes.ContainsKey($name)) {
            throw "No pinned verified hash for $name"
        }
        $destination = $Destinations[$name]
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            throw "Installed binary is missing: $destination"
        }
        $actual = Get-Sha256FileHash $destination
        if ($actual -ne $script:VerifiedBinaryHashes[$name]) {
            throw "Installed checksum mismatch for $name"
        }
    }
}

function Rollback-Binaries {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$AttemptedNames,
        [Parameter(Mandatory = $true)][hashtable]$OriginalState,
        [Parameter(Mandatory = $true)][hashtable]$Destinations
    )
    foreach ($name in $AttemptedNames) {
        $entry = @($script:InstallJournal.entries | Where-Object { $_.name -eq $name })[0]
        if ($null -eq $entry) { throw "Rollback journal entry is missing for $name" }
        $destination = [IO.Path]::GetFullPath([string]$Destinations[$name])
        if ([bool]$OriginalState[$name]) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                if ((Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                    throw "Rollback preflight found a corrupted backup: $backup"
                }
            } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                throw "Rollback preflight cannot find a verified original or backup: $destination"
            }
        } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
            if ((Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Rollback preflight found unexpected contents at $destination"
            }
        }
    }
    for ($i = $AttemptedNames.Count - 1; $i -ge 0; $i--) {
        $name = $AttemptedNames[$i]
        Rollback-Binary -Destination $Destinations[$name] -HadOriginal ([bool]$OriginalState[$name])
    }
}

function Remove-BinaryBackups {
    param([Parameter(Mandatory = $true)][hashtable]$Destinations)
    foreach ($name in $script:BinaryNames) {
        Remove-BinaryBackup $Destinations[$name]
    }
}

function Add-MachinePathEntry {
    param([string]$PathEntry)
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($machine -split ';' | Where-Object { $_ })
    if ($parts | Where-Object { $_.TrimEnd('\') -ieq $PathEntry.TrimEnd('\') }) { return }
    [Environment]::SetEnvironmentVariable('Path', (($parts + $PathEntry) -join ';'), 'Machine')
}

function Remove-EmptyDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    $child = Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop |
        Select-Object -First 1
    if (-not $child) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
}

function Test-DirectoryExistsStrict {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Expected a real, non-reparse directory at '$Path'."
        }
        return $true
    } catch {
        if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound -and
            $_.FullyQualifiedErrorId -match 'PathNotFound|ItemNotFound') {
            return $false
        }
        throw
    }
}

function Test-ServiceStateSafeForAccountRemoval {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch {
        if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound -and
            $_.FullyQualifiedErrorId -match 'PathNotFound|ItemNotFound') {
            return $true
        }
        return $false
    }
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $false
    }

    try {
        $remainingState = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        return $remainingState.Count -eq 0
    } catch {
        return $false
    }
}

function Publish-WeDecentRecoveryScript {
    $source = Join-Path $BundlePath 'Recover-WeDecentInstall.ps1'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw 'Verified installer recovery script is missing from the package.'
    }
    $target = Join-Path $InstallDir 'Recover-WeDecentInstall.ps1'
    $temp = "$target.$($script:InstallTransactionId).new"
    Copy-Item -LiteralPath $source -Destination $temp -Force
    if ((Get-Sha256FileHash $temp) -ne (Get-Sha256FileHash $source)) {
        throw 'Persisted installer recovery script failed integrity verification.'
    }
    Protect-WeDecentMetadataAcl $temp
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        $backup = Join-Path $InstallDir ('.recovery-script-' + [Guid]::NewGuid().ToString('N') + '.previous')
        [IO.File]::Replace($temp, $target, $backup, $true)
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    } else {
        [IO.File]::Move($temp, $target)
    }
    Protect-WeDecentMetadataAcl $target
}

function Invoke-RollbackStep {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    try {
        $null = & $Action
        return $true
    } catch {
        Write-Warning "Rollback step failed ($Description): $($_.Exception.Message)"
        return $false
    }
}

Assert-Administrator
if ([string]::IsNullOrWhiteSpace($BundlePath)) { $BundlePath = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($BundlePath)) { throw 'Cannot determine installer bundle path.' }
$BundlePath = (Resolve-Path -LiteralPath $BundlePath).Path
$InstallDir = Assert-SafeChildPath -Path $InstallDir -Root $env:ProgramFiles -Label 'InstallDir'
$StateDir = Assert-SafeChildPath -Path $StateDir -Root $InstallDir -Label 'StateDir'
$version = Assert-ReleaseBundle
$script:InstallTargetVersion = $version
$metadataPath = Get-WeDecentMetadataPath
$migrationModule = Join-Path $PSScriptRoot 'StateMigration.psm1'
Import-Module $migrationModule -Force -ErrorAction Stop
$migrationJournalPath = Join-Path $InstallDir 'migration\state-migration.json'
$migrationAgentPath = Join-Path $BundlePath 'wd-agent.exe'
$metadata = Read-WeDecentMetadata
$metadataTrusted = $false
if ($metadata) {
    $metadataTrusted = Test-WeDecentMetadataTrusted $metadataPath
    if (-not $metadataTrusted) {
        throw 'Existing installer metadata is not ACL-trusted; refusing migration recovery or installer state changes.'
    }
}
if (Test-Path -LiteralPath $migrationJournalPath -PathType Leaf) {
    [void](Set-WeDecentMigrationAdminDirectory -Path (Split-Path -Parent $migrationJournalPath) -AgentPath $migrationAgentPath)
    [void](Recover-WeDecentStateMigration -JournalPath $migrationJournalPath -AgentPath $migrationAgentPath -MetadataPath $metadataPath -ServiceName $ServiceName)
}
$metadata = Read-WeDecentMetadata
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
$script:InstallServiceWasRunning = $null -ne $service -and $service.State -eq 'Running'
if (-not $service) {
    if ($metadata) {
        if (-not $metadataTrusted) {
            throw 'Installer metadata exists but is not ACL-authenticated; refusing a fresh identity over potentially existing state.'
        }
        throw 'Authenticated installer metadata exists but the service is absent; refusing fresh identity creation until the existing installation state is recovered or explicitly retired.'
    }
    $legacyDefaultStateDir = Join-Path $env:ProgramData 'WeDecent\agent'
    if (Test-DirectoryExistsStrict -Path $legacyDefaultStateDir) {
        throw 'Legacy ProgramData service state exists; refusing to create a replacement identity at the Program Files location.'
    }
}
$binaryDestinations = Get-BinaryDestinations -Directory $InstallDir
Recover-InterruptedInstallerTransactions -Destinations $binaryDestinations
Assert-InstalledUserBinariesStopped -Destinations $binaryDestinations
$wdDestination = $binaryDestinations['wd.exe']
$agentDestination = $binaryDestinations['wd-agent.exe']

if ($service) {
    if (-not $metadataTrusted -or [string]::IsNullOrWhiteSpace([string]$metadata.state_dir)) {
        throw 'Existing service state location is not authenticated by protected installer metadata; refusing upgrade until an operator performs an identity-preserving offline migration.'
    }
    $recordedStateDir = [IO.Path]::GetFullPath([string]$metadata.state_dir)
    $requestedStateDir = [IO.Path]::GetFullPath($StateDir)
    $needsStateMigration = -not [string]::Equals($recordedStateDir.TrimEnd('\'), $requestedStateDir.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
    $stateArg = [regex]::Escape('--state=' + $recordedStateDir)
    if ($service.PathName -notmatch ('(?i)(?:^|\s)"?' + $stateArg + '"?(?:\s|$)')) {
        throw 'Existing SCM command line does not match the authenticated state_dir metadata; refusing upgrade.'
    }
    if ($service.StartName -match '^(LocalSystem|LocalService|NetworkService|NT AUTHORITY\\(SYSTEM|LocalService|NetworkService))$') {
        throw "Refusing to upgrade service running as built-in identity $($service.StartName)"
    }
    $expectedAgent = '^(?:"' + [Regex]::Escape($agentDestination) + '"|' + [Regex]::Escape($agentDestination) + ')(?:\s|$)'
    if ($service.PathName -notmatch $expectedAgent) {
        throw "Existing service binary path is not $agentDestination; refusing to rewrite an unrelated service"
    }
    $localName = Get-LocalAccountName $service.StartName
    if (-not $localName) { throw "Installer-managed services must use a dedicated local account; got '$($service.StartName)'." }
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $localUser = Get-LocalUser -Name $localName -ErrorAction Stop
    Assert-StandardLocalAccount $localUser
    $accountSid = $localUser.SID.Value
    $managed = $false
    if ($metadataTrusted -and $metadata.service_account_sid -eq $accountSid) {
        $managed = [bool]$metadata.managed_service_account
    }

    if (-not $PSCmdlet.ShouldProcess("$InstallDir and service '$ServiceName'", "Upgrade WeDecent to $version")) { return }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    if ($needsStateMigration) {
        $journalParent = Split-Path -Parent $migrationJournalPath
        if (-not (Test-Path -LiteralPath $journalParent -PathType Container)) {
            New-Item -ItemType Directory -Path $journalParent -Force | Out-Null
        }
        [void](Set-WeDecentMigrationAdminDirectory -Path $journalParent -AgentPath $migrationAgentPath)
        $destinationParent = Split-Path -Parent $requestedStateDir
        if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
            New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
            Set-WeDecentMigrationAdminDirectory -Path $destinationParent -AgentPath $migrationAgentPath
        } else {
            [void](Set-WeDecentMigrationAdminDirectory -Path $destinationParent -AgentPath $migrationAgentPath)
        }
        Write-Host "Migrating authenticated service state from '$recordedStateDir' to '$requestedStateDir'."
        [void](Invoke-WeDecentStateMigration -Source $recordedStateDir -Destination $requestedStateDir -AgentPath $migrationAgentPath -ServiceName $ServiceName -ServiceSid $accountSid -MetadataPath $metadataPath -JournalPath $migrationJournalPath)
        $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        $metadata = Read-WeDecentMetadata
        if ([IO.Path]::GetFullPath([string]$metadata.state_dir) -ine $requestedStateDir) {
            throw 'Authenticated installer metadata did not commit the migrated state path.'
        }
    }
    Write-Host "Upgrading existing $ServiceName service; state and service account will be preserved."
    if ($service.State -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $attemptedBinaryNames = [System.Collections.Generic.List[string]]::new()
    $binaryOriginalState = @{}
    try {
        Install-Binaries -SourceDirectory $BundlePath -Destinations $binaryDestinations -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState
        Publish-WeDecentRecoveryScript

        Assert-InstalledBinaries -Destinations $binaryDestinations
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        Write-WeDecentMetadata -AccountSid $accountSid -ManagedAccount $managed -AccountName $localName -Version $version
        Initialize-WeDecentUpdateState -Version $version -ServiceSid $accountSid
    } catch {
        $failed = $_
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $binariesRestored = Invoke-RollbackStep 'restore installed binaries' {
            Rollback-Binaries -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState -Destinations $binaryDestinations
        }
        if ($binariesRestored) {
            Invoke-RollbackStep 'restart previous agent service' {
                Start-Service -Name $ServiceName
                (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            }
        } else {
            Write-Warning 'Previous binaries could not be fully restored; the agent service is intentionally left stopped for recovery.'
        }
        throw "Upgrade failed; rollback was attempted: $($failed.Exception.Message)"
    }
    if (-not $script:IsManagedUpdate -and $script:InstallJournal) {
        $script:InstallJournal.phase = 'committed'
        Write-InstallJournal -Journal $script:InstallJournal
        Remove-CommittedTransactionBackups -Journal $script:InstallJournal
    }
} else {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $localUser = Get-LocalUser -Name $ServiceAccountName -ErrorAction SilentlyContinue
    if ($localUser) { Assert-StandardLocalAccount $localUser }

    if (-not $PSCmdlet.ShouldProcess("$InstallDir and service '$ServiceName'", "Install WeDecent $version")) { return }

    if ([string]::IsNullOrWhiteSpace($RecoveryAuthorityUrl)) {
        throw 'A recovery-authority HTTPS origin is required through -RecoveryAuthorityUrl or WEDECENT_PAIRING_RECOVERY_AUTHORITY_URL.'
    }
    $authorityUri = $null
    if (-not [Uri]::TryCreate($RecoveryAuthorityUrl, [UriKind]::Absolute, [ref]$authorityUri) -or
        $authorityUri.Scheme -ne 'https' -or [string]::IsNullOrEmpty($authorityUri.Host) -or
        $authorityUri.UserInfo -or $authorityUri.Query -or $authorityUri.Fragment -or
        ($authorityUri.AbsolutePath -ne '' -and $authorityUri.AbsolutePath -ne '/')) {
        throw 'RecoveryAuthorityUrl must be an origin-only HTTPS URL.'
    }
    if ($RecoveryAuthoritySPKISHA256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw 'RecoveryAuthoritySPKISHA256 must contain exactly 64 hexadecimal characters.'
    }
    if ([string]::IsNullOrWhiteSpace($RecoveryAuthorityTrustFile)) {
        throw 'RecoveryAuthorityTrustFile is required.'
    }
    $trustItem = Get-Item -LiteralPath $RecoveryAuthorityTrustFile -Force -ErrorAction Stop
    if ($trustItem.PSIsContainer -or
        ($trustItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'RecoveryAuthorityTrustFile must be a regular, non-reparse file.'
    }
    $RecoveryAuthorityTrustFile = $trustItem.FullName
    if ($null -eq $RecoveryAuthorityBearerToken) {
        $RecoveryAuthorityBearerToken = Read-Host -Prompt 'Short-lived recovery-authority bearer token' -AsSecureString
    }
    if ($null -eq $RecoveryAuthorityBearerToken -or $RecoveryAuthorityBearerToken.Length -lt 32 -or
        $RecoveryAuthorityBearerToken.Length -gt 4096) {
        throw 'RecoveryAuthorityBearerToken must contain 32 to 4096 characters.'
    }
    Assert-SecureStringLine -SecureString $RecoveryAuthorityBearerToken -MinimumLength 32 -MaximumLength 4096 -Label 'RecoveryAuthorityBearerToken' -RejectEdgeWhitespace

    $installDirExisted = Test-Path -LiteralPath $InstallDir -PathType Container
    $stateParent = Split-Path -Parent $StateDir
    $stateParentExisted = Test-DirectoryExistsStrict -Path $stateParent
    $stateExisted = Test-DirectoryExistsStrict -Path $StateDir
    $createdAccount = $false
    $hadLogonRight = $false
    $originalMachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $managed = $false
    $password = $null
    $attemptedBinaryNames = [System.Collections.Generic.List[string]]::new()
    $binaryOriginalState = @{}

    try {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        if ($localUser) {
            $metadataManaged = $metadataTrusted -and [bool]$metadata.managed_service_account -and $metadata.service_account_sid -eq $localUser.SID.Value
            if ($metadataManaged) {
                $plainGenerated = New-ServiceAccountPassword
                try {
                    $password = ConvertTo-SecureString $plainGenerated -AsPlainText -Force
                    Set-LocalUser -Name $ServiceAccountName -Password $password
                } finally {
                    $plainGenerated = $null
                }
                $managed = $true
            } elseif ($AdoptExistingServiceAccount) {
                if (-not $ServiceAccountCredential) {
                    throw '-AdoptExistingServiceAccount requires -ServiceAccountCredential for a pre-existing account.'
                }
                $password = $ServiceAccountCredential.Password
            } else {
                throw "Local account $ServiceAccountName already exists but is not recorded as trusted installer-managed. Use -AdoptExistingServiceAccount with an in-memory PSCredential, or choose another account name."
            }
        } else {
            if ($ServiceAccountCredential) {
                $password = $ServiceAccountCredential.Password
            } else {
                $plainGenerated = New-ServiceAccountPassword
                try {
                    $password = ConvertTo-SecureString $plainGenerated -AsPlainText -Force
                } finally {
                    $plainGenerated = $null
                }
            }
            $localUser = New-LocalUser -Name $ServiceAccountName -Password $password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description 'WeDecent dedicated terminal service account'
            $createdAccount = $true
            $managed = $true
        }

        Assert-StandardLocalAccount $localUser
        Assert-SecureStringLine -SecureString $password -MinimumLength 1 -MaximumLength 4096 -Label 'Service account password'
        $hadLogonRight = Test-ServiceLogonRight -Sid $localUser.SID.Value
        if (-not $hadLogonRight) { Set-ServiceLogonRight -Sid $localUser.SID.Value -Present $true }

        Install-Binaries -SourceDirectory $BundlePath -Destinations $binaryDestinations -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState
        Assert-InstalledBinaries -Destinations $binaryDestinations
        Invoke-AgentServiceInstall -AgentPath $agentDestination -Password $password -RecoveryBearerToken $RecoveryAuthorityBearerToken

        $finalService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        if (-not $finalService -or $finalService.State -ne 'Running') {
            throw "$ServiceName is not running after installation"
        }
        $finalSid = Resolve-AccountSid $finalService.StartName
        if ($finalSid -ne $localUser.SID.Value) {
            throw 'Installed service account SID does not match the expected local account.'
        }

        if ($AddToMachinePath) { Add-MachinePathEntry $InstallDir }
        Write-WeDecentMetadata -AccountSid $localUser.SID.Value -ManagedAccount $managed -AccountName $ServiceAccountName -Version $version
        Initialize-WeDecentUpdateState -Version $version -ServiceSid $localUser.SID.Value
        if (-not $script:IsManagedUpdate -and $script:InstallJournal) {
        $script:InstallJournal.phase = 'committed'
        Write-InstallJournal -Journal $script:InstallJournal
        Remove-CommittedTransactionBackups -Journal $script:InstallJournal
    }
    } catch {
        $failed = $_
        Invoke-RollbackStep 'remove partially created service' {
            $createdService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($createdService) {
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                & sc.exe delete $ServiceName | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE" }
            }
        }
        Invoke-RollbackStep 'restore installed binaries' {
            Rollback-Binaries -AttemptedNames $attemptedBinaryNames -OriginalState $binaryOriginalState -Destinations $binaryDestinations
        }
        if ($AddToMachinePath) {
            Invoke-RollbackStep 'restore machine PATH' {
                [Environment]::SetEnvironmentVariable('Path', $originalMachinePath, 'Machine')
            }
        }
        if (-not $stateExisted) {
            Invoke-RollbackStep 'remove only an empty installer-created state directory' {
                Remove-EmptyDirectory -Path $StateDir
            }
            if (-not $stateParentExisted) {
                Invoke-RollbackStep 'remove empty installer-created state parent' {
                    Remove-EmptyDirectory -Path $stateParent
                }
            }
            if (Test-Path -LiteralPath $StateDir -PathType Container) {
                $remainingState = @(Get-ChildItem -LiteralPath $StateDir -Force -ErrorAction Stop)
                if ($remainingState.Count -gt 0) {
                    Write-Warning "Preserving non-empty protected service state after interrupted installation. Do not delete or repair identity/trust material; use the documented offline recovery and re-enrollment procedure. State: $StateDir"
                }
            }
        }
        if (-not $installDirExisted) {
            Invoke-RollbackStep 'remove empty installer-created install directory' {
                Remove-EmptyDirectory -Path $InstallDir
            }
        }
        if ($localUser -and -not $hadLogonRight) {
            Invoke-RollbackStep 'remove SeServiceLogonRight' {
                Set-ServiceLogonRight -Sid $localUser.SID.Value -Present $false
            }
        }
        if ($createdAccount) {
            Invoke-RollbackStep 'remove installer-created service account only when protected state is empty' {
                if (Test-ServiceStateSafeForAccountRemoval -Path $StateDir) {
                    Remove-LocalUser -Name $ServiceAccountName -ErrorAction Stop
                } else {
                    Write-Warning "Retaining installer-created service account '$ServiceAccountName': protected state is non-empty, non-directory, or could not be inspected. Preserve the account for offline recovery."
                }
            }
        }
        throw "Fresh installation failed; rollback was attempted: $($failed.Exception.Message)"
    }
}

if ($service -and $AddToMachinePath) { Add-MachinePathEntry $InstallDir }

$finalService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if (-not $finalService -or $finalService.State -ne 'Running') { throw "$ServiceName is not running after installation" }

Write-Host "WeDecent $version installed successfully."
Write-Host "Client:    $wdDestination"
Write-Host "Agent:     $agentDestination"
Write-Host "RouterCtl: $($binaryDestinations['wd-routerctl.exe'])"
Write-Host "Core:      $($binaryDestinations['wd-core.exe'])"
Write-Host "UI:        $($binaryDestinations['wd-ui.exe'])"
Write-Host "State:     $StateDir"
Write-Host "Service:   $ServiceName ($($finalService.StartName))"
Write-Host 'wd-core.exe and wd-ui.exe are installed for same-user launch; the installer does not register them as services or autostart entries.'