[CmdletBinding(DefaultParameterSetName = 'Recover')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [ValidatePattern('^[a-f0-9]{32}$')]
    [string]$TransactionId,
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [Parameter(Mandatory = $true)]
    [string]$StateDir,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')]
    [string]$ServiceName,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [string]$ExpectedManifestSHA256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [string]$ExpectedPackageSHA256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [UInt64]$Sequence,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [string]$PreviousVersion,
    [Parameter(Mandatory = $true, ParameterSetName = 'Recover')]
    [string]$TargetVersion,
    [Parameter(Mandatory = $true, ParameterSetName = 'FinalizeCommitted')]
    [switch]$FinalizeCommitted,
    [Parameter(Mandatory = $true, ParameterSetName = 'FinalizeCommitted')]
    [UInt64]$ExpectedStableSequence,
    [Parameter(Mandatory = $true, ParameterSetName = 'FinalizeCommitted')]
    [string]$ExpectedInstalledVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:RecoveryExpectedServiceStartMode = $null
$BinaryNames = @('wd.exe', 'wd-agent.exe', 'wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe')
$TrustedSids = @('S-1-5-18', 'S-1-5-32-544')

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Windows installer recovery requires an elevated administrator token.'
    }
}

function Get-Sha256FileHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Recovery input is not a regular file: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Set-TrustedAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sidText in $TrustedSids) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-TrustedAcl {
    param([Parameter(Mandatory = $true)][string]$Path, [string[]]$AdditionalTrustedSids = @())
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Recovery trust path must not be a reparse point: $Path"
    }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Recovery trust path has an inheriting DACL: $Path"
    }
    $ownerSid = (New-Object Security.Principal.NTAccount -ArgumentList $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedSids -notcontains $ownerSid -and $AdditionalTrustedSids -notcontains $ownerSid) {
        throw "Recovery trust path has an untrusted owner: $Path"
    }
    foreach ($rule in @($acl.Access)) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if (($TrustedSids -notcontains $sid -and $AdditionalTrustedSids -notcontains $sid) -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "Recovery trust path has an untrusted ACL entry: $Path"
        }
    }
}

function Acquire-WeDecentRecoveryLock {
    $root = Join-Path $env:ProgramData 'WeDecent\install-transactions'
    $rootCreated = -not (Test-Path -LiteralPath $root)
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $rootInfo = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootInfo.PSIsContainer -or ($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Recovery lock directory must be a regular non-reparse directory.'
    }
    if ($rootCreated) { Set-TrustedAcl -Path $root }
    Assert-TrustedAcl -Path $root
    $path = Join-Path $root 'installer.lock'
    $lockCreated = $false
    if (-not (Test-Path -LiteralPath $path)) {
        try {
            $bootstrap = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $bootstrap.Dispose()
            $lockCreated = $true
        } catch [IO.IOException] {
            if (-not (Test-Path -LiteralPath $path)) { throw }
        }
    }
    $info = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer lock path is not a regular non-reparse file.'
    }
    if ($lockCreated) { Set-TrustedAcl -Path $path }
    Assert-TrustedAcl -Path $path
    try {
        # The same exclusive OS file handle serializes installer and updater recovery; process exit releases stale ownership.
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch [IO.IOException] {
        throw 'Another WeDecent installer or recovery operation owns the machine-wide installation lock.'
    }
    try {
        $stream.SetLength(0)
        $owner = [Text.Encoding]::ASCII.GetBytes(("pid=" + $PID + [Environment]::NewLine))
        $stream.Write($owner, 0, $owner.Length)
        $stream.Flush($true)
        return $stream
    } catch {
        $stream.Dispose()
        throw
    }
}

function Resolve-ServiceAccountSid {
    param([Parameter(Mandatory = $true)][string]$StartName)
    $account = $StartName.Trim()
    if ([string]::IsNullOrWhiteSpace($account)) {
        throw 'SCM service account is empty; refusing recovery.'
    }
    switch -Regex ($account) {
        '^(?i:LocalSystem|NT AUTHORITY\\SYSTEM)$' { return 'S-1-5-18' }
        '^(?i:NT AUTHORITY\\LOCAL SERVICE)$' { return 'S-1-5-19' }
        '^(?i:NT AUTHORITY\\NETWORK SERVICE)$' { return 'S-1-5-20' }
        default {
            if ($account.StartsWith('.\', [StringComparison]::Ordinal)) {
                $account = "$env:COMPUTERNAME\$($account.Substring(2))"
            }
            try {
                return (New-Object Security.Principal.NTAccount -ArgumentList $account).Translate([Security.Principal.SecurityIdentifier]).Value
            } catch {
                throw "SCM service account could not be resolved to a SID; refusing recovery. Cause: $($_.Exception.Message)"
            }
        }
    }
}

function Normalize-ServiceAccountName {
    param([Parameter(Mandatory = $true)][string]$Name)
    $value = $Name.Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'Service account name is empty.' }
    if ($value.StartsWith('.\', [StringComparison]::Ordinal)) {
        return "$env:COMPUTERNAME\$($value.Substring(2))"
    }
    if (-not $value.Contains('\')) { return "$env:COMPUTERNAME\$value" }
    return $value
}

function Assert-AuthenticatedRecoveryServiceIdentity {
    param(
        [Parameter(Mandatory = $true)]$Metadata,
        [Parameter(Mandatory = $true)]$ServiceConfig
    )
    if ([string]$Metadata.service_name -cne $ServiceName -or
        [string]$ServiceConfig.Name -cne $ServiceName -or
        [IO.Path]::GetFullPath([string]$Metadata.install_dir) -ine $InstallDir -or
        [IO.Path]::GetFullPath([string]$Metadata.state_dir) -ine $StateDir) {
        throw 'Protected installer metadata does not authenticate the live recovery service paths.'
    }
    $expectedSid = [Security.Principal.SecurityIdentifier]::new([string]$Metadata.service_account_sid).Value
    $metadataAccountName = Normalize-ServiceAccountName -Name ([string]$Metadata.service_account_name)
    $liveAccountName = Normalize-ServiceAccountName -Name ([string]$ServiceConfig.StartName)
    $localAccountPrefix = "$env:COMPUTERNAME\"
    if (-not $metadataAccountName.StartsWith($localAccountPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($metadataAccountName, $liveAccountName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Live SCM service account name does not exactly match protected installer metadata.'
    }
    $metadataAccountSid = Resolve-ServiceAccountSid -StartName $metadataAccountName
    $liveAccountSid = Resolve-ServiceAccountSid -StartName $liveAccountName
    if ($expectedSid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -or
        -not [string]::Equals($metadataAccountSid, $expectedSid, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($liveAccountSid, $expectedSid, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Live SCM service account SID does not match the dedicated account authenticated by protected installer metadata.'
    }
    $liveStartMode = [string]$ServiceConfig.StartMode
    if ([string]::IsNullOrWhiteSpace($liveStartMode)) {
        throw 'Live SCM service start mode is unavailable.'
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$script:RecoveryExpectedServiceStartMode)) {
        if ($liveStartMode -cne [string]$script:RecoveryExpectedServiceStartMode) {
            throw 'Live SCM service start mode changed during the authenticated recovery transaction.'
        }
    } elseif ($liveStartMode -notin @('Auto', 'Manual')) {
        throw 'Live SCM service start mode is unsupported for authenticated recovery.'
    }

    $expectedExecutable = [IO.Path]::GetFullPath((Join-Path $InstallDir 'wd-agent.exe'))
    $servicePath = [string]$ServiceConfig.PathName
    $exeMatch = [regex]::Match($servicePath, '^"([^"]+)"(?:\s|$)|^(\S+)(?:\s|$)')
    if (-not $exeMatch.Success) { throw 'Live SCM executable path is missing or ambiguous.' }
    $actualExecutable = if ($exeMatch.Groups[1].Success) { $exeMatch.Groups[1].Value } else { $exeMatch.Groups[2].Value }
    if (-not [string]::Equals([IO.Path]::GetFullPath($actualExecutable), $expectedExecutable, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Live SCM executable path does not match protected installer metadata.'
    }

    $statePattern = '(?i)(?<!\S)"--state=([^"]+)"|(?<!\S)--state="([^"]+)"|(?<!\S)--state=([^\s"]+)'
    $stateMatches = [regex]::Matches($servicePath, $statePattern)
    if ($stateMatches.Count -ne 1) { throw 'Live SCM command line must contain exactly one authenticated --state argument.' }
    $stateMatch = $stateMatches[0]
    $actualState = if ($stateMatch.Groups[1].Success) { $stateMatch.Groups[1].Value } elseif ($stateMatch.Groups[2].Success) { $stateMatch.Groups[2].Value } else { $stateMatch.Groups[3].Value }
    if (-not [string]::Equals([IO.Path]::GetFullPath($actualState), $StateDir, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Live SCM state path does not match protected installer metadata.'
    }
    return $ServiceConfig
}

function Get-AuthenticatedRecoveryServiceSnapshot {
    param([Parameter(Mandatory = $true)]$Metadata)
    $config = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if ($null -eq $config) { throw 'Live SCM service configuration is unavailable.' }
    [void](Assert-AuthenticatedRecoveryServiceIdentity -Metadata $Metadata -ServiceConfig $config)
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($null -eq $service) { throw 'Live SCM service status is unavailable.' }
    return [pscustomobject]@{ Config = $config; Service = $service }
}

if (-not ('WeDecentRecoveryScmDatabaseLock' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class WeDecentRecoveryScmDatabaseLock
{
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr OpenSCManager(IntPtr machineName, IntPtr databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern IntPtr LockServiceDatabase(IntPtr scmHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnlockServiceDatabase(IntPtr lockHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseServiceHandle(IntPtr handle);
}
'@ -ErrorAction Stop
}

function Assert-AuthenticatedRecoveryServiceAccount {
    param([Parameter(Mandatory = $true)]$Metadata)
    $config = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if ($null -eq $config -or [string]$config.Name -cne $ServiceName -or [string]$Metadata.service_name -cne $ServiceName) {
        throw 'SCM service name does not match protected installer metadata.'
    }
    $expectedSid = [Security.Principal.SecurityIdentifier]::new([string]$Metadata.service_account_sid).Value
    $metadataAccountName = Normalize-ServiceAccountName -Name ([string]$Metadata.service_account_name)
    $liveAccountName = Normalize-ServiceAccountName -Name ([string]$config.StartName)
    $localAccountPrefix = "$env:COMPUTERNAME\"
    if (-not $metadataAccountName.StartsWith($localAccountPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($metadataAccountName, $liveAccountName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Live SCM service account name does not exactly match protected installer metadata.'
    }
    $metadataSid = Resolve-ServiceAccountSid -StartName $metadataAccountName
    $liveSid = Resolve-ServiceAccountSid -StartName $liveAccountName
    if ($expectedSid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -or
        -not [string]::Equals($metadataSid, $expectedSid, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($liveSid, $expectedSid, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Live SCM service account SID does not match protected installer metadata.'
    }
    return $config
}

function Enter-RecoveryScmMutationLock {
    $manager = [WeDecentRecoveryScmDatabaseLock]::OpenSCManager([IntPtr]::Zero, [IntPtr]::Zero, 0x0009)
    if ($manager -eq [IntPtr]::Zero) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [ComponentModel.Win32Exception]::new($errorCode, "Unable to open SCM for exclusive service-configuration protection (Win32 $errorCode).")
    }
    $lock = [WeDecentRecoveryScmDatabaseLock]::LockServiceDatabase($manager)
    if ($lock -eq [IntPtr]::Zero) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [void][WeDecentRecoveryScmDatabaseLock]::CloseServiceHandle($manager)
        throw [ComponentModel.Win32Exception]::new($errorCode, 'Unable to lock SCM service configuration; refusing service mutation.')
    }
    return [pscustomobject]@{ Manager = $manager; Lock = $lock }
}

function Exit-RecoveryScmMutationLock {
    param([Parameter(Mandatory = $true)]$Handle)
    $unlockError = $null
    try {
        if (-not [WeDecentRecoveryScmDatabaseLock]::UnlockServiceDatabase($Handle.Lock)) {
            $unlockError = [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error(), 'Unable to release SCM service-configuration lock.')
        }
    } finally {
        [void][WeDecentRecoveryScmDatabaseLock]::CloseServiceHandle($Handle.Manager)
    }
    if ($null -ne $unlockError) { throw $unlockError }
}

function Stop-AuthenticatedRecoveryService {
    param([Parameter(Mandatory = $true)]$Metadata, [object]$ScmLock)
    $ownsScmLock = $null -eq $ScmLock
    if ($ownsScmLock) { $ScmLock = Enter-RecoveryScmMutationLock }
    try {
        $snapshot = Get-AuthenticatedRecoveryServiceSnapshot -Metadata $Metadata
        if ($snapshot.Service.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        }
        $stopped = Get-Service -Name $ServiceName -ErrorAction Stop
        $stopped.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        if ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne 'Stopped') {
            throw 'SCM did not confirm the service stopped.'
        }
    } finally {
        if ($ownsScmLock) { Exit-RecoveryScmMutationLock -Handle $ScmLock }
    }
}

function Start-AuthenticatedRecoveryService {
    param([Parameter(Mandatory = $true)]$Metadata, [object]$ScmLock)
    $ownsScmLock = $null -eq $ScmLock
    if ($ownsScmLock) { $ScmLock = Enter-RecoveryScmMutationLock }
    try {
        $snapshot = Get-AuthenticatedRecoveryServiceSnapshot -Metadata $Metadata
        if ($snapshot.Service.Status -eq 'Running') {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $unexpectedlyRunning = Get-Service -Name $ServiceName -ErrorAction Stop
            $unexpectedlyRunning.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            throw 'SCM service was started outside the recovery transaction; it was stopped and recovery restart was rejected.'
        }
        Start-Service -Name $ServiceName -ErrorAction Stop
        $running = Get-Service -Name $ServiceName -ErrorAction Stop
        $running.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        if ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne 'Running') {
            throw 'SCM did not confirm the service running.'
        }
    } finally {
        if ($ownsScmLock) { Exit-RecoveryScmMutationLock -Handle $ScmLock }
    }
}

function Restore-TransactionRecoveryScript {
    param([Parameter(Mandatory = $true)]$Journal)
    $target = [IO.Path]::GetFullPath((Join-Path $InstallDir 'Recover-WeDecentInstall.ps1'))
    $backup = "$target.$($Journal.transaction_id).previous"
    if (-not [IO.Path]::GetFullPath([string]$Journal.recovery_script_path).Equals($target, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath([string]$Journal.recovery_script_backup_path).Equals($backup, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Recovery script transaction paths are invalid.'
    }
    $expected = [string]$Journal.recovery_script_original_sha256
    if ($expected -notmatch '^[a-f0-9]{64}$') {
        throw 'Previous recovery script digest is invalid.'
    }
    $staging = "$backup.staging"
    if (Test-Path -LiteralPath $staging) {
        $stagingInfo = Get-Item -LiteralPath $staging -Force -ErrorAction Stop
        if ($stagingInfo.PSIsContainer -or ($stagingInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Test-Path -LiteralPath $backup) -or
            -not (Test-Path -LiteralPath $target -PathType Leaf) -or
            (Get-Sha256FileHash $target) -ne $expected) {
            throw 'Interrupted recovery-script staging file cannot be safely discarded; retaining it and refusing rollback.'
        }
        # The original script remains authoritative; only the incomplete transaction staging file is removed.
        Remove-Item -LiteralPath $staging -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $backup) {
        $backupInfo = Get-Item -LiteralPath $backup -Force -ErrorAction Stop
        if ($backupInfo.PSIsContainer -or ($backupInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Previous recovery script backup is not a regular file; retaining it and refusing rollback.'
        }
        Assert-TrustedAcl -Path $backup
        if ((Get-Sha256FileHash $backup) -ne $expected) {
            throw 'Previous recovery script backup is corrupted; retaining it and refusing rollback.'
        }
        $restore = "$target.$($Journal.transaction_id).restore"
        if (Test-Path -LiteralPath $restore) {
            $restoreInfo = Get-Item -LiteralPath $restore -Force -ErrorAction Stop
            if ($restoreInfo.PSIsContainer -or ($restoreInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Interrupted recovery-script restore path is not a regular file.'
            }
            Remove-Item -LiteralPath $restore -Force -ErrorAction Stop
        }
        Copy-Item -LiteralPath $backup -Destination $restore
        if ((Get-Sha256FileHash $restore) -ne $expected) {
            Remove-Item -LiteralPath $restore -Force -ErrorAction SilentlyContinue
            throw 'Previous recovery script restore copy failed integrity verification.'
        }
        Set-TrustedAcl -Path $restore
        Assert-TrustedAcl -Path $restore
        Move-Item -LiteralPath $restore -Destination $target -Force
        Set-TrustedAcl -Path $target
    } elseif (-not (Test-Path -LiteralPath $target -PathType Leaf) -or
        (Get-Sha256FileHash $target) -ne $expected) {
        throw 'Previous recovery script and its transaction backup are both unavailable.'
    }
    $targetInfo = Get-Item -LiteralPath $target -Force -ErrorAction Stop
    if ($targetInfo.PSIsContainer -or ($targetInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-Sha256FileHash $target) -ne $expected) {
        throw 'Restored previous recovery script failed integrity verification.'
    }
    Set-TrustedAcl -Path $target
    Assert-TrustedAcl -Path $target
    $Journal.recovery_script_sha256 = $expected
    $Journal.recovery_script_state = 'original'
    $journalPath = Join-Path (Join-Path $env:ProgramData 'WeDecent\install-transactions') ($Journal.transaction_id + '.json')
    Write-TransactionJournal -Journal $Journal -Path $journalPath
    if (Test-Path -LiteralPath $backup) {
        $backupInfo = Get-Item -LiteralPath $backup -Force -ErrorAction Stop
        if ($backupInfo.PSIsContainer -or ($backupInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Restored recovery script journal is durable, but its transaction backup is not a regular file.'
        }
        Assert-TrustedAcl -Path $backup
        if ((Get-Sha256FileHash $backup) -ne $expected) {
            throw 'Restored recovery script journal is durable, but its transaction backup failed cleanup verification.'
        }
        Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
    }
}

function Write-TransactionJournal {
    param([Parameter(Mandatory = $true)]$Journal, [Parameter(Mandatory = $true)][string]$Path)
    $directory = Split-Path -Parent $Path
    $temp = Join-Path $directory ('.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $Journal.updated_at = [DateTime]::UtcNow.ToString('o')
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Journal | ConvertTo-Json -Depth 8 -Compress) + [Environment]::NewLine)
    $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    Set-TrustedAcl -Path $temp
    Assert-TrustedAcl -Path $temp
    $backup = Join-Path $directory ('.' + [Guid]::NewGuid().ToString('N') + '.previous')
    [IO.File]::Replace($temp, $Path, $backup, $true)
    Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    Assert-TrustedAcl -Path $Path
}

function Get-TransactionRecoveryScriptBackupForCleanup {
    param([Parameter(Mandatory = $true)]$Journal, [bool]$Current = $false, [bool]$RolledBack = $false)
    $fields = @('recovery_script_path', 'recovery_script_backup_path', 'recovery_script_had_original', 'recovery_script_original_sha256', 'recovery_script_sha256', 'recovery_script_state')
    $present = @($fields | Where-Object { $null -ne $Journal.PSObject.Properties[$_] })
    if ($present.Count -eq 0) { return $null }
    if ($present.Count -ne $fields.Count) { throw 'Committed cleanup journal contains partial recovery-script authentication fields.' }
    $target = [IO.Path]::GetFullPath((Join-Path $InstallDir 'Recover-WeDecentInstall.ps1'))
    $backup = "$target.$($Journal.transaction_id).previous"
    if (-not [IO.Path]::GetFullPath([string]$Journal.recovery_script_path).Equals($target, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath([string]$Journal.recovery_script_backup_path).Equals($backup, [StringComparison]::OrdinalIgnoreCase) -or
        $Journal.recovery_script_had_original -isnot [bool]) {
        throw 'Committed cleanup recovery-script transaction paths or original-state marker are invalid.'
    }
    $hadOriginal = [bool]$Journal.recovery_script_had_original
    $originalHash = [string]$Journal.recovery_script_original_sha256
    $publishedHash = [string]$Journal.recovery_script_sha256
    $state = [string]$Journal.recovery_script_state
    if ($RolledBack) {
        $expectedState = 'absent'
        if ($hadOriginal) { $expectedState = 'original' }
        if ($state -ne $expectedState -or
            ($hadOriginal -and ($originalHash -notmatch '^[a-f0-9]{64}$' -or $publishedHash -ne $originalHash)) -or
            (-not $hadOriginal -and (-not [string]::IsNullOrEmpty($originalHash) -or -not [string]::IsNullOrEmpty($publishedHash)))) {
            throw 'Rolled-back recovery-script journal state is inconsistent with its original-file record.'
        }
    } else {
        if ($state -ne 'published' -or $publishedHash -notmatch '^[a-f0-9]{64}$' -or
            ($hadOriginal -and $originalHash -notmatch '^[a-f0-9]{64}$') -or
            (-not $hadOriginal -and -not [string]::IsNullOrEmpty($originalHash))) {
            throw 'Committed recovery-script journal does not contain a valid published identity.'
        }
        if ($Current) {
            $targetInfo = Get-Item -LiteralPath $target -Force -ErrorAction Stop
            if ($targetInfo.PSIsContainer -or ($targetInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Current committed recovery script is not a regular non-reparse file.'
            }
            Assert-TrustedAcl -Path $target
            if ((Get-Sha256FileHash $target) -ne $publishedHash) {
                throw 'Current committed recovery script does not match its transaction-authenticated digest.'
            }
        }
    }
    if (Test-Path -LiteralPath $backup) {
        $backupInfo = Get-Item -LiteralPath $backup -Force -ErrorAction Stop
        if ($backupInfo.PSIsContainer -or ($backupInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $hadOriginal) {
            throw 'Transaction recovery-script backup is not an expected regular file.'
        }
        Assert-TrustedAcl -Path $backup
        if ((Get-Sha256FileHash $backup) -ne $originalHash) {
            throw 'Transaction recovery-script backup failed its original digest check.'
        }
        return $backup
    }
    if ($hadOriginal -and -not $RolledBack -and [string]$Journal.phase -ne 'committed') {
        throw 'Recovery-script backup disappeared before durable committed journal publication.'
    }
    return $null
}
function Assert-NoRunningUserBinaries {
    $destinations = @{}
    foreach ($name in $BinaryNames) {
        $destinations[$name] = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
    }
    $processes = @(Get-CimInstance Win32_Process -Filter "Name='wd.exe' OR Name='wd-routerctl.exe' OR Name='wd-core.exe' OR Name='wd-ui.exe'" -ErrorAction Stop)
    foreach ($process in $processes) {
        if (@('wd.exe', 'wd-routerctl.exe', 'wd-core.exe', 'wd-ui.exe') -notcontains [string]$process.Name) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$process.ExecutablePath)) {
            throw "Cannot authenticate running $($process.Name) executable path; recovery will not terminate it."
        }
        $path = [IO.Path]::GetFullPath([string]$process.ExecutablePath)
        if ($path.Equals($destinations[[string]$process.Name], [StringComparison]::OrdinalIgnoreCase)) {
            throw "Close installed $($process.Name) (PID $($process.ProcessId)) before recovery."
        }
    }
}

Assert-Administrator
$recoveryLock = Acquire-WeDecentRecoveryLock
try {
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$StateDir = [IO.Path]::GetFullPath($StateDir)
if (-not $InstallDir.StartsWith([IO.Path]::GetFullPath($env:ProgramFiles) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Recovery install directory is outside Program Files.'
}
if (-not $StateDir.StartsWith($InstallDir + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Recovery state directory is outside the install directory.'
}
$installItem = Get-Item -LiteralPath $InstallDir -Force
$stateDirectoryItem = Get-Item -LiteralPath $StateDir -Force
if (-not $installItem.PSIsContainer -or -not $stateDirectoryItem.PSIsContainer -or
    (($installItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    (($stateDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Install or state directory is unavailable or a reparse point.'
}
$journalRoot = Join-Path $env:ProgramData 'WeDecent\install-transactions'
if ($PSCmdlet.ParameterSetName -eq 'FinalizeCommitted') {
    if (-not (Test-Path -LiteralPath $journalRoot -PathType Container)) { return }
    Assert-TrustedAcl -Path $journalRoot
    $metadataPath = Join-Path $env:ProgramData 'WeDecent\installer.json'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw 'Authenticated installer metadata is unavailable; committed cleanup is unsafe.'
    }
    Assert-TrustedAcl -Path $metadataPath
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    if ([string]$metadata.install_dir -ine $InstallDir -or
        [string]$metadata.state_dir -ine $StateDir -or
        [string]$metadata.service_name -cne $ServiceName -or
        [string]$metadata.service_account_sid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') {
        throw 'Installer metadata does not authenticate committed cleanup paths.'
    }
    $finalizerService = Assert-AuthenticatedRecoveryServiceAccount -Metadata $metadata
    $installOwner = (Get-Acl -LiteralPath $InstallDir).Owner
    $installOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $installOwner).Translate([Security.Principal.SecurityIdentifier]).Value
    $stateOwner = (Get-Acl -LiteralPath $StateDir).Owner
    $stateOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $stateOwner).Translate([Security.Principal.SecurityIdentifier]).Value
    $statePath = Join-Path $StateDir 'update-state.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw 'Protected updater state is unavailable; committed cleanup is unsafe.'
    }
    $stateItem = Get-Item -LiteralPath $statePath -Force
    if ($stateItem.PSIsContainer -or ($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Updater state is not a regular file.'
    }
    Assert-TrustedAcl -Path $statePath -AdditionalTrustedSids @([string]$metadata.service_account_sid, $installOwnerSid, $stateOwnerSid)
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($null -ne $state.pending_install -or
        [UInt64]$state.stable_sequence -ne $ExpectedStableSequence -or
        [string]$state.installed_version -cne $ExpectedInstalledVersion) {
        throw 'Protected updater state changed before committed backup cleanup.'
    }

    $expectedNames = @($BinaryNames | Sort-Object -CaseSensitive)
    foreach ($file in @(Get-ChildItem -LiteralPath $journalRoot -Filter '*.json' -File)) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Committed cleanup journal is a reparse point: $($file.FullName)"
        }
        Assert-TrustedAcl -Path $file.FullName
        $journal = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        $journalSequence = [UInt64]$journal.sequence
        $managedJournal = -not [string]::IsNullOrWhiteSpace([string]$journal.package_sha256) -or $journalSequence -ne 0
        if ([int]$journal.schema -ne 1 -or
            [string]$journal.transaction_id -notmatch '^[a-f0-9]{32}$' -or
            [string]$file.BaseName -cne [string]$journal.transaction_id -or
            [string]$journal.metadata_path -ine [IO.Path]::GetFullPath($metadataPath) -or
            [string]$journal.metadata_backup_path -ine [IO.Path]::GetFullPath("$metadataPath.$($journal.transaction_id).metadata.bak") -or
            $journal.metadata_had_original -isnot [bool] -or
            -not [regex]::IsMatch([string]$journal.metadata_original_sha256, '^[a-f0-9]{64}$') -or
            ($managedJournal -and ([string]$journal.package_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$journal.manifest_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$journal.previous_version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or $journalSequence -eq 0)) -or
            (-not $managedJournal -and (-not [string]::IsNullOrEmpty([string]$journal.manifest_sha256) -or
                -not [string]::IsNullOrEmpty([string]$journal.previous_version))) -or
            $journal.service_was_running -isnot [bool] -or
            [string]$journal.version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
            [string]$journal.phase -notin @('prepared', 'backups-verified', 'replacing', 'installed-awaiting-sequence-commit', 'committed', 'rolled-back') -or
            @($journal.entries).Count -ne $BinaryNames.Count) {
            throw "Committed cleanup journal is malformed: $($file.FullName)"
        }
        $journalMetadataBackup = [IO.Path]::GetFullPath([string]$journal.metadata_backup_path)
        $recoveryScriptBackup = Get-TransactionRecoveryScriptBackupForCleanup -Journal $journal -Current ($journalSequence -eq $ExpectedStableSequence) -RolledBack ($journal.phase -eq 'rolled-back')
        if ($journal.phase -eq 'rolled-back') {
            if ($recoveryScriptBackup) {
                Remove-Item -LiteralPath $recoveryScriptBackup -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $journalMetadataBackup -PathType Leaf) {
                if ((Get-Sha256FileHash $journalMetadataBackup) -ne [string]$journal.metadata_original_sha256) {
                    throw "Rolled-back journal metadata snapshot is corrupted: $journalMetadataBackup"
                }
                Remove-Item -LiteralPath $journalMetadataBackup -Force -ErrorAction Stop
            }
            continue
        }
        if ($journalSequence -gt $ExpectedStableSequence) {
            throw 'An unresolved transaction journal is ahead of protected updater sequence.'
        }

        $seen = @{}
        foreach ($entry in @($journal.entries)) {
            $name = [string]$entry.name
            if ($BinaryNames -notcontains $name -or $seen.ContainsKey($name)) {
                throw "Committed cleanup journal contains an unknown or duplicate binary: $name"
            }
            $seen[$name] = $true
            $destination = [IO.Path]::GetFullPath([string]$entry.destination)
            $expectedDestination = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
            $expectedBackup = "$expectedDestination.$($journal.transaction_id).bak"
            if (-not $destination.Equals($expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
                -not ([IO.Path]::GetFullPath([string]$entry.backup_path)).Equals($expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
                $entry.had_original -isnot [bool] -or
                [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced') -or
                [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$' -or
                [string]$entry.original_sha256 -notmatch '^(?:[a-f0-9]{64})?$' -or
                ([bool]$entry.had_original -and [string]$entry.original_sha256 -notmatch '^[a-f0-9]{64}$')) {
                throw "Committed cleanup journal entry is invalid for $name"
            }
            $backup = [string]$entry.backup_path
            if ($journalSequence -lt $ExpectedStableSequence) {
                if ($journal.phase -ne 'committed' -or (Test-Path -LiteralPath $backup -PathType Leaf)) {
                    throw "Older transaction has incomplete or non-committed cleanup: $backup"
                }
                continue
            }
            if ([string]$journal.version -cne $ExpectedInstalledVersion -or
                $journal.phase -notin @('installed-awaiting-sequence-commit', 'committed')) {
                throw 'Current journal phase or version disagrees with protected updater state.'
            }
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Current committed binary failed verification: $destination"
            }
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                if (-not [bool]$entry.had_original -or
                    (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                    throw "Committed backup integrity failure: $backup"
                }
            } elseif ([bool]$entry.had_original -and $journal.phase -ne 'committed') {
                throw "Backup disappeared before durable committed journal publication: $backup"
            }
        }
        if ($seen.Count -ne $expectedNames.Count) {
            throw 'Committed cleanup journal does not cover all five approved binaries.'
        }
        if ($journalSequence -lt $ExpectedStableSequence) {
            if ($journal.phase -ne 'committed') {
                throw 'Older transaction journal is not durably committed.'
            }
            if ($recoveryScriptBackup) {
                Remove-Item -LiteralPath $recoveryScriptBackup -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $journalMetadataBackup -PathType Leaf) {
                if ((Get-Sha256FileHash $journalMetadataBackup) -ne [string]$journal.metadata_original_sha256) {
                    throw "Refusing to clean a corrupted older transaction metadata snapshot: $journalMetadataBackup"
                }
                Remove-Item -LiteralPath $journalMetadataBackup -Force -ErrorAction Stop
            }
            continue
        }

        if ($journal.phase -ne 'committed') {
            $journal.phase = 'committed'
            Write-TransactionJournal -Journal $journal -Path $file.FullName
        }
        foreach ($entry in @($journal.entries)) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
            }
            Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
            $destination = [string]$entry.destination
            Remove-Item -LiteralPath "$destination.$($journal.transaction_id).new" -Force -ErrorAction SilentlyContinue
        }
        if ($recoveryScriptBackup) {
            Remove-Item -LiteralPath $recoveryScriptBackup -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $journalMetadataBackup -PathType Leaf) {
            if ((Get-Sha256FileHash $journalMetadataBackup) -ne [string]$journal.metadata_original_sha256) {
                throw "Refusing to clean a corrupted committed metadata snapshot: $journalMetadataBackup"
            }
            Remove-Item -LiteralPath $journalMetadataBackup -Force -ErrorAction Stop
        }
    }
    Write-Output 'committed-backup-cleanup-complete'
    exit 0
}
$journalPath = Join-Path $journalRoot ($TransactionId + '.json')
if (-not (Test-Path -LiteralPath $journalRoot -PathType Container) -or
    -not (Test-Path -LiteralPath $journalPath -PathType Leaf)) {
    throw 'Transaction journal is unavailable; recovery outcome is unknown.'
}
Assert-TrustedAcl -Path $journalRoot
Assert-TrustedAcl -Path $journalPath
$journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
if ([int]$journal.schema -ne 1 -or [string]$journal.transaction_id -cne $TransactionId -or
    [string]$journal.manifest_sha256 -cne $ExpectedManifestSHA256 -or
    [string]$journal.manifest_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$journal.package_sha256 -cne $ExpectedPackageSHA256 -or
    [string]$journal.package_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [UInt64]$journal.sequence -ne $Sequence -or $Sequence -eq 0 -or
    [string]$journal.previous_version -cne $PreviousVersion -or
    [string]$journal.previous_version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
    [string]$journal.version -cne $TargetVersion -or
    [string]$journal.version -notmatch '^v[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
    $journal.phase -notin @('prepared', 'backups-verified', 'replacing', 'installed-awaiting-sequence-commit', 'committed', 'rolled-back') -or
    $journal.service_was_running -isnot [bool] -or
    @($journal.entries).Count -ne $BinaryNames.Count) {
    throw 'Transaction journal does not match the authenticated Go transaction.'
}

$metadataPath = Join-Path $env:ProgramData 'WeDecent\installer.json'
$metadataBackupPath = "$metadataPath.$TransactionId.metadata.bak"
if (-not [IO.Path]::GetFullPath([string]$journal.metadata_path).Equals([IO.Path]::GetFullPath($metadataPath), [StringComparison]::OrdinalIgnoreCase) -or
    -not [IO.Path]::GetFullPath([string]$journal.metadata_backup_path).Equals([IO.Path]::GetFullPath($metadataBackupPath), [StringComparison]::OrdinalIgnoreCase) -or
    $journal.metadata_had_original -isnot [bool] -or -not [bool]$journal.metadata_had_original -or
    -not [regex]::IsMatch([string]$journal.metadata_original_sha256, '^[a-f0-9]{64}$')) {
    throw 'Transaction journal does not contain a verified prior installer metadata snapshot.'
}
$recoveryScriptPath = [IO.Path]::GetFullPath((Join-Path $InstallDir 'Recover-WeDecentInstall.ps1'))
$recoveryScriptBackupPath = "$recoveryScriptPath.$TransactionId.previous"
if (-not [IO.Path]::GetFullPath([string]$journal.recovery_script_path).Equals($recoveryScriptPath, [StringComparison]::OrdinalIgnoreCase) -or
    -not [IO.Path]::GetFullPath([string]$journal.recovery_script_backup_path).Equals($recoveryScriptBackupPath, [StringComparison]::OrdinalIgnoreCase) -or
    $journal.recovery_script_had_original -isnot [bool] -or -not [bool]$journal.recovery_script_had_original -or
    [string]$journal.recovery_script_original_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$journal.recovery_script_sha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$journal.recovery_script_state -notin @('original', 'publishing', 'published')) {
    throw 'Transaction journal does not contain a valid recovery-script preservation record.'
}
$recoveryScriptDigest = Get-Sha256FileHash $recoveryScriptPath
if (($journal.recovery_script_state -eq 'original' -and
        ($recoveryScriptDigest -ne [string]$journal.recovery_script_original_sha256 -or
         $recoveryScriptDigest -ne [string]$journal.recovery_script_sha256)) -or
    ($journal.recovery_script_state -eq 'publishing' -and
        $recoveryScriptDigest -ne [string]$journal.recovery_script_original_sha256 -and
        $recoveryScriptDigest -ne [string]$journal.recovery_script_sha256) -or
    ($journal.recovery_script_state -eq 'published' -and
        $recoveryScriptDigest -ne [string]$journal.recovery_script_sha256)) {
    throw 'Installed recovery script does not match a transaction-authenticated digest.'
}
if (Test-Path -LiteralPath $recoveryScriptBackupPath -PathType Leaf) {
    Assert-TrustedAcl -Path $recoveryScriptBackupPath
    if ((Get-Sha256FileHash $recoveryScriptBackupPath) -ne [string]$journal.recovery_script_original_sha256) {
        throw 'Previous recovery script backup failed integrity verification.'
    }
} elseif ($journal.recovery_script_state -ne 'original' -and $journal.phase -ne 'committed') {
    throw 'Previous recovery script backup is missing from an active publication transaction.'
}
$metadataSource = $null
if (Test-Path -LiteralPath $metadataBackupPath -PathType Leaf) {
    Assert-TrustedAcl -Path $metadataBackupPath
    if ((Get-Sha256FileHash $metadataBackupPath) -ne [string]$journal.metadata_original_sha256) {
        throw 'Prior installer metadata snapshot failed integrity verification.'
    }
    $metadataSource = $metadataBackupPath
} elseif (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
    Assert-TrustedAcl -Path $metadataPath
    if ((Get-Sha256FileHash $metadataPath) -eq [string]$journal.metadata_original_sha256) {
        $metadataSource = $metadataPath
    }
}
if (-not $metadataSource) {
    throw 'Prior installer metadata and its verified snapshot are both unavailable.'
}
$metadata = Get-Content -LiteralPath $metadataSource -Raw | ConvertFrom-Json
if ([string]$metadata.install_dir -ine $InstallDir -or
    [string]$metadata.state_dir -ine $StateDir -or
    [string]$metadata.service_name -cne $ServiceName -or
    -not [regex]::IsMatch([string]$metadata.service_account_sid, '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$')) {
    throw 'Prior installer metadata does not authenticate the requested service and state paths.'
}
$installOwner = (Get-Acl -LiteralPath $InstallDir).Owner
$installOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $installOwner).Translate([Security.Principal.SecurityIdentifier]).Value
$stateOwner = (Get-Acl -LiteralPath $StateDir).Owner
$stateOwnerSid = (New-Object Security.Principal.NTAccount -ArgumentList $stateOwner).Translate([Security.Principal.SecurityIdentifier]).Value
$statePath = Join-Path $StateDir 'update-state.json'
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw 'Protected updater state is unavailable; recovery outcome is unknown.'
}
$stateItem = Get-Item -LiteralPath $statePath -Force
if ($stateItem.PSIsContainer -or ($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Updater state is not a regular file.'
}
Assert-TrustedAcl -Path $statePath -AdditionalTrustedSids @([string]$metadata.service_account_sid, $installOwnerSid, $stateOwnerSid)
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$committed = [UInt64]$state.stable_sequence -ge $Sequence -and
    $null -eq $state.pending_install -and [string]$state.installed_version -ceq $TargetVersion

$seen = @{}
foreach ($entry in @($journal.entries)) {
    $name = [string]$entry.name
    if ($BinaryNames -notcontains $name -or $seen.ContainsKey($name)) {
        throw "Transaction journal has an unknown or duplicate binary: $name"
    }
    $seen[$name] = $true
    $destination = [IO.Path]::GetFullPath([string]$entry.destination)
    $expectedDestination = [IO.Path]::GetFullPath((Join-Path $InstallDir $name))
    $expectedBackup = "$expectedDestination.$TransactionId.bak"
    if (-not $destination.Equals($expectedDestination, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$entry.backup_path)).Equals($expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
        $entry.had_original -isnot [bool] -or
        [string]$entry.state -notin @('planned', 'backup-verified', 'replacing', 'replaced') -or
        [string]$entry.original_sha256 -notmatch '^(?:[a-f0-9]{64})?$' -or
        [string]$entry.replacement_sha256 -notmatch '^[a-f0-9]{64}$') {
        throw "Transaction journal entry is invalid for $name"
    }
    if ([bool]$entry.had_original) {
        if ([string]$entry.original_sha256 -notmatch '^[a-f0-9]{64}$') {
            throw "Original binary digest is missing for $name"
        }
        if (Test-Path -LiteralPath $expectedBackup -PathType Leaf) {
            if ((Get-Sha256FileHash $expectedBackup) -ne [string]$entry.original_sha256) {
                throw "Transaction backup integrity failure: $expectedBackup"
            }
        } elseif ($committed) {
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
                (Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
                throw "Committed transaction has neither its backup nor the verified replacement: $destination"
            }
        } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
            throw "Original binary and verified backup are both unavailable: $destination"
        }
    } elseif (-not [string]::IsNullOrEmpty([string]$entry.original_sha256)) {
        throw "Unexpected original digest for $name"
    }
}
if ($seen.Count -ne $BinaryNames.Count) {
    throw 'Transaction journal does not cover all five approved binaries.'
}

if ($journal.phase -eq 'committed' -and -not $committed) {
    throw 'Journal claims commit but protected updater state does not confirm it.'
}
if ($journal.phase -eq 'rolled-back' -and $committed) {
    throw 'Journal claims rollback but protected updater state confirms commit.'
}
if ($committed) {
    foreach ($entry in @($journal.entries)) {
        if ((Get-Sha256FileHash ([string]$entry.destination)) -ne [string]$entry.replacement_sha256) {
            throw "Committed sequence has a mismatched binary: $($entry.destination)"
        }
    }
    $journal.phase = 'committed'
    Write-TransactionJournal -Journal $journal -Path $journalPath
    foreach ($entry in @($journal.entries)) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ([bool]$entry.had_original -and
                (Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Refusing to clean a corrupted committed backup: $backup"
            }
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        }
        Remove-Item -LiteralPath "$backup.sha256" -Force -ErrorAction SilentlyContinue
        $destination = [string]$entry.destination
        Remove-Item -LiteralPath "$destination.$TransactionId.new" -Force -ErrorAction SilentlyContinue
    }
    Write-Output 'applied'
    exit 0
}

$pending = $state.pending_install
if ($null -eq $pending -or [string]$pending.id -cne $TransactionId -or
    [UInt64]$pending.sequence -ne $Sequence -or
    [string]$pending.manifest_digest -cne $ExpectedManifestSHA256 -or
    [string]$pending.package_digest -cne $ExpectedPackageSHA256 -or
    [string]$pending.previous_version -cne $PreviousVersion -or
    [string]$pending.target_version -cne $TargetVersion) {
    throw 'Updater state does not contain the exact pending transaction; recovery is ambiguous.'
}

# Preflight every original and backup before stopping services or changing files.
foreach ($entry in @($journal.entries)) {
    $destination = [string]$entry.destination
    if ([bool]$entry.had_original) {
        $backup = [string]$entry.backup_path
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            if ((Get-Sha256FileHash $backup) -ne [string]$entry.original_sha256) {
                throw "Corrupted transaction backup: $backup"
            }
        } elseif (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
            throw "No verified original or backup is available: $destination"
        }
    } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
        if ((Get-Sha256FileHash $destination) -ne [string]$entry.replacement_sha256) {
            throw "Unexpected binary contents prevent safe rollback: $destination"
        }
    }
}
Assert-NoRunningUserBinaries

# Hold the SCM database lock through rollback and restart so service identity cannot be reconfigured between admission and use.
$recoveryScmMutationLock = Enter-RecoveryScmMutationLock
try {
    $initialServiceSnapshot = Get-AuthenticatedRecoveryServiceSnapshot -Metadata $metadata
    $script:RecoveryExpectedServiceStartMode = [string]$initialServiceSnapshot.Config.StartMode
    $restartService = [bool]$journal.service_was_running
    Stop-AuthenticatedRecoveryService -Metadata $metadata -ScmLock $recoveryScmMutationLock
    try {
    for ($i = @($journal.entries).Count - 1; $i -ge 0; $i--) {
        $entry = @($journal.entries)[$i]
        $destination = [string]$entry.destination
        if ([bool]$entry.had_original) {
            $backup = [string]$entry.backup_path
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                $restore = "$destination.$TransactionId.recover"
                Copy-Item -LiteralPath $backup -Destination $restore -Force
                if ((Get-Sha256FileHash $restore) -ne [string]$entry.original_sha256) {
                    Remove-Item -LiteralPath $restore -Force -ErrorAction SilentlyContinue
                    throw "Restored backup verification failed: $destination"
                }
                Move-Item -LiteralPath $restore -Destination $destination -Force
            }
            if ((Get-Sha256FileHash $destination) -ne [string]$entry.original_sha256) {
                throw "Rollback verification failed: $destination"
            }
        } elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
            Remove-Item -LiteralPath $destination -Force
        }
        Remove-Item -LiteralPath "$destination.$TransactionId.new" -Force -ErrorAction SilentlyContinue
    }
    Restore-TransactionRecoveryScript -Journal $journal
    $metadataTemp = "$metadataPath.$TransactionId.restore"
    Copy-Item -LiteralPath $metadataBackupPath -Destination $metadataTemp -Force
    if ((Get-Sha256FileHash $metadataTemp) -ne [string]$journal.metadata_original_sha256) {
        Remove-Item -LiteralPath $metadataTemp -Force -ErrorAction SilentlyContinue
        throw 'Restored installer metadata failed its original digest check.'
    }
    Set-TrustedAcl -Path $metadataTemp
    Move-Item -LiteralPath $metadataTemp -Destination $metadataPath -Force
    Set-TrustedAcl -Path $metadataPath
    if ((Get-Sha256FileHash $metadataPath) -ne [string]$journal.metadata_original_sha256) {
        throw 'Final restored installer metadata failed verification.'
    }
    $journal.phase = 'rolled-back'
    Write-TransactionJournal -Journal $journal -Path $journalPath
} catch {
    $failure = $_
    $stopFailure = $null
    try { Stop-AuthenticatedRecoveryService -Metadata $metadata -ScmLock $recoveryScmMutationLock } catch { $stopFailure = $_.Exception.Message }
    if ($null -ne $stopFailure) {
        throw "Windows transaction recovery failed; protected backups and pending authorization were retained. SCM stop was not attempted after identity/lock revalidation failed. Cause: $($failure.Exception.Message); stop guard: $stopFailure"
    }
    throw "Windows transaction recovery failed closed; authenticated service was left stopped and pending authorization/backups were retained. Cause: $($failure.Exception.Message)"
}
try {
    if ($restartService) {
        Start-AuthenticatedRecoveryService -Metadata $metadata -ScmLock $recoveryScmMutationLock
    } else {
        $finalSnapshot = Get-AuthenticatedRecoveryServiceSnapshot -Metadata $metadata
        if ($finalSnapshot.Service.Status -ne 'Stopped') {
            throw 'SCM service was expected to remain stopped after recovery.'
        }
    }
} catch {
    $failure = $_
    $stopFailure = $null
    try { Stop-AuthenticatedRecoveryService -Metadata $metadata -ScmLock $recoveryScmMutationLock } catch { $stopFailure = $_.Exception.Message }
    if ($null -ne $stopFailure) {
        throw "Previous binaries and metadata were restored, but service state is uncertain; no stop mutation was attempted without fresh identity/lock authorization. Cause: $($failure.Exception.Message); stop guard: $stopFailure"
    }
    throw "Previous binaries and metadata were restored, but SCM restart/state verification failed; authenticated service was left stopped. Cause: $($failure.Exception.Message)"
    }
} finally {
    Exit-RecoveryScmMutationLock -Handle $recoveryScmMutationLock
}
Write-Output 'not-applied'
} finally {
    if ($null -ne $recoveryLock) {
        $recoveryLock.Dispose()
        $recoveryLock = $null
    }
}
