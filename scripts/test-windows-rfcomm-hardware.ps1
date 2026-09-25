$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'Windows is required'
}

function Require-EnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "set $Name"
    }
    return $value
}

$peerMac = Require-EnvironmentValue 'WEDECENT_RFCOMM_PEER_MAC'
$channelText = Require-EnvironmentValue 'WEDECENT_RFCOMM_CHANNEL'
$fingerprint = Require-EnvironmentValue 'WEDECENT_RFCOMM_FINGERPRINT'
$pairingSecret = Require-EnvironmentValue 'WEDECENT_RFCOMM_PAIRING_SECRET'

if ($peerMac -notmatch '^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$') {
    throw 'WEDECENT_RFCOMM_PEER_MAC must be a six-octet colon-separated Bluetooth address'
}
$channel = 0
if (-not [int]::TryParse($channelText, [ref]$channel) -or $channel -lt 1 -or $channel -gt 30 -or $channelText -ne $channel.ToString()) {
    throw 'WEDECENT_RFCOMM_CHANNEL must be canonical decimal 1-30'
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw 'go is required'
}
if (-not (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)) {
    throw 'Get-PnpDevice is required to verify native Bluetooth hardware'
}
$bluetoothDevices = @(Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' })
if ($bluetoothDevices.Count -eq 0) {
    throw 'no present, healthy Windows Bluetooth device is available'
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('wedecent-rfcomm-hardware-' + [guid]::NewGuid().ToString('N'))
$bin = Join-Path $work 'bin'
$state = Join-Path $work 'state'
New-Item -ItemType Directory -Path $bin, $state | Out-Null

try {
    $wd = Join-Path $bin 'wd.exe'
    & go build -trimpath -buildvcs=false -o $wd ./cmd/wd
    if ($LASTEXITCODE -ne 0) {
        throw 'go build ./cmd/wd failed'
    }

    $oldPairingSecret = $env:WEDECENT_PAIRING_SECRET
    try {
        $env:WEDECENT_PAIRING_SECRET = $pairingSecret
        $pairOutput = @(& $wd pair `
            --state $state `
            --name 'wedecent-windows-rfcomm-hardware-gate' `
            --rfcomm "${peerMac}/${channel}" `
            --fingerprint $fingerprint 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "RFCOMM pairing failed:`n$($pairOutput -join [Environment]::NewLine)"
        }
    }
    finally {
        $env:WEDECENT_PAIRING_SECRET = $oldPairingSecret
    }

    $pairText = $pairOutput -join [Environment]::NewLine
    Write-Output $pairText
    if ($pairText -notmatch ' via rfcomm://') {
        throw 'pairing did not persist an RFCOMM locator'
    }
    $match = [regex]::Match($pairText, 'Paired .* \((wd_[a-z2-7]{16})\) via rfcomm://')
    if (-not $match.Success) {
        throw 'could not extract paired WeDecent device ID'
    }
    $pairedDeviceID = $match.Groups[1].Value

    $expectedDeviceID = [Environment]::GetEnvironmentVariable('WEDECENT_RFCOMM_EXPECT_DEVICE_ID')
    if (-not [string]::IsNullOrWhiteSpace($expectedDeviceID) -and $pairedDeviceID -ne $expectedDeviceID) {
        throw 'paired device ID does not match WEDECENT_RFCOMM_EXPECT_DEVICE_ID'
    }

    Write-Output 'WEDECENT_WINDOWS_RFCOMM_PAIR_HARDWARE_OK'

    $grantFile = [Environment]::GetEnvironmentVariable('WEDECENT_RFCOMM_CONNECTION_GRANT_FILE')
    if ([string]::IsNullOrWhiteSpace($grantFile)) {
        Write-Output 'Pairing hardware gate passed. Set WEDECENT_RFCOMM_CONNECTION_GRANT_FILE, WEDECENT_RFCOMM_TERMINAL_INPUT_FILE, and WEDECENT_RFCOMM_TERMINAL_MARKER to also run the authorized terminal gate.'
        exit 0
    }
    if (-not (Test-Path -LiteralPath $grantFile -PathType Leaf)) {
        throw 'WEDECENT_RFCOMM_CONNECTION_GRANT_FILE is not a regular file'
    }

    $terminalInputFile = Require-EnvironmentValue 'WEDECENT_RFCOMM_TERMINAL_INPUT_FILE'
    $terminalMarker = Require-EnvironmentValue 'WEDECENT_RFCOMM_TERMINAL_MARKER'
    if (-not (Test-Path -LiteralPath $terminalInputFile -PathType Leaf)) {
        throw 'WEDECENT_RFCOMM_TERMINAL_INPUT_FILE is not a regular file'
    }
    $terminalInput = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $terminalInputFile).Path)
    if ($terminalInput.Contains($terminalMarker)) {
        throw 'terminal input already contains WEDECENT_RFCOMM_TERMINAL_MARKER contiguously; use split input so PTY/console echo cannot satisfy the assertion'
    }

    $timeoutSeconds = 60
    $timeoutText = [Environment]::GetEnvironmentVariable('WEDECENT_RFCOMM_TERMINAL_TIMEOUT_SECONDS')
    if (-not [string]::IsNullOrWhiteSpace($timeoutText)) {
        if (-not [int]::TryParse($timeoutText, [ref]$timeoutSeconds) -or $timeoutSeconds -lt 1 -or $timeoutSeconds -gt 300 -or $timeoutText -ne $timeoutSeconds.ToString()) {
            throw 'WEDECENT_RFCOMM_TERMINAL_TIMEOUT_SECONDS must be canonical decimal 1-300'
        }
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $wd
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
        'connect',
        '--state', $state,
        '--rfcomm', "${peerMac}/${channel}",
        '--lan-timeout', '0',
        '--connection-grant-file', (Resolve-Path -LiteralPath $grantFile).Path,
        $pairedDeviceID
    )) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'failed to start wd connect'
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write($terminalInput)
    $process.StandardInput.Close()
    if (-not $process.WaitForExit($timeoutSeconds * 1000)) {
        try {
            $process.Kill($true)
        }
        catch {
            $process.Kill()
        }
        [void]$process.WaitForExit(5000)
        throw "authorized RFCOMM terminal exceeded ${timeoutSeconds}s timeout"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()

    Write-Output $stdout
    if (-not [string]::IsNullOrEmpty($stderr)) {
        [Console]::Error.Write($stderr)
    }
    if ($process.ExitCode -ne 0) {
        throw "authorized RFCOMM terminal exited with code $($process.ExitCode)"
    }
    if (-not $stdout.Contains($terminalMarker)) {
        throw 'authorized RFCOMM terminal did not emit the expected marker'
    }

    Write-Output 'WEDECENT_WINDOWS_RFCOMM_TERMINAL_SESSION_HARDWARE_OK'
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
