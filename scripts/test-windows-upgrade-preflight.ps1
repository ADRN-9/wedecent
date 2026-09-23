$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$installerPath = Join-Path $repoRoot 'installer\windows\Install-WeDecent.ps1'
$content = Get-Content -LiteralPath $installerPath -Raw

$functionMarker = 'function Assert-InstalledUserBinariesStopped'
$nextFunctionMarker = 'function Install-Binaries'
$callMarker = 'Assert-InstalledUserBinariesStopped -Destinations $binaryDestinations'
$serviceBranchMarker = 'if ($service) {'
$stopMarker = 'Stop-Service -Name $ServiceName -Force'

$functionStart = $content.IndexOf($functionMarker, [StringComparison]::Ordinal)
if ($functionStart -lt 0) { throw 'Installer user-process preflight function is missing.' }
$functionEnd = $content.IndexOf($nextFunctionMarker, $functionStart, [StringComparison]::Ordinal)
if ($functionEnd -lt 0) { throw 'Cannot determine installer user-process preflight function boundary.' }
$body = $content.Substring($functionStart, $functionEnd - $functionStart)

foreach ($required in @('wd-core.exe', 'wd-ui.exe', 'Win32_Process', 'ExecutablePath')) {
    if ($body.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "Installer user-process preflight is missing required check: $required"
    }
}
foreach ($forbidden in @('Stop-Process', 'taskkill', '.Terminate(', 'Terminate()')) {
    if ($body.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Installer user-process preflight must not terminate processes: $forbidden"
    }
}

$call = $content.IndexOf($callMarker, [StringComparison]::Ordinal)
$serviceBranch = $content.IndexOf($serviceBranchMarker, [StringComparison]::Ordinal)
$stop = $content.IndexOf($stopMarker, [StringComparison]::Ordinal)
if ($call -lt 0 -or $serviceBranch -lt 0 -or $stop -lt 0) {
    throw 'Installer preflight ordering markers are missing.'
}
if ($call -ge $serviceBranch -or $call -ge $stop) {
    throw 'Installer must run the user-process preflight before service mutation.'
}

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $installerPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw 'Installer must parse successfully before preflight behavior can be tested.'
}
$functionAst = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-InstalledUserBinariesStopped'
}, $true)
if (-not $functionAst) { throw 'Cannot extract installer preflight function.' }
Invoke-Expression $functionAst.Extent.Text

$script:FakeProcesses = @()
function Get-CimInstance {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$ClassName,
        [string]$Filter
    )
    if ($ClassName -ne 'Win32_Process') {
        throw "Unexpected CIM class in preflight test: $ClassName"
    }
    return @($script:FakeProcesses)
}

$destinations = @{
    'wd-core.exe' = 'C:\Program Files\WeDecent\wd-core.exe'
    'wd-ui.exe'   = 'C:\Program Files\WeDecent\wd-ui.exe'
}

Assert-InstalledUserBinariesStopped -Destinations $destinations

$script:FakeProcesses = @(
    [pscustomobject]@{
        Name           = 'wd-ui.exe'
        ProcessId      = 101
        ExecutablePath = 'C:\Other\wd-ui.exe'
    }
)
Assert-InstalledUserBinariesStopped -Destinations $destinations

foreach ($case in @(
    [pscustomobject]@{
        Label = 'installed UI'
        Process = [pscustomobject]@{
            Name           = 'wd-ui.exe'
            ProcessId      = 102
            ExecutablePath = 'c:\PROGRAM FILES\WeDecent\wd-ui.exe'
        }
    },
    [pscustomobject]@{
        Label = 'installed Core'
        Process = [pscustomobject]@{
            Name           = 'wd-core.exe'
            ProcessId      = 103
            ExecutablePath = 'C:\Program Files\WeDecent\wd-core.exe'
        }
    },
    [pscustomobject]@{
        Label = 'unreadable matching process'
        Process = [pscustomobject]@{
            Name           = 'wd-ui.exe'
            ProcessId      = 104
            ExecutablePath = $null
        }
    }
)) {
    $script:FakeProcesses = @($case.Process)
    $threw = $false
    try {
        Assert-InstalledUserBinariesStopped -Destinations $destinations
    } catch {
        $threw = $true
        if ($_.Exception.Message -notmatch 'installer will not terminate interactive processes') {
            throw "Unexpected $($case.Label) preflight error: $($_.Exception.Message)"
        }
    }
    if (-not $threw) {
        throw "Preflight did not reject $($case.Label)."
    }
}

Write-Host 'Windows upgrade user-process preflight behavior and ordering verified.'
