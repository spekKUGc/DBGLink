[CmdletBinding()]
param(
    [string]$GhidraHome,
    [string]$BundleRoot,
    [ValidateSet('x64', 'Win32', 'both')][string]$Architecture = 'both',
    [switch]$KeepRunDir
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($BundleRoot)) { $BundleRoot = Join-Path $root 'artifacts/current' }
if (-not (Test-Path -LiteralPath $BundleRoot)) {
    throw "Packaged bundle was not found at '$BundleRoot'. Run tools\build.cmd first to produce the artifacts package."
}
$bundle = (Resolve-Path -LiteralPath $BundleRoot).Path
$bridgeZip = Join-Path $bundle 'x64/plugins/GhidraBridge.zip'
if (-not (Test-Path -LiteralPath $bridgeZip -PathType Leaf)) {
    throw "Packaged Ghidra bridge was not found at '$bridgeZip'. Run tools\build.cmd first."
}

function Resolve-GhidraHome {
    param([string]$Path)

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Ghidra installation was not found at: '$Path'"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    foreach ($cand in @($env:DBGLINK_GHIDRA_HOME, $env:GHIDRA_INSTALL_DIR) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        if ((Test-Path -LiteralPath (Join-Path $cand 'ghidraRun.bat')) -and (Test-Path -LiteralPath (Join-Path $cand 'support/analyzeHeadless.bat'))) {
            return (Resolve-Path -LiteralPath $cand).Path
        }
        if (Test-Path -LiteralPath $cand) {
            return (Resolve-Path -LiteralPath $cand).Path
        }
    }

    # S-1: only explicit locations and the machine-wide Program Files trees are
    # searched. Downloads, Desktop, %USERPROFILE% and %LOCALAPPDATA% are NEVER
    # searched — resolving (and executing) a planted analyzeHeadless.bat from an
    # attacker-writable directory is exactly the auto-exec hazard. Fail closed
    # with an explicit-path instruction otherwise.
    $searchRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }

    foreach ($base in $searchRoots) {
        if ((Test-Path -LiteralPath (Join-Path $base 'ghidraRun.bat')) -and (Test-Path -LiteralPath (Join-Path $base 'support/analyzeHeadless.bat'))) {
            return (Resolve-Path -LiteralPath $base).Path
        }
        $dirs = Get-ChildItem -LiteralPath $base -Filter 'ghidra*' -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $dirs) {
            if ((Test-Path -LiteralPath (Join-Path $dir.FullName 'ghidraRun.bat')) -and (Test-Path -LiteralPath (Join-Path $dir.FullName 'support/analyzeHeadless.bat'))) {
                return (Resolve-Path -LiteralPath $dir.FullName).Path
            }
            $subdirs = Get-ChildItem -LiteralPath $dir.FullName -Filter 'ghidra*' -Directory -ErrorAction SilentlyContinue
            foreach ($sub in $subdirs) {
                if ((Test-Path -LiteralPath (Join-Path $sub.FullName 'ghidraRun.bat')) -and (Test-Path -LiteralPath (Join-Path $sub.FullName 'support/analyzeHeadless.bat'))) {
                    return (Resolve-Path -LiteralPath $sub.FullName).Path
                }
            }
        }
    }

    return $null
}

$ghidra = Resolve-GhidraHome $GhidraHome
if ([string]::IsNullOrWhiteSpace($ghidra)) {
    throw "Ghidra installation path is required. Pass -GhidraHome <path> or set `$env:DBGLINK_GHIDRA_HOME` or `$env:GHIDRA_INSTALL_DIR`."
}
$run = Join-Path $root ('artifacts/verification/static-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $run -Force | Out-Null
Expand-Archive -LiteralPath $bridgeZip -DestinationPath (Join-Path $run 'extension')
$jar = Get-ChildItem -LiteralPath (Join-Path $run 'extension') -Recurse -Filter GhidraBridge.jar -File | Select-Object -First 1 -ExpandProperty FullName
if (-not $jar) { throw 'Packaged GhidraBridge.jar not found' }
$oldProfile = $env:USERPROFILE
$oldAppData = $env:APPDATA
$oldLocalAppData = $env:LOCALAPPDATA
$oldJavaHome = $env:JAVA_HOME
try {
    if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
        $javaCmd = Get-Command java.exe -ErrorAction SilentlyContinue
        if ($javaCmd) {
            $env:JAVA_HOME = Split-Path -Parent (Split-Path -Parent $javaCmd.Source)
        }
        else {
            throw 'No Java runtime was found. Set $env:JAVA_HOME to a JDK 21+ installation or add java.exe to PATH.'
        }
    }
    $env:USERPROFILE = Join-Path $run 'profile'
    $env:APPDATA = Join-Path $run 'profile/AppData/Roaming'
    $env:LOCALAPPDATA = Join-Path $run 'profile/AppData/Local'
    New-Item -ItemType Directory -Path $env:APPDATA,$env:LOCALAPPDATA -Force | Out-Null
    $architectures = if ($Architecture -eq 'both') { @('x64', 'Win32') } else { @($Architecture) }
    foreach ($arch in $architectures) {
        $fixture = Join-Path $root "artifacts/fixtures/$arch/AnalysisTarget.exe"
        if (-not (Test-Path -LiteralPath $fixture)) { throw "Build fixture first: $fixture" }
        $log = Join-Path $run "$arch.log"
        $prevEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & (Join-Path $ghidra 'support\analyzeHeadless.bat') $run "Static-$arch" `
                -import $fixture -scriptPath (Join-Path $root 'tests\ghidra') `
                -postScript StaticBridgeChecks.java $jar -deleteProject 2>&1 |
                ForEach-Object { $_.ToString() } |
                Tee-Object -FilePath $log
        } finally {
            $ErrorActionPreference = $prevEap
        }
        if ($LASTEXITCODE -ne 0 -or -not (Select-String -LiteralPath $log -SimpleMatch 'STATIC_BRIDGE_INTEGRATION_PASS' -Quiet)) {
            throw "Static integration failed; see $log"
        }
    }
    Write-Output "Static bridge integration passed. Logs: $run"
    if (-not $KeepRunDir) {
        Remove-Item -LiteralPath $run -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Cleaned static verification run directory."
    }
} finally {
    $env:USERPROFILE = $oldProfile
    $env:APPDATA = $oldAppData
    $env:LOCALAPPDATA = $oldLocalAppData
    $env:JAVA_HOME = $oldJavaHome
}
