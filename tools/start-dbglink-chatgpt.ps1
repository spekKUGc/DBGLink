[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter()]
    [string] $TunnelId = $env:CONTROL_PLANE_TUNNEL_ID,

    [Parameter()]
    [string] $TunnelClientPath = "",

    [Parameter()]
    [int] $Port = 50301,

    [Parameter()]
    [string[]] $LauncherArguments = @()
)

$ErrorActionPreference = "Stop"

function Assert-ReparseFree([string] $Path) {
    $current = Get-Item -LiteralPath $Path -Force
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse points are not allowed in executable paths: $($current.FullName)"
        }
        $current = $current.Parent
    }
}

function Resolve-Executable([string] $PathOrName) {
    # S-2: the tunnel client inherits CONTROL_PLANE_API_KEY, so it must never
    # resolve via PATH — a planted tunnel-client.exe in an attacker-writable
    # PATH entry would receive the key. A fully-qualified, reparse-free path is
    # required; fail closed otherwise.
    if ([string]::IsNullOrWhiteSpace($PathOrName) -or -not [IO.Path]::IsPathRooted($PathOrName)) {
        throw "A fully-qualified -TunnelClientPath is required (PATH lookup is disabled for the tunnel client). Pass the exact tunnel-client.exe path."
    }

    $full = [IO.Path]::GetFullPath($PathOrName)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "The tunnel-client executable was not found: $full"
    }
    Assert-ReparseFree $full
    return $full
}

function Resolve-PowerShell {
    # S-2: resolve the launcher host without PATH: our own $PSHOME first, then
    # the well-known System32 location. Both candidates are verified
    # reparse-free before use.
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($PSHOME)) {
        $candidates += (Join-Path $PSHOME "powershell.exe")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $candidates += (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe")
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Assert-ReparseFree $candidate
            return $candidate
        }
    }
    throw "powershell.exe was not found via `$PSHOME or %SystemRoot%\System32\WindowsPowerShell\v1.0."
}

function ConvertTo-WindowsCommandLineArgument([string] $Value) {
    if ($null -eq $Value -or $Value.Length -eq 0) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $result = [Text.StringBuilder]::new()
    [void]$result.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            [void]$result.Append('\' * (2 * $slashes + 1))
            [void]$result.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$result.Append('\' * $slashes)
            $slashes = 0
        }
        [void]$result.Append($character)
    }
    if ($slashes -gt 0) {
        [void]$result.Append('\' * (2 * $slashes))
    }
    [void]$result.Append('"')
    return $result.ToString()
}

if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be between 1 and 65535."
}
if ($TunnelId -notmatch '^tunnel_[0-9a-f]{32}$') {
    throw "TunnelId must match tunnel_<32 lowercase hexadecimal characters>."
}
if ([string]::IsNullOrWhiteSpace($env:CONTROL_PLANE_API_KEY)) {
    throw "CONTROL_PLANE_API_KEY must contain a runtime API key for tunnel-client."
}
foreach ($argument in $LauncherArguments) {
    if ($null -eq $argument -or $argument.IndexOf([char]0) -ge 0 -or $argument -match '[\r\n]') {
        throw "Launcher arguments must be non-null, single-line values."
    }
    $option = ($argument -split '=', 2)[0].ToLowerInvariant()
    if ($option -in @('--port', '--json', '--text', '--help', '-h', '/?')) {
        throw "$option is controlled by start-dbglink-chatgpt.ps1 and cannot be overridden."
    }
}

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$launcherScript = Join-Path $PSScriptRoot "start-dbglink.ps1"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("DBGLink-ChatGPT-" + [Guid]::NewGuid().ToString("N"))
$stdoutPath = Join-Path $tempRoot "launcher.stdout.log"
$stderrPath = Join-Path $tempRoot "launcher.stderr.log"
$launcher = $null
$tunnelExitCode = 1
$previousTunnelId = $env:CONTROL_PLANE_TUNNEL_ID
$previousMcpUrl = $env:MCP_SERVER_URL
$previousWait = $env:MCP_STARTUP_WAIT_TIMEOUT

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    # -ExecutionPolicy Bypass is scoped to this single child invocation of our own
    # repo-pinned start-dbglink.ps1 (literal path, no PATH search). RemoteSigned
    # would be preferable, but bundle/install trees distributed as zips carry
    # Mark-of-the-Web and would refuse to run unsigned; the tradeoff is
    # documented here instead of weakening launch robustness.
    $launcherArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $launcherScript) +
        $LauncherArguments + @("--port", $Port.ToString(), "--json")
    $launcherArgumentLine = ($launcherArgs | ForEach-Object {
        ConvertTo-WindowsCommandLineArgument ([string]$_)
    }) -join ' '
    $launcher = Start-Process -FilePath (Resolve-PowerShell) `
        -ArgumentList $launcherArgumentLine `
        -WorkingDirectory $root `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -WindowStyle Hidden `
        -PassThru

    $startupStopwatch = [Diagnostics.Stopwatch]::StartNew()
    $ready = $false
    while ($startupStopwatch.Elapsed -lt [TimeSpan]::FromMinutes(3)) {
        if ($launcher.HasExited) {
            $diagnostics = @()
            if (Test-Path -LiteralPath $stdoutPath) { $diagnostics += Get-Content -LiteralPath $stdoutPath -Raw }
            if (Test-Path -LiteralPath $stderrPath) { $diagnostics += Get-Content -LiteralPath $stderrPath -Raw }
            throw "DBGLink launcher exited before ready (code $($launcher.ExitCode)). $($diagnostics -join ' ')"
        }

        if ((Test-Path -LiteralPath $stdoutPath -PathType Leaf) -and
            (Get-Content -LiteralPath $stdoutPath -Raw).Contains('"type":"ready"')) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        throw "DBGLink launcher did not become ready within three minutes."
    }

    $env:CONTROL_PLANE_TUNNEL_ID = $TunnelId
    $env:MCP_SERVER_URL = "http://127.0.0.1:$Port/mcp"
    $env:MCP_STARTUP_WAIT_TIMEOUT = "60s"

    Write-Output "DBGLink is ready for ChatGPT through Secure MCP Tunnel."
    Write-Output "Local MCP endpoint: $($env:MCP_SERVER_URL)"
    Write-Output "Tunnel ID: $TunnelId"
    Write-Output "Keep this window open while using the ChatGPT app."

    & (Resolve-Executable $TunnelClientPath) run
    $tunnelExitCode = $LASTEXITCODE
}
finally {
    if ($null -ne $launcher -and -not $launcher.HasExited) {
        Stop-Process -Id $launcher.Id -Force -ErrorAction SilentlyContinue
    }

    $env:CONTROL_PLANE_TUNNEL_ID = $previousTunnelId
    $env:MCP_SERVER_URL = $previousMcpUrl
    $env:MCP_STARTUP_WAIT_TIMEOUT = $previousWait

    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit $tunnelExitCode
