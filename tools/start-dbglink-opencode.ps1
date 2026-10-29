<#
.SYNOPSIS
  One-click start for DbgLink + OpenCode Desktop.
.DESCRIPTION
  Ensures the DbgLink server is running, syncs the bearer token, then
  restarts OpenCode Desktop so its backend connects to DbgLink over MCP.

  Why the restart order matters: OpenCode Desktop reuses a live background
  opencode-cli.exe process across window restarts, and that backend opens the
  MCP connection to DbgLink only once at its own startup. If the server was
  down when the backend started, the chat has no DbgLink tools until the
  backend itself is killed and relaunched while the server is already up.
  This script enforces exactly that order: server first, app second.

  A fresh backend proves itself in /metrics: the mcpMethods.initialize
  counter increments once the backend completes the MCP handshake, so the
  script polls it to confirm the connection instead of guessing.
.EXAMPLE
  .\tools\start-dbglink-opencode.ps1
.EXAMPLE
  .\tools\start-dbglink-opencode.ps1 -Input "C:\path\to\target.exe"
.EXAMPLE
  .\tools\start-dbglink-opencode.ps1 -X64DbgPath "C:\path\to\x64dbg.exe" -GhidraHome "C:\path\to\ghidra"
  (first run: tool paths are validated once and stored in the user environment)
.EXAMPLE
  .\tools\start-dbglink-opencode.ps1 -ServerOnly
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [int] $Port = 50301,
    [switch] $ServerOnly,
    [int] $ReadyTimeoutSec = 180,
    [string] $ServerStartScript = "",
    [string] $X64DbgPath = "",
    [string] $X32DbgPath = "",
    [string] $GhidraHome = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $LauncherArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# powershell.exe -File leaves ValueFromRemainingArguments as $null, and
# @($null).Count is 1 in PS 5.1, so normalize to a real (possibly empty) array
# once; otherwise an empty-string element would leak into the child command
# line and trip the launcher's "Unknown argument" error.
$LauncherArguments = @($LauncherArguments | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if ([string]::IsNullOrWhiteSpace($ServerStartScript)) {
    # Resolved here (not as a param default) because $PSScriptRoot is not
    # populated yet while parameter defaults are evaluated.
    if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        throw "Cannot resolve the default server start script: run this script by its path (e.g. .\tools\start-dbglink-opencode.ps1) or pass -ServerStartScript explicitly."
    }
    $ServerStartScript = Join-Path $PSScriptRoot "start-dbglink.ps1"
}

if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be between 1 and 65535."
}
if ($ReadyTimeoutSec -lt 1 -or $ReadyTimeoutSec -gt 3600) {
    throw "ReadyTimeoutSec must be between 1 and 3600."
}
if ([string]::IsNullOrWhiteSpace($ServerStartScript)) {
    throw "ServerStartScript must not be empty."
}
$ServerStartScript = [IO.Path]::GetFullPath($ServerStartScript)
if (-not (Test-Path -LiteralPath $ServerStartScript -PathType Leaf)) {
    throw "Server start script was not found: $ServerStartScript"
}

if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw "The LOCALAPPDATA environment variable is not set; cannot locate OpenCode Desktop."
}
$OpenCodeExe = Join-Path $env:LOCALAPPDATA "Programs\@opencodedesktop\OpenCode.exe"
$ConnectTimeoutSec = 120

# Persists a tool path for future runs (user environment, so Explorer-launched
# processes see it) and for this process (so the detached server started below
# inherits it). Idempotent: no write and no output when already stored.
function Sync-ToolPathEnv([string] $EnvName, [string] $Value) {
    $existing = [Environment]::GetEnvironmentVariable($EnvName, "User")
    if ($existing -cne $Value) {
        [Environment]::SetEnvironmentVariable($EnvName, $Value, "User")
        Write-Output "Stored $EnvName in the user environment."
    }
    [Environment]::SetEnvironmentVariable($EnvName, $Value, "Process")
}

if (-not [string]::IsNullOrWhiteSpace($X64DbgPath)) {
    if (-not (Test-Path -LiteralPath $X64DbgPath -PathType Leaf)) {
        throw "x64dbg was not found: $X64DbgPath. Pass the full path to x64dbg.exe via -X64DbgPath."
    }
    $X64DbgPath = [IO.Path]::GetFullPath($X64DbgPath)
    Sync-ToolPathEnv "DBGLINK_X64DBG_PATH" $X64DbgPath
}
if (-not [string]::IsNullOrWhiteSpace($X32DbgPath)) {
    if (-not (Test-Path -LiteralPath $X32DbgPath -PathType Leaf)) {
        throw "x32dbg was not found: $X32DbgPath. Pass the full path to x32dbg.exe via -X32DbgPath."
    }
    $X32DbgPath = [IO.Path]::GetFullPath($X32DbgPath)
    Sync-ToolPathEnv "DBGLINK_X32DBG_PATH" $X32DbgPath
}
if (-not [string]::IsNullOrWhiteSpace($GhidraHome)) {
    if (-not (Test-Path -LiteralPath $GhidraHome -PathType Container)) {
        throw "Ghidra home directory was not found: $GhidraHome. Pass the Ghidra installation directory via -GhidraHome."
    }
    $GhidraHome = [IO.Path]::GetFullPath($GhidraHome)
    if (-not (Test-Path -LiteralPath (Join-Path $GhidraHome "ghidraRun.bat") -PathType Leaf)) {
        throw "Ghidra home does not contain ghidraRun.bat: $GhidraHome. Pass the Ghidra installation directory (the one with ghidraRun.bat) via -GhidraHome."
    }
    Sync-ToolPathEnv "DBGLINK_GHIDRA_HOME" $GhidraHome
}

# Hydrate the process environment from the user hive: this shell may predate
# the stored tool paths (a long-open terminal), but the launcher only reads
# the process environment. An explicit in-process value always wins.
foreach ($toolVar in @("DBGLINK_X64DBG_PATH", "DBGLINK_X32DBG_PATH", "DBGLINK_GHIDRA_HOME")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($toolVar, "Process"))) {
        $userValue = [Environment]::GetEnvironmentVariable($toolVar, "User")
        if (-not [string]::IsNullOrWhiteSpace($userValue)) {
            [Environment]::SetEnvironmentVariable($toolVar, $userValue, "Process")
        }
    }
}

function Test-TcpPort([string] $ComputerName, [int] $TcpPort, [int] $TimeoutMs) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $TcpPort, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

# StrictMode-safe property read for ConvertFrom-Json output: referencing a
# missing property on a PSCustomObject throws under Set-StrictMode -Version
# Latest, so probe the property collection instead and return $null when absent.
function Get-JsonProperty($Object, [string] $Name) {
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

# Read-only probe of candidate tokens (never writes anything; the
# authoritative sync happens later via install-dbglink-opencode.ps1).
# Both are tried because this shell's $env: may be stale while the config
# holds the token the running server actually uses (or vice versa).
function Get-ProbeTokens {
    $tokens = @()
    if (-not [string]::IsNullOrWhiteSpace($env:DBGLINK_BEARER_TOKEN)) {
        $tokens += $env:DBGLINK_BEARER_TOKEN
    }
    $configPath = $null
    if (-not [string]::IsNullOrWhiteSpace($env:DBGLINK_CONFIG_PATH)) {
        $configPath = [IO.Path]::GetFullPath($env:DBGLINK_CONFIG_PATH)
    }
    else {
        $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
            $configPath = (Join-Path $localAppData "DBGLink\mcp_config.json")
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($configPath) -and (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        try {
            $config = [System.IO.File]::ReadAllText($configPath) | ConvertFrom-Json
            $configToken = Get-JsonProperty $config "AuthToken"
            if (($configToken -is [string]) -and -not [string]::IsNullOrWhiteSpace($configToken) -and -not ($tokens -ccontains $configToken)) {
                $tokens += $configToken
            }
        }
        catch {
        }
    }
    return $tokens
}

# Returns a hashtable: Ok, StatusCode (nullable int), UptimeSeconds, Initialize.
function Get-ServerMetrics([string] $Token) {
    $result = @{ Ok = $false; StatusCode = $null; UptimeSeconds = $null; Initialize = $null }
    if ([string]::IsNullOrWhiteSpace($Token)) {
        return $result
    }
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/metrics" -Headers @{ Authorization = "Bearer $Token" } -UseBasicParsing -TimeoutSec 10
        $result.StatusCode = [int]$response.StatusCode
        if ([int]$response.StatusCode -ne 200) {
            return $result
        }
        $metrics = $response.Content | ConvertFrom-Json
        $result.UptimeSeconds = Get-JsonProperty $metrics "uptimeSeconds"
        $mcpMethods = Get-JsonProperty $metrics "mcpMethods"
        $initialize = Get-JsonProperty $mcpMethods "initialize"
        if ($null -ne $initialize) {
            $result.Initialize = [long]$initialize
        }
        else {
            $result.Initialize = 0
        }
        if ($null -ne $result.UptimeSeconds) {
            $result.Ok = $true
        }
        return $result
    }
    catch {
        try {
            $result.StatusCode = [int]$_.Exception.Response.StatusCode
        }
        catch {
            $result.StatusCode = $null
        }
        return $result
    }
}

# Quotes one argv element for CreateProcess. PowerShell 5.1 Start-Process does
# NOT quote array elements (it joins them with plain spaces), so a path with
# spaces would split into several arguments in the child. Quote by hand using
# the CommandLineToArgvW rules the C runtime uses to split: wrap in "..." when
# the value contains whitespace or a quote, escape each embedded " as \" (and
# double any backslash run in front of it, plus trailing backslashes, so they
# do not escape the closing quote themselves).
function Format-CommandArgument([string] $Value) {
    if ($Value -eq "") {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

# Fast liveness check: TCP first (cheap), then an authenticated /metrics read
# with each candidate token.
function Test-ServerAlive {
    if (-not (Test-TcpPort "127.0.0.1" $Port 500)) {
        return $false
    }
    foreach ($candidate in (Get-ProbeTokens)) {
        $probe = Get-ServerMetrics $candidate
        if ($probe.Ok) {
            return $true
        }
    }
    return $false
}

# Step 1-2: reuse the running server when it is alive; start it detached otherwise.
# Exit code 2 from the launcher means required tools were not found; point the
# user at the one-time path bootstrap (or the raw launcher flags).
$missingToolsHint = "Exit code 2 usually means the debugger or Ghidra tools were not found: pass -X64DbgPath/-X32DbgPath/-GhidraHome once (they are stored in your user environment) or the launcher flags --x64dbg/--x32dbg/--ghidra-home."
$serverWasAlive = Test-ServerAlive
if ($serverWasAlive) {
    Write-Output "DbgLink server is already running on port $Port; reusing it."
    if ($LauncherArguments.Count -gt 0) {
        Write-Warning "Launcher arguments were ignored because the server is already running. Load the target via OpenDebugTarget in the chat instead."
    }
}
else {
    $serverArgs = @()
    if ($Port -ne 50301) {
        # The launcher listens on 50301 unless told otherwise (--port), while
        # this script probes $Port; forward the custom port unless the caller
        # already passed --port explicitly (either "--port N" or "--port=N").
        $hasPortFlag = $false
        foreach ($arg in $LauncherArguments) {
            if ($arg -like "--port*") {
                $hasPortFlag = $true
                break
            }
        }
        if (-not $hasPortFlag) {
            $serverArgs += @("--port", "$Port")
        }
        else {
            Write-Warning "Custom -Port $Port was requested and --port was also passed to the server; probing port $Port."
        }
    }
    $serverArgs += $LauncherArguments

    Write-Output "Starting DbgLink server in a separate window..."
    # -ExecutionPolicy Bypass targets only our own script by literal path
    # (same rationale as the sibling tools: zip trees carry Mark-of-the-Web,
    # which RemoteSigned would refuse).
    # A single pre-quoted command line: Start-Process in PS 5.1 joins an array
    # with plain spaces (no quoting), so Format-CommandArgument quotes each
    # element first; a single string is passed through to CreateProcess as-is.
    $argumentList = ((@("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $ServerStartScript) + $serverArgs) | ForEach-Object { Format-CommandArgument $_ }) -join " "
    $serverProcess = Start-Process powershell.exe -ArgumentList $argumentList -PassThru

    $deadline = (Get-Date).AddSeconds($ReadyTimeoutSec)
    $lastProgress = [DateTime]::MinValue
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        try {
            if ($serverProcess.HasExited) {
                $serverExitCode = $serverProcess.ExitCode
                $exitDetail = "Check the server window for errors, then re-run this script."
                if ($serverExitCode -eq 2) {
                    $exitDetail = $missingToolsHint
                }
                throw "The DbgLink server process exited with code $serverExitCode before becoming ready. $exitDetail"
            }
        }
        catch [System.InvalidOperationException] {
            # HasExited raced with process startup; keep waiting.
        }
        if ((Test-TcpPort "127.0.0.1" $Port 500) -and (Test-ServerAlive)) {
            $ready = $true
            break
        }
        if (((Get-Date) - $lastProgress).TotalSeconds -ge 2) {
            Write-Output "Waiting for the DbgLink server on port $Port..."
            $lastProgress = Get-Date
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        # The wait loop already throws when the process exits, so reaching the
        # timeout normally means it is still alive; re-check once in case it
        # just died, so a code-2 misconfiguration still gets the right hint.
        $timeoutDetail = "Check the server window for errors, then re-run this script."
        try {
            if ($serverProcess.HasExited -and $serverProcess.ExitCode -eq 2) {
                $timeoutDetail = $missingToolsHint
            }
        }
        catch [System.InvalidOperationException] {
        }
        throw "Timed out after $ReadyTimeoutSec seconds waiting for the DbgLink server on port $Port. $timeoutDetail"
    }
    Write-Output "DbgLink server is ready on port $Port."
}

# Step 3: authoritative token sync. Dot-sourced (not a child process) so that
# the $env:DBGLINK_BEARER_TOKEN it sets survives in this process and is
# inherited by OpenCode Desktop launched below.
. (Join-Path $PSScriptRoot "install-dbglink-opencode.ps1") -Port $Port

# Hard gate: the token we are about to hand to the app must be accepted by the
# server right now (fail closed). The server may still be warming up, so retry.
$tokenAccepted = $false
$tokenDeadline = (Get-Date).AddSeconds(20)
$lastStatus = $null
while ((Get-Date) -lt $tokenDeadline) {
    $check = Get-ServerMetrics $env:DBGLINK_BEARER_TOKEN
    $lastStatus = $check.StatusCode
    if ($check.Ok) {
        $tokenAccepted = $true
        break
    }
    if ($lastStatus -eq 401 -or $lastStatus -eq 403) {
        break
    }
    Start-Sleep -Milliseconds 1000
}
if (-not $tokenAccepted) {
    if ($lastStatus -eq 401 -or $lastStatus -eq 403) {
        throw "The server rejected the bearer token (HTTP $lastStatus). The token was probably rotated: delete %LOCALAPPDATA%\DBGLink\mcp_config.json, restart the server, and re-run this script."
    }
    throw "The server did not accept the bearer token on port $Port (last status: $lastStatus). Make sure the server is running, then re-run this script."
}

# Baseline for the connection check: a backend that starts now must push the
# counter above whatever it was before the app restart.
$baselineMetrics = Get-ServerMetrics $env:DBGLINK_BEARER_TOKEN
$baselineInitialize = 0
if ($null -ne $baselineMetrics.Initialize) {
    $baselineInitialize = $baselineMetrics.Initialize
}

if ($ServerOnly) {
    Write-Output "Server ready; OpenCode left untouched."
    exit 0
}

# Step 4: restart OpenCode Desktop so its backend starts while the server is up.
if (-not (Test-Path -LiteralPath $OpenCodeExe -PathType Leaf)) {
    throw "OpenCode Desktop was not found at $OpenCodeExe. Install OpenCode Desktop first, then re-run this script."
}

# Close the UI gently first (lets the app save state), then force leftovers.
# The backend (opencode-cli.exe) outlives the window and is what actually holds
# the stale MCP connection, so it must be stopped explicitly.
$uiProcesses = @(Get-Process -Name "OpenCode" -ErrorAction SilentlyContinue)
if ($uiProcesses.Count -gt 0) {
    foreach ($ui in $uiProcesses) {
        try {
            $ui.CloseMainWindow() | Out-Null
        }
        catch {
        }
    }
    $graceDeadline = (Get-Date).AddSeconds(5)
    while ((Get-Date) -lt $graceDeadline) {
        if (@(Get-Process -Name "OpenCode" -ErrorAction SilentlyContinue).Count -eq 0) {
            break
        }
        Start-Sleep -Milliseconds 500
    }
    @(Get-Process -Name "OpenCode" -ErrorAction SilentlyContinue) | ForEach-Object {
        try {
            Stop-Process -InputObject $_ -Force -ErrorAction SilentlyContinue
        }
        catch {
        }
    }
}
@(Get-Process -Name "opencode-cli" -ErrorAction SilentlyContinue) | ForEach-Object {
    try {
        Stop-Process -InputObject $_ -Force -ErrorAction SilentlyContinue
    }
    catch {
    }
}

# Wait until both the UI and every orphaned backend are really gone; starting
# the app while a stale backend still holds the port/state would silently reuse it.
$stopDeadline = (Get-Date).AddSeconds(10)
while ((Get-Date) -lt $stopDeadline) {
    $leftUi = @(Get-Process -Name "OpenCode" -ErrorAction SilentlyContinue).Count
    $leftCli = @(Get-Process -Name "opencode-cli" -ErrorAction SilentlyContinue).Count
    if ($leftUi -eq 0 -and $leftCli -eq 0) {
        break
    }
    Start-Sleep -Milliseconds 500
}
$leftUi = @(Get-Process -Name "OpenCode" -ErrorAction SilentlyContinue).Count
$leftCli = @(Get-Process -Name "opencode-cli" -ErrorAction SilentlyContinue).Count
if ($leftUi -gt 0 -or $leftCli -gt 0) {
    throw "Could not stop the running OpenCode processes (OpenCode: $leftUi, opencode-cli: $leftCli). Close OpenCode Desktop manually and re-run this script."
}

# Inherits this process's environment, including the synced DBGLINK_BEARER_TOKEN.
Start-Process -FilePath $OpenCodeExe | Out-Null
Write-Output "OpenCode Desktop started; waiting for it to connect to DbgLink..."

$connectDeadline = (Get-Date).AddSeconds($ConnectTimeoutSec)
$lastProgress = [DateTime]::MinValue
$connected = $false
$initializeCount = $baselineInitialize
while ((Get-Date) -lt $connectDeadline) {
    $snapshot = Get-ServerMetrics $env:DBGLINK_BEARER_TOKEN
    if ($null -ne $snapshot.Initialize) {
        $initializeCount = $snapshot.Initialize
        if ($initializeCount -gt $baselineInitialize) {
            $connected = $true
            break
        }
    }
    if (((Get-Date) - $lastProgress).TotalSeconds -ge 10) {
        Write-Output "Waiting for OpenCode to complete the MCP handshake..."
        $lastProgress = Get-Date
    }
    Start-Sleep -Seconds 2
}

if ($connected) {
    Write-Output "OpenCode is connected to DbgLink (MCP initialize: $initializeCount)."
    exit 0
}

Write-Warning "OpenCode did not complete the MCP handshake within $ConnectTimeoutSec seconds. Checklist: did the OpenCode window open? Is the backend alive (look for 'v2 CLI background service ready' in the newest %APPDATA%\ai.opencode.desktop\logs\<date>\main.log)? If the window never appeared, launch OpenCode Desktop manually; the token and server are already in place."
exit 1
