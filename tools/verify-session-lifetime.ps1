[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$TargetPath,
    [int]$Port = 50301,
    [string]$LogPath
)

# Run against a launcher-owned test session. This replaces its live target and
# debugger; leave the requested target paused and ready for further inspection.
$ErrorActionPreference = 'Stop'

if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be between 1 and 65535."
}
if ([string]::IsNullOrWhiteSpace($TargetPath) -or -not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
    throw "TargetPath was not found: $TargetPath"
}
if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
    $logParent = Split-Path -Parent $LogPath
    if (-not [string]::IsNullOrWhiteSpace($logParent)) {
        New-Item -ItemType Directory -Path $logParent -Force | Out-Null
    }
}

function Get-DbgLinkBearerToken {
    # H-1: the server enforces `Authorization: Bearer` on /mcp by default.
    # Resolve the token like the server does and fail closed when absent.
    $environmentToken = [Environment]::GetEnvironmentVariable("DBGLINK_BEARER_TOKEN")
    if (-not [string]::IsNullOrWhiteSpace($environmentToken)) {
        return $environmentToken
    }
    $configPath = if (-not [string]::IsNullOrWhiteSpace($env:DBGLINK_CONFIG_PATH)) {
        $env:DBGLINK_CONFIG_PATH
    } else {
        Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) "DBGLink\mcp_config.json"
    }
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "DBGLink bearer token was not found: $configPath does not exist. Start the server once so it generates mcp_config.json."
    }
    $token = ([System.IO.File]::ReadAllText($configPath) | ConvertFrom-Json).AuthToken
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw "DBGLink config file contains no AuthToken: $configPath."
    }
    return $token
}

$script:requestId = 0

function Invoke-LifecycleTool([string]$Name, [hashtable]$Arguments) {
    $script:requestId++
    $body = @{
        jsonrpc = '2.0'; id = $script:requestId; method = 'tools/call'
        params = @{ name = $Name; arguments = $Arguments }
    } | ConvertTo-Json -Depth 12 -Compress
    $reply = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/mcp" -Method Post `
        -ContentType 'application/json' -Headers @{ Accept = 'application/json, text/event-stream'; Authorization = "Bearer $(Get-DbgLinkBearerToken)" } `
        -Body $body -TimeoutSec 45 -UseBasicParsing
    $json = [string]$reply.Content
    if ($json.StartsWith('event:') -or $json.StartsWith('data:')) {
        $dataLine = @($json -split "`n" | Where-Object { $_.StartsWith('data: ') } | Select-Object -First 1)
        if ($dataLine.Count -eq 0 -or $dataLine[0].Length -le 6) {
            throw "MCP reply contained no data payload: $json"
        }
        $json = $dataLine[0].Substring(6)
    }
    $rpc = $json | ConvertFrom-Json
    $record = @{ timestamp = [DateTimeOffset]::UtcNow.ToString('o'); tool = $Name; response = $rpc }
    if ($LogPath) { $record | ConvertTo-Json -Depth 50 -Compress | Add-Content -LiteralPath $LogPath }
    if ($null -ne $rpc.error -or $null -eq $rpc.result -or $rpc.result.isError) { throw "$Name failed: $json" }
    $rpc.result.content[0].text | ConvertFrom-Json
}

$TargetPath = (Resolve-Path -LiteralPath $TargetPath).Path
$initial = Invoke-LifecycleTool 'ListAnalysisSessions' @{}
$session = $initial.sessions | Where-Object analysisId -eq 'default'
if ($null -eq $session) { throw 'The default test session is missing.' }

$opened = Invoke-LifecycleTool 'OpenDebugTarget' @{ analysisId = 'default'; path = $TargetPath; architecture = 'auto' }
if (-not $opened.opened) { throw 'The target did not open.' }
Write-Output "Opened target: architecture=$($opened.architecture), debuggerPid=$($opened.debuggerPid)"

foreach ($attempt in 1..3) {
    # Each delay crosses the old watchdog's two-second polling interval.
    Start-Sleep -Seconds 3
    $null = Invoke-LifecycleTool 'GetAnalysisSnapshot' @{ analysisId = 'default'; maxChars = 12000 }
    $null = Invoke-LifecycleTool 'GetServerStatus' @{ analysisId = 'default' }
    Write-Output "Snapshot/status pair $attempt passed."
}

$otherArchitecture = if ($opened.architecture -eq 'x86') { 'x64' } else { 'x86' }
$switched = Invoke-LifecycleTool 'OpenDebugTarget' @{ analysisId = 'default'; path = $TargetPath; architecture = $otherArchitecture }
if (-not $switched.opened -or -not $switched.debuggerChanged) { throw 'The second architecture switch did not occur.' }
Start-Sleep -Seconds 3
$null = Invoke-LifecycleTool 'GetServerStatus' @{ analysisId = 'default' }
$reopened = Invoke-LifecycleTool 'OpenDebugTarget' @{ analysisId = 'default'; path = $TargetPath; architecture = 'auto' }
if (-not $reopened.opened -or -not $reopened.debuggerChanged) { throw 'Automatic reopening did not replace the debugger.' }
Start-Sleep -Seconds 3
$null = Invoke-LifecycleTool 'GetAnalysisSnapshot' @{ analysisId = 'default'; maxChars = 12000 }
$null = Invoke-LifecycleTool 'GetServerStatus' @{ analysisId = 'default' }
$final = Invoke-LifecycleTool 'ListAnalysisSessions' @{}
$finalSession = $final.sessions | Where-Object analysisId -eq 'default'
if ($finalSession.ghidraLauncherPid -ne $session.ghidraLauncherPid) { throw 'Ghidra was replaced during the debugger switch.' }
Write-Output "PASS: MCP survived architecture changes; Ghidra preserved; target reopened in debugger PID $($reopened.debuggerPid)."
