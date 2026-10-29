<#
.SYNOPSIS
  Syncs the DBGLink bearer token into the user environment for OpenCode Desktop.
.DESCRIPTION
  Resolves AuthToken exactly like the server does (DBGLINK_BEARER_TOKEN first,
  then mcp_config.json) and stores it in the user environment variable
  DBGLINK_BEARER_TOKEN. The project is already wired via opencode.json
  (headers: Authorization Bearer {env:DBGLINK_BEARER_TOKEN}), so no config
  files are touched.

  Why the user environment: OpenCode Desktop is started from Explorer, not from
  this shell, so it never inherits the current shell's $env:. Explorer picks up
  the User registry hive for newly launched processes, and a full restart of
  OpenCode Desktop is required to inherit the updated variable.
.EXAMPLE
  .\tools\install-dbglink-opencode.ps1
#>
[CmdletBinding()]
param(
    [int] $Port = 50301
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be between 1 and 65535."
}

# H-1: the server enforces `Authorization: Bearer <AuthToken>` on /mcp by
# default (ServerConfig.RequireAuthToken defaults to true). OpenCode Desktop
# reads the token from the user environment via opencode.json
# (headers: Authorization Bearer {env:DBGLINK_BEARER_TOKEN}), so sync the token
# exactly like the server resolves it (DBGLINK_BEARER_TOKEN env first, then the
# local mcp_config.json) and keep the secret out of config files. Fail closed
# when no valid token is available.
function Test-BearerToken([string] $Token) {
    if ([string]::IsNullOrEmpty($Token) -or $Token.Length -lt 32 -or $Token.Length -gt 512) {
        return $false
    }
    if ($Token.ToCharArray() | Where-Object { [char]::IsControl($_) }) {
        return $false
    }
    $paddingStart = $Token.IndexOf('=')
    $valueEnd = if ($paddingStart -lt 0) { $Token.Length } else { $paddingStart }
    if ($valueEnd -eq 0) {
        return $false
    }
    $valuePart = $Token.Substring(0, $valueEnd)
    if ($valuePart -cnotmatch '^[A-Za-z0-9\-._~+/]+$') {
        return $false
    }
    if ($paddingStart -ge 0 -and $Token.Substring($paddingStart) -cnotmatch '^=+$') {
        return $false
    }
    return $true
}

function Get-DbgLinkConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($env:DBGLINK_CONFIG_PATH)) {
        return [IO.Path]::GetFullPath($env:DBGLINK_CONFIG_PATH)
    }
    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
        throw "The local application-data directory is unavailable; cannot locate mcp_config.json."
    }
    return (Join-Path $localAppData "DBGLink\mcp_config.json")
}

function Get-DbgLinkBearerToken {
    $environmentToken = $env:DBGLINK_BEARER_TOKEN
    if (Test-BearerToken $environmentToken) {
        return $environmentToken
    }

    $configPath = Get-DbgLinkConfigPath
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "DBGLink bearer token was not found: $configPath does not exist. Start the server once with .\tools\start-dbglink.ps1 (it generates mcp_config.json with a fresh AuthToken), then re-run this script."
    }
    $configLength = (Get-Item -LiteralPath $configPath).Length
    if ($configLength -le 0 -or $configLength -gt 65536) {
        throw "DBGLink config file has an unexpected size: $configPath"
    }
    try {
        $config = [System.IO.File]::ReadAllText($configPath) | ConvertFrom-Json
    }
    catch {
        throw "DBGLink config file could not be parsed: $configPath ($($_.Exception.Message))"
    }
    # StrictMode-safe read: a missing AuthToken property would throw
    # PropertyNotFoundStrict here instead of the clear error below.
    $authTokenProperty = $config.PSObject.Properties["AuthToken"]
    $token = $null
    if ($null -ne $authTokenProperty) {
        $token = $authTokenProperty.Value
    }
    if ($token -isnot [string] -or -not (Test-BearerToken $token)) {
        throw "DBGLink config file contains no valid AuthToken: $configPath. Delete it and restart the server to regenerate, then re-run this script."
    }
    return $token
}

$bearerToken = Get-DbgLinkBearerToken

# Persist the token for OpenCode Desktop, which does not inherit this shell's
# environment. The value lives in the user registry hive (not in opencode.json),
# mirroring how the server itself protects mcp_config.json.
$existingUserToken = [Environment]::GetEnvironmentVariable("DBGLINK_BEARER_TOKEN", "User")
if ($existingUserToken -cne $bearerToken) {
    [Environment]::SetEnvironmentVariable("DBGLINK_BEARER_TOKEN", $bearerToken, "User")
    Write-Output "Stored DBGLINK_BEARER_TOKEN in the user environment."
}
# Also export for this session so tools launched from here work immediately.
$env:DBGLINK_BEARER_TOKEN = $bearerToken

# Best-effort liveness check against the running server (Windows PowerShell 5.1
# compatible: -UseBasicParsing, status via $_.Exception.Response.StatusCode).
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/metrics" -Headers @{ Authorization = "Bearer $bearerToken" } -UseBasicParsing -TimeoutSec 10
    if ($response.StatusCode -eq 200) {
        Write-Output "Server reachable; bearer token accepted."
    }
    else {
        Write-Warning ("Server returned an unexpected status code: " + [int]$response.StatusCode + ".")
    }
}
catch {
    $statusCode = $null
    try {
        $statusCode = [int]$_.Exception.Response.StatusCode
    }
    catch {
        $statusCode = $null
    }
    if ($statusCode -eq 401 -or $statusCode -eq 403) {
        Write-Warning "Server rejected the bearer token (HTTP $statusCode). Restart the server with .\tools\start-dbglink.ps1 and re-run this script to re-sync the token."
    }
    elseif ($null -ne $statusCode) {
        Write-Warning ("Server returned an unexpected status code: $statusCode.")
    }
    else {
        Write-Warning "Server not reachable on port $Port; start it with .\tools\start-dbglink.ps1."
    }
}

Write-Output "Close and reopen OpenCode Desktop completely so it picks up the user environment variable (the project is already configured via opencode.json)."
Write-Output "Token rotation: delete %LOCALAPPDATA%\DBGLink\mcp_config.json (or set a new DBGLINK_BEARER_TOKEN) and restart the server, then re-run this script."
