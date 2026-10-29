[CmdletBinding()]
param(
    [int] $Port = 50301,
    [string] $ServerName = "dbglink",
    [switch] $NoBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be between 1 and 65535."
}

if ($ServerName -notmatch "^[A-Za-z0-9_-]+$") {
    throw "ServerName may contain only letters, digits, '_' and '-'."
}

# H-1: the server enforces `Authorization: Bearer <AuthToken>` on /mcp by
# default (ServerConfig.RequireAuthToken defaults to true). Codex never sends
# the token unless configured, so every request would 401. Resolve the token
# exactly like the server does (DBGLINK_BEARER_TOKEN env first, then the local
# mcp_config.json) and wire it via bearer_token_env_var — the Codex-native
# equivalent of a static `Authorization: Bearer` header, which keeps the secret
# out of config.toml. Fail closed when no valid token is available.
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
    $token = $config.AuthToken
    if ($token -isnot [string] -or -not (Test-BearerToken $token)) {
        throw "DBGLink config file contains no valid AuthToken: $configPath. Delete it and restart the server to regenerate, then re-run this script."
    }
    return $token
}

$bearerToken = Get-DbgLinkBearerToken

# Persist the token for Codex Desktop, which does not inherit this shell's
# environment. The value lives in the user registry hive (not in config.toml),
# mirroring how the server itself protects mcp_config.json.
$existingUserToken = [Environment]::GetEnvironmentVariable("DBGLINK_BEARER_TOKEN", "User")
if ($existingUserToken -cne $bearerToken) {
    [Environment]::SetEnvironmentVariable("DBGLINK_BEARER_TOKEN", $bearerToken, "User")
    Write-Output "Stored DBGLINK_BEARER_TOKEN in the user environment."
}
# Also export for this session so `codex` launched from here works immediately.
$env:DBGLINK_BEARER_TOKEN = $bearerToken

$codexDirectory = Join-Path $env:USERPROFILE ".codex"
$codexConfigPath = Join-Path $codexDirectory "config.toml"
New-Item -ItemType Directory -Force -Path $codexDirectory | Out-Null

$block = @"
[mcp_servers.$ServerName]
url = "http://127.0.0.1:$Port/mcp"
bearer_token_env_var = "DBGLINK_BEARER_TOKEN"
startup_timeout_sec = 15
tool_timeout_sec = 120
default_tools_approval_mode = "prompt"
enabled = true
"@

if (Test-Path -LiteralPath $codexConfigPath -PathType Leaf) {
    $content = [System.IO.File]::ReadAllText($codexConfigPath)
}
else {
    $content = ""
}

$escapedName = [regex]::Escape($ServerName)
$pattern = "(?ms)^\[mcp_servers\.$escapedName\]\r?\n.*?(?=^\[|\z)"
if ([regex]::IsMatch($content, $pattern)) {
    $updated = [regex]::Replace($content, $pattern, $block.Trim() + [Environment]::NewLine + [Environment]::NewLine, 1)
}
else {
    $separator = if ($content.Length -gt 0 -and -not $content.EndsWith("`n")) { [Environment]::NewLine } else { "" }
    $updated = $content + $separator + [Environment]::NewLine + $block.Trim() + [Environment]::NewLine
}

if ((Test-Path -LiteralPath $codexConfigPath -PathType Leaf) -and -not $NoBackup) {
    $backupPath = "$codexConfigPath.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item -LiteralPath $codexConfigPath -Destination $backupPath
    Write-Output "Backed up Codex config to $backupPath"
}

$utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
$temporaryConfigPath = "$codexConfigPath.tmp-$([Guid]::NewGuid().ToString('N'))"
try {
    [System.IO.File]::WriteAllText($temporaryConfigPath, $updated, $utf8NoBom)
    if (Test-Path -LiteralPath $codexConfigPath) {
        Remove-Item -LiteralPath $codexConfigPath -Force
    }
    [System.IO.File]::Move($temporaryConfigPath, $codexConfigPath)
}
finally {
    if (Test-Path -LiteralPath $temporaryConfigPath -PathType Leaf) {
        Remove-Item -LiteralPath $temporaryConfigPath -Force -ErrorAction SilentlyContinue
    }
}

Write-Output "Configured Codex MCP server '$ServerName' with bearer-token auth (DBGLINK_BEARER_TOKEN)."
Write-Output "Config: $codexConfigPath"
Write-Output "Endpoint: http://127.0.0.1:$Port/mcp"
Write-Output "Start DBGLink with .\tools\start-dbglink.ps1 and wait until the MCP server is ready, then restart Codex Desktop (restart is required to pick up the user environment variable)."
Write-Output "Token rotation: delete %LOCALAPPDATA%\DBGLink\mcp_config.json (or set a new DBGLINK_BEARER_TOKEN) and restart the server, then re-run this script to re-sync Codex."
