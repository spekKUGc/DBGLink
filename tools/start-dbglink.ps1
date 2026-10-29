<#
.SYNOPSIS
  Starts the DBGLink headless launcher (MCP server + debugger + Ghidra toolkit).
.DESCRIPTION
  Forwards all arguments to DbgLink.Launcher.Cli. Prefers the packaged binary
  (tools\DbgLink.Launcher.Cli.exe or artifacts\current\launcher\), then a
  Release/Debug build output, and finally `dotnet run`.
  All arguments are forwarded to the launcher: `--help` shows its options.
.EXAMPLE
  .\tools\start-dbglink.ps1
.EXAMPLE
  .\tools\start-dbglink.ps1 -Input "C:\path\to\target.exe"
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $LauncherArguments
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$packagedLauncher = Join-Path $PSScriptRoot "DbgLink.Launcher.Cli.exe"
if (-not (Test-Path -LiteralPath $packagedLauncher -PathType Leaf)) {
    $packagedLauncher = Join-Path $root "artifacts\current\launcher\DbgLink.Launcher.Cli.exe"
}
if (Test-Path -LiteralPath $packagedLauncher -PathType Leaf) {
    & $packagedLauncher @LauncherArguments
    exit $LASTEXITCODE
}
$releaseCandidates = @(
    (Join-Path $PSScriptRoot "DbgLink.Launcher.Cli.exe"),
    (Join-Path $root "src\launcher\DbgLink.Launcher.Cli\bin\Release\net10.0\DbgLink.Launcher.Cli.exe"),
    (Join-Path $root "src\launcher\DbgLink.Launcher.Cli\bin\x64\Release\net10.0\DbgLink.Launcher.Cli.exe")
)
$debugCandidates = @(
    (Join-Path $root "src\launcher\DbgLink.Launcher.Cli\bin\Debug\net10.0\DbgLink.Launcher.Cli.exe"),
    (Join-Path $root "src\launcher\DbgLink.Launcher.Cli\bin\x64\Debug\net10.0\DbgLink.Launcher.Cli.exe")
)
$release = $releaseCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Sort-Object { (Get-Item -LiteralPath $_).LastWriteTimeUtc } -Descending |
    Select-Object -First 1
$debug = $debugCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Sort-Object { (Get-Item -LiteralPath $_).LastWriteTimeUtc } -Descending |
    Select-Object -First 1

if (-not [string]::IsNullOrWhiteSpace($release)) {
    & $release @LauncherArguments
    exit $LASTEXITCODE
}
if (-not [string]::IsNullOrWhiteSpace($debug)) {
    & $debug @LauncherArguments
    exit $LASTEXITCODE
}

$project = Join-Path $root "src\launcher\DbgLink.Launcher.Cli\DbgLink.Launcher.Cli.csproj"
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if ($null -eq $dotnet) {
    throw "No launcher binary was found and 'dotnet' is not on PATH. Build first (tools\build.cmd) or install the .NET 10 SDK."
}
& dotnet run --project $project --configuration Release -- @LauncherArguments
exit $LASTEXITCODE
