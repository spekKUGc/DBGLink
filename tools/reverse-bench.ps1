param(
  [string]$Tool = "",
  [string]$ArgsJson = "",
  [string]$ArgsFile = "",
  [switch]$Stats,
  [switch]$Reset,
  [switch]$List
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$csproj = Join-Path $root 'tools\ReverseBench\ReverseBench.csproj'
$dll = Join-Path $root 'tools\ReverseBench\bin\x64\Release\net10.0\ReverseBench.dll'
dotnet build $csproj -c Release --nologo -v q | Out-Null
if ($Stats) { dotnet $dll stats; return }
if ($Reset) { dotnet $dll reset; return }
if ($List) { dotnet $dll list; return }
if (-not $Tool) { Write-Error 'pass -Tool <Name> -ArgsJson ''{...}'' or -Tool <Name> -ArgsFile <path> (or -Stats / -Reset)'; return }
if ($ArgsFile -and $ArgsJson) { Write-Error 'pass either -ArgsJson or -ArgsFile, not both'; return }
if ($ArgsFile) { dotnet $dll call-file $Tool $ArgsFile; return }
if (-not $ArgsJson) { $ArgsJson = '{}' }
dotnet $dll call $Tool $ArgsJson
