[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$OutputDirectory,
    [string]$GhidraExtensionZip,
    [switch]$StageOnly
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactsDirectory = Join-Path $root "artifacts"
$packageName = if ($StageOnly) { "pending" } else { "current" }
$expectedOutputDirectory = [IO.Path]::GetFullPath((Join-Path $artifactsDirectory $packageName))
$OutputDirectory = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $expectedOutputDirectory
} else {
    [IO.Path]::GetFullPath($OutputDirectory)
}
if (-not [string]::Equals(
    $OutputDirectory.TrimEnd('\', '/'),
    $expectedOutputDirectory.TrimEnd('\', '/'),
    [StringComparison]::OrdinalIgnoreCase)) {
    throw "Packages may only be published to $expectedOutputDirectory"
}

function Assert-ReparseFree {
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$MustExist
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw "Required path was not found: $fullPath"
    }
    $current = if (Test-Path -LiteralPath $fullPath) {
        Get-Item -LiteralPath $fullPath -Force
    } else {
        Get-Item -LiteralPath (Split-Path -Parent $fullPath) -Force
    }
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse points are not allowed in package paths: $($current.FullName)"
        }
        $current = $current.Parent
    }
}

function Copy-RequiredFile {
    param(
        [Parameter(Mandatory = $true)] [string]$Source,
        [Parameter(Mandatory = $true)] [string]$DestinationDirectory,
        [string]$DestinationName
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Required build artifact was not found: $Source"
    }
    Assert-ReparseFree -Path $Source -MustExist
    New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
    $destination = if ([string]::IsNullOrWhiteSpace($DestinationName)) {
        Join-Path $DestinationDirectory (Split-Path -Leaf $Source)
    } else {
        Join-Path $DestinationDirectory $DestinationName
    }
    Copy-Item -LiteralPath $Source -Destination $destination -Force
}

function Copy-DirectoryFiles {
    param(
        [Parameter(Mandatory = $true)] [string]$SourceDirectory,
        [Parameter(Mandatory = $true)] [string]$DestinationDirectory
    )

    if (-not (Test-Path -LiteralPath $SourceDirectory -PathType Container)) {
        throw "Required build output directory was not found: $SourceDirectory"
    }
    Assert-ReparseFree -Path $SourceDirectory -MustExist
    New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $SourceDirectory -File |
        Where-Object { $_.Name -notin @("mcp_config.json") }) {
        Assert-ReparseFree -Path $file.FullName -MustExist
        Copy-Item -LiteralPath $file.FullName -Destination $DestinationDirectory -Force
    }
}

New-Item -ItemType Directory -Path $artifactsDirectory -Force | Out-Null
Assert-ReparseFree -Path $artifactsDirectory -MustExist
$publishId = [Guid]::NewGuid().ToString("N")
$stagingDirectory = Join-Path $artifactsDirectory (".current-stage-" + $publishId)
$backupDirectory = Join-Path $artifactsDirectory (".current-backup-" + $publishId)
New-Item -ItemType Directory -Path $stagingDirectory | Out-Null

$x64Plugins = Join-Path $stagingDirectory "x64\plugins"
$x86Plugins = Join-Path $stagingDirectory "x86\plugins"

$serverOutput = Join-Path $root "bin\publish\DbgLink.Server"
$x64NativeOutput = Join-Path $root "bin\x64\$Configuration"
$x86NativeOutput = Join-Path $root "bin\x86\$Configuration"
$headlessLauncherOutput = Join-Path $root "bin\publish\DbgLink.Launcher.Cli"
foreach ($requiredOutput in @($serverOutput, $headlessLauncherOutput)) {
    if (-not (Test-Path -LiteralPath $requiredOutput -PathType Container)) {
        throw "Self-contained publish output was not found: $requiredOutput. Run tools\build.cmd first."
    }
}

try {
    Copy-RequiredFile (Join-Path $root "src\native\DbgLink.Native\third_party\nlohmann\LICENSE.MIT") (Join-Path $stagingDirectory "licenses") "nlohmann-json-LICENSE.MIT"
    Copy-RequiredFile (Join-Path $root "src\mcp\DbgLink.Server\third_party\ModelContextProtocol.LICENSE") (Join-Path $stagingDirectory "licenses")
    Copy-RequiredFile (Join-Path $x64NativeOutput "DbgLink.dp64") $x64Plugins
    Copy-RequiredFile (Join-Path $x86NativeOutput "DbgLink.dp32") $x86Plugins
    Copy-DirectoryFiles $serverOutput $x64Plugins
    Copy-DirectoryFiles $serverOutput $x86Plugins
    Copy-DirectoryFiles $headlessLauncherOutput (Join-Path $stagingDirectory "launcher")
    Copy-RequiredFile (Join-Path $root "tools\start-dbglink.ps1") (Join-Path $stagingDirectory "launcher")
    Copy-RequiredFile (Join-Path $root "tools\start-dbglink.cmd") (Join-Path $stagingDirectory "launcher")
    Copy-RequiredFile (Join-Path $root "tools\start-dbglink-chatgpt.ps1") (Join-Path $stagingDirectory "launcher")
    Copy-RequiredFile (Join-Path $root "tools\install-dbglink-codex.ps1") (Join-Path $stagingDirectory "launcher")

    if ([string]::IsNullOrWhiteSpace($GhidraExtensionZip)) {
        $GhidraExtensionZip = Get-ChildItem -LiteralPath (Join-Path $root "src\ghidra\GhidraBridge\dist") `
            -Filter "*.zip" -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
    Copy-RequiredFile $GhidraExtensionZip $x64Plugins "GhidraBridge.zip"
    Copy-RequiredFile $GhidraExtensionZip $x86Plugins "GhidraBridge.zip"

    # B-2/S-3: emit a SHA256SUMS manifest (GNU sha256sum format, '/' separators)
    # covering every staged file. InstallBundle (HeadlessConfiguration) verifies
    # it before installing anything; a missing/mismatching manifest fails closed.
    $manifestPath = Join-Path $stagingDirectory "SHA256SUMS"
    $stagingPrefixLength = $stagingDirectory.TrimEnd('\', '/').Length
    $manifestEntries = @(Get-ChildItem -LiteralPath $stagingDirectory -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            $relative = $_.FullName.Substring($stagingPrefixLength).TrimStart('\', '/').Replace('\', '/')
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$hash  $relative"
        })
    if ($manifestEntries.Count -eq 0) {
        throw "Staged bundle is empty; refusing to write a vacuous SHA256SUMS manifest."
    }
    $manifestEncoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllLines($manifestPath, $manifestEntries, $manifestEncoding)

    if (Test-Path -LiteralPath $OutputDirectory) {
        Assert-ReparseFree -Path $OutputDirectory -MustExist
        # Same-volume directory rename is atomic. Move-Item can recursively move
        # some files before failing on a running launcher, damaging the old bundle.
        [IO.Directory]::Move($OutputDirectory, $backupDirectory)
    }
    try {
        [IO.Directory]::Move($stagingDirectory, $OutputDirectory)
    }
    catch {
        if (Test-Path -LiteralPath $backupDirectory) {
            [IO.Directory]::Move($backupDirectory, $OutputDirectory)
        }
        throw
    }
    if (Test-Path -LiteralPath $backupDirectory) {
        Remove-Item -LiteralPath $backupDirectory -Recurse -Force
    }
}
finally {
    if (Test-Path -LiteralPath $stagingDirectory) {
        Remove-Item -LiteralPath $stagingDirectory -Recurse -Force
    }
}

Write-Host "Package created at $OutputDirectory"
Write-Host "Use x64\plugins for x64dbg and x86\plugins for x32dbg. Launchers are self-contained; no .NET runtime is required."
Write-Host "No debugger installation was modified."
