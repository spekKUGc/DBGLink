[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $WrapperPath,

    [Parameter(Mandatory = $true)]
    [string] $ProjectPath,

    [Parameter(Mandatory = $true)]
    [string] $GhidraHome
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$wrapper = (Resolve-Path -LiteralPath $WrapperPath).Path
$project = (Resolve-Path -LiteralPath $ProjectPath).Path
$ghidra = (Resolve-Path -LiteralPath $GhidraHome).Path
$gradleHome = Join-Path $root "obj\gradle-home"
New-Item -ItemType Directory -Path $gradleHome -Force | Out-Null
$env:GRADLE_USER_HOME = $gradleHome

# The wrapper always opens its global distribution lock, even when the
# distribution is already unpacked. Sandboxed builds and an elevated Gradle
# process can make that lock inaccessible. Reuse the exact cached distribution
# directly when it exists; otherwise let the wrapper install it normally.
$propertiesPath = Join-Path (Split-Path -Parent $wrapper) "gradle-wrapper.properties"
$distributionUrl = Get-Content -LiteralPath $propertiesPath |
    Where-Object { $_ -match '^distributionUrl=' } |
    Select-Object -First 1
$distributionFile = if ($distributionUrl) {
    [IO.Path]::GetFileName(($distributionUrl -split '=', 2)[1])
} else {
    $null
}
$distributionDirectory = if ($distributionFile) {
    $distributionFile -replace '\.zip$', ''
} else {
    $null
}
$gradle = $null
if ($distributionDirectory) {
    $globalDists = Join-Path $env:USERPROFILE ".gradle\wrapper\dists\$distributionDirectory"
    $unpackedDirectory = $distributionDirectory -replace '-(bin|all)$', ''
    if (Test-Path -LiteralPath $globalDists -PathType Container) {
        $gradle = Get-ChildItem -LiteralPath $globalDists -Filter "gradle.bat" -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*\$unpackedDirectory\bin\gradle.bat" } |
            Select-Object -First 1 -ExpandProperty FullName
    }
}
if ([string]::IsNullOrWhiteSpace($gradle)) {
    $gradle = $wrapper
}

& $gradle `
    -p $project `
    "-PGHIDRA_INSTALL_DIR=$ghidra" `
    --no-daemon `
    compileJava `
    distributeExtension
exit $LASTEXITCODE
