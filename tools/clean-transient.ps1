[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$rootPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar

function Remove-VerifiedDirectory {
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string[]]$AllowedLeafNames
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    $fullPath = [IO.Path]::GetFullPath($item.FullName)
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a transient directory outside the repository: $fullPath"
    }
    if ($item.Name -notin $AllowedLeafNames) {
        throw "Refusing to remove a directory whose name is not allowlisted: $fullPath"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to recursively remove a reparse point: $fullPath"
    }
    Remove-Item -LiteralPath $fullPath -Recurse -Force
}

$buildDirectories = Get-ChildItem -LiteralPath $root -Directory -Recurse -Force |
    Where-Object {
        $_.Name -in @('bin', 'obj') -and
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
    } |
    Sort-Object { $_.FullName.Length } -Descending
foreach ($directory in $buildDirectories) {
    Remove-VerifiedDirectory -Path $directory.FullName -AllowedLeafNames @('bin', 'obj')
}

$knownGradleDirectories = @(
    (Join-Path $root ".gradle-home"),
    (Join-Path $root "src\ghidra\GhidraBridge\.gradle"),
    (Join-Path $root "src\ghidra\GhidraBridge\build"),
    (Join-Path $root "src\ghidra\GhidraBridge\dist"),
    (Join-Path $root "src\ghidra\GhidraBridge\lib")
)
foreach ($directory in $knownGradleDirectories) {
    Remove-VerifiedDirectory -Path $directory -AllowedLeafNames @('.gradle-home', '.gradle', 'build', 'dist', 'lib')
}
