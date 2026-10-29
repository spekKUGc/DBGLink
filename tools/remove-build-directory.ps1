param([Parameter(Mandatory = $true)][ValidateSet('publish', 'nuget')][string]$Kind)
$ErrorActionPreference = 'Stop'
$workspaceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ($Kind -eq 'publish') {
    $target = [IO.Path]::GetFullPath((Join-Path $workspaceRoot 'bin\publish'))
    $expectedParent = [IO.Path]::GetFullPath((Join-Path $workspaceRoot 'bin'))
} else {
    if ([string]::IsNullOrWhiteSpace($env:NUGET_SCRATCH)) { return }
    $target = [IO.Path]::GetFullPath($env:NUGET_SCRATCH)
    $expectedParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
    if ([IO.Path]::GetFileName($target) -notmatch '^DBGLinkNuGetScratch-[0-9a-f]{32}$') {
        throw "Unexpected NuGet scratch directory: $target"
    }
}
if (-not [string]::Equals([IO.Path]::GetDirectoryName($target), $expectedParent, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to delete an unexpected build path: $target"
}
if (Test-Path -LiteralPath $target) {
    $current = Get-Item -LiteralPath $target -Force
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to delete through a reparse point: $($current.FullName)"
        }
        $current = $current.Parent
    }
    Remove-Item -LiteralPath $target -Recurse -Force
}
