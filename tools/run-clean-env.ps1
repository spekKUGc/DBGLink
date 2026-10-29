param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [string]$ArgumentList
)

$cleanEnvironment = @{}
$processEnvironment = [Environment]::GetEnvironmentVariables('Process')
foreach ($key in $processEnvironment.Keys) {
    if ($key -ne 'PATH' -and $key -ne 'Path') {
        $cleanEnvironment[$key] = [string]$processEnvironment[$key]
    }
}

$pathValue = [Environment]::GetEnvironmentVariable('Path', 'Process')
if ([string]::IsNullOrWhiteSpace($pathValue)) {
    $pathValue = [Environment]::GetEnvironmentVariable('PATH', 'Process')
}
if (-not [string]::IsNullOrWhiteSpace($pathValue)) {
    $cleanEnvironment['Path'] = $pathValue
}

$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $FilePath
$startInfo.Arguments = $ArgumentList
$startInfo.WorkingDirectory = (Get-Location).Path
$startInfo.UseShellExecute = $false

# Start-Process -Wait waits for the complete descendant tree on Windows. MSBuild
# intentionally leaves compiler-server descendants alive, so that API can hang a
# completed build forever. Process.WaitForExit waits for the process we launched.
$startInfo.EnvironmentVariables.Clear()
foreach ($key in $cleanEnvironment.Keys) {
    $startInfo.EnvironmentVariables[[string]$key] = [string]$cleanEnvironment[$key]
}

$child = [System.Diagnostics.Process]::Start($startInfo)
if ($null -eq $child) {
    throw "Could not start build process: $FilePath"
}

try {
    $child.WaitForExit()
    $exitCode = $child.ExitCode
}
finally {
    $child.Dispose()
}

exit $exitCode
