<#
.SYNOPSIS
  Coverage/test-count gate: fails if a .trx result drops below the floor.
  Blocks silent loss of test insurance (deleted/weakened tests).

.DESCRIPTION
  Parses the <Counters> element of a VSTest .trx file (total/passed/failed)
  and enforces:
    - failed + error + aborted + timeout must be 0 (unless -AllowFailed is set);
    - total (executed test cases) must be >= -Floor.

  The floor is the surrogate coverage gate: with no per-line coverage
  history for the fast path, a drop in executed cases is the measurable
  signal that KEEP insurance disappeared.

.PARAMETER TrxPath
  Path to the .trx file produced by `dotnet test --logger trx`.

.PARAMETER Floor
  Minimum accepted total executed cases. Current calibration
  (2026-10-10): full suite = 1824, KEEP filter
  (SecurityFix|CommandInjection|NativeAddressParity|ServerEndToEnd|SessionFallback) = 334.
  Recommended CI floors: 1600 for the full suite, 334 for the KEEP filter.

.PARAMETER AllowFailed
  Do not fail on failed/error/aborted/timeout counters (floor check only).

.EXAMPLE
  dotnet test tests/DbgLink.Tests/DbgLink.Tests.csproj -c Release --logger "trx;LogFileName=full.trx"
  powershell -NoProfile -ExecutionPolicy Bypass -File tools/check-test-floor.ps1 -TrxPath tests/DbgLink.Tests/TestResults/full.trx -Floor 1600
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$TrxPath,

  [Parameter(Mandatory = $true)]
  [int]$Floor,

  [switch]$AllowFailed
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $TrxPath)) {
  Write-Error "trx file not found: $TrxPath"
  exit 2
}

[xml]$trx = Get-Content -LiteralPath $TrxPath -Raw
$counters = $trx.TestRun.ResultSummary.Counters

if ($null -eq $counters) {
  Write-Error "no <Counters> element in $TrxPath (not a valid VSTest trx?)"
  exit 2
}

$total  = [int]$counters.total
$passed = [int]$counters.passed
$failed = [int]$counters.failed
$errors = [int]$counters.error
$aborted = [int]$counters.aborted
$timeout = [int]$counters.timeout
$bad = $failed + $errors + $aborted + $timeout

Write-Output "trx=$TrxPath total=$total passed=$passed failed=$failed error=$errors aborted=$aborted timeout=$timeout floor=$Floor"

$exitCode = 0

if (-not $AllowFailed -and $bad -gt 0) {
  Write-Error "GATE FAIL: $bad unsuccessful test(s) (failed=$failed error=$errors aborted=$aborted timeout=$timeout), expected 0."
  $exitCode = 1
}

if ($total -lt $Floor) {
  Write-Error "GATE FAIL: total=$total below floor=$Floor -- test insurance was silently lost."
  $exitCode = 1
}

if ($exitCode -eq 0) {
  Write-Output "GATE PASS: total=$total >= floor=$Floor (failed=$failed error=$errors aborted=$aborted timeout=$timeout)."
}

exit $exitCode
