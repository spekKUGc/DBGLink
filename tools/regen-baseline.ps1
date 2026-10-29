<#
.SYNOPSIS
  Deliberate refresh of the committed baseline mirrors from test scratch output.

.DESCRIPTION
  The baseline writer Facts (RoundTripBaselineTests.RoundTrip_Baseline_OverWire,
  TokenBaselineTests.PerTool_TokenBaseline_OverWire) regenerate ONLY the
  gitignored scratch reports under artifacts/benchmark/. Tests must never write
  committed files as a side effect.

  This script is the single documented copy step: after reviewing the fresh
  scratch output (diff the artifact, confirm the mockFingerprint is unchanged
  unless seeds changed deliberately, confirm the writer Fact stayed green),
  run this script to copy the artifacts over the committed mirrors under
  docs/reverse-speedup/benchmarks/, then commit the mirrors.

  Flow:
    1. dotnet test --filter "FullyQualifiedName~Baseline_OverWire" (regen scratch)
    2. inspect artifacts/benchmark/*-baseline.json
    3. powershell -NoProfile -ExecutionPolicy Bypass -File tools/regen-baseline.ps1
    4. git add docs/reverse-speedup/benchmarks/ && git commit

  The script validates that each artifact parses as JSON and carries the
  expected schemaVersion before copying. It never touches src/ or tests/.

.PARAMETER RepoRoot
  Repository root. Defaults to the git worktree root containing this script.

.PARAMETER WhatIf
  Standard PowerShell -WhatIf: prints the copies without performing them.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File tools/regen-baseline.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RepoRoot = ""
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $here = Split-Path -Parent $PSCommandPath
    $RepoRoot = Split-Path -Parent $here
}

$pairs = @(
    @{ Artifact = "artifacts/benchmark/roundtrip-baseline.json"; Mirror = "docs/reverse-speedup/benchmarks/roundtrip-baseline.json"; SchemaVersion = 1 },
    @{ Artifact = "artifacts/benchmark/token-baseline.json"; Mirror = "docs/reverse-speedup/benchmarks/token-baseline.json"; SchemaVersion = 1 },
    @{ Artifact = "artifacts/benchmark/semi-auto-baseline.json"; Mirror = "docs/reverse-speedup/benchmarks/semi-auto-baseline.json"; SchemaVersion = 1 },
    @{ Artifact = "artifacts/benchmark/semi-auto-recipe.json"; Mirror = "docs/reverse-speedup/benchmarks/semi-auto-recipe.json"; SchemaVersion = 1 }
)

foreach ($pair in $pairs) {
    $src = Join-Path $RepoRoot $pair.Artifact
    $dst = Join-Path $RepoRoot $pair.Mirror

    if (-not (Test-Path -LiteralPath $src)) {
        Write-Warning "SKIP $($pair.Artifact): scratch artifact not found. Run the writer Facts first:"
        Write-Warning "  dotnet test tests/DbgLink.Tests/DbgLink.Tests.csproj -c Release --filter ""FullyQualifiedName~Baseline_OverWire"""
        continue
    }

    try {
        $json = Get-Content -LiteralPath $src -Raw | ConvertFrom-Json
    }
    catch {
        Write-Error "REFUSE $($pair.Artifact): scratch artifact is not valid JSON: $_"
        exit 2
    }
    if ($null -eq $json.schemaVersion -or [int]$json.schemaVersion -ne [int]$pair.SchemaVersion) {
        Write-Error "REFUSE $($pair.Artifact): schemaVersion=$($json.schemaVersion), expected $($pair.SchemaVersion)."
        exit 2
    }

    if ($PSCmdlet.ShouldProcess($pair.Mirror, "Copy baseline mirror from $($pair.Artifact)")) {
        Copy-Item -LiteralPath $src -Destination $dst -Force
        $bytes = (Get-Item -LiteralPath $dst).Length
        Write-Output "MIRRORED $($pair.Artifact) -> $($pair.Mirror) ($bytes bytes). Review and commit the mirror."
    }
}

Write-Output "Done. Next: git diff --stat docs/reverse-speedup/benchmarks/ ; git add docs/reverse-speedup/benchmarks/ ; git commit"
