# Verification scripts

Three PowerShell scripts cover the live toolkit. All require Windows and a
built package (`tools\build.cmd` first, so `artifacts\current` exists).

| Script | Needs debugger | Needs Ghidra | Against running MCP | What it proves |
| :--- | :---: | :---: | :---: | :--- |
| `tools\verify-e2e.ps1` | yes (x64dbg/x32dbg) | yes | no (starts its own launcher) | Launcher -> MCP -> native bridge -> Ghidra -> graceful stop, no orphaned processes, plugin state restored |
| `tools\verify-static.ps1` | no | yes | no (headless Ghidra only) | Packaged `GhidraBridge.jar` imports fixtures and passes `StaticBridgeChecks.java` |
| `tools\verify-session-lifetime.ps1` | yes (via launcher) | yes (preserved) | **yes** (attach to `$Port`) | Session survives debugger architecture switches; Ghidra process is preserved; target auto-reopens |

## verify-e2e.ps1

```powershell
.\tools\verify-e2e.ps1                                   # both architectures, notepad targets
.\tools\verify-e2e.ps1 -Architecture x64                # one architecture only
.\tools\verify-e2e.ps1 -AnalysisFixtures                # + known-function/xref/Unicode checks on built fixtures
.\tools\verify-e2e.ps1 -KeepInstalled                   # leave plugins installed, keep backup under artifacts\.e2e-backup
```

Ports start at `-Port` (default 50317) and increment per architecture check.
The script saves/restores debugger `plugins\` state, waits for the JSON
`ready` event (10 min timeout), runs `initialize` + `tools/list` + snapshot /
decompile / inspect checks, then stops the launcher via the shutdown-file
protocol and fails if any child process (`DbgLink.Server.exe`, debuggers)
remains.

Authentication (H-1): every MCP request carries
`Authorization: Bearer <token>`, resolved like the server does
(`DBGLINK_BEARER_TOKEN`, then `AuthToken` from `mcp_config.json`); without a
token the script fails closed instead of collecting noise 401s.

Debugger discovery (S-1): only the explicit `-X64DbgPath` / `-X32DbgPath`
flags, their `DBGLINK_X64DBG_PATH` / `DBGLINK_X32DBG_PATH` environment
variables, the caller's `PATH`, the staged `artifacts\current` bundle and
Program Files are consulted. Downloads, Desktop, the repo root/CWD and the
rest of `%USERPROFILE%` are never searched; an unknown location fails closed
with an explicit-path instruction.

## verify-static.ps1

```powershell
.\tools\verify-static.ps1 -GhidraHome "C:\ghidra"       # explicit Ghidra
$env:DBGLINK_GHIDRA_HOME = "C:\ghidra"                  # or via environment (also honors GHIDRA_INSTALL_DIR)
.\tools\verify-static.ps1 -Architecture x64            # x64 | Win32 | both (default)
.\tools\verify-static.ps1 -KeepRunDir                  # keep artifacts\verification\static-* logs on success
```

Resolves Ghidra from `-GhidraHome`, then `DBGLINK_GHIDRA_HOME` /
`GHIDRA_INSTALL_DIR`, then Program Files only (S-1: Downloads, Desktop,
`%USERPROFILE%` and `%LOCALAPPDATA%` are never searched; anything else fails
closed with an explicit-path instruction). Runs headless
`analyzeHeadless.bat` with an isolated `USERPROFILE`/`APPDATA`/`LOCALAPPDATA`
under `artifacts\verification\static-*` so the user profile is untouched.
Requires `artifacts\fixtures\<arch>\AnalysisTarget.exe` (built by
`tools\build.cmd`). Passes when the log contains
`STATIC_BRIDGE_INTEGRATION_PASS`.

## verify-session-lifetime.ps1

```powershell
.\tools\start-dbglink.ps1 -Input "C:\path\to\target.exe"   # terminal 1: start MCP (default port 50301)
.\tools\verify-session-lifetime.ps1 -TargetPath "C:\path\to\target.exe"  # terminal 2
.\tools\verify-session-lifetime.ps1 -TargetPath "C:\t.exe" -Port 50317 -LogPath lifecycle.jsonl
```

Attaches to an already running MCP server: opens the target, takes three
snapshot/status pairs spaced 3 s apart (crossing the old watchdog polling
interval), switches debugger architecture, re-opens, and asserts the Ghidra
launcher PID is unchanged. Every request carries `Authorization: Bearer`
(resolved like the server does; fail closed without a token). Leaves the target paused for further inspection.
With `-LogPath`, every tool round-trip is appended as JSONL
(`timestamp`, `tool`, `response`).

## Tool catalog (single standard)

One catalog for every caller (lean/comprehensive merged).
`DBGLINK_TOOL_PROFILE` / `DBGLINK_PROFILE` / `DBGLINK_LEAN` are ignored.
Hidden tools stay callable by name, so `verify-session-lifetime.ps1` and the
`MapStaticFunctionToLive` step of `verify-e2e.ps1` keep working; the
`tools/list` advertisement assertion in `verify-e2e.ps1` expects the standard
catalog.

## Nightly E2E (CI)

`.github/workflows/nightly-e2e.yml` runs the three scripts above where `ci.yml`
cannot: on real `windows-latest` runners with a real x64dbg, a real Ghidra
distribution, and a staged `artifacts\current` bundle. `ci.yml` is untouched;
this workflow is additive. It never runs locally (no self-hosted runner);
the file is verified by reading only.

Triggers: `schedule` cron `0 2 * * *` (02:00 UTC daily) plus
`workflow_dispatch` with inputs `architecture` (`both` | `x64` | `x86`,
narrowing the matrix) and `e2e_port` (base MCP port).
Concurrency group `nightly-e2e` with `cancel-in-progress: false` serializes
runs so two nightlies never fight over ports or debugger installs.

The job is a `fail-fast: false` matrix over `x64` and `x86`: each architecture
is a separate runner, so a failing x64 run cannot skip the x86 check (and vice
versa). `verify-e2e.ps1` receives `-Architecture ${{ matrix.architecture }}`
and launch logs/artifacts are named per architecture.

Pipeline (per matrix job, `timeout-minutes: 360`):

1. Checkout, `setup-msbuild`, `setup-dotnet 10`, `setup-java` (Temurin 21).
2. Fixtures Release x64 (all three targets) + `AnalysisTarget` Win32 —
   the Win32 binary is needed because `verify-static.ps1` defaults to `both`.
3. `dotnet build DbgLink.Managed.slnf -c Release`, then `dotnet test`
   with a trx logger into `artifacts/test-results` (the `.trx` uploaded below).
4. Native `DbgLink.Native` x64 + Win32 (both are required by
   `tools/package.ps1`: `bin\x64\Release\DbgLink.dp64`,
   `bin\x86\Release\DbgLink.dp32`), plus the native JSON test harness,
   mirroring the `native` job in `ci.yml`.
5. Ghidra 12.1.3 download with `actions/cache` (same key as `ci.yml`),
   SHA-256-verified against the pinned `GHIDRA_SHA256` before unpack,
   extension build via `tools/run-gradle.ps1`, artifact
   `GhidraBridge-nightly-<architecture>`.
6. x64dbg rolling `snapshot` release via the GitHub API (first
   `snapshot_*.zip` asset, excluding `symbols-*`), verified against the
   asset's API-reported `sha256` digest before unpack (a rolling tag cannot be
   pinned; the verified hash is recorded to `x64dbg-snapshot.SHA256SUMS`),
   unpacked to `RUNNER_TEMP`;
   `x64dbg.exe`/`x32dbg.exe` located by recursive search and exported as
   `DBGLINK_X64DBG_PATH` / `DBGLINK_X32DBG_PATH`.
7. `dotnet publish` of server + launcher (same flags as `tools/build.cmd`)
   followed by `tools/package.ps1`, producing the `artifacts\current`
   bundle the verify scripts require.
8. `verify-e2e.ps1 -AnalysisFixtures -KeepInstalled -Architecture
   ${{ matrix.architecture }}` (150 min timeout). `-KeepInstalled` keeps
   launcher stdout/stderr under the deterministic `artifacts\.e2e-backup`
   path for upload; the runner VM is ephemeral so leaving plugins installed is
   harmless.
9. `verify-static.ps1 -KeepRunDir` (60 min timeout, x64 job only) so the
   `artifacts\verification\static-*` logs survive for upload. This covers
   both static fixture architectures once; it is not duplicated per matrix job.
10. Session lifetime (30 min timeout, x64 job only): the workflow starts the
    packaged launcher itself (`--input` x64 fixture, `--json`,
    `--shutdown-file`, both debuggers, `--ghidra-home`), waits up to 10 min
    for the `ready` JSON event, runs `verify-session-lifetime.ps1 -LogPath
    artifacts\verification\lifetime.jsonl`, then stops the server through
    the shutdown-file protocol.
11. `nightly-e2e-logs-${{ matrix.architecture }}` artifact (`if: always()`,
    `if-no-files-found: warn`):
    `artifacts/verification/` (`*-analysis.json`, `static-*` logs,
    `lifetime-server.*.log`, `lifetime.jsonl`), `artifacts/.e2e-backup/`
    (E2E launcher logs), `artifacts/test-results/*.trx`.

Ports are not hardcoded: workflow env `E2E_PORT` resolves as dispatch input
`e2e_port` → repo variable `E2E_PORT` → secret `E2E_PORT` → default `50301`,
and is passed as `-Port` to `verify-e2e.ps1` (each matrix job uses its own
runner, so the same base port is safe) and to the lifetime server /
`verify-session-lifetime.ps1`. `verify-static.ps1` takes no port (headless
Ghidra only).

Manual run: Actions → "Nightly E2E" → "Run workflow" (optionally pick
`architecture` or a free `e2e_port`); results are under the run's
`nightly-e2e-logs-x64` / `nightly-e2e-logs-x86` and
`GhidraBridge-nightly-*` artifacts.

## Coverage gate (managed tests)

Closes the historical gap "no collector, no numbers, no gate" for managed tests.
Two layers block silent loss of test insurance; re-validated locally on
2026-10-10 (dotnet 10.0.401):

| Layer | Mechanism | Threshold (calibration 2026-10-10) |
| :--- | :--- | :--- |
| Line coverage | `coverlet.collector` 6.0.4 + `tests/DbgLink.Tests/coverlet.runsettings` (`--settings` on `dotnet test`) | `Threshold` 72% Line/Total; last measured 74.7% (Server 80.0%, Launcher.Core 55.8%) |
| Test-count floor | `tools/check-test-floor.ps1` parses the `.trx` `<Counters>` | Full suite total >= 1600 (measured 1824); KEEP filter total >= 334 (measured 334/334), failed = 0 |

The runsettings includes only product assemblies
(`[DbgLink.Server]*`, `[DbgLink.Launcher.Core]*`) and excludes the test
assembly (`[DbgLink.Tests]*`, harnesses live there). Threshold 72 is
~2.7 pp below the measured 74.7%, per the coverage rule
(>2 pp drop = block, 0.5-2 pp = investigate): genuine regressions fail
the run, ordinary churn does not. Recalibrate `Threshold` if the product
surface changes materially (re-measure with the commands below and keep
~2-3 pp of headroom).

Reproduce locally (Windows, no msbuild needed for the gate itself):

```powershell
dotnet test tests/DbgLink.Tests/DbgLink.Tests.csproj -c Release `
  --settings tests/DbgLink.Tests/coverlet.runsettings `
  --logger "trx;LogFileName=full.trx" --results-directory tests/DbgLink.Tests/TestResults
powershell -NoProfile -ExecutionPolicy Bypass -File tools/check-test-floor.ps1 `
  -TrxPath tests/DbgLink.Tests/TestResults/full.trx -Floor 1600
dotnet test tests/DbgLink.Tests/DbgLink.Tests.csproj -c Release `
  --filter "FullyQualifiedName~SecurityFix|FullyQualifiedName~CommandInjection|FullyQualifiedName~NativeAddressParity|FullyQualifiedName~ServerEndToEnd|FullyQualifiedName~SessionFallback" `
  --logger "trx;LogFileName=keep.trx" --results-directory tests/DbgLink.Tests/TestResults
powershell -NoProfile -ExecutionPolicy Bypass -File tools/check-test-floor.ps1 `
  -TrxPath tests/DbgLink.Tests/TestResults/keep.trx -Floor 334
```

Known local-only deviation: without msbuild-built fixture binaries
(`HardenedStressTarget.exe`, `HostileStressTarget.exe` — CI builds them
in the `managed` job before `dotnet test`), ~9 fixture-dependent tests
fail locally with `FileNotFoundException` (2 `RealOpenedServerCommand`,
7 `Live*`), giving ~1815/1824 instead of 1824/1824. These are environment
artifacts, not product regressions: total stays 1824 (floor holds) and
the KEEP filter stays 334/334 green. In CI, where fixtures are built,
`failed` must be 0 everywhere.

CI wiring (for the integrator — `ci.yml` is NOT touched by this change):
see the copy-paste block in the coverage-gate commit message / PR notes;
it adds, after `Run managed tests`, a coverage run (`--settings` +
`--logger trx`), the two `check-test-floor.ps1` gates, the KEEP-filter
run, and a `coverage.cobertura.xml` artifact upload.
