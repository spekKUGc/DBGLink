# DBGLink

![DBGLink logo](docs/assets/dbglink-logo.svg)

Local MCP server (Model Context Protocol) for reverse engineering. Unifies **x64dbg / x32dbg** (dynamic analysis and debugger control) with **Ghidra** (static analysis and decompilation) into a single interface for AI assistants (Codex Desktop, Claude Desktop, and others).

- **Primary endpoint:** `http://127.0.0.1:50301/mcp`
- **Config:** `%LOCALAPPDATA%\DBGLink\mcp_config.json`
- **Auth:** `Authorization: Bearer <AuthToken>` on `/mcp` (by default) — see "Security".
- **Permissions:** all operations (mutations, annotations, debugger control) enabled by default.

---

## Project layout

- `src/mcp` — .NET 10 MCP/HTTP server (`ModelContextProtocol.AspNetCore`).
- `src/native` — C++ bridge plugin for x64dbg and x32dbg.
- `src/ghidra` — Java bridge for Ghidra.
- `src/launcher` — single launcher for automatic startup and process cleanup.
- `src/shared` — shared contracts: bridge envelope, config paths, named pipes, and protocol validation.
- `tools` — build (`build.cmd`), packaging (`package.ps1`), launch (`start-dbglink.*`, `start-dbglink-opencode.ps1`, `install-dbglink-codex.ps1`, `install-dbglink-opencode.ps1`), verification (`verify-e2e.ps1`, `verify-static.ps1`, `verify-session-lifetime.ps1`), and measurements on real binaries (`bench-corpus.ps1`); details in [docs/verification.md](docs/verification.md).
- `tests` — .NET unit tests (`DbgLink.Tests`), native JSON tests, and fixtures (`AnalysisTarget`).
- `docs` — documentation (`verification.md`, `fid-import.md`); `artifacts\current` — ready self-contained package after a build.

---

## Quickstart

### Requirements
- **OS:** Windows 10 / 11
- **Build tools:** Visual Studio with C++ Desktop, .NET 10 SDK
- **Debugger:** x64dbg / x32dbg
- **Decompiler:** Ghidra 12.1.3 + JDK 21

### 1. Build
```powershell
# Full build (managed + native x64/x86 + Ghidra extension + package)
.\tools\build.cmd --configuration Release --ghidra-home "C:\path\to\ghidra"

# Managed part only (fast dev loop, no Visual Studio required)
dotnet build DbgLink.Managed.slnf --configuration Release
```
`build.cmd` builds the managed code, the native x64/x86 plugins, the Ghidra extension, and assembles a ready self-contained package in `artifacts\current`. The `DbgLink.sln` solution contains vcxproj files and is built with MSBuild from Visual Studio; for `dotnet build` use the `DbgLink.Managed.slnf` filter. Every push is checked in GitHub Actions (`.github/workflows/ci.yml`): managed build with tests, native build with JSON tests, and Ghidra extension build.

> **Tip:** if the server is already running, use `--stage-package` — the output goes to `artifacts\pending` without locking live files.

### 2. Connect to Codex Desktop
Run once:
```powershell
.\tools\install-dbglink-codex.ps1
```
The script registers the `dbglink` server in `%USERPROFILE%\.codex\config.toml`. In Codex, check status with `/mcp`.
The script also wires authentication (the server requires a Bearer token, see "Security"):
it reads `AuthToken` from `mcp_config.json` (or `DBGLINK_BEARER_TOKEN`), sets
`bearer_token_env_var = "DBGLINK_BEARER_TOKEN"`, and stores the token in the user
environment. Without a token the script fails closed.
After running, **restart Codex Desktop** so it picks up the variable.

### 3. Run
```powershell
.\tools\start-dbglink.ps1
```
Or pass a target executable directly:
```powershell
.\tools\start-dbglink.ps1 -Input "C:\path\to\target.exe"
```
The built package can also run without an installed SDK: `artifacts\current\launcher\start-dbglink.cmd`.
For everyday pairing with OpenCode Desktop there is a single command — it brings the server
up (if not running), syncs the token, and restarts OpenCode Desktop so that
its backend connects to DbgLink:
```powershell
.\tools\start-dbglink-opencode.ps1
```
With `-ServerOnly` the script only brings up the server and syncs the token,
leaving the app alone; `-Input <path>` (and other launcher args) are forwarded to the server.
First run — with tool paths (checked once and stored in the
user variables `DBGLINK_X64DBG_PATH` / `DBGLINK_X32DBG_PATH` /
`DBGLINK_GHIDRA_HOME`; afterwards plain `.\tools\start-dbglink-opencode.ps1` is enough):
```powershell
.\tools\start-dbglink-opencode.ps1 `
  -X64DbgPath "C:\tools\x64dbg\release\x64\x64dbg.exe" `
  -X32DbgPath "C:\tools\x64dbg\release\x32\x32dbg.exe" `
  -GhidraHome "C:\tools\ghidra_12.1.3_PUBLIC"
```
Launcher flags (`--x64dbg`, `-Input <path>`, etc.) can still be passed directly.
For access via ChatGPT (Secure MCP Tunnel): `tools\start-dbglink-chatgpt.ps1` — brings up the launcher, waits for `ready`, and runs `tunnel-client.exe run` (requires `CONTROL_PLANE_API_KEY`, `-TunnelId tunnel_<32 hex>`, and a full `-TunnelClientPath` without reparse points).

> **N1 pipe-auth:** the launcher picks up the native bridge channel name and token from
> `%LOCALAPPDATA%\DBGLink\native-endpoint.json` and passes them to the server: the channel name via
> `--pipe-name`, the token via the `DBGLINK_NATIVE_PIPE_TOKEN` environment variable (the command
> line won't do — any local process can read it via `Win32_Process.CommandLine`).
> When running `DbgLink.Server.exe` manually without the launcher, pass `--pipe-token <token>`
> yourself — without it the server fails closed before the first channel call,
> and the bridge without the correct token answers `unauthorized` and executes nothing.

### Security

**Authentication (H-1).** By default the server requires `Authorization: Bearer <AuthToken>`
on `/mcp` (`RequireAuthToken=true`; on `/metrics` — always). Clients must send the token:
without it or with a wrong one — rejection (fail closed), no anonymous calls. The token is stored in
`%LOCALAPPDATA%\DBGLink\mcp_config.json` (ACL for the current user only;
overridable via `DBGLINK_BEARER_TOKEN`, path via `DBGLINK_CONFIG_PATH`):
- **Codex:** `install-dbglink-codex.ps1` reads the token and writes
  `bearer_token_env_var = "DBGLINK_BEARER_TOKEN"` into `config.toml` (the secret is not
  duplicated into the file), then restart Codex Desktop.
- **opencode:** `opencode.json` already contains
  `headers: { "Authorization": "Bearer {env:DBGLINK_BEARER_TOKEN}" }` — run
  `.\tools\install-dbglink-opencode.ps1` once (it stores the token in the user
  variable and checks it against the live server), then fully restart
  OpenCode Desktop. Repeat on token rotation. For everyday runs
  use `.\tools\start-dbglink-opencode.ps1` — it does all of this in one command.
- **Claude Desktop:** in `%APPDATA%\Claude\claude_desktop_config.json`:
  ```json
  { "mcpServers": { "dbglink": {
    "url": "http://127.0.0.1:50301/mcp",
    "headers": { "Authorization": "Bearer <AuthToken from mcp_config.json>" } } } }
  ```
  then restart the app.
- **Probes:** `verify-e2e.ps1` / `verify-session-lifetime.ps1` read the token the same way
  as the server and fail closed without it.
- **Rotation:** delete `mcp_config.json` (or set a new `DBGLINK_BEARER_TOKEN`),
  restart the server (the token is regenerated), then re-run
  `install-dbglink-codex.ps1` / update the other clients' environments.

**Debugger and Ghidra discovery (S-1).** Auto-discovery uses explicit paths only
(flags `--x64dbg`/`--x32dbg`/`--ghidra-home`, `DBGLINK_*` variables, PATH),
the staged package, and Program Files. Downloads, Desktop, CWD, and `%USERPROFILE%` are never
scanned and anything found there is never executed — without an explicit path startup fails
closed with an error.

**Tunnel (S-2).** `start-dbglink-chatgpt.ps1` requires a full `-TunnelClientPath`
without reparse points (PATH lookup disabled: the client inherits `CONTROL_PLANE_API_KEY`)
and resolves `powershell.exe` via `$PSHOME`/System32.

**Supply chain (C-1 / B-1 / B-2).** CI verifies the SHA-256 of Ghidra, jtokkit, and the
x64dbg snapshot before unpack/execution (for the rolling snapshot — the digest from the
GitHub API response; pinning is impossible by design); third-party GitHub Actions are pinned to
commit SHA; NuGet audit is on (only GHSA-73j8-2gch-69rq suppressed, not applicable
on net10 — see the comment in csproj); restore writes `packages.lock.json`
(native vcxproj and Gradle are outside NuGet, no lock files for them by design);
`package.ps1` puts `SHA256SUMS` into the package, `--install` verifies it before copying.
`-ExecutionPolicy Bypass` is used only to launch own scripts by literal path
(see the comment in `start-dbglink-chatgpt.ps1`):
trees from zips carry Mark-of-the-Web, which `RemoteSigned` would refuse.

---

## Main MCP tools

### 1. Session and target management
| Tool | Description |
| :--- | :--- |
| `OpenDebugTarget` | Open a binary in the debugger with auto-selected bitness (x86/x64). |
| `OpenGhidraFile` | Open a file in Ghidra. `waitMs` (default 30s) long-polls until ready: if import fits the budget it returns a ready session (`opened`+`analysisId`, registered immediately — 1 call); on a slow import it returns `operationId`+`pending` for `GetGhidraOpenStatus`. |
| `GetGhidraOpenStatus` | Import status; `waitMs` up to 30s — long-poll, `cancel=true` — cancel the operation. Registers the session on completion (only needed for imports that exceed `OpenGhidraFile.waitMs`). |
| `ListAnalysisSessions` / `CloseAnalysisSession` | List active analysis sessions and close them, freeing memory. |
| `ReopenAnalysisSession` | Reopen a restored session (`restored:true`) in one call: returns a NEW `analysisId`, the old one stays invalid. |
| `GetServerStatus` | Check Ghidra/debugger readiness and session availability. |
| `Checkpoint` | Save (`action=create`) and restore (`action=restore`) LLM investigation context (keyed by SHA-256; `sha256` for create is optional — resolved by the server when `analysisId` is known). |

### 2. Dynamic analysis (x64dbg / x32dbg)
> Most mutating commands require the debugged process to be paused.

| Tool | Description |
| :--- | :--- |
| `GetAnalysisSnapshot` | State slice: registers, current CIP, threads, modules, consistency flags. |
| `TraceUntil` | Step (`count`, prefer 1-10) or trace until a condition (mnemonic e.g. call/ret, address, or maxSteps) returning a state slice in 1 round-trip. |
| `BatchDebuggerOperations` | Batch up to 16 debugger operations in one call (memory, breakpoints, registers, threads, backtrace, memory map, pattern search). Expressions are not part of the batch — use `EvaluateExpressions` (up to 16 per call). |
| `SetBreakpoint` / `ClearBreakpoint` | Set/remove soft, HW, and memory breakpoints. `SetBreakpoint` takes a live debugger address or a `module`+`rva` pair (raw Ghidra static addresses don't work: live address = module base + RVA). List via `BatchDebuggerOperations`. |
| `ControlDebuggerExecution` | Resume (`action=run`) and suspend (`action=pause`) the process. |
| `SetRegister` | Change register values (`rax..r15`, `rip`, `eflags`, `eax..edi`, etc.). |
| `WriteMemory` | Write bytes into the debugged process memory (up to 4096 bytes per call). |
| `ReadMemAtAddress` / `EvaluateExpressions` | Read memory (up to 4096 bytes, or `ranges`: up to 8 chunks, ≤16KB total per call) and evaluate up to 16 debugger expressions (`[rsp+8]`, `peb()`, `cip`) in one call. |
| `ListThreads` / `GetBacktrace` | Thread list and call stack (backtrace). Active thread switching — via the `SwitchThread` op inside `BatchDebuggerOperations`. |
| `InspectAddressStructure` | Address slice in 1 call: bytes, pointers, printable derefs, and xrefs (thin wrapper, batchable). |
| `GetMemoryMap` | Target process memory layout and page protections (read-only). |
| `SampleCallStacks` | Stack sampling: unique module+RVA frames with hit counts (top-N). Caps: `durationMs` 0–15000, `maxSamples` 1–100. Pause the target first or pass `autoPause:true` (pauses for the sampling window and restores prior state). |
| `ProbeFunction` | Live function call in 1 call: `runAfter=true` (default) performs the call, waits for the pause, and reads the return; `runAfter=false` only stages (no verdict). `probes[1..8]` proves several hypotheses per call (address or name — the server resolves mapping, shared `waitMs` budget): a failing probe stops the batch, the rest are marked `skipped`. |
| `ListLiveFunctions` | Module functions from the debugger's live DB (`DbgFunctionGet` + export fallback) in 1 call. |

### 3. Static analysis (Ghidra)
| Tool | Description |
| :--- | :--- |
| `GetModuleMap` | Map-first entry: identity, sections and entry point, imports by `refCount`, exports, IOC strings, and a function sample in 1 bounded call — no decompilation. Continue with `InspectFunction`/`AnalyzeFunctions` and `includeDecomp:false`; decompile only what you actually need. |
| `InspectFunction` | Decompilation of one function, cross-references, signature, and locals. Flags `includeStrings`/`includeConstants` add strings from body data-refs and significant scalar operands. To tie statics to live state, prefer `GetInvestigationBrief`. |
| `AnalyzeFunctions` | Digest of up to 8 functions per call: identity, decompilation, brief callers/callees, strings, and constants. `includeDecomp:false` drops the C and skips the decompiler (same digest without decompilation). `functions` (array of 1-8) XOR `start`+`maxFunctions` (ordered continuation); unresolvable selectors — indexed `not_found`; the shared budget trims records. |
| `GetAnalysisQueue` | Bottom-up function queue (leaves→root): `limit` up to 64, EXTERNAL skipped, continuation via `limit`; skips already-annotated functions (`excludeAnnotated`, via journal) and returns `doneCount`/`remainingCount`. `withDigests` embeds digests (up to 16 lines, `digestLimit` up to 24, batches of 8). |
| `CallGraph` | Read-only call graph: nodes + aggregated edges (call-count), caps 256 nodes / 1024 edges, external calls dropped. |
| `GetInvestigationBrief` | The tie-in: static function + live debugger state + verified address mapping in 1 call. |
| `DecompileModule` | Address-ordered module decompilation slice (bounded sample, continue via `start=nextFunction`; single function — via `InspectFunction`). |
| `Triage` | Import triage (`kind=imports`, risk-ranked, instead of full `ListSymbols`) or IOC strings (`kind=strings`, ~95% token savings vs raw dump); `kind=both` — both at once. |
| `MapStaticFunctionToLive` | Map one Ghidra function onto the debugger's live module by identity+RVA (hidden from the list, call directly; for the tie-in prefer `GetInvestigationBrief`). |
| `Xrefs` | Static references (`direction=to|from`) to/from an address/function; if Ghidra's xref table is empty, a bounded scan runs with an honest `fallbackScan` / `scanComplete` report. |
| `ListSymbols` | Import/export table view (`kind=imports|exports`). |
| `ListFunctions` | Function list with addresses, sizes, and complexity (`instructionCount`/`branchCount` for routing) without decompilation. |
| `ReadStaticBytes` | Raw image bytes from the Ghidra database (up to 4096 bytes per call; page via `address`+`length`). |
| `BatchStaticQueries` | Batch of up to 16 static read-only queries per call (`DumpStrings`, `ReadStaticBytes`, `Xrefs`, `ListSymbols`, `ListFunctions`, `InspectFunction`, `AnalyzeFunctions`, `DecompileModule`). |
| `BatchAnnotate` | Batch of up to 16 rename/comment/vartype/define ops per call: one transaction, per-op errors by index, journal per successful op. |
| `SubmitAnnotations` | Apply an annotation batch (same shape as `BatchAnnotate`) and return durable progress (`progress.doneCount`); applied ops are journaled, so `GetAnalysisQueue` stops offering those functions. |

---

## Demo: see → prove → record in 4 calls

Full reverse loop on the bundled fixture (`tests/fixtures/AnalysisTarget.cpp`,
3 functions) — text of a real session, no staging:

```
# 1. Map the binary: sections, imports, strings (1 call, no decompilation)
GetModuleMap
# 2. Digest + decompile only what matters (1 call, up to 8 functions)
AnalyzeFunctions(functions=[...], includeDecomp:true)
# 3. Prove hypotheses live in x64dbg (1 call, up to 8 probes)
ProbeFunction(probes=[...])  →  matched=true
# 4. Record names/comments durably (1 call, up to 16 ops)
BatchAnnotate(operations=[...])  →  committed=6/6
```

Measured mirrors (`docs/reverse-speedup/benchmarks/semi-auto-*.json`):
manual baseline **10 calls / 2293 tok** → recipe **4 calls / 2370 tok (−60% turns)**.
A blind re-check by an independent model found the same shape on its own
(3 batched calls), so the savings come from the workflow, not a scripted path.

---

## Testing and verification

Full script matrix — in [docs/verification.md](docs/verification.md).

```powershell
# Full E2E test (launch -> MCP -> native -> Ghidra -> stop)
.\tools\verify-e2e.ps1

# E2E test with analysis verification on reference fixtures
.\tools\verify-e2e.ps1 -AnalysisFixtures

# Static bridge only (no debugger launch)
.\tools\verify-static.ps1

# Session lifetime check: debugger arch switch without losing Ghidra
# (runs against launcher-raised MCP on $Port)
.\tools\verify-session-lifetime.ps1 -TargetPath "C:\path\to\target.exe"

# .NET unit tests
dotnet test tests\DbgLink.Tests\DbgLink.Tests.csproj --configuration Release

# Native JSON tests (after building DbgLink.Native.Tests.vcxproj)
bin\native-tests\x64\Release\DbgLink.Native.Json.Tests.exe
```

### Standard tool catalog

One catalog for everyone (`lean`/`comprehensive` merged; `DBGLINK_TOOL_PROFILE`/`DBGLINK_PROFILE`/`DBGLINK_LEAN` ignored). Remaining tools stay callable by name but are not listed. Token counting everywhere is real cl100k_base BPE with no heuristics: .NET tests and prod telemetry (`tests/DbgLink.Tests/TokenCounter.cs`, `src/mcp/DbgLink.Server/TokenMeter.cs`, `Microsoft.ML.Tokenizers` package) and the Java bench `tests/ghidra/TokenEfficiencyBenchmark.java` (jtokkit, same cl100k_base); call sides without text score 0 tokens, byte-based estimation is no longer used.

---

## Troubleshooting

- **Process conflicts / server not responding:**
  Kill stuck processes (`DbgLink.Server.exe`, `x64dbg.exe`, `x32dbg.exe`), close the client (Codex/Claude). Start the server **first** (`start-dbglink.ps1`), and only after the `ready` event open the client.
- **Ghidra cache cleanup:**
  To free space or reset projects, delete `%LOCALAPPDATA%\DBGLink\GhidraCache` and `%LOCALAPPDATA%\DBGLink\GhidraProjects`.
- **Very large binary exceeds analysis time:**
  Ghidra gets 10 minutes by default; on overrun the session comes up without auto-analysis (imports/sections/strings and live debugging still available). Set `DBGLINK_GHIDRA_IMPORT_TIMEOUT_MS` (1–15 minutes) for a longer full analysis. Total startup is watchdog-bounded (import budget + 2 minutes) and ends with `startup_timeout` instead of hanging.
- **Need a fast triage start:**
  Set `DBGLINK_GHIDRA_FAST=1` before launch. The initial import skips auto-analysis: imports, sections, strings, and live debugging are available immediately; on real binaries startup dropped from 92–250s to 27–34s.
- **Port busy (`verify-e2e.ps1` reports it immediately):**
  Pass a free `-Port`; each arch check takes its own port (`-Port`, `-Port`+1, ...).
- **Verify scripts need a built package:**
  `verify-e2e.ps1`/`verify-static.ps1` work on `artifacts\current` — run `tools\build.cmd` first. `verify-static.ps1` says exactly what's missing: Ghidra path, `GhidraBridge.zip` in the package, or Java (JDK 21+ / `JAVA_HOME` needed).
