# FID databases at import (DBGLINK_FIDB)

`DBGLINK_FIDB` points the headless Ghidra import at Function ID databases
(`.fidb` packed, `.fidbf` raw): one file, one directory, or entries separated
with `;`. Directories are expanded to the `.fidb`/`.fidbf` files inside.

```powershell
$env:DBGLINK_FIDB = "C:\fid\win32.fidb;C:\fid\extra"
```

When set, the import appends `-preScript ApplyFidb.java <spec>`; the
`ApplyFidb.java` script (shipped in the extension `ghidra_scripts/`) attaches
the databases via `FidFileManager.addUserFidFile` before analysis, so the
built-in "Function ID" analyzer applies them. Missing or unsafe entries are
ignored with a warning; the import proceeds as before.

Limits:

- Fast imports (`-noanalysis`) skip analysis, so attached FID data is not
  applied to names there; the project-cache key includes the FID spec, so
  cached projects never mix FID/non-FID results.
- Paths with spaces are supported only via `;` separation (headless splits
  script arguments on spaces; the script rejoins them).

## Provenance report (what the model sees)

FID application is silent no more. When user databases are attached at
import, every program summary carries `fidApplied: true` plus the
`fidDatabases` basenames; without FID both keys stay absent (no extra bytes).
Each digest/queue function row carries `nameSource`: `ANALYSIS`/`IMPORTED`
(known origin — FID database, PDB/DWARF, imports — skip first), `DEFAULT`
(auto-generated — still needs review), `USER_DEFINED` (already annotated —
done), `unknown` (unreadable symbol). `AnalyzeFunctions` responses add a
`libraryMatched` count of ANALYSIS/IMPORTED rows, so triage can start with
the unknown remainder. Triage rule of thumb: `DEFAULT` first, `ANALYSIS`
last, `USER_DEFINED` never.
