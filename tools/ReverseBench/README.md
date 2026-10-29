# ReverseBench

One DbgLink MCP tool call at a time over the real wire (`POST $DBGLINK_URL`,
default `http://127.0.0.1:50301/mcp`), bearer token from `DBGLINK_BEARER_TOKEN`
else `%LOCALAPPDATA%\DBGLink\mcp_config.json` (`AuthToken`). Token never printed.

## Usage

```powershell
.\tools\reverse-bench.ps1 -Tool GetAnalysisSnapshot -ArgsJson '{}'
.\tools\reverse-bench.ps1 -Stats
.\tools\reverse-bench.ps1 -Reset
```

PowerShell strips double quotes, so `-ArgsJson '{"a":1}'` usually arrives
broken. For anything non-trivial put the JSON in a file (recommended):

```powershell
'{"address":"0x140003000"}' | Set-Content $env:TEMP\args.json -Encoding utf8
.\tools\reverse-bench.ps1 -Tool InspectAddressStructure -ArgsFile $env:TEMP\args.json
```

On invalid JSON the harness prints one line:
`args JSON invalid: <reason>. Tip: put the JSON in a file and use -ArgsFile <path>.`

`call` prints the tool's text result to stdout; exit 0 ok, 1 tool/JSON-RPC error
(error text still printed), 2 usage/connection failure.

## Scoring

Every call appends one JSON line to `artifacts/reverse-bench/calls.jsonl`:
`ts, tool, argChars, respChars, respTokens, elapsedMs, isError, httpStatus`.
`respTokens` is real cl100k_base BPE (`Microsoft.ML.Tokenizers`, same as tests).
`stats` prints totals: `calls errors chars tokens ms avgMs`. Score = fewest
calls + tokens to reach the answer; `reset` starts a new session.
