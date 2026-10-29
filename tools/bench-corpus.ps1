[CmdletBinding()]
param(
    [ValidateSet("x64", "x86", "both")]
    [string]$Architecture = "both",
    [string[]]$Targets,
    [string]$OutputDirectory = "artifacts\corpus",
    [int]$Port = 50417,
    [int]$TimeoutSeconds = 180,
    [string]$X64DbgPath,
    [string]$X32DbgPath,
    [string]$GhidraHome,
    [switch]$NoDecompile,
    [switch]$Deep
)

# Real-binary corpus runner. Starts one launcher per target so Ghidra is
# prepared for that exact binary, then records startup, per-tool latency,
# response size, and tool errors as JSONL plus a summary JSON.
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http | Out-Null
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$packageRoot = Join-Path $root "artifacts\current"
$launcher = Join-Path $packageRoot "launcher\DbgLink.Launcher.Cli.exe"
$protocol = "2025-06-18"
$stamp = [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss")
$runDirectory = Join-Path $root $OutputDirectory
$runDirectory = Join-Path $runDirectory $stamp
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
$jsonlPath = Join-Path $runDirectory "calls.jsonl"
$probePath = Join-Path $runDirectory "probes.jsonl"
$summaryPath = Join-Path $runDirectory "summary.json"

function Assert-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Resolve-Debugger {
    param([string]$Specified, [string]$Name, [string[]]$Candidates, [string]$EnvironmentName)
    foreach ($explicit in @($Specified, [Environment]::GetEnvironmentVariable($EnvironmentName)) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        $full = [IO.Path]::GetFullPath($explicit)
        Assert-Condition (Test-Path -LiteralPath $full -PathType Leaf) "Debugger was not found: $full"
        return $full
    }
    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "$Name was not found. Pass -X64DbgPath/-X32DbgPath or set $EnvironmentName."
}

function Resolve-Ghidra {
    param([string]$Specified)
    foreach ($candidate in @($Specified, $env:DBGLINK_GHIDRA_HOME, $env:GHIDRA_INSTALL_DIR) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        if (Test-Path -LiteralPath (Join-Path $candidate "ghidraRun.bat") -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "Ghidra was not found. Pass -GhidraHome or set DBGLINK_GHIDRA_HOME/GHIDRA_INSTALL_DIR."
}

function Get-BearerToken {
    $value = [Environment]::GetEnvironmentVariable("DBGLINK_BEARER_TOKEN")
    if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    $config = if (-not [string]::IsNullOrWhiteSpace($env:DBGLINK_CONFIG_PATH)) {
        $env:DBGLINK_CONFIG_PATH
    } else {
        Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) "DBGLink\mcp_config.json"
    }
    Assert-Condition (Test-Path -LiteralPath $config -PathType Leaf) "Bearer config was not found: $config"
    $token = (Get-Content -LiteralPath $config -Raw | ConvertFrom-Json).AuthToken
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($token)) "Bearer config has no AuthToken: $config"
    return $token
}

function Get-PeMachine {
    param([string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        $stream.Position = $peOffset + 4
        return $reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Get-TargetArchitecture {
    param([string]$Path)
    if ((Get-PeMachine $Path) -eq 0x8664) { return "x64" }
    return "x86"
}

function Get-ProcessTreeIds {
    param([int]$RootProcessId)
    $processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $ids = [System.Collections.Generic.HashSet[int]]::new()
    [void]$ids.Add($RootProcessId)
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($process in $processes) {
            if ($ids.Contains([int]$process.ParentProcessId) -and $ids.Add([int]$process.ProcessId)) {
                $changed = $true
            }
        }
    }
    return @($ids)
}

function Merge-ProcessIds {
    param([int[]]$Left, [int[]]$Right)
    $set = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($id in @($Left) + @($Right)) { [void]$set.Add([int]$id) }
    return @($set)
}

function Read-TextShared {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
    try {
        $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $reader = [IO.StreamReader]::new($stream)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose(); $stream.Dispose() }
    }
    catch { return "" }
}

function ConvertTo-Arg {
    param([string]$Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-McpRequest {
    param($HttpClient, [string]$Uri, $Payload)
    $json = $Payload | ConvertTo-Json -Compress -Depth 16
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Uri)
    $content = [System.Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, "application/json")
    [void]$request.Headers.Accept.ParseAdd("application/json, text/event-stream")
    [void]$request.Headers.Add("MCP-Protocol-Version", $protocol)
    [void]$request.Headers.Add("Authorization", "Bearer $(Get-BearerToken)")
    $request.Content = $content
    try {
        $response = $HttpClient.SendAsync($request).GetAwaiter().GetResult()
        try {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($response.Content.Headers.ContentType.MediaType -eq "text/event-stream") {
                $messages = @($body -split '\r?\n' | Where-Object { $_.StartsWith('data: ') } |
                    ForEach-Object { $_.Substring(6) })
                $reply = @($messages | Where-Object {
                    $event = $_ | ConvertFrom-Json
                    $null -ne $event.id -and $event.id -eq $Payload.id
                })
                Assert-Condition ($reply.Count -eq 1) "Expected one MCP reply in the SSE response."
                $body = $reply[0]
            }
            return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Body = $body }
        }
        finally { $response.Dispose() }
    }
    finally { $content.Dispose(); $request.Dispose() }
}

function Invoke-Tool {
    param($HttpClient, [string]$Uri, [ref]$Id, [string]$Name, $Arguments)
    $Id.Value++
    $callId = $Id.Value
    $payload = [ordered]@{
        jsonrpc = "2.0"; id = $callId; method = "tools/call"
        params = [ordered]@{ name = $Name; arguments = $Arguments }
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $ok = $false
    $status = 0
    $errorText = ""
    $text = ""
    $document = $null
    try {
        $response = Invoke-McpRequest $HttpClient $Uri $payload
        $status = $response.StatusCode
        $document = $response.Body | ConvertFrom-Json
        if ($null -eq $document.result) { throw "no MCP result" }
        if ($document.result.isError -eq $true) {
            $text = [string]$document.result.content[0].text
            $errorText = $text
        } else {
            $text = [string]$document.result.content[0].text
            $ok = $true
        }
    }
    catch {
        $errorText = $_.Exception.Message
    }
    finally { $watch.Stop() }

    $record = [ordered]@{
        timestamp = [DateTimeOffset]::UtcNow.ToString("o")
        tool = $Name
        status = $status
        ok = $ok
        durationMs = [Math]::Round($watch.Elapsed.TotalMilliseconds, 1)
        responseChars = $text.Length
        error = if ($errorText.Length -gt 1200) { $errorText.Substring(0, 1200) } else { $errorText }
    }
    if ($script:currentTarget) { $record.target = $script:currentTarget }
    $record | ConvertTo-Json -Compress -Depth 6 | Add-Content -LiteralPath $jsonlPath -Encoding utf8
    return [pscustomobject]@{
        Ok = $ok; Status = $status; Text = $text; Document = $document
        DurationMs = $record.durationMs; Chars = $text.Length; Error = $errorText
    }
}

function Write-Probe {
    param([string]$Name, $Result, $Details)
    $record = [ordered]@{
        timestamp = [DateTimeOffset]::UtcNow.ToString("o")
        target = $script:currentTarget
        probe = $Name
        ok = $Result.Ok
        durationMs = $Result.DurationMs
        responseChars = $Result.Chars
        details = $Details
    }
    $record | ConvertTo-Json -Compress -Depth 10 | Add-Content -LiteralPath $probePath -Encoding utf8
}

function Get-JsonText {
    param($Result)
    if (-not $Result.Ok -or [string]::IsNullOrWhiteSpace($Result.Text)) { return $null }
    try { return $Result.Text | ConvertFrom-Json } catch { return $null }
}

function Stop-Launcher {
    param($Process, [string]$ShutdownPath, [int[]]$OwnedIds)
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            [IO.File]::WriteAllText($ShutdownPath, "stop`n", [Text.Encoding]::UTF8)
            if (-not $Process.WaitForExit(30000)) {
                try { $Process.Kill($true) } catch { try { $Process.Kill() } catch { } }
            }
        }
    }
    catch { }
    finally {
        foreach ($id in $OwnedIds) {
            $child = Get-Process -Id $id -ErrorAction SilentlyContinue
            if ($null -ne $child -and -not $child.HasExited) {
                try { $child.Kill() } catch { }
            }
        }
        try { $Process.Dispose() } catch { }
    }
}

function Invoke-Target {
    param([string]$Target, [string]$ExpectedArch, [string]$AltX64, [string]$AltX86)

    $targetName = Split-Path -Leaf $Target
    $safeName = "$ExpectedArch-$([IO.Path]::GetFileNameWithoutExtension($Target))"
    $stdout = Join-Path $runDirectory "$safeName.stdout.log"
    $stderr = Join-Path $runDirectory "$safeName.stderr.log"
    $shutdownPath = Join-Path $runDirectory "$safeName.shutdown"
    if (Test-Path -LiteralPath $shutdownPath) { Remove-Item -LiteralPath $shutdownPath -Force }

    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add("--input"); [void]$arguments.Add($Target)
    [void]$arguments.Add("--port"); [void]$arguments.Add("$Port")
    [void]$arguments.Add("--json")
    [void]$arguments.Add("--shutdown-file"); [void]$arguments.Add($shutdownPath)
    [void]$arguments.Add("--x64dbg"); [void]$arguments.Add($AltX64)
    [void]$arguments.Add("--x32dbg"); [void]$arguments.Add($AltX86)
    [void]$arguments.Add("--ghidra-home"); [void]$arguments.Add($GhidraHome)
    [void]$arguments.Add("--bundle-root"); [void]$arguments.Add($packageRoot)

    $process = $null
    $owned = @()
    $http = $null
    $startupMs = 0
    $result = [ordered]@{
        target = $Target; architecture = $ExpectedArch; startupMs = 0
        totalMs = 0; calls = 0; errors = 0; errorTools = @()
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        Assert-Condition (Test-Path -LiteralPath $Target -PathType Leaf) "Target was not found: $Target"
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        try { $listener.Start() } finally { $listener.Stop() }
        $http = [System.Net.Http.HttpClient]::new()
        $http.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $commandLine = [string]::Join(" ", @($arguments | ForEach-Object { ConvertTo-Arg $_ }))
        $process = Start-Process -FilePath $launcher -ArgumentList $commandLine `
            -WorkingDirectory (Split-Path -Parent $launcher) `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
            -WindowStyle Hidden -PassThru
        $owned = Get-ProcessTreeIds $process.Id
        $deadline = [DateTime]::UtcNow.AddMinutes(15)
        $readyLine = $null
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($process.HasExited) {
                throw "$targetName launcher exited before ready (code $($process.ExitCode)). $(Read-TextShared $stdout) $(Read-TextShared $stderr)"
            }
            $readyLine = (Read-TextShared $stdout) -split "`r?`n" |
                Where-Object { $_ -match '"type"\s*:\s*"ready"' } | Select-Object -Last 1
            if ($null -ne $readyLine) { break }
            Start-Sleep -Milliseconds 500
        }
        Assert-Condition ($null -ne $readyLine) "$targetName did not become ready. $(Read-TextShared $stdout) $(Read-TextShared $stderr)"
        $ready = $readyLine | ConvertFrom-Json
        $startupMs = [int]$ready.data.startupMs
        $result.startupMs = $startupMs
        $owned = Merge-ProcessIds $owned (Get-ProcessTreeIds $process.Id)

        $uri = "http://127.0.0.1:$Port/mcp"
        $id = 0
        $init = Invoke-McpRequest $http $uri ([ordered]@{
                jsonrpc = "2.0"; id = 1; method = "initialize"
                params = [ordered]@{
                    protocolVersion = $protocol; capabilities = [ordered]@{}
                    clientInfo = [ordered]@{ name = "DBGLink.Corpus"; version = "1" }
                }
            })
        Assert-Condition ($init.StatusCode -eq 200 -and ($init.Body | ConvertFrom-Json).result) "initialize failed: $($init.Body)"
        $null = $http.PostAsync($uri, [System.Net.Http.StringContent]::new(
                '{"jsonrpc":"2.0","method":"notifications/initialized"}', [Text.Encoding]::UTF8, "application/json")).GetAwaiter().GetResult()

        $calls = @(
            @{ Name = "GetServerStatus"; Args = [ordered]@{} },
            @{ Name = "GetAnalysisSnapshot"; Args = [ordered]@{ maxChars = 12000 } },
            @{ Name = "GetModuleMap"; Args = [ordered]@{ maxSections = 12; maxSymbols = 12; maxFunctions = 8; maxStrings = 8 } },
            @{ Name = "ListFunctions"; Args = [ordered]@{ maxItems = 32; compact = $true } },
            @{ Name = "Triage"; Args = [ordered]@{ kind = "strings"; section = ".rdata"; maxItems = 32; maxPages = 1; compact = $true } },
            @{ Name = "GetAnalysisQueue"; Args = [ordered]@{ limit = 8 } },
            @{ Name = "GetAnalysisQueue"; Args = [ordered]@{ limit = 8 } }
        )
        $mapResult = $null
        foreach ($call in $calls) {
            $callResult = Invoke-Tool $http $uri ([ref]$id) $call.Name $call.Args
            if ($call.Name -eq "GetModuleMap") { $mapResult = $callResult }
            if ($call.Name -eq "GetAnalysisQueue") { $queueResult = $callResult }
        }

        $selectors = @()
        $map = Get-JsonText $mapResult
        if ($null -ne $map -and $null -ne $map.functions -and $null -ne $map.functions.sample) {
            $selectors = @($map.functions.sample | Select-Object -First 4 | ForEach-Object { [string]$_.entry })
            $selectors = @($selectors | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
        if ($selectors.Count -gt 0) {
            $null = Invoke-Tool $http $uri ([ref]$id) "AnalyzeFunctions" ([ordered]@{
                    functions = $selectors; maxChars = 12000; maxItems = 8
                })
            $defaultSelectors = @($selectors | Select-Object -First 4)
            $analyzeDefault = Invoke-Tool $http $uri ([ref]$id) "AnalyzeFunctions" ([ordered]@{
                    functions = $defaultSelectors
                })
            Write-Probe "analyze-default" $analyzeDefault ([ordered]@{
                    functions = $defaultSelectors.Count
                })
            $null = Invoke-Tool $http $uri ([ref]$id) "GetInvestigationBrief" ([ordered]@{
                    functions = $selectors; maxChars = 12000; maxItems = 8
                    includeLive = $true; includeDecomp = $false
                })
            $null = Invoke-Tool $http $uri ([ref]$id) "CallGraph" ([ordered]@{
                    function = $selectors[0]; depth = 1; direction = "both"
                    maxNodes = 48; maxEdges = 128
                })
            $null = Invoke-Tool $http $uri ([ref]$id) "MapStaticFunctionToLive" ([ordered]@{
                    function = $selectors[0]
                })
        }
        if ($Deep -and $selectors.Count -gt 0) {
            $briefDefault = Invoke-Tool $http $uri ([ref]$id) "GetInvestigationBrief" ([ordered]@{
                    functions = $selectors; maxItems = 16
                })
            $brief = Get-JsonText $briefDefault
            if ($env:DBGLINK_DUMP_BRIEF) {
                ($brief.sections | ConvertTo-Json -Depth 32) | Set-Content -LiteralPath $env:DBGLINK_DUMP_BRIEF -Encoding utf8
            }
            Write-Probe "brief-default" $briefDefault ([ordered]@{
                    liveReady = $brief.summary.liveReady
                    staticReady = $brief.summary.staticReady
                    mappingSource = $brief.mappingSource
                    sectionNames = @($brief.sections.PSObject.Properties.Name)
                    bridgeCalls = $brief.bridgeCalls
                    sectionChars = [ordered]@{
                        static = ($brief.sections.static | ConvertTo-Json -Compress -Depth 24).Length
                        mapping = ($brief.sections.mapping | ConvertTo-Json -Compress -Depth 24).Length
                        live = ($brief.sections.live | ConvertTo-Json -Compress -Depth 24).Length
                    }
                    usedChars = $brief.usedChars
                    maxChars = $brief.maxChars
                    textLength = $briefDefault.Chars
                })

            $briefNoConstants = Invoke-Tool $http $uri ([ref]$id) "GetInvestigationBrief" ([ordered]@{
                    functions = $selectors; maxItems = 16; includeConstants = $false
                })
            $briefNc = Get-JsonText $briefNoConstants
            Write-Probe "brief-no-constants" $briefNoConstants ([ordered]@{
                    mappingSource = $briefNc.mappingSource
                    bridgeCalls = $briefNc.bridgeCalls
                    sectionNames = @($briefNc.sections.PSObject.Properties.Name)
                    usedChars = $briefNc.usedChars
                    textLength = $briefNoConstants.Chars
                })

            $briefWide = Invoke-Tool $http $uri ([ref]$id) "GetInvestigationBrief" ([ordered]@{
                    functions = $selectors; maxItems = 16; maxChars = 24000
                })
            $briefW = Get-JsonText $briefWide
            Write-Probe "brief-wide" $briefWide ([ordered]@{
                    mappingSource = $briefW.mappingSource
                    bridgeCalls = $briefW.bridgeCalls
                    sectionNames = @($briefW.sections.PSObject.Properties.Name)
                    sectionChars = [ordered]@{
                        static = ($briefW.sections.static | ConvertTo-Json -Compress -Depth 24).Length
                        mapping = ($briefW.sections.mapping | ConvertTo-Json -Compress -Depth 24).Length
                        live = ($briefW.sections.live | ConvertTo-Json -Compress -Depth 24).Length
                    }
                    usedChars = $briefW.usedChars
                    textLength = $briefWide.Chars
                })

            $batchStatic = Invoke-Tool $http $uri ([ref]$id) "BatchStaticQueries" ([ordered]@{
                    requests = @(
                        [ordered]@{ method = "ListFunctions"; arguments = [ordered]@{ maxItems = 16 } },
                        [ordered]@{ method = "Triage"; arguments = [ordered]@{ kind = "strings"; section = ".rdata"; maxItems = 16 } },
                        [ordered]@{ method = "ListSymbols"; arguments = [ordered]@{ kind = "imports"; maxItems = 16 } },
                        [ordered]@{ method = "Xrefs"; arguments = [ordered]@{ address = $selectors[0]; direction = "both"; maxItems = 8 } }
                    )
                })
            $batchDoc = Get-JsonText $batchStatic
            Write-Probe "batch-static-4" $batchStatic ([ordered]@{
                    rows = @($batchDoc.results).Count
                    partial = $batchDoc.partial
                    textLength = $batchStatic.Chars
                })

            $bogus = @("0x1", "0x2", "0x3", "0x4")
            $briefBudget = Invoke-Tool $http $uri ([ref]$id) "GetInvestigationBrief" ([ordered]@{
                    functions = $bogus; maxTokens = 500; maxChars = 16000; includeLive = $false
                })
            $budgetDoc = Get-JsonText $briefBudget
            Write-Probe "brief-bogus-budget" $briefBudget ([ordered]@{
                    textLength = $briefBudget.Chars
                    maxChars = $budgetDoc.maxChars
                    usedChars = $budgetDoc.usedChars
                    maxTokens = $budgetDoc.maxTokens
                    usedTokensEstimate = $budgetDoc.usedTokensEstimate
                    overMaxChars = $briefBudget.Chars -gt ([int]$budgetDoc.maxChars + 512)
                    errorCount = @($budgetDoc.errors).Count
                })

            $mapBefore = Invoke-Tool $http $uri ([ref]$id) "MapStaticFunctionToLive" ([ordered]@{
                    function = $selectors[0]
                })
            $beforeDoc = Get-JsonText $mapBefore
            $reopen = Invoke-Tool $http $uri ([ref]$id) "OpenDebugTarget" ([ordered]@{
                    path = $Target; architecture = "auto"
                })
            $mapAfter = Invoke-Tool $http $uri ([ref]$id) "MapStaticFunctionToLive" ([ordered]@{
                    function = $selectors[0]
                })
            $afterDoc = Get-JsonText $mapAfter
            Write-Probe "reopen-mapping" $mapAfter ([ordered]@{
                    reopened = $reopen.Ok
                    exposesNativeToken = $reopen.Text.Contains("nativePipeToken")
                    beforeMatch = $beforeDoc.match
                    afterMatch = $afterDoc.match
                    beforeAddress = $beforeDoc.liveAddress
                    afterAddress = $afterDoc.liveAddress
                    addressChanged = $beforeDoc.liveAddress -ne $afterDoc.liveAddress
                    beforeBase = $beforeDoc.module.base
                    afterBase = $afterDoc.module.base
                    afterCalls = $afterDoc.bridgeCalls
                    afterReason = $afterDoc.reason
                    afterCandidates = @($afterDoc.candidates).Count
                })

            $repeatSelector = if ($selectors.Count -gt 1) { $selectors[1] } else { $selectors[0] }
            $mapRepeat1 = Invoke-Tool $http $uri ([ref]$id) "MapStaticFunctionToLive" ([ordered]@{
                    function = $repeatSelector; verifyHash = $false
                })
            $repeat1 = Get-JsonText $mapRepeat1
            $mapRepeat2 = Invoke-Tool $http $uri ([ref]$id) "MapStaticFunctionToLive" ([ordered]@{
                    function = $repeatSelector; verifyHash = $false
                })
            $repeat2 = Get-JsonText $mapRepeat2
            Write-Probe "map-repeat" $mapRepeat2 ([ordered]@{
                    firstCalls = $repeat1.bridgeCalls
                    secondCalls = $repeat2.bridgeCalls
                    firstMs = $mapRepeat1.DurationMs
                    secondMs = $mapRepeat2.DurationMs
                    sameAddress = $repeat1.liveAddress -eq $repeat2.liveAddress
                })

            $mapCompact = Invoke-Tool $http $uri ([ref]$id) "GetModuleMap" ([ordered]@{
                    maxSections = 12; maxSymbols = 20; maxFunctions = 8; maxStrings = 8; compact = $true
                })
            $compactDoc = Get-JsonText $mapCompact
            Write-Probe "map-compact" $mapCompact ([ordered]@{
                    textLength = $mapCompact.Chars
                    hasColumns = $null -ne $compactDoc.columns
                    hasRows = $null -ne $compactDoc.rows
                })

            $map20 = Invoke-Tool $http $uri ([ref]$id) "GetModuleMap" ([ordered]@{
                    maxSections = 12; maxSymbols = 20; maxFunctions = 8; maxStrings = 8
                })
            $map20Doc = Get-JsonText $map20
            $triage64 = Invoke-Tool $http $uri ([ref]$id) "Triage" ([ordered]@{
                    kind = "imports"; top = 64; maxChars = 30000
                })
            $triage64Doc = Get-JsonText $triage64
            $mapImports = @($map20Doc.imports.top | ForEach-Object { [string]$_.name })
            $triageImportsTop = @($triage64Doc.imports | Select-Object -First 20 | ForEach-Object { [string]$_.name })
            Write-Probe "map-import-ranking" $map20 ([ordered]@{
                    mapTop = $mapImports.Count
                    triageTop = $triageImportsTop.Count
                    mapTruncated = $map20Doc.imports.truncated
                    mapRefs = @($map20Doc.imports.top | ForEach-Object { "$($_.name):$($_.refCount)" })
                    triageRefs = @($triage64Doc.imports | Select-Object -First 20 | ForEach-Object { "$($_.name):$($_.refCount)" })
                    missingFromMap = @($triageImportsTop | Where-Object { $_ -notin $mapImports })
                })

            $symbols = Invoke-Tool $http $uri ([ref]$id) "ListSymbols" ([ordered]@{
                    kind = "both"; maxItems = 20
                })
            $symbolsDoc = Get-JsonText $symbols
            Write-Probe "symbols-both" $symbols ([ordered]@{
                    textLength = $symbols.Chars
                    imports = @($symbolsDoc.imports).Count
                    exports = @($symbolsDoc.exports).Count
                    nextOffsetImports = $symbolsDoc.nextOffsetImports
                    nextOffsetExports = $symbolsDoc.nextOffsetExports
                })
            $symbols2 = Invoke-Tool $http $uri ([ref]$id) "ListSymbols" ([ordered]@{
                    kind = "both"; maxItems = 20
                })
            Write-Probe "symbols-repeat" $symbols2 ([ordered]@{
                    firstMs = $symbols.DurationMs
                    secondMs = $symbols2.DurationMs
                    same = $symbols.Text -eq $symbols2.Text
                })

            $triageImports = Invoke-Tool $http $uri ([ref]$id) "Triage" ([ordered]@{
                    kind = "imports"; maxItems = 32; maxChars = 1000
                })
            $triageImportsDoc = Get-JsonText $triageImports
            Write-Probe "triage-imports-budget" $triageImports ([ordered]@{
                    textLength = $triageImports.Chars
                    truncated = $triageImportsDoc.truncated
                    nextOffset = $triageImportsDoc.nextOffset
                    rows = @($triageImportsDoc.imports).Count
                })
            $triageDefault = Invoke-Tool $http $uri ([ref]$id) "Triage" ([ordered]@{ kind = "imports" })
            $triageDefaultDoc = Get-JsonText $triageDefault
            Write-Probe "triage-imports-default" $triageDefault ([ordered]@{
                    textLength = $triageDefault.Chars
                    truncated = $triageDefaultDoc.truncated
                    rows = @($triageDefaultDoc.imports).Count
                    suspiciousCount = $triageDefaultDoc.suspiciousCount
                    nextOffset = $triageDefaultDoc.nextOffset
                })

            $triageExports = Invoke-Tool $http $uri ([ref]$id) "Triage" ([ordered]@{
                    kind = "imports"; includeExports = $true; top = 8
                })
            $triageExportsDoc = Get-JsonText $triageExports
            Write-Probe "triage-imports-exports" $triageExports ([ordered]@{
                    textLength = $triageExports.Chars
                    imports = @($triageExportsDoc.imports).Count
                    exports = @($triageExportsDoc.exports).Count
                    exportsTruncated = $triageExportsDoc.exportsTruncated
                    exportNextOffset = $triageExportsDoc.exportNextOffset
                })

            $triageStrings = Invoke-Tool $http $uri ([ref]$id) "Triage" ([ordered]@{
                    kind = "strings"; section = ".rdata"; maxItems = 64; maxPages = 8
                })
            Write-Probe "triage-strings-pages" $triageStrings ([ordered]@{
                    textLength = $triageStrings.Chars
                })
            $triageStringsMax = Invoke-Tool $http $uri ([ref]$id) "Triage" ([ordered]@{
                    kind = "strings"; section = ".rdata"; maxItems = 512; maxPages = 8
                })
            Write-Probe "triage-strings-max" $triageStringsMax ([ordered]@{
                    textLength = $triageStringsMax.Chars
                })

            $graph2 = Invoke-Tool $http $uri ([ref]$id) "CallGraph" ([ordered]@{
                    function = $selectors[0]; depth = 2; direction = "both"
                    maxNodes = 128; maxEdges = 256
                })
            $graphDoc = Get-JsonText $graph2
            Write-Probe "callgraph-depth2" $graph2 ([ordered]@{
                    textLength = $graph2.Chars
                    nodes = @($graphDoc.nodes).Count
                    edges = @($graphDoc.edges).Count
                    truncated = $graphDoc.truncated
                    hasNextBest = $null -ne $graphDoc.nextBest
                })

            $xrefs = Invoke-Tool $http $uri ([ref]$id) "Xrefs" ([ordered]@{
                    address = $selectors[0]; direction = "both"; maxItems = 16
                })
            $xrefsDoc = Get-JsonText $xrefs
            Write-Probe "xrefs-both" $xrefs ([ordered]@{
                    textLength = $xrefs.Chars
                    toCount = @($xrefsDoc.to).Count
                    fromCount = @($xrefsDoc.from).Count
                })

            $inspect = Invoke-Tool $http $uri ([ref]$id) "InspectFunction" ([ordered]@{
                    function = $selectors[0]; maxItems = 16; maxChars = 12000
                })
            $inspectDoc = Get-JsonText $inspect
            Write-Probe "inspect-default" $inspect ([ordered]@{
                    textLength = $inspect.Chars
                    decompilationStatus = $inspectDoc.summary.decompilationStatus
                    truncated = $inspectDoc.truncated
                })
            $inspectRealDefault = Invoke-Tool $http $uri ([ref]$id) "InspectFunction" ([ordered]@{
                    function = $selectors[0]
                })
            $inspectRealDoc = Get-JsonText $inspectRealDefault
            Write-Probe "inspect-real-default" $inspectRealDefault ([ordered]@{
                    textLength = $inspectRealDefault.Chars
                    decompilationStatus = $inspectRealDoc.summary.decompilationStatus
                    truncated = $inspectRealDoc.truncated
                })
            $inspectContext = Invoke-Tool $http $uri ([ref]$id) "InspectFunction" ([ordered]@{
                    function = $selectors[0]; includeDecomp = $false; maxItems = 16
                })
            $inspectContextDoc = Get-JsonText $inspectContext
            Write-Probe "inspect-context" $inspectContext ([ordered]@{
                    textLength = $inspectContext.Chars
                    decompilationStatus = $inspectContextDoc.summary.decompilationStatus
                    truncated = $inspectContextDoc.truncated
                })

            $queueDigest = Invoke-Tool $http $uri ([ref]$id) "GetAnalysisQueue" ([ordered]@{
                    limit = 8; withDigests = $true
                })
            $queueDoc = Get-JsonText $queueDigest
            Write-Probe "queue-digests" $queueDigest ([ordered]@{
                    textLength = $queueDigest.Chars
                    digestedCount = $queueDoc.digestedCount
                    digestsTruncated = $queueDoc.digestsTruncated
                })

            $snapshot1 = Invoke-Tool $http $uri ([ref]$id) "GetAnalysisSnapshot" ([ordered]@{})
            $snapshot2 = Invoke-Tool $http $uri ([ref]$id) "GetAnalysisSnapshot" ([ordered]@{})
            $snapshotDoc = Get-JsonText $snapshot2
            Write-Probe "snapshot-repeat" $snapshot2 ([ordered]@{
                    firstMs = $snapshot1.DurationMs
                    secondMs = $snapshot2.DurationMs
                    bridgeCalls = $snapshotDoc.bridgeCalls
                    transport = $snapshotDoc.transport
                })

            $decompile1 = Invoke-Tool $http $uri ([ref]$id) "DecompileModule" ([ordered]@{
                    maxFunctions = 1; maxChars = 10000
                })
            $decompile2 = Invoke-Tool $http $uri ([ref]$id) "DecompileModule" ([ordered]@{
                    maxFunctions = 1; maxChars = 10000
                })
            Write-Probe "decompile-repeat" $decompile2 ([ordered]@{
                    firstMs = $decompile1.DurationMs
                    secondMs = $decompile2.DurationMs
                    same = $decompile1.Text -eq $decompile2.Text
                })
        }
        if (-not $NoDecompile) {
            $null = Invoke-Tool $http $uri ([ref]$id) "DecompileModule" ([ordered]@{
                    maxFunctions = 1; maxChars = 10000
                })
        }
    }
    catch {
        $result.error = $_.Exception.Message
        $result.errorDetail = $_.ScriptStackTrace
        $result.errors++
        $result.errorTools = @("startup")
    }
    finally {
        $watch.Stop()
        $result.totalMs = [Math]::Round($watch.Elapsed.TotalMilliseconds, 1)
        $records = @(Get-Content -LiteralPath $jsonlPath -ErrorAction SilentlyContinue |
            ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.target -eq $Target })
        $result.calls = @($records).Count
        $result.errors = [int]$result.errors + @($records | Where-Object { $_.ok -ne $true }).Count
        $result.errorTools = @($records | Where-Object { $_.ok -ne $true } | ForEach-Object { $_.tool })
        if ($null -ne $http) { $http.Dispose() }
        Stop-Launcher $process $shutdownPath $owned
        $result | ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath (Join-Path $runDirectory "targets.jsonl") -Encoding utf8
        Write-Host ("{0,-36} {1,-4} startup={2,7}ms total={3,8}ms calls={4,3} errors={5}" -f
            $targetName, $ExpectedArch, $result.startupMs, $result.totalMs, $result.calls, $result.errors)
    }
    return [pscustomobject]$result
}

Assert-Condition (Test-Path -LiteralPath $launcher -PathType Leaf) "Self-contained launcher was not found: $launcher. Run tools\build.cmd first."
if ([string]::IsNullOrWhiteSpace($GhidraHome)) { $GhidraHome = Resolve-Ghidra "" }
$X64DbgPath = Resolve-Debugger $X64DbgPath "x64dbg.exe" @(
    "$packageRoot\release\x64\x64dbg.exe", "$packageRoot\x64\x64dbg.exe",
    "C:\Program Files\x64dbg\release\x64\x64dbg.exe") "DBGLINK_X64DBG_PATH"
$X32DbgPath = Resolve-Debugger $X32DbgPath "x32dbg.exe" @(
    "$packageRoot\release\x32\x32dbg.exe", "$packageRoot\x32\x32dbg.exe",
    "C:\Program Files\x64dbg\release\x32\x32dbg.exe") "DBGLINK_X32DBG_PATH"

if ($null -eq $Targets -or $Targets.Count -eq 0) {
    $Targets = @(
        "$env:SystemRoot\System32\notepad.exe",
        "$env:SystemRoot\System32\cmd.exe",
        "$env:SystemRoot\System32\charmap.exe",
        "$env:SystemRoot\System32\wscript.exe",
        "$env:SystemRoot\System32\mshta.exe",
        "$env:SystemRoot\regedit.exe",
        "$env:SystemRoot\System32\taskmgr.exe",
        "$env:SystemRoot\System32\mmc.exe",
        "$env:SystemRoot\System32\eventvwr.exe",
        "$env:SystemRoot\System32\dxdiag.exe",
        "$env:SystemRoot\SysWOW64\notepad.exe",
        "$env:SystemRoot\SysWOW64\cmd.exe",
        "$env:SystemRoot\SysWOW64\charmap.exe",
        "$env:SystemRoot\SysWOW64\wscript.exe",
        "$env:SystemRoot\SysWOW64\mshta.exe",
        "$env:SystemRoot\SysWOW64\regedit.exe"
    )
}
$Targets = @($Targets | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    ForEach-Object { (Resolve-Path -LiteralPath $_).Path } |
    Where-Object {
        $machine = Get-PeMachine $_
        ($machine -eq 0x8664 -and $Architecture -in @("x64", "both")) -or
        ($machine -eq 0x14c -and $Architecture -in @("x86", "both"))
    })

if ($Targets.Count -lt 1) {
    Write-Host "Architecture filter: '$Architecture'."
    foreach ($candidate in @($Targets)) { Write-Host "filtered: $candidate" }
}
Assert-Condition ($Targets.Count -ge 1) "No matching targets were found."
Write-Output "DBGLink corpus: $($Targets.Count) target(s), output $runDirectory"
$results = [System.Collections.Generic.List[object]]::new()
$index = 0
foreach ($target in $Targets) {
    $arch = Get-TargetArchitecture $target
    $script:currentTarget = $target
    $results.Add((Invoke-Target $target $arch $X64DbgPath $X32DbgPath))
    $index++
    if ($index -lt $Targets.Count) { Start-Sleep -Seconds 1 }
}

$records = @(Get-Content -LiteralPath $jsonlPath -ErrorAction SilentlyContinue |
    ForEach-Object { $_ | ConvertFrom-Json })
$toolSummary = @($records | Group-Object tool | ForEach-Object {
        $durations = @($_.Group | ForEach-Object { [double]$_.durationMs } | Sort-Object)
        $p95Index = [Math]::Min($durations.Count - 1, [Math]::Max(0, [int][Math]::Ceiling($durations.Count * 0.95) - 1))
        [pscustomobject][ordered]@{
            tool = $_.Name; calls = $_.Count
            failures = @($_.Group | Where-Object { $_.ok -ne $true }).Count
            p50Ms = if ($durations.Count) { [Math]::Round($durations[[int][Math]::Floor(($durations.Count - 1) / 2)], 1) } else { 0 }
            p95Ms = if ($durations.Count) { [Math]::Round($durations[$p95Index], 1) } else { 0 }
            maxMs = if ($durations.Count) { [Math]::Round($durations[-1], 1) } else { 0 }
            responseChars = ($_.Group | Measure-Object responseChars -Sum).Sum
        }
    })
$summary = [ordered]@{
    schemaVersion = 1
    timestamp = [DateTimeOffset]::UtcNow.ToString("o")
    architecture = $Architecture
    targets = @($results)
    tools = $toolSummary
    targetCount = @($results).Count
    failedCalls = @($records | Where-Object { $_.ok -ne $true }).Count
    totalCalls = @($records).Count
    totalResponseChars = ($records | Measure-Object responseChars -Sum).Sum
    startedAt = $stamp
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding utf8
Write-Output ""
$toolSummary | Format-Table -AutoSize | Out-String -Width 200 | Write-Output
Write-Output "Summary: $summaryPath"
if ($summary.failedCalls -gt 0) {
    Write-Output "Failures:"
    $records | Where-Object { $_.ok -ne $true } |
        Select-Object target, tool, durationMs, error | Format-Table -Wrap -AutoSize | Out-String -Width 220 | Write-Output
}
