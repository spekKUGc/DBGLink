[CmdletBinding()]
param(
    [ValidateSet("x64", "x86", "both")]
    [string]$Architecture = "both",
    [string]$X64DbgPath,
    [string]$X32DbgPath,
    [string]$GhidraHome,
    [string]$BundleRoot,
    [string]$InputFile = "$env:SystemRoot\System32\notepad.exe",
    [string]$X86InputFile = "$env:SystemRoot\SysWOW64\notepad.exe",
    [int]$Port = 50317,
    [switch]$AnalysisFixtures,
    [switch]$KeepInstalled
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http | Out-Null
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$packageRoot = Join-Path $root "artifacts\current"
$launcher = Join-Path $packageRoot "launcher\DbgLink.Launcher.Cli.exe"
$protocol = "2025-06-18"
$ownedRuntimeNames = @(
    "DbgLink.Server.exe",
    "DbgLink.Server.dll",
    "DbgLink.Server.deps.json",
    "DbgLink.Server.runtimeconfig.json",
    "DbgLink.Server.pdb",
    "GhidraBridge.zip"
)
$readyTimeoutMinutes = 10

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)] [bool]$Condition,
        [Parameter(Mandatory = $true)] [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-PortFree {
    param([Parameter(Mandatory = $true)] [int]$CheckPort)

    # Fail fast when another process already owns the MCP port. Without this
    # preflight the launcher starts and the run dies only at the 10-minute
    # readiness timeout with misleading diagnostics.
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $CheckPort)
        $listener.Start()
    }
    catch {
        throw "Port $CheckPort is already in use. Pass -Port with free ports for every architecture check."
    }
    finally {
        if ($null -ne $listener) { $listener.Stop() }
    }
}

function Get-DbgLinkBearerToken {
    # H-1: the server enforces `Authorization: Bearer` on /mcp by default, so
    # every probe request must carry the token. Resolve it exactly like the
    # server (DBGLINK_Bearer env override, then the shared mcp_config.json) and
    # fail closed — an unauthenticated probe would only produce noise 401s.
    $environmentToken = [Environment]::GetEnvironmentVariable("DBGLINK_BEARER_TOKEN")
    if (-not [string]::IsNullOrWhiteSpace($environmentToken)) {
        return $environmentToken
    }
    $configPath = if (-not [string]::IsNullOrWhiteSpace($env:DBGLINK_CONFIG_PATH)) {
        $env:DBGLINK_CONFIG_PATH
    } else {
        Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) "DBGLink\mcp_config.json"
    }
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "DBGLink bearer token was not found: $configPath does not exist. Start the server once so it generates mcp_config.json."
    }
    $token = ([System.IO.File]::ReadAllText($configPath) | ConvertFrom-Json).AuthToken
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw "DBGLink config file contains no AuthToken: $configPath."
    }
    return $token
}

function Resolve-Debugger {
    param(
        [string]$Specified,
        [string]$Name,
        [string[]]$RelativeCandidates,
        [string]$EnvironmentName,
        [string]$ParameterName
    )

    # S-1: only explicit locations are trusted. An explicit -XPath flag or its
    # DBGLINK_* env var wins and fails closed on bogus values; then the user's
    # own PATH, the staged bundle, and the machine-wide Program Files trees.
    # CWD, the repo root, %USERPROFILE%, Downloads and Desktop are NEVER
    # searched — resolving (and later executing) a planted debugger binary from
    # an attacker-writable directory is exactly the auto-exec hazard.
    foreach ($explicit in @($Specified, [Environment]::GetEnvironmentVariable($EnvironmentName)) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        $full = [IO.Path]::GetFullPath($explicit)
        Assert-Condition (Test-Path -LiteralPath $full -PathType Leaf) "Debugger was not found ($EnvironmentName): $full"
        return $full
    }

    $pathValue = [Environment]::GetEnvironmentVariable("Path")
    if (-not [string]::IsNullOrWhiteSpace($pathValue)) {
        foreach ($directory in $pathValue.Split([IO.Path]::PathSeparator, [StringSplitOptions]::RemoveEmptyEntries)) {
            $candidate = Join-Path $directory.Trim().Trim('"') $Name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        }
    }

    $programFiles = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Container) }
    $roots = @($packageRoot) + @($programFiles)
    foreach ($searchRoot in $roots) {
        $levels = @($searchRoot)
        if ($searchRoot -ne $packageRoot) {
            # One bounded level under Program Files (e.g. "x64dbg\release\x64").
            $children = @(Get-ChildItem -LiteralPath $searchRoot -Directory -ErrorAction SilentlyContinue |
                Select-Object -First 512)
            $levels += @($children | ForEach-Object { $_.FullName })
        }
        foreach ($level in $levels) {
            foreach ($relative in $RelativeCandidates) {
                $candidate = Join-Path $level $relative
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return (Resolve-Path -LiteralPath $candidate).Path
                }
            }
        }
    }

    throw "$Name was not found. Pass -$ParameterName <path> or set $EnvironmentName."
}

function Save-PluginState {
    param(
        [Parameter(Mandatory = $true)] [string]$DebuggerPath,
        [Parameter(Mandatory = $true)] [string]$PluginName,
        [Parameter(Mandatory = $true)] [string]$BackupRoot,
        [Parameter(Mandatory = $true)] [string]$ArchitectureName
    )

    $pluginDirectory = Join-Path (Split-Path -Parent $DebuggerPath) "plugins"
    Assert-Condition (Test-Path -LiteralPath $pluginDirectory -PathType Container) "Plugin directory was not found: $pluginDirectory"
    $state = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @($PluginName) + $ownedRuntimeNames) {
        $target = Join-Path $pluginDirectory $name
        $backup = Join-Path $BackupRoot (Join-Path $ArchitectureName $name)
        $exists = Test-Path -LiteralPath $target -PathType Leaf
        if ($exists) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $backup) -Force | Out-Null
            Copy-Item -LiteralPath $target -Destination $backup -Force
        }
        $state.Add([pscustomobject]@{
            Target = $target
            Backup = $backup
            Existed = $exists
        })
    }
    return $state
}

function Restore-PluginState {
    param([Parameter(Mandatory = $true)] [System.Collections.IEnumerable]$State)

    # The debugger may still hold the plugin files (loaded DbgLink.dpXX,
    # running DbgLink.Server.exe) for a moment after the graceful shutdown, and
    # a hardened file DACL (owner-only without DELETE) denies replacement
    # until repaired. Retry each item so a slow process exit does not fail the
    # whole E2E run; non-IO failures (missing backup, bad path) still fail fast.
    foreach ($item in $State) {
        $restored = $false
        $lastError = $null
        for ($attempt = 0; $attempt -lt 30 -and -not $restored; $attempt++) {
            if ($attempt -gt 0) { Start-Sleep -Milliseconds 1000 }
            try {
                if ($item.Existed) {
                    if (Test-Path -LiteralPath $item.Target -PathType Leaf) {
                        try { [IO.File]::SetAttributes($item.Target, [IO.FileAttributes]::Normal) } catch { }
                    }
                    Copy-Item -LiteralPath $item.Backup -Destination $item.Target -Force
                } elseif (Test-Path -LiteralPath $item.Target -PathType Leaf) {
                    Remove-Item -LiteralPath $item.Target -Force
                }
                $restored = $true
            }
            catch {
                $lastError = $_
                $inner = $_.Exception.InnerException
                $denied = ($_.Exception -is [System.UnauthorizedAccessException]) -or `
                    ($null -ne $inner -and $inner -is [System.UnauthorizedAccessException])
                if ($denied -and (Test-Path -LiteralPath $item.Target -PathType Leaf)) {
                    # A hardened DACL denies even the owner: restore the
                    # inherited ACL (no ownership seizure) and retry; the owner
                    # may always re-grant itself.
                    try { & icacls.exe $item.Target /reset | Out-Null } catch { }
                }
                $retryable = ($_.Exception -is [System.IO.IOException]) -or `
                    ($_.Exception -is [System.UnauthorizedAccessException]) -or `
                    ($null -ne $inner -and (($inner -is [System.IO.IOException]) -or `
                        ($inner -is [System.UnauthorizedAccessException])))
                if (-not $retryable) { throw }
            }
        }
        if (-not $restored) {
            throw "Plugin restoration failed for $($item.Target): $($lastError.Exception.Message)"
        }
    }
}

function Get-ProcessTreeIds {
    param([Parameter(Mandatory = $true)] [int]$RootProcessId)

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

function Get-LogText {
    param([Parameter(Mandatory = $true)] [string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $stream = $null
        $reader = $null
        try {
            $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $reader = [IO.StreamReader]::new($stream)
            return $reader.ReadToEnd()
        }
        catch [IO.IOException] {
            return ""
        }
        finally {
            if ($null -ne $reader) { $reader.Dispose() }
            elseif ($null -ne $stream) { $stream.Dispose() }
        }
    }
    return ""
}

function ConvertTo-WindowsCommandLineArgument {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }

    # Start-Process joins -ArgumentList into one command line on Windows.
    # Apply the CommandLineToArgvW quoting rules before passing that string so
    # paths containing spaces, quotes, or a trailing backslash stay one arg.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-McpRequest {
    param(
        [Parameter(Mandatory = $true)] [System.Net.Http.HttpClient]$HttpClient,
        [Parameter(Mandatory = $true)] [string]$Uri,
        [Parameter(Mandatory = $true)] [string]$ProtocolVersion,
        [Parameter(Mandatory = $true)] [object]$Payload
    )

    $json = $Payload | ConvertTo-Json -Compress -Depth 12
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Uri)
    $content = [System.Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, "application/json")
    [void]$request.Headers.Accept.ParseAdd("application/json, text/event-stream")
    [void]$request.Headers.Add("MCP-Protocol-Version", $ProtocolVersion)
    # H-1: the server requires Authorization: Bearer on /mcp by default.
    [void]$request.Headers.Add("Authorization", "Bearer $(Get-DbgLinkBearerToken)")
    $request.Content = $content
    try {
        $response = $HttpClient.SendAsync($request).GetAwaiter().GetResult()
        try {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($response.Content.Headers.ContentType.MediaType -eq "text/event-stream") {
                $messages = @($body -split '\r?\n' | Where-Object { $_.StartsWith('data: ') } |
                    ForEach-Object { $_.Substring(6) })
                $reply = @($messages | Where-Object {
                    $eventDocument = $_ | ConvertFrom-Json
                    $null -ne $eventDocument.id -and $eventDocument.id -eq $Payload.id
                })
                if ($reply.Count -ne 1) { throw "Expected one MCP reply in the SSE response." }
                $body = $reply[0]
            }
            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Body = $body
            }
        }
        finally {
            $response.Dispose()
        }
    }
    finally {
        $content.Dispose()
        $request.Dispose()
    }
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory = $true)] [System.Net.Http.HttpClient]$HttpClient,
        [Parameter(Mandatory = $true)] [string]$Uri,
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $true)] [object]$Arguments,
        [Parameter(Mandatory = $true)] [int]$Id
    )

    $payload = [ordered]@{
        jsonrpc = "2.0"
        id = $Id
        method = "tools/call"
        params = [ordered]@{
            name = $Name
            arguments = $Arguments
        }
    }
    $response = Invoke-McpRequest $HttpClient $Uri $protocol $payload
    Assert-Condition ($response.StatusCode -eq 200) "$Name returned HTTP $($response.StatusCode): $($response.Body)"
    $document = $response.Body | ConvertFrom-Json
    Assert-Condition ($null -ne $document.result) "$Name returned no MCP result: $($response.Body)"
    return $document
}

function Invoke-ArchitectureCheck {
    param(
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $true)] [string]$Target,
        [Parameter(Mandatory = $true)] [int]$CheckPort,
        [Parameter(Mandatory = $true)] [string]$X64Path,
        [Parameter(Mandatory = $true)] [string]$X86Path,
        [Parameter(Mandatory = $true)] [string]$BackupRoot
    )

    $state = @()
    $stdoutPath = Join-Path $BackupRoot "$Name.stdout.log"
    $stderrPath = Join-Path $BackupRoot "$Name.stderr.log"
    $shutdownSignalPath = Join-Path $BackupRoot "$Name.shutdown"
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add("--input")
    [void]$arguments.Add($Target)
    [void]$arguments.Add("--port")
    [void]$arguments.Add($CheckPort.ToString([Globalization.CultureInfo]::InvariantCulture))
    [void]$arguments.Add("--json")
    [void]$arguments.Add("--shutdown-file")
    [void]$arguments.Add($shutdownSignalPath)
    if (-not [string]::IsNullOrWhiteSpace($X64DbgPath)) { [void]$arguments.Add("--x64dbg"); [void]$arguments.Add($X64DbgPath) }
    if (-not [string]::IsNullOrWhiteSpace($X32DbgPath)) { [void]$arguments.Add("--x32dbg"); [void]$arguments.Add($X32DbgPath) }
    if (-not [string]::IsNullOrWhiteSpace($GhidraHome)) { [void]$arguments.Add("--ghidra-home"); [void]$arguments.Add($GhidraHome) }
    if (-not [string]::IsNullOrWhiteSpace($BundleRoot)) { [void]$arguments.Add("--bundle-root"); [void]$arguments.Add($BundleRoot) }

    $launcherProcess = $null
    $ownedProcessIds = @()
    $http = $null
    $shutdownRequested = $false
    $primaryFailure = $null
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    try {
        Assert-Condition (Test-Path -LiteralPath $Target -PathType Leaf) "The $Name target was not found: $Target"
        Assert-PortFree $CheckPort
        $state = @(
            Save-PluginState $X64Path "DbgLink.dp64" $BackupRoot "x64"
            Save-PluginState $X86Path "DbgLink.dp32" $BackupRoot "x86"
        )
        if (Test-Path -LiteralPath $shutdownSignalPath) {
            Remove-Item -LiteralPath $shutdownSignalPath -Force
        }

        $http = [System.Net.Http.HttpClient]::new()
        $http.Timeout = [TimeSpan]::FromSeconds(60)
        $commandLine = [string]::Join(
            " ",
            [string[]]@($arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument $_ }))
        $launcherProcess = Start-Process -FilePath $launcher `
            -ArgumentList $commandLine `
            -WorkingDirectory (Split-Path -Parent $launcher) `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -WindowStyle Hidden `
            -PassThru

        # Capture the process tree before readiness as well. Startup failures
        # must be checked for orphaned debugger/Ghidra/server descendants too.
        $ownedProcessIds = Get-ProcessTreeIds $launcherProcess.Id
        $ready = $false
        $deadline = [DateTime]::UtcNow.AddMinutes($readyTimeoutMinutes)
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($launcherProcess.HasExited) {
                throw "$Name launcher exited before ready (code $($launcherProcess.ExitCode)). $(Get-LogText $stdoutPath) $(Get-LogText $stderrPath)"
            }
            $log = Get-LogText $stdoutPath
            $readyLine = $log -split "`r?`n" | Where-Object { $_ -match '"type"\s*:\s*"ready"' } | Select-Object -Last 1
            if ($null -ne $readyLine) {
                $ready = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
        Assert-Condition $ready "$Name launcher did not become ready within $readyTimeoutMinutes minutes. $(Get-LogText $stdoutPath) $(Get-LogText $stderrPath)"
        $readyDocument = $readyLine | ConvertFrom-Json
        Assert-Condition ($null -ne $readyDocument.data -and [double]$readyDocument.data.startupMs -gt 0) "$Name ready event did not report startupMs."
        $readyTarget = $readyDocument.data.target
        Assert-Condition ($null -ne $readyTarget -and [string]$readyTarget.fileName -eq [IO.Path]::GetFileName($Target)) "$Name ready event did not report the opened target."
        Assert-Condition (-not [string]::IsNullOrWhiteSpace([string]$readyTarget.format) -and
            -not [string]::IsNullOrWhiteSpace([string]$readyTarget.architecture) -and
            [int]$readyTarget.functionCount -ge 0) "$Name ready event target summary is incomplete."
        $ownedProcessIds = @($ownedProcessIds + (Get-ProcessTreeIds $launcherProcess.Id) | Sort-Object -Unique)

        $uri = "http://127.0.0.1:$CheckPort/mcp"
        $initialize = [ordered]@{
            jsonrpc = "2.0"
            id = 1
            method = "initialize"
            params = [ordered]@{
                protocolVersion = $protocol
                capabilities = [ordered]@{}
                clientInfo = [ordered]@{ name = "DBGLink.E2E"; version = "1" }
            }
        }
        $initializeResponse = Invoke-McpRequest $http $uri $protocol $initialize
        Assert-Condition ($initializeResponse.StatusCode -eq 200) "initialize returned HTTP $($initializeResponse.StatusCode): $($initializeResponse.Body)"
        $initializeDocument = $initializeResponse.Body | ConvertFrom-Json
        Assert-Condition ($null -ne $initializeDocument.result) "initialize returned an MCP error: $($initializeResponse.Body)"

        $listPayload = [ordered]@{ jsonrpc = "2.0"; id = 2; method = "tools/list" }
        $listResponse = Invoke-McpRequest $http $uri $protocol $listPayload
        Assert-Condition ($listResponse.StatusCode -eq 200) "tools/list returned HTTP $($listResponse.StatusCode): $($listResponse.Body)"
        $listDocument = $listResponse.Body | ConvertFrom-Json
        $toolNames = @($listDocument.result.tools | ForEach-Object { $_.name })
        Assert-Condition ($toolNames -contains "GetServerStatus" -and $toolNames -contains "DecompileModule") "tools/list did not advertise native and Ghidra tools."
        $statusDocument = Invoke-Tool $http $uri "GetServerStatus" ([ordered]@{}) 3
        $statusText = [string]$statusDocument.result.content[0].text
        $status = $statusText | ConvertFrom-Json
        Assert-Condition ($status.ok -eq $true -and $status.bridge -eq "native" -and [int]$status.pid -gt 0) "GetServerStatus did not confirm the native bridge: $statusText"

        $contextDocument = Invoke-Tool $http $uri "InspectAddressStructure" ([ordered]@{
                address = "cip"; pointerCount = 4; byteCount = 64
            }) 4
        Assert-Condition ($contextDocument.result.isError -ne $true -and $null -ne $contextDocument.result.content[0].text) "InspectAddressStructure returned no response text."

        $snapshotDocument = Invoke-Tool $http $uri "GetAnalysisSnapshot" ([ordered]@{ maxChars = 24000; includeModules = $true }) 11
        $snapshot = $snapshotDocument.result.content[0].text | ConvertFrom-Json
        Assert-Condition ($snapshot.consistency.status -eq 'unchanged' -and $snapshot.consistency.atomic -eq $false) "Paused snapshot did not pass its state checks: $($snapshotDocument.result.content[0].text)"
        # readyForAnalysis was intentionally dropped in the token phase (derive it):
        # a paused, state-unchanged snapshot with modules present is ready for analysis.
        Assert-Condition ($snapshot.summary.running -eq $false -and
            $snapshot.summary.consistency -eq 'unchanged' -and [int]$snapshot.summary.moduleCount -gt 0) "Snapshot summary was incomplete: $($snapshotDocument.result.content[0].text)"
        Assert-Condition ($snapshot.sections.modules.modules.Count -gt 0) 'Snapshot did not return structured modules.'

        if ($AnalysisFixtures) {
            $callerDocument = Invoke-Tool $http $uri 'InspectFunction' ([ordered]@{ function = 'FixtureCaller'; maxChars = 12000; maxItems = 64 }) 12
            $caller = $callerDocument.result.content[0].text | ConvertFrom-Json
            Assert-Condition ($caller.schemaVersion -eq 2 -and $caller.decompilation.status -eq 'ok' -and
                $caller.summary.decompilationStatus -eq 'ok' -and
                $caller.function.name -eq 'FixtureCaller') 'Known caller did not decompile with a usable summary.'
            $calleeDocument = Invoke-Tool $http $uri 'InspectFunction' ([ordered]@{ function = 'FixtureCallee'; includeDecomp = $false }) 13
            $callee = $calleeDocument.result.content[0].text | ConvertFrom-Json
            $evidenceDirectory = Join-Path $root 'artifacts\verification'
            New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
            [ordered]@{ snapshot = $snapshot; caller = $caller; callee = $callee } | ConvertTo-Json -Depth 24 |
                Set-Content -LiteralPath (Join-Path $evidenceDirectory "$Name-analysis.json") -Encoding utf8
            Assert-Condition (@($caller.references.xrefsFrom | Where-Object { $_.to -eq $callee.function.entry }).Count -gt 0) "Known caller-to-callee reference was not found; see artifacts/verification/$Name-analysis.json."
            $mappingDocument = Invoke-Tool $http $uri 'MapStaticFunctionToLive' ([ordered]@{ function = 'FixtureCaller' }) 14
            $mapping = $mappingDocument.result.content[0].text | ConvertFrom-Json
            Assert-Condition ($mapping.match -eq $true -and $mapping.identity.hashVerified -eq $true) 'Known function did not map with verified file identity.'
            $expectedAddress = [Convert]::ToUInt64(($mapping.module.base -replace '^0x', ''), 16) + [Convert]::ToUInt64(($caller.function.rva -replace '^0x', ''), 16)
            Assert-Condition ([Convert]::ToUInt64(($mapping.liveAddress -replace '^0x', ''), 16) -eq $expectedAddress) 'Live address did not equal relocated base + known RVA.'
            $pointerDocument = Invoke-Tool $http $uri 'InspectAddressStructure' ([ordered]@{
                address = 'AnalysisTarget.exe:FixtureUnicodePointer'; pointerCount = 1; byteCount = 16; stringBytes = 128; includeXrefs = $false
            }) 15
            $pointerText = [string]$pointerDocument.result.content[0].text
            $expectedPointerText = 'utf16="DBGLink ' + (-join @([char]0x041F, [char]0x0440, [char]0x0438, [char]0x0432, [char]0x0435, [char]0x0442, ' ', [char]0x4E2D, [char]0xD83D, [char]0xDE00)) + '"'
            Assert-Condition ($pointerDocument.result.isError -ne $true -and $pointerText.Contains($expectedPointerText)) "Unicode pointer evidence was lost: $pointerText"
            Assert-Condition (-not $pointerText.Contains('bookmark=false')) 'Inspection reported an unqueried bookmark value.'
            [ordered]@{ passed = $true; architecture = $Name; snapshot = $snapshot; caller = $caller;
                callee = $callee; mapping = $mapping; pointer = $pointerText } | ConvertTo-Json -Depth 24 |
                Set-Content -LiteralPath (Join-Path $evidenceDirectory "$Name-analysis.json") -Encoding utf8
            Write-Output "${Name}: known functions, xref, relocated mapping, Unicode pointer and snapshot consistency passed."
        }

        $decompileDocument = Invoke-Tool $http $uri "DecompileModule" ([ordered]@{ maxFunctions = 1; maxChars = 10000 }) 5
        Assert-Condition ($decompileDocument.result.isError -ne $true) "DecompileModule returned an MCP tool error: $($decompileDocument | ConvertTo-Json -Compress -Depth 8)"
        $decompileText = [string]$decompileDocument.result.content[0].text
        $decompile = $decompileText | ConvertFrom-Json
        Assert-Condition ($decompile.schemaVersion -eq 2 -and @($decompile.functions).Count -gt 0) "DecompileModule returned no functions: $decompileText"
        Assert-Condition ($null -ne $decompile.module.summary -and
            [string]$decompile.module.summary.fileName -eq [IO.Path]::GetFileName($Target) -and
            -not [string]::IsNullOrWhiteSpace([string]$decompile.module.summary.format) -and
            -not [string]::IsNullOrWhiteSpace([string]$decompile.module.summary.architecture)) "DecompileModule returned no useful module summary."
        Assert-Condition ([string]::Equals([string]$decompile.module.path, $Target, [StringComparison]::OrdinalIgnoreCase)) "DecompileModule did not return the user-selected target path."
        Assert-Condition ($null -ne $decompile.functions[0].analysis -and
            [string]$decompile.functions[0].analysis.nameKind -in @('generated', 'named')) "DecompileModule returned no function analysis metadata."
        Assert-Condition ([int]$decompile.summary.returnedFunctions -eq @($decompile.functions).Count -and
            -not [string]::IsNullOrWhiteSpace([string]$decompile.summary.nextAction)) "DecompileModule summary was incomplete."
        $entry = [string]$decompile.functions[0].entry
        Assert-Condition (-not [string]::IsNullOrWhiteSpace($entry)) "DecompileModule returned a function without an entry address."

        $selectedDocument = Invoke-Tool $http $uri "InspectFunction" ([ordered]@{
            function = $entry
            maxChars = 10000
        }) 6
        Assert-Condition ($selectedDocument.result.isError -ne $true) "InspectFunction single-function selection returned an MCP tool error: $($selectedDocument | ConvertTo-Json -Compress -Depth 8)"
        $selectedText = [string]$selectedDocument.result.content[0].text
        Assert-Condition (-not [string]::IsNullOrWhiteSpace($selectedText)) "InspectFunction single-function selection returned empty content."
        if (-not [string]::IsNullOrWhiteSpace([string]$decompile.nextFunction)) {
            $continuedDocument = Invoke-Tool $http $uri "DecompileModule" ([ordered]@{
                start = [string]$decompile.nextFunction
                maxFunctions = 1
                maxChars = 10000
            }) 7
            Assert-Condition ($continuedDocument.result.isError -ne $true) "DecompileModule continuation returned an MCP tool error: $($continuedDocument | ConvertTo-Json -Compress -Depth 8)"
            $continued = $continuedDocument.result.content[0].text | ConvertFrom-Json
            Assert-Condition (@($continued.functions).Count -gt 0 -and [string]$continued.functions[0].entry -eq [string]$decompile.nextFunction) "DecompileModule continuation did not start at nextFunction."
        }

        $inspectDocument = Invoke-Tool $http $uri "InspectFunction" ([ordered]@{
            function = $entry
            maxChars = 10000
            maxItems = 4
            includeDecomp = $true
            includeDisassembly = $true
            includeReferences = $true
            includeSymbols = $true
        }) 8
        Assert-Condition ($inspectDocument.result.isError -ne $true) "InspectFunction returned an MCP tool error: $($inspectDocument | ConvertTo-Json -Compress -Depth 8)"
        $inspect = $inspectDocument.result.content[0].text | ConvertFrom-Json
        Assert-Condition ($inspect.schemaVersion -eq 2 -and $null -ne $inspect.function.analysis -and
            [string]$inspect.function.analysis.nameKind -in @('generated', 'named')) "InspectFunction returned no function quality metadata."
        Assert-Condition (-not [string]::IsNullOrWhiteSpace([string]$inspect.function.name) -and
            $inspect.summary.decompilationStatus -eq 'ok') "InspectFunction summary was incomplete."
        $smallDocument = Invoke-Tool $http $uri "InspectFunction" ([ordered]@{
            function = $entry; maxChars = 10000; maxItems = 1
            includeDecomp = $false; includeDisassembly = $true; includeReferences = $true; includeSymbols = $true
        }) 9
        Assert-Condition ($smallDocument.result.isError -ne $true) "Limited InspectFunction failed."
        $small = $smallDocument.result.content[0].text | ConvertFrom-Json
        if (@($inspect.disassembly).Count -gt 1) {
            Assert-Condition ($small.truncated -eq $true -and $small.truncatedSections -contains "disassembly") "Instruction limit was not reported as truncation."
        }
        if (@($inspect.references.xrefsFrom).Count -gt 1) {
            Assert-Condition ($small.truncatedSections -contains "references.xrefsFrom") "Outgoing reference limit was not reported."
        }
        $compactDocument = Invoke-Tool $http $uri "InspectFunction" ([ordered]@{ function = $entry; maxItems = 4; maxChars = 10000 }) 10
        Assert-Condition ($compactDocument.result.isError -ne $true) "Default InspectFunction failed."
        $compact = $compactDocument.result.content[0].text | ConvertFrom-Json
        Assert-Condition ($null -ne $compact.decompilation -and $null -ne $compact.references) "Compact inspection omitted core evidence."
        Assert-Condition ($null -eq $compact.disassembly -and $null -eq $compact.symbols -and $null -eq $compact.types) "Default inspection included optional detail."
        Write-Output "${Name}: inspection characters: full=$($inspectDocument.result.content[0].text.Length), compact=$($compactDocument.result.content[0].text.Length); truncation checks passed."
        Write-Output "${Name}: initialize, tools/list, native status/context, selected Ghidra DecompileModule and InspectFunction passed."
    }
    catch {
        $primaryFailure = $_
    }
    finally {
        if ($null -ne $launcherProcess) {
            try {
                # Signal the CLI through its normal cancellation path. This
                # exercises ToolkitCoordinator.StopAsync and Ghidra cleanup.
                $ownedProcessIds = @($ownedProcessIds + (Get-ProcessTreeIds $launcherProcess.Id) | Sort-Object -Unique)
                if (-not $launcherProcess.HasExited) {
                    [IO.File]::WriteAllText($shutdownSignalPath, "stop`n", [Text.Encoding]::UTF8)
                    $shutdownRequested = $true
                    if (-not $launcherProcess.WaitForExit(30000)) {
                        $cleanupFailures.Add("$Name launcher did not stop after the graceful shutdown signal.")
                        try { $launcherProcess.Kill() } catch { }
                        try { $launcherProcess.WaitForExit(15000) } catch { }
                    }
                }
                if ($shutdownRequested -and $launcherProcess.HasExited) {
                    $launcherProcess.Refresh()
                    $stopLog = Get-LogText $stdoutPath
                    $exitCode = $launcherProcess.ExitCode
                    if ($exitCode -is [int] -and $exitCode -ne 0) {
                        $cleanupFailures.Add("$Name launcher exited with code $($launcherProcess.ExitCode) during graceful shutdown.")
                    }
                    if ($stopLog -notmatch '"type"\s*:\s*"stopped"') {
                        $cleanupFailures.Add("$Name launcher did not report a completed graceful shutdown.")
                    }
                    if ($stopLog -match 'Ghidra isolated-session cleanup did not complete') {
                        $cleanupFailures.Add("$Name Ghidra isolated-session cleanup did not complete.")
                    }
                }
            }
            catch {
                $cleanupFailures.Add("$Name graceful shutdown failed: $($_.Exception.Message)")
            }
        }

        $remaining = @()
        try {
            for ($attempt = 0; $attempt -lt 30; $attempt++) {
                $remaining = @($ownedProcessIds | Where-Object {
                    $process = Get-Process -Id ([int]$_) -ErrorAction SilentlyContinue
                    $null -ne $process -and -not $process.HasExited
                })
                if ($remaining.Count -eq 0) { break }
                Start-Sleep -Milliseconds 500
            }
            if ($remaining.Count -ne 0) {
                $cleanupFailures.Add("$Name left child processes running: $($remaining -join ', ')")
            }
        }
        catch {
            $cleanupFailures.Add("$Name child-process cleanup check failed: $($_.Exception.Message)")
        }

        try {
            $serverPaths = @(
                (Join-Path (Split-Path -Parent $X64Path) "plugins\DbgLink.Server.exe"),
                (Join-Path (Split-Path -Parent $X86Path) "plugins\DbgLink.Server.exe")
            )
            $runningServers = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "DbgLink.Server.exe" -and $_.ExecutablePath -in $serverPaths })
            if ($runningServers.Count -ne 0) {
                $cleanupFailures.Add("$Name left DbgLink.Server.exe processes running.")
            }
        }
        catch {
            $cleanupFailures.Add("$Name server cleanup check failed: $($_.Exception.Message)")
        }

        if ($null -ne $http) {
            try { $http.Dispose() } catch { $cleanupFailures.Add("$Name HTTP client cleanup failed: $($_.Exception.Message)") }
        }
        if (-not $KeepInstalled -and $state.Count -gt 0) {
            try { Restore-PluginState $state }
            catch {
                $script:e2eKeepBackup = $true
                $cleanupFailures.Add("$Name plugin restoration failed: $($_.Exception.Message)")
            }
        }
        if ($null -ne $launcherProcess) {
            try { $launcherProcess.Dispose() } catch { }
        }
    }

    if ($null -ne $primaryFailure) {
        if ($cleanupFailures.Count -eq 0) {
            throw $primaryFailure
        }
        throw "$($primaryFailure.Exception.Message) Cleanup failures: $($cleanupFailures -join ' | ')"
    }
    if ($cleanupFailures.Count -ne 0) {
        $script:e2eKeepBackup = $true
        throw ($cleanupFailures -join " | ")
    }
}

Assert-Condition (Test-Path -LiteralPath $launcher -PathType Leaf) "Self-contained CLI was not found: $launcher. Run tools\build.cmd first."
Assert-Condition ($Port -ge 1 -and $Port + 1 -le 65535) "Port must leave room for both architecture checks."
# Single standard catalog: DBGLINK_TOOL_PROFILE / DBGLINK_PROFILE / DBGLINK_LEAN
# are ignored by the server (lean/comprehensive merged). No profile gate here.
if ($AnalysisFixtures) {
    $InputFile = Join-Path $root 'artifacts\fixtures\x64\AnalysisTarget.exe'
    $X86InputFile = Join-Path $root 'artifacts\fixtures\Win32\AnalysisTarget.exe'
}
if (-not $KeepInstalled) {
    $backupRoot = Join-Path ([IO.Path]::GetTempPath()) ("DBGLink-E2E-" + [Guid]::NewGuid().ToString("N"))
} else {
    $backupRoot = Join-Path $root "artifacts\.e2e-backup"
}
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

$script:e2eKeepBackup = $false
$completed = 0
try {
    $x64 = Resolve-Debugger $X64DbgPath "x64dbg.exe" @("release\x64\x64dbg.exe", "x64\x64dbg.exe", "x64dbg.exe") "DBGLINK_X64DBG_PATH" "X64DbgPath"
    $x86 = Resolve-Debugger $X32DbgPath "x32dbg.exe" @("release\x32\x32dbg.exe", "x32\x32dbg.exe", "x32dbg.exe") "DBGLINK_X32DBG_PATH" "X32DbgPath"
    $checks = if ($Architecture -eq "x64") {
        @(@{ Name = "x64"; Target = $InputFile })
    } elseif ($Architecture -eq "x86") {
        @(@{ Name = "x86"; Target = $X86InputFile })
    } else {
        @(@{ Name = "x64"; Target = $InputFile }, @{ Name = "x86"; Target = $X86InputFile })
    }

    foreach ($check in $checks) {
        Write-Output "Starting $($check.Name) end-to-end check..."
        Invoke-ArchitectureCheck $check.Name $check.Target ($Port + $completed) $x64 $x86 $backupRoot
        $completed++
    }
    Write-Output "DBGLink E2E PASS ($completed architecture check(s)); no started processes remained."
}
finally {
    if (-not $KeepInstalled -and (Test-Path -LiteralPath $backupRoot)) {
        if ($script:e2eKeepBackup) {
            Write-Warning "DBGLink E2E kept the plugin backup because restoration failed: $backupRoot"
        } else {
            $resolvedBackup = [IO.Path]::GetFullPath($backupRoot)
            $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
            if ([IO.Path]::GetDirectoryName($resolvedBackup) -ne $tempParent -or
                [IO.Path]::GetFileName($resolvedBackup) -notmatch '^DBGLink-E2E-[0-9a-f]{32}$') {
                throw "Unexpected E2E cleanup path: $resolvedBackup"
            }
            Remove-Item -LiteralPath $resolvedBackup -Recurse -Force -ErrorAction SilentlyContinue
            for ($attempt = 0; $attempt -lt 30 -and (Test-Path -LiteralPath $resolvedBackup); $attempt++) {
                Start-Sleep -Milliseconds 1000
                Remove-Item -LiteralPath $resolvedBackup -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
