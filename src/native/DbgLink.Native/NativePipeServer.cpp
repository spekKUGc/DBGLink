#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeControlHandlers.h"
#include "NativeCoverage.h"
#include "NativeInspectionHandlers.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeModuleFunctions.h"
#include "NativePipeServer.h"
#include "NativeSearchHandlers.h"
#include "NativeSecondaryHandlers.h"
#include "NativeStringReferenceTrace.h"
#include "NativeStringSearchHandlers.h"

namespace dbglink
{
    namespace
    {
        // Environment variable that carries the native pipe token to the
        // auto-started server. Must match
        // DbgLink.Shared.DbgLinkConfigPath.NativePipeTokenEnvironmentVariable.
        constexpr wchar_t kNativePipeTokenEnvironmentVariable[] = L"DBGLINK_NATIVE_PIPE_TOKEN";

        /// <summary>
        /// Builds the environment block for the auto-started server: the
        /// parent's environment with DBGLINK_NATIVE_PIPE_TOKEN set to the
        /// session token.
        ///
        /// The token is a per-session credential. On the command line it would
        /// be readable by every local process through
        /// Win32_Process.CommandLine; the environment block is not.
        ///
        /// Returns false when the parent environment cannot be read or the
        /// token cannot be encoded, so the caller fails closed instead of
        /// starting a server without the credential.
        /// </summary>
        bool BuildEnvironmentWithToken(std::vector<wchar_t>& environmentBlock)
        {
            environmentBlock.clear();
            wchar_t* parentBlock = GetEnvironmentStringsW();
            if (parentBlock == nullptr)
                return false;

            // The token is lowercase hex, so the narrow-to-wide copy is exact.
            const std::wstring token(g_pipeToken.begin(), g_pipeToken.end());
            const std::wstring prefix(kNativePipeTokenEnvironmentVariable);
            const std::wstring assignment = prefix + L"=" + token;

            const wchar_t* cursor = parentBlock;
            while (*cursor != L'\0')
            {
                const size_t length = wcslen(cursor);
                // Replace an inherited value instead of appending a second
                // entry: Windows uses the first match.
                if (wcsncmp(cursor, prefix.c_str(), prefix.size()) == 0 && cursor[prefix.size()] == L'=')
                {
                    cursor += length + 1;
                    continue;
                }
                environmentBlock.insert(environmentBlock.end(), cursor, cursor + length + 1);
                cursor += length + 1;
            }

            // The assignment is the only guaranteed entry (the parent block is
            // never empty in practice, but a leading empty string would make
            // CreateProcessW treat the whole block as empty).
            environmentBlock.insert(environmentBlock.end(), assignment.begin(), assignment.end());
            environmentBlock.push_back(L'\0');
            // The block ends with an extra terminator.
            environmentBlock.push_back(L'\0');

            FreeEnvironmentStringsW(parentBlock);
            return true;
        }

        // Single dispatch table for bridge methods. Each method name appears
        // exactly once: the previous design listed every method in a gating
        // condition and again in a linear dispatch chain, so a method added to
        // the gate but forgotten in the chain silently fell through to
        // HandleModules(id, "GetAllModulesFromMemMap").
        struct BridgeMethodEntry
        {
            std::string_view method;
            std::string(*handler)(const std::string& request, const std::string& id);
        };

        // Adapters for the few handlers that ignore the request payload.
        std::string HandleSnapshotStateRequest(const std::string& request, const std::string& id)
        {
            (void)request;
            return HandleSnapshotState(id);
        }

        std::string HandleAllRegistersRequest(const std::string& request, const std::string& id)
        {
            (void)request;
            return HandleAllRegisters(id);
        }

        std::string HandleAllActiveThreadsRequest(const std::string& request, const std::string& id)
        {
            (void)request;
            return HandleAllActiveThreads(id);
        }

        std::string HandleAllModulesFromMemMap(const std::string& request, const std::string& id)
        {
            (void)request;
            return HandleModules(id, "GetAllModulesFromMemMap");
        }

        // X1: wait (bounded) for the client to consume the response before
        // the instance is disconnected. DisconnectNamedPipe discards any
        // outbound bytes the client has not read yet, so tearing down
        // immediately after the write loses data deterministically: a client
        // that is descheduled ~100 ms sees an empty read 10/10, and any
        // response larger than the 8 KiB kernel out-buffer is truncated the
        // same way (ListBreakpoints with 60+ items, full GetMemoryMap).
        //
        // The one-shot protocol never sends a second message on an instance:
        // the client reads exactly one response and closes. An inbound read
        // therefore pends until the client has consumed the response and
        // closed (ERROR_BROKEN_PIPE), which is exactly when disconnecting
        // stops discarding data. A zero-length ReadFile would complete
        // immediately and wait for nothing, so read one byte (there is never
        // a second request to consume). Bounded by the existing write
        // timeout; on timeout the caller disconnects anyway. Uses
        // WaitForPipeIo so g_stopRequested still wakes the wait promptly.
        bool WaitForClientDrain(HANDLE pipe, HANDLE ioEvent)
        {
            if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE || ioEvent == nullptr)
                return false;
            if (!ResetEvent(ioEvent))
                return false;
            OVERLAPPED overlapped{};
            overlapped.hEvent = ioEvent;
            char drainByte = 0;
            DWORD drainRead = 0;
            if (ReadFile(pipe, &drainByte, sizeof(drainByte), &drainRead, &overlapped))
                return true;
            const DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE)
                return true; // Client already closed after reading.
            if (error == ERROR_PIPE_NOT_CONNECTED)
                return true; // Torn down already; nothing left to protect.
            if (error != ERROR_IO_PENDING)
                return false;
            if (!WaitForPipeIo(pipe, overlapped, kPipeWriteTimeoutMilliseconds))
                return false;
            DWORD ignored = 0;
            if (GetOverlappedResult(pipe, &overlapped, &ignored, FALSE))
                return true;
            const DWORD drainError = GetLastError();
            return drainError == ERROR_BROKEN_PIPE || drainError == ERROR_PIPE_NOT_CONNECTED;
        }

        // A landed CallFunction return is reported once, on the next ok:true
        // response, as additive `returnValue` + `registersAfter` members of
        // the existing result object. Error envelopes never carry it, and a
        // response without a result object leaves it queued for the next one.
        //
        // SEC N8: merged structurally (parse/build), never by string splice.
        // The old substring insert produced invalid JSON for an empty `{}`:
        // `"result":{"returnValue":...,"registersAfter":{...},}` (trailing
        // comma). Normal-case bytes are unchanged: returnValue/registersAfter
        // still lead the result object and every other member keeps its order
        // and encoding. The capture is consumed only on a successful merge,
        // so every early return below leaves it queued exactly as before.
        void AttachLandedCallReturn(std::string& response)
        {
            if (response.find("\"ok\":true") == std::string::npos)
                return;
            if (!g_lastCallReturn.ready)
                return;
            nlohmann::ordered_json envelope;
            try
            {
                envelope = nlohmann::ordered_json::parse(response);
            }
            catch (const nlohmann::json::exception&)
            {
                return;
            }
            if (!envelope.is_object())
                return;
            const auto okIt = envelope.find("ok");
            if (okIt == envelope.end() || !okIt->is_boolean() || !okIt->get<bool>())
                return;
            const auto resultIt = envelope.find("result");
            if (resultIt == envelope.end() || !resultIt->is_object())
                return;
            CallReturnCapture capture;
            if (!TakeLastCallReturn(capture))
                return;
            nlohmann::ordered_json registersAfter = nlohmann::ordered_json::object();
            if constexpr (sizeof(std::uintptr_t) == 8)
            {
                registersAfter["rip"] = capture.cip;
                registersAfter["rsp"] = capture.csp;
                registersAfter["rax"] = capture.returnValue;
            }
            else
            {
                registersAfter["eip"] = capture.cip;
                registersAfter["esp"] = capture.csp;
                registersAfter["eax"] = capture.returnValue;
            }
            nlohmann::ordered_json merged = nlohmann::ordered_json::object();
            merged["returnValue"] = capture.returnValue;
            merged["registersAfter"] = std::move(registersAfter);
            for (auto member = resultIt->begin(); member != resultIt->end(); ++member)
                merged[member.key()] = member.value();
            envelope["result"] = std::move(merged);
            response = envelope.dump();
        }

        constexpr BridgeMethodEntry kBridgeMethods[] = {
            {"GetAnalysisSnapshot", HandleAnalysisSnapshot},
            {"GetModuleRecords", HandleModuleRecords},
            {"GetSnapshotState", HandleSnapshotStateRequest},
            {"GetCurrentContext", HandleCurrentContext},
            {"GetAllRegisters", HandleAllRegistersRequest},
            {"GetAllActiveThreads", HandleAllActiveThreadsRequest},
            {"GetCallStack", HandleCallStack},
            {"SampleCallStacks", HandleSampleCallStacks},
            {"ReadMemAtAddress", HandleReadMemory},
            {"ReadDismAtAddress", HandleDisassembly},
            {"FindBytePatternInModule", HandleFindBytePatternInModule},
            {"FindStringInModule", HandleFindStringInModule},
            {"FindInterestingStrings", HandleFindInterestingStrings},
            {"GetXrefs", HandleGetXrefs},
            {"InspectAddressStructure", HandleInspectAddressStructure},
            {"TraceStringReferences", HandleTraceStringReferences},
            {"ReadStringAtAddress", HandleReadString},
            {"GetAllModulesFromMemMap", HandleAllModulesFromMemMap},
            {"OpenDebugTarget", HandleOpenDebugTarget},
            {"SetBreakpoint", HandleSetBreakpoint},
            {"ClearBreakpoint", HandleClearBreakpoint},
            {"ListBreakpoints", HandleListBreakpoints},
            {"StepInto", HandleStepInto},
            {"StepOver", HandleStepOver},
            {"StepOut", HandleStepOut},
            {"RunDebugger", HandleRunDebugger},
            {"PauseDebugger", HandlePauseDebugger},
            {"ContinueDebugger", HandleContinueDebugger},
            {"SetRegister", HandleSetRegister},
            {"WriteMemory", HandleWriteMemory},
            {"CallFunction", HandleCallFunction},
            {"SwitchThread", HandleSwitchThread},
            {"ListThreads", HandleListThreads},
            {"GetBacktrace", HandleBacktrace},
            {"ReadMemoryChunk", HandleReadMemoryChunk},
            {"ReadDisassemblyChunk", HandleReadDisassemblyChunk},
            {"EvaluateExpression", HandleEvaluateExpression},
            {"GetMemoryMap", HandleGetMemoryMap},
            {"GetModuleFunctions", HandleGetModuleFunctions},
            {"SetLabel", HandleSetLabel},
            {"SetComment", HandleSetComment},
            {"SetBookmark", HandleSetBookmark},
        };
    }

    std::string HandleRequest(const std::string& request)
    {
        BeginJsonRequestParse(request);
        if (!IsJsonObjectRequest(request))
            return ErrorResponse("null", "Native bridge request is invalid JSON.");

        const auto id = ExtractId(request);

        // N1 pipe auth: when the plugin holds a session token, every request
        // must carry the exact top-level "token" or nothing executes. The
        // empty-token path exists only for the unit-test harness; production
        // always generates a token at startup.
        if (!g_pipeToken.empty())
        {
            std::string presented;
            if (!ExtractEnvelopeString(request, "token", presented) ||
                !ConstantTimeEquals(presented, g_pipeToken))
            {
                return UnauthorizedResponse(id, "Missing or invalid bridge token.");
            }
        }

        std::string method;
        if (!ExtractJsonString(request, "method", method))
            return ErrorResponse(id, "Native bridge request requires a method.");

        if (method == "ping" || method == "GetServerStatus")
        {
            const bool debugging = IsDebugging();

            return "{\"id\":" + id +
                ",\"ok\":true,\"plugin\":\"DBGLink\",\"bridge\":\"native\",\"pid\":" +
                std::to_string(GetCurrentProcessId()) +
                ",\"debugging\":" + (debugging ? "true" : "false") +
                ",\"capabilities\":{\"analysisSnapshot\":true}}";
        }

        for (const auto& entry : kBridgeMethods)
        {
            if (method != entry.method)
                continue;
            // Every bridge method runs under g_debuggerCallMutex: handlers
            // read debugger state, and ApplyPendingCallRestore must land an
            // in-flight CallFunction return before any of them runs.
            // SEC N3: SampleCallStacks is the exception. It samples with
            // Sleep-spaced snapshots and takes the mutex per snapshot
            // itself, so the dispatcher must not hold it across the call:
            // std::mutex is non-recursive (holding it here would deadlock
            // the handler) and holding it across Sleeps would starve
            // Pause/WriteMemory/CallFunction meanwhile.
            if (entry.handler == HandleSampleCallStacks)
            {
                {
                    std::lock_guard<std::mutex> lock(g_debuggerCallMutex);
                    ApplyPendingCallRestore();
                }
                std::string response = entry.handler(request, id);
                {
                    std::lock_guard<std::mutex> lock(g_debuggerCallMutex);
                    AttachLandedCallReturn(response);
                }
                return response;
            }
            std::lock_guard<std::mutex> lock(g_debuggerCallMutex);
            // Land any pending CallFunction return (csp restore) before a
            // handler reads debugger state.
            ApplyPendingCallRestore();
            std::string response = entry.handler(request, id);
            AttachLandedCallReturn(response);
            return response;
        }

        return ErrorResponse(id, "Unknown bridge method.");
    }

    void WakePipe() noexcept
    {
        try
        {
            const std::wstring fullName = L"\\\\.\\pipe\\" + g_pipeName;
            ScopedHandle client(CreateFileW(
                fullName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr));
            if (client)
            {
                // The wake ping only needs to unblock the pipe loop; it still
                // carries the session token so the loop does not log an auth
                // rejection for its own shutdown signal.
                std::string wake = "{\"id\":0,\"method\":\"ping\"";
                if (!g_pipeToken.empty())
                    wake += ",\"token\":\"" + g_pipeToken + "\"";
                wake += "}\n";
                DWORD written = 0;
                (void)WriteFile(client.get(), wake.data(), static_cast<DWORD>(wake.size()), &written, nullptr);
            }
        }
        catch (...)
        {
        }
    }

    void PipeLoopCore()
    {
        const std::wstring fullName = L"\\\\.\\pipe\\" + g_pipeName;
        constexpr DWORD pipeFlags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        std::vector<char> buffer(kPipeReadChunkBytes);
        // N1 pipe auth: the first instance is claimed with
        // FILE_FLAG_FIRST_PIPE_INSTANCE so a pre-existing pipe under our
        // randomized name (squat) fails creation instead of being adopted.
        bool firstInstance = true;

        while (!g_stopRequested)
        {
            SECURITY_ATTRIBUTES securityAttributes{};
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            if (!CreateLocalPipeSecurity(securityAttributes, securityDescriptor))
            {
                Log("Could not create local native pipe security.");
                return;
            }

            ScopedHandle pipe(CreateNamedPipeW(
                fullName.c_str(),
                pipeFlags | (firstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                8192,
                8192,
                1000,
                &securityAttributes));
            LocalFree(securityDescriptor);

            if (!pipe)
            {
                const DWORD error = GetLastError();
                if (firstInstance && (error == ERROR_ACCESS_DENIED || error == ERROR_PIPE_BUSY))
                {
                    Log("DBGLink native pipe name is already claimed by another server "
                        "(CreateNamedPipe error " + std::to_string(error) +
                        " with FILE_FLAG_FIRST_PIPE_INSTANCE); possible pipe squatting. "
                        "Refusing to serve and never adopting the pre-existing pipe.");
                    return;
                }
                Log("CreateNamedPipe failed: " + std::to_string(error));
                Sleep(50);
                continue;
            }
            firstInstance = false;

            ScopedHandle ioEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!ioEvent)
            {
                Log("CreateEvent failed for native pipe I/O: " + std::to_string(GetLastError()));
                continue;
            }

            const BOOL connected = ConnectPipeWithTimeout(pipe.get(), ioEvent.get()) ? TRUE : FALSE;

            if (!connected)
            {
                if (g_stopRequested)
                    return;
                continue;
            }

            std::string request;
            bool requestTooLarge = false;
            bool readFailed = false;
            const ULONGLONG requestDeadline =
                GetTickCount64() + kPipeRequestTimeoutMilliseconds;
            // SEC N7: the first chunk carries the shorter first-byte budget so
            // a connected-but-idle holder is dropped fast. Later chunks keep
            // the existing 2 s cap and the 10 s total is unchanged.
            bool firstChunk = true;
            for (;;)
            {
                const ULONGLONG now = GetTickCount64();
                if (now >= requestDeadline)
                {
                    readFailed = true;
                    break;
                }
                const DWORD chunkBudget = firstChunk
                    ? kPipeFirstByteTimeoutMilliseconds
                    : kPipeReadTimeoutMilliseconds;
                const DWORD readTimeout = static_cast<DWORD>(std::min<ULONGLONG>(
                    requestDeadline - now,
                    chunkBudget));
                DWORD read = 0;
                bool moreData = false;
                const bool readSucceeded = ReadPipeChunk(
                    pipe.get(),
                    ioEvent.get(),
                    buffer.data(),
                    static_cast<DWORD>(buffer.size()),
                    read,
                    moreData,
                    readTimeout);
                firstChunk = false;
                if (read > 0 && !requestTooLarge)
                {
                    const std::size_t remaining = request.size() < kMaxPipeRequestBytes
                        ? kMaxPipeRequestBytes - request.size()
                        : 0;
                    const std::size_t accepted = std::min<std::size_t>(remaining, read);
                    request.append(buffer.data(), accepted);
                    if (accepted < read)
                        requestTooLarge = true;
                }

                if (!readSucceeded)
                {
                    readFailed = true;
                    break;
                }

                if (!moreData)
                    break;
            }

            try
            {
                std::string response;
                if (requestTooLarge)
                {
                    response = ErrorResponse("null", "Native bridge request exceeds the 65536-byte limit.");
                }
                else if (readFailed)
                {
                    response = ErrorResponse("null", "Native bridge request could not be read.");
                }
                else
                {
                    response = HandleRequest(request);
                }

                if (response.size() >= kMaxPipeResponseBytes)
                    response = ErrorResponse("null", "Native bridge response exceeds the bounded response size.");
                response.push_back('\n');
                const DWORD responseSize = static_cast<DWORD>(response.size());
                if (!WritePipeMessageWithTimeout(
                        pipe.get(),
                        ioEvent.get(),
                        response.data(),
                        responseSize,
                        kPipeWriteTimeoutMilliseconds))
                {
                    Log("Native bridge response write failed.");
                }
                else
                {
                    // X1 drain: a successful write only queues the response.
                    // Disconnecting now would discard whatever the client has
                    // not read yet (empty reads under load, truncated large
                    // responses). Hold the instance until the client consumes
                    // the message and closes, or the bounded drain expires.
                    (void)WaitForClientDrain(pipe.get(), ioEvent.get());
                }
            }
            catch (...)
            {
                Log("Native bridge request handling failed.");
            }
            DisconnectNamedPipe(pipe.get());
        }
    }

    void PipeLoop() noexcept
    {
        try
        {
            PipeLoopCore();
        }
        catch (...)
        {
            Log("Native bridge pipe loop stopped unexpectedly.");
            g_stopRequested = true;
        }
    }

    std::wstring ModuleDirectory()
    {
        wchar_t path[MAX_PATH]{};
        const DWORD length = GetModuleFileNameW(g_module, path, MAX_PATH);
        if (length == 0 || length >= MAX_PATH)
            return L"";

        std::wstring result(path, length);
        const auto separator = result.find_last_of(L"\\/");
        return separator == std::wstring::npos ? L"" : result.substr(0, separator);
    }

    // Default loopback MCP port. Contractual user-facing default (matches
    // DbgLink.Server ServerConfig.DefaultPort); do not change the value.
    constexpr wchar_t kDefaultMcpPort[] = L"50301";

    std::wstring ServerPort()
    {
        wchar_t value[16]{};
        constexpr DWORD capacity = static_cast<DWORD>(sizeof(value) / sizeof(value[0]));
        const DWORD length = GetEnvironmentVariableW(L"DBGLINK_PORT", value, capacity);
        if (length == 0 || length >= capacity)
            return kDefaultMcpPort;

        wchar_t* end = nullptr;
        const unsigned long parsed = std::wcstoul(value, &end, 10);
        if (end == value || *end != L'\0' || parsed < 1 || parsed > 65535)
            return kDefaultMcpPort;
        return std::to_wstring(parsed);
    }

    bool EnvironmentFlagEnabled(const wchar_t* name)
    {
        wchar_t value[16]{};
        constexpr DWORD capacity = static_cast<DWORD>(sizeof(value) / sizeof(value[0]));
        const DWORD length = GetEnvironmentVariableW(name, value, capacity);
        if (length == 0 || length >= capacity)
            return false;

        return _wcsicmp(value, L"1") == 0 ||
            _wcsicmp(value, L"true") == 0 ||
            _wcsicmp(value, L"yes") == 0;
    }

    void StartServerProcess()
    {
        if (EnvironmentFlagEnabled(L"DBGLINK_SKIP_SERVER_AUTOSTART"))
        {
            Log("DBGLink server auto-start is disabled for the launcher-managed session.");
            return;
        }

        const std::wstring directory = ModuleDirectory();
        if (directory.empty())
        {
            Log("Could not resolve plugin directory; server auto-start skipped.");
            return;
        }

        const std::wstring serverPath = directory + L"\\DbgLink.Server.exe";
        if (!IsSafeLocalPath(serverPath))
        {
            Log("DbgLink.Server.exe is not a safe regular file beside the plugin; start the server manually for now.");
            return;
        }

        std::wstring commandLine = L"\"" + serverPath + L"\" --pipe-name \"" + g_pipeName +
            L"\" --port " + ServerPort();
        // N1 pipe auth: the auto-started server must present the same session
        // token the plugin requires on every request. The token is a
        // per-session credential, so it travels in the child's environment
        // block, NOT on the command line: argv is readable by every local
        // process through Win32_Process.CommandLine.
        std::vector<wchar_t> environmentBlock;
        if (!g_pipeToken.empty())
        {
            if (!BuildEnvironmentWithToken(environmentBlock))
            {
                Log("Could not build the server environment block; server auto-start skipped.");
                return;
            }
        }
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};

        DWORD creationFlags = CREATE_NO_WINDOW;
        void* environment = nullptr;
        if (!environmentBlock.empty())
        {
            creationFlags |= CREATE_UNICODE_ENVIRONMENT;
            environment = environmentBlock.data();
        }

        if (!CreateProcessW(
            serverPath.c_str(),
            commandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            creationFlags,
            environment,
            directory.c_str(),
            &startup,
            &process))
        {
            Log("Could not start DbgLink.Server.exe: " + std::to_string(GetLastError()));
            return;
        }

        CloseHandle(process.hThread);
        g_serverProcess = process.hProcess;
        Log("DBGLink native bridge started the local .NET server.");
    }

}
