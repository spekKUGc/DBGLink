#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeCommandText.h"
#include "NativeJsonFormatting.h"

namespace dbglink
{
    // RtlGenRandom: OS CSPRNG exported by Advapi32 (already linked). Never
    // rand(): the session token and pipe suffix must be unpredictable.
    extern "C" BOOLEAN WINAPI SystemFunction036(PVOID randomBuffer, ULONG randomBufferLength);

    namespace
    {
        constexpr char kLowerHex[] = "0123456789abcdef";

        bool FillSecureRandom(void* buffer, std::size_t size)
        {
            if (buffer == nullptr || size == 0 || size > ULONG_MAX)
                return false;
            return SystemFunction036(buffer, static_cast<ULONG>(size)) == TRUE;
        }

        template <typename Char>
        void AppendLowerHex(std::basic_string<Char>& out, const unsigned char* bytes, std::size_t count)
        {
            out.reserve(out.size() + count * 2);
            for (std::size_t i = 0; i < count; ++i)
            {
                out.push_back(static_cast<Char>(kLowerHex[bytes[i] >> 4]));
                out.push_back(static_cast<Char>(kLowerHex[bytes[i] & 0x0F]));
            }
        }

        std::string WideToUtf8(const std::wstring& text)
        {
            if (text.empty())
                return {};
            const int required = WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                nullptr, 0, nullptr, nullptr);
            if (required <= 0)
                return {};
            std::string result(static_cast<std::size_t>(required), '\0');
            if (WideCharToMultiByte(
                    CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                    result.data(), required, nullptr, nullptr) != required)
                return {};
            return result;
        }

        std::wstring DebuggerImagePath()
        {
            std::vector<wchar_t> buffer(32768, L'\0');
            const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (length == 0 || length >= buffer.size())
                return L"";
            return std::wstring(buffer.data(), length);
        }

        bool CurrentUserOnlySddl(std::wstring& sddl)
        {
            HANDLE tokenHandle = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
                return false;
            ScopedHandle token(tokenHandle);

            DWORD requiredBytes = 0;
            if (GetTokenInformation(token.get(), TokenUser, nullptr, 0, &requiredBytes) ||
                GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
                requiredBytes == 0 || requiredBytes > 64 * 1024)
            {
                return false;
            }

            std::vector<unsigned char> tokenBuffer(requiredBytes);
            if (!GetTokenInformation(
                    token.get(),
                    TokenUser,
                    tokenBuffer.data(),
                    requiredBytes,
                    &requiredBytes))
            {
                return false;
            }

            const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.data());
            if (tokenUser->User.Sid == nullptr || !IsValidSid(tokenUser->User.Sid))
                return false;

            LPWSTR sidText = nullptr;
            if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidText) || sidText == nullptr)
                return false;
            std::wstring userSid(sidText);
            LocalFree(sidText);
            if (userSid.empty())
                return false;

            sddl = L"D:P(D;;GA;;;AN)(A;;GA;;;" + userSid + L")";
            return true;
        }
    }
    HMODULE g_module = nullptr;
    std::atomic_bool g_stopRequested = false;
    std::atomic<std::uint64_t> g_debuggerGeneration{0};
    std::thread g_pipeThread;
    std::wstring g_pipeName;
    std::string g_pipeToken;
    std::wstring g_rendezvousPathOverride;
    HANDLE g_serverProcess = nullptr;
    std::mutex g_debuggerCallMutex;
    PendingCallRestore g_pendingCallRestore{};
    CallReturnCapture g_lastCallReturn{};

    bool SoftBreakpointExists(std::uintptr_t address)
    {
        auto getList = GetDebuggerBridgeFunction<DbgGetBpListFunction>("DbgGetBpList");
        auto bridgeFree = GetDebuggerBridgeFunction<BridgeFreeFunction>("BridgeFree");
        if (getList == nullptr || bridgeFree == nullptr || address == 0)
            return false;

        NativeBreakpointMapGuard guard;
        guard.freeFunction = bridgeFree;
        const int count = getList(static_cast<int>(BpListType::Normal), &guard.map);
        if (count < 0 || !ValidateBridgeList(guard.map.count, guard.map.bp, 4096))
            return false;

        for (int i = 0; i < guard.map.count; ++i)
        {
            if (guard.map.bp[i].addr == address)
                return true;
        }
        return false;
    }

    void ApplyPendingCallRestore()
    {
        if (!g_pendingCallRestore.armed)
            return;

        auto valueFromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        if (valueFromString == nullptr)
            return;
        if (!IsDebugging())
        {
            // The session ended; any breakpoint we created is gone with it.
            g_pendingCallRestore = {};
            g_lastCallReturn = {};
            return;
        }
        if (IsRunning())
            return;

        const std::uintptr_t cip = valueFromString("cip");
        const std::uintptr_t csp = valueFromString("csp");
        const bool trapPresent = SoftBreakpointExists(g_pendingCallRestore.returnAddress);

        if (cip == g_pendingCallRestore.returnAddress &&
            csp == g_pendingCallRestore.expectedCsp)
        {
            // Our injected `ret` just landed on the return point. Snapshot
            // the return value and post-ret registers BEFORE restoring csp:
            // rax/eax holds the callee result, cip is the return address,
            // csp is the post-ret stack (pre-restore). Idempotent: a failed
            // csp write retries on the next request and rewrites identical
            // values.
            const char* retReg = sizeof(std::uintptr_t) == 8 ? "rax" : "eax";
            g_lastCallReturn = CallReturnCapture{
                true, HexAddress(valueFromString(retReg)), HexAddress(cip), HexAddress(csp)};
            // The csp write below restores the original stack; the captured
            // post-ret csp stays in registersAfter for the agent to see.
            auto toString = GetDebuggerBridgeFunction<DbgValToStringFunction>("DbgValToString");
            if (toString == nullptr || !toString("csp", g_pendingCallRestore.restoreCsp))
            {
                // Keep armed so the next request retries the csp write.
                Log("CallFunction restore: the debugger rejected the csp write.");
                return;
            }

            if (g_pendingCallRestore.ownsBreakpoint && trapPresent)
                (void)ExecDirect("bc " + HexAddress(g_pendingCallRestore.returnAddress));
            g_pendingCallRestore = {};
            return;
        }

        // Keep the return trap armed for the whole in-flight call: without it
        // the injected `ret` would resume the original code with a csp still
        // shifted by the reserved frame.
        if (!trapPresent &&
            ExecDirect("bp " + HexAddress(g_pendingCallRestore.returnAddress)))
            g_pendingCallRestore.ownsBreakpoint = true;
    }

    bool TakeLastCallReturn(CallReturnCapture& out)
    {
        if (!g_lastCallReturn.ready)
            return false;
        out = g_lastCallReturn;
        g_lastCallReturn = {};
        return true;
    }


    const wchar_t* DebuggerBridgeModuleName()
    {
        return sizeof(std::uintptr_t) == 8 ? L"x64bridge.dll" : L"x32bridge.dll";
    }



    void Log(const std::string& text) noexcept
    {
        try
        {
            // The log target is the host debugger module: x64dbg.dll on
            // 64-bit, x32dbg.dll on 32-bit. Probing only one name leaves the
            // other bitness logging to OutputDebugStringA.
            HMODULE dbg = GetModuleHandleW(L"x64dbg.dll");
            if (dbg == nullptr)
                dbg = GetModuleHandleW(L"x32dbg.dll");
            if (dbg)
            {
                auto logPuts = reinterpret_cast<PluginLogPuts>(GetProcAddress(dbg, "_plugin_logputs"));
                if (logPuts)
                {
                    logPuts((text + "\n").c_str());
                    return;
                }
            }

            OutputDebugStringA(("[DBGLink] " + text + "\n").c_str());
        }
        catch (...)
        {
            OutputDebugStringA("[DBGLink] logging failed.\n");
        }
    }

    bool IsSafeLocalPath(const std::wstring& path)
    {
        // SEC J5 mirror of the OpenDebugTarget drive-path gate: device names
        // (CON/NUL/...) resolve to devices, never to the regular file the
        // only caller launches with CreateProcessW. Mirrors the
        // IsLocalAbsoluteDrivePath ADS/mixed-separator rules: any `:` past
        // the drive colon is an NTFS stream, any doubled separator
        // (`\\`, `//`, `\/`, `/\`) is UNC smuggling, and `?` only appears in
        // device prefixes.
        for (std::size_t i = 0; i < path.size(); ++i)
        {
            if (path[i] == L':' && i != 1)
                return false;
            if (path[i] == L'?')
                return false;
            if (i + 1 < path.size())
            {
                const bool aSep = path[i] == L'\\' || path[i] == L'/';
                const bool bSep = path[i + 1] == L'\\' || path[i + 1] == L'/';
                if (aSep && bSep)
                    return false;
            }
        }
        if (PathHasDosDeviceComponent(std::wstring_view(path)))
            return false;
        if (path.size() < 3 || path.size() >= 32768 || path[1] != L':' ||
            (path[2] != L'\\' && path[2] != L'/'))
        {
            return false;
        }

        std::wstring current = path;
        for (int depth = 0; depth < 64; ++depth)
        {
            const DWORD attributes = GetFileAttributesW(current.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                return false;
            }
            // The plugin auto-start target must be a regular file, never a
            // directory: the only caller launches it with CreateProcessW.
            if (current == path &&
                (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                return false;
            }

            const auto separator = current.find_last_of(L"\\/");
            if (separator == std::wstring::npos)
                return true;

            std::wstring parent = current.substr(0, separator);
            if (parent.size() == 2 && parent[1] == L':')
                parent.push_back(L'\\');
            if (parent.empty() || parent == current)
                return true;
            current = std::move(parent);
        }

        return false;
    }

    bool CreateLocalPipeSecurity(
        SECURITY_ATTRIBUTES& attributes,
        PSECURITY_DESCRIPTOR& descriptor)
    {
        attributes = {};
        descriptor = nullptr;
        // Use an explicit ACL because the x64dbg process default DACL can be
        // inherited from an elevated or hardened host and deny the ordinary
        // launcher/server client. Grant access only to the account that owns
        // the debugger; PIPE_REJECT_REMOTE_CLIENTS below adds a separate
        // remote-client defense.
        std::wstring pipeSecurity;
        if (!CurrentUserOnlySddl(pipeSecurity))
            return false;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                pipeSecurity.c_str(), SDDL_REVISION_1, &descriptor, nullptr) || descriptor == nullptr)
        {
            descriptor = nullptr;
            return false;
        }
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
        attributes.bInheritHandle = FALSE;
        return true;
    }

    bool WaitForPipeIo(HANDLE pipe, OVERLAPPED& overlapped, DWORD timeoutMilliseconds)
    {
        const ULONGLONG deadline = GetTickCount64() + std::max<DWORD>(1, timeoutMilliseconds);
        while (!g_stopRequested)
        {
            const ULONGLONG now = GetTickCount64();
            if (now >= deadline)
                break;
            const ULONGLONG remaining = deadline - now;

            const DWORD waitMilliseconds = static_cast<DWORD>(std::min<ULONGLONG>(
                remaining,
                kPipeIoStopPollMilliseconds));
            const DWORD waitResult = WaitForSingleObject(overlapped.hEvent, waitMilliseconds);
            if (waitResult == WAIT_OBJECT_0)
                return true;
            if (waitResult == WAIT_FAILED)
                break;
        }

        (void)CancelIoEx(pipe, &overlapped);
        // OVERLAPPED and its event are owned by the caller's stack frame.  Do
        // not let either leave scope until cancellation has completed.
        DWORD ignored = 0;
        (void)GetOverlappedResult(pipe, &overlapped, &ignored, TRUE);
        return false;
    }

    bool ConnectPipeWithTimeout(HANDLE pipe, HANDLE ioEvent)
    {
        if (ioEvent == nullptr || !ResetEvent(ioEvent))
            return false;

        OVERLAPPED overlapped{};
        overlapped.hEvent = ioEvent;
        if (ConnectNamedPipe(pipe, &overlapped))
            return true;

        const DWORD error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED)
            return true;
        if (error != ERROR_IO_PENDING || !WaitForPipeIo(pipe, overlapped, kPipeConnectTimeoutMilliseconds))
            return false;

        DWORD ignored = 0;
        if (GetOverlappedResult(pipe, &overlapped, &ignored, FALSE))
            return true;
        return GetLastError() == ERROR_PIPE_CONNECTED;
    }

    bool ReadPipeChunk(
        HANDLE pipe,
        HANDLE ioEvent,
        void* buffer,
        DWORD bufferSize,
        DWORD& bytesRead,
        bool& moreData,
        DWORD timeoutMilliseconds)
    {
        bytesRead = 0;
        moreData = false;
        if (ioEvent == nullptr || !ResetEvent(ioEvent))
            return false;

        OVERLAPPED overlapped{};
        overlapped.hEvent = ioEvent;
        if (ReadFile(pipe, buffer, bufferSize, &bytesRead, &overlapped))
            return true;

        DWORD error = GetLastError();
        if (error == ERROR_MORE_DATA)
        {
            moreData = true;
            return true;
        }
        if (error != ERROR_IO_PENDING || !WaitForPipeIo(pipe, overlapped, timeoutMilliseconds))
            return false;

        if (GetOverlappedResult(pipe, &overlapped, &bytesRead, FALSE))
            return true;

        error = GetLastError();
        if (error == ERROR_MORE_DATA)
        {
            moreData = true;
            return true;
        }
        return false;
    }

    bool WritePipeMessageWithTimeout(
        HANDLE pipe,
        HANDLE ioEvent,
        const void* buffer,
        DWORD bufferSize,
        DWORD timeoutMilliseconds)
    {
        if (ioEvent == nullptr || !ResetEvent(ioEvent))
            return false;

        OVERLAPPED overlapped{};
        overlapped.hEvent = ioEvent;
        DWORD bytesWritten = 0;
        if (!WriteFile(pipe, buffer, bufferSize, &bytesWritten, &overlapped))
        {
            const DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING || !WaitForPipeIo(pipe, overlapped, timeoutMilliseconds) ||
                !GetOverlappedResult(pipe, &overlapped, &bytesWritten, FALSE))
            {
                return false;
            }
        }

        return bytesWritten == bufferSize;
    }

    bool ConstantTimeEquals(std::string_view left, std::string_view right)
    {
        if (left.size() != right.size())
            return false;
        unsigned char diff = 0;
        for (std::size_t i = 0; i < left.size(); ++i)
            diff |= static_cast<unsigned char>(left[i] ^ right[i]);
        return diff == 0;
    }

    bool GenerateSessionToken(std::string& token)
    {
        unsigned char bytes[32]{};
        if (!FillSecureRandom(bytes, sizeof(bytes)))
            return false;
        token.clear();
        AppendLowerHex(token, bytes, sizeof(bytes));
        SecureZeroMemory(bytes, sizeof(bytes));
        return token.size() == 64;
    }

    bool GeneratePipeSuffix(std::wstring& suffix)
    {
        unsigned char bytes[4]{};
        if (!FillSecureRandom(bytes, sizeof(bytes)))
            return false;
        suffix.clear();
        AppendLowerHex(suffix, bytes, sizeof(bytes));
        SecureZeroMemory(bytes, sizeof(bytes));
        return suffix.size() == 8;
    }

    std::wstring BuildPipeName(DWORD pid, const std::wstring& suffix)
    {
        return std::wstring(kPipePrefix) + std::to_wstring(pid) + L"." + suffix;
    }

    std::wstring RendezvousPath()
    {
        if (!g_rendezvousPathOverride.empty())
            return g_rendezvousPathOverride;
        wchar_t localAppData[MAX_PATH]{};
        const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
        if (length == 0 || length >= MAX_PATH)
            return L"";
        std::wstring directory(localAppData, length);
        if (directory.size() + 64 >= 32768)
            return L"";
        // N1 per-PID rendezvous (B4/B5): one file per debugger process so two
        // x64dbg instances never clobber each other's pipe/token record. The
        // launcher reads native-endpoint-<pid>.json for the pid it spawned.
        return directory + L"\\DBGLink\\native-endpoint-" +
            std::to_wstring(GetCurrentProcessId()) + L".json";
    }

    bool WriteRendezvousFile()
    {
        if (g_pipeToken.empty() || g_pipeName.empty())
        {
            Log("DBGLink rendezvous write refused: no session token or pipe name.");
            return false;
        }
        const std::wstring path = RendezvousPath();
        if (path.empty() || path.size() >= 32768)
        {
            Log("DBGLink rendezvous write failed: %LOCALAPPDATA% is unavailable.");
            return false;
        }

        const auto separator = path.find_last_of(L"\\/");
        if (separator == std::wstring::npos)
            return false;
        // Best-effort directory creation; the write below still validates.
        (void)CreateDirectoryW(path.substr(0, separator).c_str(), nullptr);

        const std::string pipeUtf8 = WideToUtf8(L"\\\\.\\pipe\\" + g_pipeName);
        const std::string imageUtf8 = WideToUtf8(DebuggerImagePath());
        if (pipeUtf8.empty())
        {
            Log("DBGLink rendezvous write failed: pipe name is not representable.");
            return false;
        }
        const std::string content = "{\"schemaVersion\":1,\"pid\":" +
            std::to_string(GetCurrentProcessId()) +
            ",\"pipeName\":\"" + JsonEscape(pipeUtf8) +
            "\",\"token\":\"" + g_pipeToken +
            "\",\"debugger\":\"x64dbg\",\"imagePath\":\"" + JsonEscape(imageUtf8) + "\"}";

        const std::wstring tmpPath =
            path + L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";

        SECURITY_ATTRIBUTES securityAttributes{};
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        if (!CreateLocalPipeSecurity(securityAttributes, securityDescriptor))
        {
            Log("DBGLink rendezvous write failed: could not build the user-only security descriptor.");
            return false;
        }

        ScopedHandle file(CreateFileW(
            tmpPath.c_str(),
            GENERIC_WRITE,
            0,
            &securityAttributes,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
        LocalFree(securityDescriptor);
        if (!file)
        {
            Log("DBGLink rendezvous write failed: could not create the temporary file.");
            return false;
        }

        DWORD written = 0;
        const bool writeOk = WriteFile(
                file.get(), content.data(), static_cast<DWORD>(content.size()), &written, nullptr) &&
            written == content.size() &&
            FlushFileBuffers(file.get()) != FALSE;
        // Release the handle before any move/delete: the tmp file must not
        // stay open on the failure paths below.
        file.reset();
        if (!writeOk)
        {
            Log("DBGLink rendezvous write failed: could not write the temporary file.");
            (void)DeleteFileW(tmpPath.c_str());
            return false;
        }

        if (MoveFileExW(
                tmpPath.c_str(),
                path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE)
        {
            Log("DBGLink rendezvous publish failed: could not move the temporary file into place.");
            (void)DeleteFileW(tmpPath.c_str());
            return false;
        }
        // The intra-directory move preserves the user-only DACL the tmp file
        // was created with; nothing further to enforce.
        return true;
    }

    void RemoveRendezvousFile() noexcept
    {
        try
        {
            const std::wstring path = RendezvousPath();
            if (!path.empty())
                (void)DeleteFileW(path.c_str());
        }
        catch (...)
        {
        }
    }

}
