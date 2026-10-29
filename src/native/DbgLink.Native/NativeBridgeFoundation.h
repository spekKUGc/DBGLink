#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    extern std::mutex g_debuggerCallMutex;
    extern HANDLE g_serverProcess;
    extern std::wstring g_pipeName;
    // N1 pipe auth: per-session bridge token (32 CSPRNG bytes as 64 lowercase
    // hex). Empty means no token is required (unit-test harness only); the
    // plugin always generates one at startup and HandleRequest rejects every
    // request whose top-level "token" does not match exactly.
    extern std::string g_pipeToken;
    // Test-only rendezvous path override. Empty selects the production
    // %LOCALAPPDATA%\DBGLink\native-endpoint-<pid>.json location.
    extern std::wstring g_rendezvousPathOverride;
    extern std::thread g_pipeThread;
    extern std::atomic_bool g_stopRequested;
    extern std::atomic<std::uint64_t> g_debuggerGeneration;
    extern HMODULE g_module;
    // State of an in-flight CallFunction injection. Guarded by
    // g_debuggerCallMutex: the injected `ret` lands on a temporary breakpoint
    // at the original cip, and the next bridge request under the mutex
    // restores csp before any original instruction executes.
    struct PendingCallRestore
    {
        bool armed = false;
        bool ownsBreakpoint = false;
        std::uintptr_t returnAddress = 0; // original cip (temporary bp here)
        std::uintptr_t restoreCsp = 0;    // original csp to restore
        std::uintptr_t expectedCsp = 0;   // csp right after the injected ret
    };
    extern PendingCallRestore g_pendingCallRestore;
    // Result captured when an in-flight CallFunction injection lands on its
    // temporary return breakpoint. Filled by ApplyPendingCallRestore before
    // the csp restore; consumed once by HandleRequest, which merges it into
    // the next ok:true bridge response as additive `returnValue` (rax/eax by
    // bitness) and `registersAfter` (rip/rsp/rax or eip/esp/eax hex).
    struct CallReturnCapture
    {
        bool ready = false;
        std::string returnValue;
        std::string cip;
        std::string csp;
    };
    extern CallReturnCapture g_lastCallReturn;
    // Consume-once take; returns false when no call return landed since the
    // previous take. Callers merge the fragment only into ok:true responses
    // so error envelopes stay clean and the value survives until delivered.
    bool TakeLastCallReturn(CallReturnCapture& out);
    // NOTE: the legacy LastCallReturnFragment string-splice helper was
    // removed (m6 dead code): NativePipeServer now merges the capture
    // structurally via ordered_json, so no string fragment is needed.
    struct ScopedHandle
    {
        HANDLE value = nullptr;

        ScopedHandle() = default;
        explicit ScopedHandle(HANDLE handle) : value(handle) {}
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        void reset(HANDLE handle = nullptr)
        {
            if (value != nullptr && value != INVALID_HANDLE_VALUE)
                CloseHandle(value);
            value = handle;
        }

        ~ScopedHandle()
        {
            if (value != nullptr && value != INVALID_HANDLE_VALUE)
                CloseHandle(value);
        }

        HANDLE get() const { return value; }
        explicit operator bool() const { return value != nullptr && value != INVALID_HANDLE_VALUE; }
    };
    const wchar_t* DebuggerBridgeModuleName();
    template <typename T>
    T GetDebuggerBridgeFunction(const char* name)
    {
        const HMODULE bridge = GetModuleHandleW(DebuggerBridgeModuleName());
        return bridge == nullptr ? nullptr : reinterpret_cast<T>(GetProcAddress(bridge, name));
    }
    // Shared bridge lookups used by several handler TUs: the previous code
    // re-implemented these two-liners (and the ExecDirect lookup) per file.
    inline bool IsDebugging()
    {
        auto isDebugging = GetDebuggerBridgeFunction<DbgIsDebuggingFunction>("DbgIsDebugging");
        return isDebugging != nullptr && isDebugging();
    }
    inline bool IsRunning()
    {
        auto isRunning = GetDebuggerBridgeFunction<DbgIsDebuggingFunction>("DbgIsRunning");
        return isRunning != nullptr && isRunning();
    }
    inline bool ExecDirect(const std::string& command)
    {
        auto execute = GetDebuggerBridgeFunction<DbgCmdExecDirectFunction>("DbgCmdExecDirect");
        return execute != nullptr && execute(command.c_str());
    }
    // True when a software (normal) breakpoint already exists at the address.
    bool SoftBreakpointExists(std::uintptr_t address);
    // After an injected CallFunction returns to its temporary breakpoint,
    // restores the original csp and removes the breakpoint we created.
    // The caller must hold g_debuggerCallMutex.
    void ApplyPendingCallRestore();
    void Log(const std::string& text) noexcept;
    bool IsSafeLocalPath(const std::wstring& path);
    // Fixed-time equality for secret comparison (token validation). Returns
    // false on length mismatch; the accumulation loop itself is constant-time
    // in the shared length.
    bool ConstantTimeEquals(std::string_view left, std::string_view right);
    // 32 OS-CSPRNG bytes rendered as 64 lowercase hex (N1 session token).
    bool GenerateSessionToken(std::string& token);
    // 4 OS-CSPRNG bytes rendered as 8 lowercase hex (pipe-name suffix).
    bool GeneratePipeSuffix(std::wstring& suffix);
    // DbgLink.Control.<pid>.<8 hex suffix> (without the \\.\pipe\ prefix).
    std::wstring BuildPipeName(DWORD pid, const std::wstring& suffix);
    // Rendezvous file location
    // (%LOCALAPPDATA%\DBGLink\native-endpoint-<pid>.json) or the test
    // override when set.
    std::wstring RendezvousPath();
    // Atomically (tmp + move) writes the rendezvous JSON with a user-only
    // DACL; false leaves nothing behind for the launcher to consume.
    bool WriteRendezvousFile();
    // Deletes the rendezvous file; best-effort, never throws.
    void RemoveRendezvousFile() noexcept;
    bool CreateLocalPipeSecurity(
        SECURITY_ATTRIBUTES& attributes,
        PSECURITY_DESCRIPTOR& descriptor);
    bool WaitForPipeIo(HANDLE pipe, OVERLAPPED& overlapped, DWORD timeoutMilliseconds);
    bool ConnectPipeWithTimeout(HANDLE pipe, HANDLE ioEvent);
    bool ReadPipeChunk(
        HANDLE pipe,
        HANDLE ioEvent,
        void* buffer,
        DWORD bufferSize,
        DWORD& bytesRead,
        bool& moreData,
        DWORD timeoutMilliseconds);
    bool WritePipeMessageWithTimeout(
        HANDLE pipe,
        HANDLE ioEvent,
        const void* buffer,
        DWORD bufferSize,
        DWORD timeoutMilliseconds);
}
