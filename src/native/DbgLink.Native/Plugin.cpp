#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativePipeServer.h"

using namespace dbglink;

// Exported callbacks are registered by x64dbg. Keep them allocation-free and
// independent of the request mutex so resume/stop transitions remain observable.
extern "C" __declspec(dllexport) void CBINITDEBUG(int, void*) noexcept { ++g_debuggerGeneration; }
extern "C" __declspec(dllexport) void CBSTOPDEBUG(int, void*) noexcept { ++g_debuggerGeneration; }
extern "C" __declspec(dllexport) void CBPAUSEDEBUG(int, void*) noexcept { ++g_debuggerGeneration; }
extern "C" __declspec(dllexport) void CBRESUMEDEBUG(int, void*) noexcept { ++g_debuggerGeneration; }
extern "C" __declspec(dllexport) void CBSTEPPED(int, void*) noexcept { ++g_debuggerGeneration; }
extern "C" __declspec(dllexport) void CBDEBUGEVENT(int, void*) noexcept { ++g_debuggerGeneration; }

namespace
{
    void StopOwnedServerProcess() noexcept
    {
        if (g_serverProcess == nullptr)
            return;

        if (WaitForSingleObject(g_serverProcess, 1500) != WAIT_OBJECT_0)
        {
            // This handle is retained only for the server process spawned by
            // this plugin instance.  Prevent an orphan from retaining the
            // fixed MCP port across plugin reloads.
            (void)TerminateProcess(g_serverProcess, ERROR_CANCELLED);
            (void)WaitForSingleObject(g_serverProcess, 1500);
        }

        CloseHandle(g_serverProcess);
        g_serverProcess = nullptr;
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_module = module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) noexcept
{
    try
    {
        if (!initStruct || g_pipeThread.joinable() || g_serverProcess != nullptr)
            return false;

        initStruct->sdkVersion = kPluginSdkVersion;
        initStruct->pluginVersion = kPluginVersion;
        strncpy_s(initStruct->pluginName, kPluginName, _TRUNCATE);

        g_stopRequested = false;
        // N1 pipe auth: per-session token + randomized pipe name. Both must
        // exist before the pipe thread starts (it serves under them).
        std::string sessionToken;
        if (!GenerateSessionToken(sessionToken))
        {
            Log("DBGLink native plugin refused to start: the OS CSPRNG produced no session token.");
            return false;
        }
        std::wstring pipeSuffix;
        if (!GeneratePipeSuffix(pipeSuffix))
        {
            Log("DBGLink native plugin refused to start: the OS CSPRNG produced no pipe-name suffix.");
            return false;
        }
        g_pipeToken = sessionToken;
        g_pipeName = BuildPipeName(GetCurrentProcessId(), pipeSuffix);
        g_pipeThread = std::thread(PipeLoop);
        // The launcher discovers the randomized endpoint through this file;
        // without it the session is unreachable, so fail closed.
        if (!WriteRendezvousFile())
        {
            Log("DBGLink native plugin refused to start: the rendezvous file could not be published.");
            g_stopRequested = true;
            WakePipe();
            try
            {
                if (g_pipeThread.joinable())
                    g_pipeThread.join();
            }
            catch (...)
            {
                Log("DBGLink native plugin initialization cleanup failed.");
            }
            g_pipeToken.clear();
            g_pipeName.clear();
            return false;
        }
        StartServerProcess();
        Log("DBGLink native plugin loaded.");
        return true;
    }
    catch (...)
    {
        g_stopRequested = true;
        WakePipe();
        try
        {
            if (g_pipeThread.joinable())
                g_pipeThread.join();
        }
        catch (...)
        {
            Log("DBGLink native plugin initialization cleanup failed.");
        }
        if (g_serverProcess != nullptr)
            StopOwnedServerProcess();
        RemoveRendezvousFile();
        g_pipeToken.clear();
        g_pipeName.clear();
        Log("DBGLink native plugin initialization failed.");
        return false;
    }
}

extern "C" __declspec(dllexport) bool plugstop() noexcept
{
    try
    {
        g_stopRequested = true;
        WakePipe();
        if (g_pipeThread.joinable())
            g_pipeThread.join();

        StopOwnedServerProcess();

        RemoveRendezvousFile();
        g_pipeToken.clear();
        g_pipeName.clear();

        Log("DBGLink native plugin stopped.");
        return true;
    }
    catch (...)
    {
        Log("DBGLink native plugin shutdown failed.");
        return false;
    }
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*) noexcept
{
}
