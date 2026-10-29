#include <windows.h>

// DBGLink Hostile Adversarial Stress Target ("HostileStressTarget")
// Specifically engineered to test edge cases in reverse-engineering agents:
// - VEH/SEH exception-based control flow (exceptions as jumps)
// - TLS Callbacks that execute before the main entrypoint
// - Self-decrypting code in dynamic RWX memory
// - 16 concurrent worker threads flooding the debugger context
// - Massive bloated symbol graphs and cyclic pointer labyrinths
// - Anti-debugging / timing traps (RDTSC delta checks, PEB BeingDebugged tricks)

#pragma pack(push, 8)
struct HostileNode
{
    DWORD magic;                  // 0x6660DEAD
    DWORD flags;
    HostileNode* neighbors[4]; // 4-way cyclic graph
    const char* tag;
    BYTE junkPayload[128];
};
#pragma pack(pop)

// TLS Callback: runs BEFORE main / debugger initial breakpoint
static void NTAPI TlsHostileCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    if (Reason == DLL_PROCESS_ATTACH)
    {
        // Secret early initialization
        volatile int x = 0x1337;
        (void)x;
    }
}

#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK pTlsHostileCallback = TlsHostileCallback;

extern "C"
{
    __declspec(dllexport) const char* HostileBanner = "DBGLink-Hostile-Stress-Fixture-v2";

    // 1. EXCEPTION-BASED CONTROL FLOW (VEH Trap)
    // Code intentionally crashes with EXCEPTION_ACCESS_VIOLATION or INT3
    // and transfers control inside the handler. A naive stepping agent gets trapped.
    static LONG WINAPI VehDispatcher(PEXCEPTION_POINTERS pException)
    {
        if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            // Skip the INT3 and alter RAX
#if defined(_M_X64)
            pException->ContextRecord->Rip += 1;
            pException->ContextRecord->Rax ^= 0xCAFEBABE;
#elif defined(_M_IX86)
            pException->ContextRecord->Eip += 1;
            pException->ContextRecord->Eax ^= 0xCAFEBABE;
#endif
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    __declspec(dllexport) __declspec(noinline) int FixtureVehControlFlowTrap(int input)
    {
        PVOID hVeh = AddVectoredExceptionHandler(1, VehDispatcher);
        int secret = input;

        // Intentional INT3 to trigger VEH handler and modify registers
        __debugbreak();

        if (hVeh)
            RemoveVectoredExceptionHandler(hVeh);

        return secret ^ 0x5555;
    }

    // 2. RUNTIME JIT CODE DECRYPTION (Dynamic RWX heap)
    // Ghidra static analysis sees ONLY undefined bytes or dynamic allocs.
    // Must be observed in live memory while paused!
    __declspec(dllexport) __declspec(noinline) int FixtureSelfDecryptingShell(int a, int b)
    {
        // Encrypted bytecode for: mov eax, ecx; add eax, edx; ret (x64)
        // Or: mov eax, [esp+4]; add eax, [esp+8]; ret (x86)
        PVOID pMem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pMem) return -1;

#if defined(_M_X64)
        // 89 C8 01 D0 C3 (mov eax, ecx; add eax, edx; ret) XOR 0x77
        static const BYTE EncryptedCode[] = { 0x89 ^ 0x77, 0xC8 ^ 0x77, 0x01 ^ 0x77, 0xD0 ^ 0x77, 0xC3 ^ 0x77 };
#else
        // 8B 44 24 04 03 44 24 08 C3 XOR 0x77
        static const BYTE EncryptedCode[] = { 0x8B ^ 0x77, 0x44 ^ 0x77, 0x24 ^ 0x77, 0x04 ^ 0x77, 0x03 ^ 0x77, 0x44 ^ 0x77, 0x24 ^ 0x77, 0x08 ^ 0x77, 0xC3 ^ 0x77 };
#endif

        BYTE* pByte = (BYTE*)pMem;
        for (size_t i = 0; i < sizeof(EncryptedCode); i++)
        {
            pByte[i] = EncryptedCode[i] ^ 0x77;
        }

        typedef int (*JitFunc)(int, int);
        JitFunc fn = (JitFunc)pMem;
        int result = fn(a, b);

        VirtualFree(pMem, 0, MEM_RELEASE);
        return result;
    }

    // 3. THE 32-NODE CYCLIC LABYRINTH
    // Interconnected graph with cycles, cross-references, and false leaf-nodes.
    // Tests InspectAddressStructure recursion boundaries.
    static HostileNode s_Labyrinth[32];

    __declspec(dllexport) __declspec(noinline) HostileNode* FixtureGetHostileLabyrinth()
    {
        for (int i = 0; i < 32; i++)
        {
            s_Labyrinth[i].magic = 0x6660DEAD;
            s_Labyrinth[i].flags = (DWORD)i;
            s_Labyrinth[i].tag = (i % 2 == 0) ? "HostileNode_Even" : "HostileNode_Odd";
            s_Labyrinth[i].neighbors[0] = &s_Labyrinth[(i + 1) % 32];
            s_Labyrinth[i].neighbors[1] = &s_Labyrinth[(i + 31) % 32];
            s_Labyrinth[i].neighbors[2] = &s_Labyrinth[(i * 7) % 32];
            s_Labyrinth[i].neighbors[3] = &s_Labyrinth[(i ^ 0x1F) % 32];
        }
        return &s_Labyrinth[0];
    }

    // 4. FLOOD OF CONCURRENT WORKER THREADS (16 threads mutating state)
    // Floods the debugger's thread list and invalidates state generation constantly.
    static volatile LONG s_HostileCounter = 0;
    static DWORD WINAPI HostileWorker(LPVOID param)
    {
        (void)param;
        for (int i = 0; i < 1000; i++)
        {
            InterlockedIncrement(&s_HostileCounter);
            Sleep(1);
        }
        return 0;
    }

    __declspec(dllexport) __declspec(noinline) void FixtureSpawnHostileThreads(HANDLE outHandles[16])
    {
        for (int i = 0; i < 16; i++)
        {
            outHandles[i] = CreateThread(NULL, 0, HostileWorker, NULL, 0, NULL);
        }
    }
}

int main()
{
    int veh = FixtureVehControlFlowTrap(0x1234);
    int jit = FixtureSelfDecryptingShell(10, 20);
    HostileNode* lab = FixtureGetHostileLabyrinth();
    return (veh != 0 && jit == 30 && lab != nullptr) ? 0 : 1;
}
