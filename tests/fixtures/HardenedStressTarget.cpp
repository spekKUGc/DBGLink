#include <windows.h>

// DBGLink Hardened Adversarial Stress Target
// Specifically designed to expose token waste, excessive round-trips,
// and tool call inefficiency in AI-driven reverse engineering agents.

#pragma pack(push, 8)
struct ComplexNode
{
    DWORD magic;                  // 0xDEADBEEF
    DWORD id;
    ComplexNode* next;
    ComplexNode* prev;
    ComplexNode* child;
    const wchar_t* label;
    BYTE payload[32];
};
#pragma pack(pop)

typedef int (*OperationFunc)(int a, int b);

extern "C"
{
    __declspec(dllexport) const char* TargetBanner = "DBGLink-Hardened-Adversarial-Target-v2.0";

    // 1. OBFUSCATED & STACK STRINGS (Defeats naive DumpStrings without live memory analysis)
    __declspec(dllexport) __declspec(noinline) void FixtureObfuscatedStrings(wchar_t* outDecrypted, char* outStack)
    {
        // Stack string: built char-by-char at runtime (absent from .rdata)
        volatile char stackBuf[32];
        stackBuf[0] = 'D'; stackBuf[1] = 'B'; stackBuf[2] = 'G'; stackBuf[3] = '_';
        stackBuf[4] = 'S'; stackBuf[5] = 'T'; stackBuf[6] = 'A'; stackBuf[7] = 'C';
        stackBuf[8] = 'K'; stackBuf[9] = '_'; stackBuf[10] = 'K'; stackBuf[11] = 'E';
        stackBuf[12] = 'Y'; stackBuf[13] = '\0';
        for (int i = 0; i < 14; i++) {
            outStack[i] = stackBuf[i];
        }

        // XOR-encrypted UTF-16 string (XOR key 0x5A)
        static const unsigned short EncryptedWide[] = {
            0x001E, 0x0018, 0x001D, 0x0016, 0x0033, 0x0034, 0x0031, // "DBGLink" ^ 0x5A
            0x0005, 0x000F, 0x003F, 0x003E, 0x003F, 0x003B, 0x003E, 0x0000
        };
        for (int i = 0; EncryptedWide[i] != 0; i++) {
            outDecrypted[i] = static_cast<wchar_t>(EncryptedWide[i] ^ 0x5A);
        }
        outDecrypted[14] = L'\0';
    }

    // 2. CONTROL FLOW FLATTENING / STATE MACHINE (Forces 15-30 steps if an agent doesn't understand high-level flow)
    __declspec(dllexport) __declspec(noinline) int FixtureStateMachineDispatcher(int input, int rounds)
    {
        int state = 0x10;
        int accumulator = input;
        int iterations = 0;

        while (state != 0x99 && iterations < rounds)
        {
            iterations++;
            switch (state)
            {
                case 0x10:
                    accumulator ^= 0x5A5A;
                    state = (accumulator & 1) ? 0x20 : 0x30;
                    break;
                case 0x20:
                    accumulator = (accumulator << 3) | ((accumulator >> 29) & 0x7);
                    state = 0x40;
                    break;
                case 0x30:
                    accumulator = (accumulator * 33) + 7;
                    state = 0x40;
                    break;
                case 0x40:
                    accumulator ^= (state * 0x1337);
                    state = (iterations >= rounds) ? 0x99 : 0x50;
                    break;
                case 0x50:
                    accumulator += iterations;
                    state = 0x10;
                    break;
                default:
                    state = 0x99;
                    break;
            }
        }
        return accumulator;
    }

    // 3. INDIRECT CALL TABLE & POLYMORPHISM (Defeats simple static call-graph resolution)
    static int OpAdd(int a, int b) { return a + b; }
    static int OpSub(int a, int b) { return a - b; }
    static int OpXor(int a, int b) { return a ^ b; }
    static int OpMul(int a, int b) { return (a * b) & 0x7FFFFFFF; }

    static OperationFunc DispatchTable[4] = { &OpAdd, &OpSub, &OpXor, &OpMul };

    __declspec(dllexport) __declspec(noinline) int FixtureIndirectCall(int opIndex, int a, int b)
    {
        int safeIndex = (opIndex >= 0 && opIndex < 4) ? opIndex : 0;
        OperationFunc fn = DispatchTable[safeIndex];
        return fn(a, b);
    }

    // 4. DEEP RECURSION (Tests callstack frame limits and pagination)
    __declspec(dllexport) __declspec(noinline) int FixtureDeepRecursion(int depth, int value)
    {
        if (depth <= 0)
            return value * 2;
        return FixtureDeepRecursion(depth - 1, value ^ depth) + 1;
    }

    // 5. CYCLIC HEAP STRUCTURE (Tests pointer chasing, InspectAddressStructure & cyclic reference detection)
    static ComplexNode s_RootNode;
    static ComplexNode s_ChildNode;
    static ComplexNode s_PeerNode;

    __declspec(dllexport) __declspec(noinline) ComplexNode* FixtureGetCyclicStructure()
    {
        s_RootNode.magic = 0xDEADBEEF;
        s_RootNode.id = 1;
        s_RootNode.label = L"RootNode";
        s_RootNode.next = &s_PeerNode;
        s_RootNode.prev = nullptr;
        s_RootNode.child = &s_ChildNode;

        s_ChildNode.magic = 0xCAFEBABE;
        s_ChildNode.id = 2;
        s_ChildNode.label = L"ChildNode";
        s_ChildNode.next = nullptr;
        s_ChildNode.prev = nullptr;
        s_ChildNode.child = &s_RootNode; // CYCLIC POINTER BACK TO ROOT

        s_PeerNode.magic = 0xBAADF00D;
        s_PeerNode.id = 3;
        s_PeerNode.label = L"PeerNode";
        s_PeerNode.next = &s_RootNode;   // CYCLIC POINTER BACK TO ROOT
        s_PeerNode.prev = &s_RootNode;
        s_PeerNode.child = nullptr;

        return &s_RootNode;
    }

    // 6. MULTI-THREAD SIMULATION (Tests thread context switching and state generation changes)
    static volatile LONG s_ThreadCounter = 0;
    static DWORD WINAPI WorkerThread(LPVOID param)
    {
        int limit = (int)(intptr_t)param;
        for (int i = 0; i < limit; i++) {
            InterlockedIncrement(&s_ThreadCounter);
            Sleep(1);
        }
        return 0;
    }

    __declspec(dllexport) __declspec(noinline) HANDLE FixtureSpawnWorker(int iterations)
    {
        return CreateThread(NULL, 0, WorkerThread, (LPVOID)(intptr_t)iterations, 0, NULL);
    }
}

int main()
{
    wchar_t decrypted[32];
    char stackStr[32];
    FixtureObfuscatedStrings(decrypted, stackStr);
    int sm = FixtureStateMachineDispatcher(42, 5);
    int ic = FixtureIndirectCall(2, 10, 20);
    int dr = FixtureDeepRecursion(10, 7);
    ComplexNode* node = FixtureGetCyclicStructure();
    return (sm != 0 && ic != 0 && dr != 0 && node != nullptr) ? 0 : 1;
}
