#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <exception>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace dbglink
{

    constexpr int kPluginSdkVersion = 1;
    constexpr int kPluginVersion = 1;
    constexpr wchar_t kPipePrefix[] = L"DbgLink.Control.";
    constexpr char kPluginName[] = "DBGLink";
    constexpr std::size_t kMaxMnemonicSize = 64;
    constexpr std::size_t kMaxPipeRequestBytes = 64 * 1024;
    constexpr std::size_t kMaxPipeResponseBytes = 256 * 1024;
    constexpr std::size_t kPipeReadChunkBytes = 16 * 1024;
    constexpr DWORD kPipeConnectTimeoutMilliseconds = 30000;
    constexpr DWORD kPipeReadTimeoutMilliseconds = 2000;
    constexpr DWORD kPipeWriteTimeoutMilliseconds = 5000;
    constexpr DWORD kPipeRequestTimeoutMilliseconds = 10000;
    // SEC N7: a connected client must deliver the first request byte quickly;
    // trickling/idle holders are dropped without changing the 10 s total and
    // 2 s per-chunk caps above.
    constexpr DWORD kPipeFirstByteTimeoutMilliseconds = 1500;
    constexpr DWORD kPipeIoStopPollMilliseconds = 50;
    constexpr std::size_t kMaxMemoryReadBytes = 65536;
    constexpr std::size_t kMaxStringReadBytes = 8192;
    constexpr std::size_t kMaxModuleMapEntries = 65536;
    constexpr std::size_t kMaxModuleOutputChars = 120000;
    constexpr std::size_t kMaxThreadOutputChars = 120000;
    constexpr std::size_t kMaxCallStackOutputChars = 120000;
    constexpr std::size_t kMaxDisassemblyOutputChars = 120000;
    constexpr std::size_t kMaxSearchOutputChars = 120000;
    constexpr std::size_t kDefaultSearchScanBytes = 32 * 1024 * 1024;
    constexpr std::size_t kMaxSearchScanBytes = 64 * 1024 * 1024;
    constexpr std::size_t kDefaultInspectAddressScanBytes = 4 * 1024 * 1024;
    constexpr std::size_t kMaxInspectPointerCount = 64;
    constexpr std::size_t kMaxInspectByteCount = 4096;
    constexpr std::size_t kMaxInspectStringBytes = 1024;
    constexpr std::size_t kMaxInspectXrefs = 256;
    constexpr std::size_t kDefaultTraceXrefScanBytes = 4 * 1024 * 1024;
    constexpr std::size_t kMaxTraceStringMatches = 64;
    constexpr std::size_t kMaxTraceXrefsPerMatch = 64;
    constexpr std::size_t kMaxTraceInspectBytes = 256;
    constexpr std::size_t kMaxTraceEvidenceItems = 256;
    constexpr std::size_t kMaxSearchTextBytes = 256;
    constexpr std::size_t kMaxSearchResults = 512;
    constexpr std::size_t kMaxXrefResults = 512;
    constexpr std::size_t kMaxInterestingNeedles = 10;
    constexpr std::size_t kMaxInterestingResultsPerNeedle = 32;
    constexpr const char* kInterestingNeedles[kMaxInterestingNeedles] =
    {
        "error", "fail", "debug", "password", "token",
        "key", "http", "https", "license", "serial",
    };
    constexpr std::size_t kMaxBytePatternChars = 1024;
    constexpr std::size_t kMaxBytePatternTokens = 256;
    constexpr std::size_t kMaxModuleSize = 256;
    constexpr int kMaxThreadEntries = 4096;
    constexpr int kDefaultCallStackFrames = 32;
    constexpr int kMaxCallStackFrames = 256;
    constexpr int kMaxDisassemblyInstructions = 5000;
    constexpr std::size_t kMaxControlWriteBytes = 4096;
    constexpr std::size_t kMaxControlHexChars = 12288;
    constexpr std::size_t kMaxBreakpointNameChars = 64;
    constexpr std::size_t kMaxControlAddressText = 256;
    constexpr std::size_t kMaxPagedReadBytes = 8192;
    constexpr std::size_t kMaxPagedInstructions = 100;
    constexpr std::size_t kMaxBreakpointRecords = 512;
    // Mirrors x64dbg BPXTYPE from bridgemain.h. NOTE: this is a bitmask
    // (memory=4, dll=8, exception=16), not a sequence; DbgGetBpList returns
    // 0 for any other value.
    enum class BpListType : int
    {
        None = 0,
        Normal = 1,
        Hardware = 2,
        Memory = 4,
        Dll = 8,
        Exception = 16,
    };
    constexpr std::size_t kMaxBreakpointText = 256;
    constexpr std::size_t kMaxConditionalExprText = 256;
    constexpr std::size_t kMaxConditionalLogText = 256;
    // Native-only tools without a managed schema: caps bound the quoted
    // argument in the ExecDirect command line (see NativeCommandText.h).
    constexpr std::size_t kMaxLabelText = 256;
    constexpr std::size_t kMaxCommentText = 1024;
    constexpr std::size_t kMaxTargetPathText = 32760;
    constexpr std::size_t kMaxTargetArgumentsText = 4096;
    constexpr std::size_t kMaxTargetWorkDirText = 32760;
    struct NativeBreakpoint
    {
        int type = 0;
        std::uintptr_t addr = 0;
        bool enabled = false;
        bool singleshoot = false;
        bool active = false;
        char name[kMaxBreakpointText]{};
        char mod[kMaxModuleSize]{};
        unsigned short slot = 0;
        unsigned char typeEx = 0;
        unsigned char hwSize = 0;
        unsigned int hitCount = 0;
        bool fastResume = false;
        bool silent = false;
        char breakCondition[kMaxConditionalExprText]{};
        char logText[kMaxConditionalLogText]{};
        char logCondition[kMaxConditionalExprText]{};
        char commandText[kMaxConditionalLogText]{};
        char commandCondition[kMaxConditionalExprText]{};
    };
#ifdef _WIN64
    static_assert(sizeof(NativeBreakpoint) == 1824, "Unexpected x64 NativeBreakpoint ABI");
    // sizeof alone does not catch a field reorder that keeps the total size:
    // such a reorder would silently shift addr/name/mod and corrupt every
    // breakpoint reply. These offsets pin the hot fields against upstream
    // bridgemain.h (BRIDGEBP).
    static_assert(offsetof(NativeBreakpoint, type) == 0, "Unexpected x64 BRIDGEBP type offset");
    static_assert(offsetof(NativeBreakpoint, addr) == 8, "Unexpected x64 BRIDGEBP addr offset");
    static_assert(offsetof(NativeBreakpoint, enabled) == 16, "Unexpected x64 BRIDGEBP enabled offset");
    static_assert(offsetof(NativeBreakpoint, singleshoot) == 17, "Unexpected x64 BRIDGEBP singleshoot offset");
    static_assert(offsetof(NativeBreakpoint, active) == 18, "Unexpected x64 BRIDGEBP active offset");
    static_assert(offsetof(NativeBreakpoint, name) == 19, "Unexpected x64 BRIDGEBP name offset");
    static_assert(offsetof(NativeBreakpoint, mod) == 275, "Unexpected x64 BRIDGEBP mod offset");
    static_assert(offsetof(NativeBreakpoint, slot) == 532, "Unexpected x64 BRIDGEBP slot offset");
    static_assert(offsetof(NativeBreakpoint, hitCount) == 536, "Unexpected x64 BRIDGEBP hitCount offset");
    static_assert(offsetof(NativeBreakpoint, breakCondition) == 542, "Unexpected x64 BRIDGEBP breakCondition offset");
#else
    static_assert(sizeof(NativeBreakpoint) == 1816, "Unexpected x86 NativeBreakpoint ABI");
    static_assert(offsetof(NativeBreakpoint, type) == 0, "Unexpected x86 BRIDGEBP type offset");
    static_assert(offsetof(NativeBreakpoint, addr) == 4, "Unexpected x86 BRIDGEBP addr offset");
    static_assert(offsetof(NativeBreakpoint, enabled) == 8, "Unexpected x86 BRIDGEBP enabled offset");
    static_assert(offsetof(NativeBreakpoint, singleshoot) == 9, "Unexpected x86 BRIDGEBP singleshoot offset");
    static_assert(offsetof(NativeBreakpoint, active) == 10, "Unexpected x86 BRIDGEBP active offset");
    static_assert(offsetof(NativeBreakpoint, name) == 11, "Unexpected x86 BRIDGEBP name offset");
    static_assert(offsetof(NativeBreakpoint, mod) == 267, "Unexpected x86 BRIDGEBP mod offset");
    static_assert(offsetof(NativeBreakpoint, slot) == 524, "Unexpected x86 BRIDGEBP slot offset");
    static_assert(offsetof(NativeBreakpoint, hitCount) == 528, "Unexpected x86 BRIDGEBP hitCount offset");
    static_assert(offsetof(NativeBreakpoint, breakCondition) == 534, "Unexpected x86 BRIDGEBP breakCondition offset");
#endif
    struct NativeBreakpointMap
    {
        int count = 0;
        NativeBreakpoint* bp = nullptr;
    };
    struct NativeBreakpointMapGuard
    {
        NativeBreakpointMap map{};
        void(__cdecl* freeFunction)(void*) = nullptr;
        ~NativeBreakpointMapGuard()
        {
            if (map.bp != nullptr && freeFunction != nullptr)
                freeFunction(map.bp);
        }
    };

    struct PLUG_INITSTRUCT
    {
        int pluginHandle;
        int sdkVersion;
        int pluginVersion;
        char pluginName[256];
    };

    struct PLUG_SETUPSTRUCT;

    enum class XrefType : std::int32_t
    {
        None = 0,
        Data = 1,
        Jmp = 2,
        Call = 3,
    };

#ifdef _WIN64
#pragma pack(push, 16)
#else
#pragma pack(push, 8)
#endif
    // Mirrors x64dbg's XREF_INFO/XREF_RECORD ABI from bridgemain.h.
    struct XREF_RECORD
    {
        std::uintptr_t address;
        XrefType type;
    };

    struct XREF_INFO
    {
        std::uintptr_t refcount;
        XREF_RECORD* references;
    };
#pragma pack(pop)

#ifdef _WIN64
    static_assert(sizeof(XREF_RECORD) == 16, "Unexpected x64 XREF_RECORD ABI");
    static_assert(sizeof(XREF_INFO) == 16, "Unexpected x64 XREF_INFO ABI");
#else
    static_assert(sizeof(XREF_RECORD) == 8, "Unexpected x86 XREF_RECORD ABI");
    static_assert(sizeof(XREF_INFO) == 8, "Unexpected x86 XREF_INFO ABI");
#endif

    using PluginLogPuts = void(__cdecl*)(const char* text);
    using DbgIsDebuggingFunction = bool(__cdecl*)();
    using DbgValFromStringFunction = std::uintptr_t(__cdecl*)(const char* expression);
    using DbgIsValidExpressionFunction = bool(__cdecl*)(const char* expression);
    using DbgValToStringFunction = bool(__cdecl*)(const char* expression, std::uintptr_t value);
    using DbgMemReadFunction = bool(__cdecl*)(std::uintptr_t address, void* destination, std::uintptr_t size);
    using DbgMemWriteFunction = bool(__cdecl*)(std::uintptr_t address, const void* source, std::uintptr_t size);
    using DbgMemMapFunction = bool(__cdecl*)(void* memoryMap);
    using DbgMemFindBaseAddrFunction = std::uintptr_t(__cdecl*)(std::uintptr_t address, std::uintptr_t* size);
    using DbgGetProcessHandleFunction = HANDLE(__cdecl*)();
    using DbgGetThreadListFunction = void(__cdecl*)(void* threadList);
    using BridgeFreeFunction = void(__cdecl*)(void* buffer);
    using DbgDisasmFastAtFunction = void(__cdecl*)(std::uintptr_t address, void* instruction);
    using DbgGetModuleAtFunction = bool(__cdecl*)(std::uintptr_t address, char* text);
    using DbgFunctionGetFunction = bool(__cdecl*)(std::uintptr_t address, std::uintptr_t* start, std::uintptr_t* end);
    using DbgGetLabelAtFunction = bool(__cdecl*)(std::uintptr_t address, int segment, char* text);
    using DbgGetCommentAtFunction = bool(__cdecl*)(std::uintptr_t address, char* text);
    using DbgXrefGetFunction = bool(__cdecl*)(std::uintptr_t address, XREF_INFO* info);
    using DbgGetXrefCountAtFunction = std::uintptr_t(__cdecl*)(std::uintptr_t address);
    using DbgCmdExecDirectFunction = bool(__cdecl*)(const char* cmd);
    using DbgGetBpListFunction = int(__cdecl*)(int type, void* list);

    struct VALUE_INFO
    {
        std::uintptr_t value;
        int size;
    };

    struct MEMORY_INFO
    {
        std::uintptr_t value;
        int size;
        char mnemonic[kMaxMnemonicSize];
    };

    // Mirrors x64dbg's BASIC_INSTRUCTION_INFO from bridgemain.h.
    struct BASIC_INSTRUCTION_INFO
    {
        std::uint32_t type;
        VALUE_INFO value;
        MEMORY_INFO memory;
        std::uintptr_t addr;
        unsigned char branch;
        unsigned char call;
        int size;
        char instruction[kMaxMnemonicSize * 4];
    };

#ifdef _WIN64
    static_assert(sizeof(BASIC_INSTRUCTION_INFO) == 376, "Unexpected x64 BASIC_INSTRUCTION_INFO ABI");
#else
    static_assert(sizeof(BASIC_INSTRUCTION_INFO) == 352, "Unexpected x86 BASIC_INSTRUCTION_INFO ABI");
#endif

#ifdef _WIN64
#pragma pack(push, 16)
#else
#pragma pack(push, 8)
#endif
    // Mirrors x64dbg's MEMPAGE/MEMMAP layout from bridgemain.h.
    struct BRIDGE_MEMORY_PAGE
    {
        MEMORY_BASIC_INFORMATION mbi;
        char info[kMaxModuleSize];
    };

    struct BRIDGE_MEMORY_MAP
    {
        int count;
        BRIDGE_MEMORY_PAGE* page;
    };

    // Mirrors x64dbg's THREADINFO, THREADALLINFO and THREADLIST from bridgemain.h.
    struct BRIDGE_THREAD_INFO
    {
        int threadNumber;
        HANDLE handle;
        DWORD threadId;
        std::uintptr_t threadStartAddress;
        std::uintptr_t threadLocalBase;
        char threadName[256];
    };

    struct BRIDGE_THREAD_ALL_INFO
    {
        BRIDGE_THREAD_INFO basicInfo;
        std::uintptr_t threadCip;
        DWORD suspendCount;
        std::int32_t priority;
        std::int32_t waitReason;
        DWORD lastError;
        FILETIME userTime;
        FILETIME kernelTime;
        FILETIME creationTime;
        std::uint64_t cycles;
    };

    struct BRIDGE_THREAD_LIST
    {
        int count;
        BRIDGE_THREAD_ALL_INFO* list;
        int currentThread;
    };
#pragma pack(pop)

#ifdef _WIN64
    static_assert(sizeof(BRIDGE_THREAD_INFO) == 296, "Unexpected x64 THREADINFO ABI");
    static_assert(sizeof(BRIDGE_THREAD_ALL_INFO) == 352, "Unexpected x64 THREADALLINFO ABI");
    static_assert(sizeof(BRIDGE_MEMORY_MAP) == 16, "Unexpected x64 MEMMAP ABI");
    static_assert(sizeof(BRIDGE_THREAD_LIST) == 24, "Unexpected x64 THREADLIST ABI");
#else
    static_assert(sizeof(BRIDGE_THREAD_INFO) == 276, "Unexpected x86 THREADINFO ABI");
    static_assert(sizeof(BRIDGE_THREAD_ALL_INFO) == 328, "Unexpected x86 THREADALLINFO ABI");
    static_assert(sizeof(BRIDGE_MEMORY_MAP) == 8, "Unexpected x86 MEMMAP ABI");
    static_assert(sizeof(BRIDGE_THREAD_LIST) == 12, "Unexpected x86 THREADLIST ABI");
#endif

    struct ModuleRecord
    {
        std::uintptr_t base = 0;
        std::uintptr_t end = 0;
        std::string name;
        std::string path;
    };

    struct SearchPattern
    {
        std::string encoding;
        std::vector<unsigned char> bytes;
        std::string preview;
    };

    struct MaskedBytePattern
    {
        std::vector<unsigned char> bytes;
        std::vector<unsigned char> exact;
    };

    struct StringSearchMatch
    {
        std::uintptr_t address = 0;
        std::string module;
        std::string encoding;
        std::size_t length = 0;
        std::string preview;
    };

    struct StringSearchResult
    {
        std::vector<StringSearchMatch> matches;
        std::size_t scannedBytes = 0;
        bool scanTruncated = false;
        bool readFailure = false;
        bool addressOverflow = false;
        bool resultLimitReached = false;
        bool moduleMapTruncated = false;
    };

    struct InterestingSearchPattern
    {
        std::string needle;
        std::size_t group = 0;
        SearchPattern pattern;
    };

    struct InterestingStringMatch
    {
        std::uintptr_t address = 0;
        std::string module;
        std::string needle;
        std::string encoding;
        std::size_t length = 0;
        std::string preview;
    };

    struct InterestingStringResult
    {
        std::vector<InterestingStringMatch> matches;
        std::size_t scannedBytes = 0;
        bool scanTruncated = false;
        bool readFailure = false;
        bool addressOverflow = false;
        bool resultLimitReached = false;
        bool moduleMapTruncated = false;
    };

    struct ByteSearchMatch
    {
        std::uintptr_t address = 0;
        std::string module;
    };

    struct ByteSearchResult
    {
        std::vector<ByteSearchMatch> matches;
        std::size_t scannedBytes = 0;
        bool scanTruncated = false;
        bool readFailure = false;
        bool addressOverflow = false;
        bool resultLimitReached = false;
        bool moduleMapTruncated = false;
    };

    struct XrefMatch
    {
        std::uintptr_t address = 0;
        XrefType type = XrefType::None;
        std::string source;
        std::string instruction;
    };

    struct XrefSearchResult
    {
        std::vector<XrefMatch> matches;
        std::size_t reportedCount = 0;
        std::size_t scannedBytes = 0;
        bool xrefDbAvailable = false;
        bool xrefDbMalformed = false;
        bool xrefDbTruncated = false;
        bool scanFallbackUsed = false;
        bool scanFallbackUnavailable = false;
        bool scanTruncated = false;
        bool addressOverflow = false;
        bool moduleMapTruncated = false;
    };

    struct BridgeMemoryMapGuard
    {
        BRIDGE_MEMORY_MAP map{};
        BridgeFreeFunction freeFunction = nullptr;

        ~BridgeMemoryMapGuard()
        {
            if (map.page != nullptr && freeFunction != nullptr)
                freeFunction(map.page);
        }
    };

    struct BridgeThreadListGuard
    {
        BRIDGE_THREAD_LIST list{};
        BridgeFreeFunction freeFunction = nullptr;

        ~BridgeThreadListGuard()
        {
            if (list.list != nullptr && freeFunction != nullptr)
                freeFunction(list.list);
        }
    };

}
