// NativeReadHandlersTests.cpp — read/secondary handlers.
//
// Covers NativeReadHandlers.cpp (ReadMemoryChunk, ReadDisassemblyChunk,
// EvaluateExpression), NativeMemoryQueries.cpp (GetMemoryMap),
// NativeSecondaryHandlers.cpp (ReadStringAtAddress, GetAllModulesFromMemMap,
// GetXrefs, OpenDebugTarget), NativeInspectionHandlers.cpp
// (InspectAddressStructure) and NativeStringReferenceTrace.cpp
// (TraceStringReferences): capped-parameter boundaries, paged envelopes and
// success paths over scripted shim memory, map pages and the xref database.
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "../../src/native/DbgLink.Native/NativeControlHandlers.h"
#include "../../src/native/DbgLink.Native/NativeBridgeFoundation.h"
#include "../../src/native/DbgLink.Native/NativeInspectionHandlers.h"
#include "../../src/native/DbgLink.Native/NativeJsonFormatting.h"
#include "../../src/native/DbgLink.Native/NativeModuleFunctions.h"
#include "../../src/native/DbgLink.Native/NativeMemoryQueries.h"
#include "../../src/native/DbgLink.Native/NativeSecondaryHandlers.h"
#include "../../src/native/DbgLink.Native/NativeStringReferenceTrace.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"
#include "../../src/native/DbgLink.Native/NativeControlSupport.h"
#include "../../src/native/DbgLink.Native/NativeHexFormat.h"
#include "../../src/native/DbgLink.Native/X64DbgApiShim.h"

namespace dbglink_read_tests
{
    using namespace dbglink;

    void Require(bool condition, std::string_view message)
    {
        if (!condition)
            throw std::runtime_error(std::string(message));
    }

    bool Contains(const std::string& haystack, const std::string& needle)
    {
        return haystack.find(needle) != std::string::npos;
    }

    std::string Req(const char* method, const std::string& params, const char* id = "7")
    {
        return std::string("{\"id\":") + id + ",\"method\":\"" + method + "\",\"params\":{" + params + "}}";
    }

    void ExpectError(const std::string& response, std::string_view fragment)
    {
        Require(Contains(response, "\"ok\":false"), "expected ok:false");
        Require(Contains(response, "\"code\":\"native_error\""), "expected native_error code");
        Require(Contains(response, "\"id\":7"), "expected id echo");
        Require(Contains(response, std::string(fragment)), "expected error fragment");
    }

    void ExpectOk(const std::string& response)
    {
        Require(Contains(response, "\"ok\":true"), "expected ok:true");
        Require(Contains(response, "\"id\":7"), "expected id echo");
    }

    void ImageModule()
    {
        testshim::Reset();
        testshim::SetMemoryPages({testshim::MakeImagePage(0x400000, 0x1000, PAGE_EXECUTE_READ, "C:\\test\\app.exe")});
        testshim::SetModuleName(0x400000, "app.exe");
        testshim::WriteImageBytes(0x400000, std::vector<unsigned char>(0x1000, 0x90));
    }

    void TestReadMemoryChunk()
    {
        ImageModule();
        ExpectError(HandleReadMemoryChunk(Req("ReadMemoryChunk", ""), "7"),
            "ReadMemoryChunk address must be a non-empty printable expression");
        ExpectError(HandleReadMemoryChunk(Req("ReadMemoryChunk", "\"address\":\"0x400000\",\"length\":0"), "7"),
            "ReadMemoryChunk length must be between 1 and 8192. Page larger dumps via offset.");
        ExpectError(HandleReadMemoryChunk(
            Req("ReadMemoryChunk", "\"address\":\"0x400000\",\"length\":8193"), "7"),
            "ReadMemoryChunk length must be between 1 and 8192. Page larger dumps via offset.");
        if constexpr (sizeof(std::uintptr_t) == 8)
        {
            ExpectError(HandleReadMemoryChunk(
                Req("ReadMemoryChunk", "\"address\":\"0xFFFFFFFFFFFFFFFF\",\"offset\":1,\"length\":1"), "7"),
                "ReadMemoryChunk offset overflows the address space.");
        }
        else
        {
            ExpectError(HandleReadMemoryChunk(
                Req("ReadMemoryChunk", "\"address\":\"0xFFFFFFFF\",\"offset\":1,\"length\":1"), "7"),
                "ReadMemoryChunk offset overflows the address space.");
        }
        // SEC N6: an offset wider than uintptr_t must fail before the
        // narrowing cast. On 32-bit 2^32 would otherwise truncate to 0 and
        // read `base`; on 64-bit size_t is lossless so the max-uint64 offset
        // overflows the add instead — same wire error either way.
        if constexpr (sizeof(std::uintptr_t) == 4)
        {
            ExpectError(HandleReadMemoryChunk(
                Req("ReadMemoryChunk", "\"address\":\"0x400000\",\"offset\":4294967296,\"length\":1"), "7"),
                "ReadMemoryChunk offset overflows the address space.");
        }
        else
        {
            ExpectError(HandleReadMemoryChunk(
                Req("ReadMemoryChunk", "\"address\":\"0x400000\",\"offset\":18446744073709551615,\"length\":1"), "7"),
                "ReadMemoryChunk offset overflows the address space.");
        }
        ExpectError(HandleReadMemoryChunk(Req("ReadMemoryChunk", "\"address\":\"0x600000\",\"length\":8"), "7"),
            "Failed to read memory at " + HexAddress(0x600000));

        testshim::WriteImageBytes(0x400010, {0x41, 0x42, 0x00, 0x7F});
        const std::string ok = HandleReadMemoryChunk(
            Req("ReadMemoryChunk", "\"address\":\"0x400000\",\"offset\":16,\"length\":4"), "7");
        ExpectOk(ok);
        Require(Contains(ok, "\"base\":\"" + HexAddress(0x400000) + "\""), "chunk base mismatch");
        Require(Contains(ok, "\"address\":\"" + HexAddress(0x400010) + "\""), "chunk address mismatch");
        Require(Contains(ok, "\"length\":4"), "chunk length mismatch");
        Require(Contains(ok, "\"bytesHex\":\"41 42 00 7F\""), "chunk bytesHex mismatch");
        Require(Contains(ok, "\"ascii\":\"AB..\""), "chunk ascii preview mismatch");
        Require(Contains(ok, "\"nextOffset\":20"), "chunk nextOffset mismatch");
    }

    void TestReadDisassemblyChunk()
    {
        ImageModule();
        testshim::SetDisasm("nop", 2);
        testshim::WriteImageBytes(0x401000, {0x90, 0x90, 0x90, 0x90});

        ExpectError(HandleReadDisassemblyChunk(Req("ReadDisassemblyChunk", ""), "7"),
            "ReadDisassemblyChunk address must be a non-empty printable expression");
        ExpectError(HandleReadDisassemblyChunk(
            Req("ReadDisassemblyChunk", "\"address\":\"0x401000\",\"maxInstructions\":0"), "7"),
            "ReadDisassemblyChunk maxInstructions must be between 1 and 100.");
        ExpectError(HandleReadDisassemblyChunk(
            Req("ReadDisassemblyChunk", "\"address\":\"0x401000\",\"maxInstructions\":101"), "7"),
            "ReadDisassemblyChunk maxInstructions must be between 1 and 100.");
        // SEC N6: same narrowing-cast guard as ReadMemoryChunk above.
        if constexpr (sizeof(std::uintptr_t) == 4)
        {
            ExpectError(HandleReadDisassemblyChunk(
                Req("ReadDisassemblyChunk", "\"address\":\"0x401000\",\"offset\":4294967296"), "7"),
                "ReadDisassemblyChunk offset overflows the address space.");
        }
        else
        {
            ExpectError(HandleReadDisassemblyChunk(
                Req("ReadDisassemblyChunk", "\"address\":\"0x401000\",\"offset\":18446744073709551615"), "7"),
                "ReadDisassemblyChunk offset overflows the address space.");
        }

        const std::string ok = HandleReadDisassemblyChunk(
            Req("ReadDisassemblyChunk", "\"address\":\"0x401000\",\"maxInstructions\":2"), "7");
        ExpectOk(ok);
        Require(Contains(ok, "\"base\":\"" + HexAddress(0x401000) + "\""), "disasm chunk base mismatch");
        Require(Contains(ok, "\"instructionCount\":2"), "disasm chunk count mismatch");
        Require(Contains(ok, "\"bytesTotal\":4"), "disasm chunk bytesTotal mismatch");
        Require(Contains(ok, "\"instruction\":\"nop\""), "scripted instruction missing");
        Require(Contains(ok, "\"nextOffset\":4"), "disasm chunk nextOffset mismatch");

        testshim::SetDisasm("", 0);
        Require(Contains(HandleReadDisassemblyChunk(
            Req("ReadDisassemblyChunk", "\"address\":\"0x401000\",\"maxInstructions\":1"), "7"),
            "<undecodable>"),
            "zero-size disassembly must render <undecodable>");
    }

    void TestEvaluateExpression()
    {
        testshim::Reset();
        ExpectError(HandleEvaluateExpression(Req("EvaluateExpression", "\"expression\":\"0x1\""), "7"),
            "No active debug session.");

        testshim::SetDebugging(true);
        ExpectError(HandleEvaluateExpression(Req("EvaluateExpression", ""), "7"),
            "EvaluateExpression expression is required.");
        ExpectError(HandleEvaluateExpression(
            Req("EvaluateExpression", "\"expression\":\"" + std::string(513, '1') + "\""), "7"),
            "EvaluateExpression expression is too long.");
        ExpectError(HandleEvaluateExpression(Req("EvaluateExpression", "\"expression\":\"!!!\""), "7"),
            "Could not evaluate expression: !!!");

        // 0x401000 == 4198400: the unsigned rendering is assertion-friendly.
        testshim::WriteImageBytes(0x401000, {0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        const std::string ok = HandleEvaluateExpression(
            Req("EvaluateExpression", "\"expression\":\"0x401000\""), "7");
        ExpectOk(ok);
        Require(Contains(ok, "\"expression\":\"0x401000\""), "expression echo missing");
        Require(Contains(ok, "\"valueHex\":\"" + HexAddress(0x401000) + "\""), "valueHex mismatch");
        Require(Contains(ok, "\"valueUnsigned\":\"4198400\""), "valueUnsigned mismatch");
        Require(Contains(ok, "\"dereference\":\"" + HexAddress(5) + "\""), "pointer dereference missing");
    }

    void TestGetMemoryMap()
    {
        testshim::Reset();
        ExpectError(HandleGetMemoryMap(Req("GetMemoryMap", ""), "7"), "No active debug session.");

        testshim::SetDebugging(true);
        testshim::FakePage image = testshim::MakeImagePage(0x400000, 0x10000, PAGE_EXECUTE_READ, "app.exe");
        testshim::FakePage data{};
        data.mbi.BaseAddress = reinterpret_cast<PVOID>(0x600000);
        data.mbi.AllocationBase = reinterpret_cast<PVOID>(0x600000);
        data.mbi.RegionSize = 0x2000;
        data.mbi.State = MEM_COMMIT;
        data.mbi.Protect = PAGE_READWRITE;
        data.mbi.Type = MEM_PRIVATE;
        data.info = "heap";
        testshim::SetMemoryPages({image, data});

        const std::string all = HandleGetMemoryMap(Req("GetMemoryMap", ""), "7");
        ExpectOk(all);
        Require(Contains(all, "\"totalMatched\":2"), "map must match both pages");
        Require(Contains(all, "\"baseAddress\":\"" + HexAddress(0x400000) + "\""), "image page base missing");
        // Single protect representation: the human string stays, the
        // derivable protectValue/isExecutable/isRwx are dropped.
        Require(Contains(all, "\"protect\":\"PAGE_EXECUTE_READ\""), "protect string missing");
        Require(!Contains(all, "\"protectValue\""), "protectValue duplicate must be dropped");
        Require(!Contains(all, "\"isExecutable\""), "isExecutable duplicate must be dropped");
        Require(!Contains(all, "\"isRwx\""), "isRwx duplicate must be dropped");

        const std::string exec = HandleGetMemoryMap(Req("GetMemoryMap", "\"executableOnly\":true"), "7");
        ExpectOk(exec);
        Require(Contains(exec, "\"totalMatched\":1"), "executableOnly must drop the RW page");

        // fullProtect=true restores the machine-readable triple alongside
        // the protect string (same keys as before the slimming).
        const std::string full = HandleGetMemoryMap(Req("GetMemoryMap", "\"fullProtect\":true"), "7");
        ExpectOk(full);
        Require(Contains(full, "\"totalMatched\":2"), "full map must match both pages");
        Require(Contains(full, "\"protect\":\"PAGE_EXECUTE_READ\""), "full map must keep the protect string");
        Require(Contains(full, "\"protectValue\":" + std::to_string(PAGE_EXECUTE_READ)),
            "full map must restore protectValue for the image page");
        Require(Contains(full, "\"protectValue\":" + std::to_string(PAGE_READWRITE)),
            "full map must restore protectValue for the private page");
        Require(Contains(full, "\"isExecutable\":true"), "image page must report isExecutable");
        Require(Contains(full, "\"isExecutable\":false"), "private page must report isExecutable=false");
        Require(Contains(full, "\"isRwx\":false"), "neither fixture page is RWX");
        ExpectError(HandleGetMemoryMap(Req("GetMemoryMap", "\"fullProtect\":\"yes\""), "7"),
            "GetMemoryMap fullProtect must be a boolean.");

        const std::string priv = HandleGetMemoryMap(Req("GetMemoryMap", "\"type\":\"private\""), "7");
        ExpectOk(priv);
        Require(Contains(priv, "\"totalMatched\":1"), "type=private must match one page");
        Require(Contains(priv, "\"baseAddress\":\"" + HexAddress(0x600000) + "\""), "private page base missing");

        // Truncation means "more data remains" (ComputePageWindow): the first
        // page of two reports truncated=true with nextOffset, the tail page
        // reports truncated=false with no nextOffset.
        const std::string first = HandleGetMemoryMap(Req("GetMemoryMap", "\"offset\":0,\"maxItems\":1"), "7");
        ExpectOk(first);
        Require(Contains(first, "\"totalMatched\":2"), "first map page must see both matches");
        Require(Contains(first, "\"truncated\":true"), "first map page must report truncated");
        Require(Contains(first, "\"nextOffset\":1"), "first map page must report nextOffset");

        const std::string page = HandleGetMemoryMap(Req("GetMemoryMap", "\"offset\":1,\"maxItems\":1"), "7");
        ExpectOk(page);
        Require(Contains(page, "\"totalMatched\":2"), "tail map page must see both matches");
        Require(Contains(page, "\"truncated\":false"), "tail map page must not report truncated");
        Require(Contains(page, "\"baseAddress\":\"" + HexAddress(0x600000) + "\""), "tail page must carry the heap page");

        ExpectError(HandleGetMemoryMap(Req("GetMemoryMap", "\"executableOnly\":\"yes\""), "7"),
            "GetMemoryMap executableOnly must be a boolean.");
    }

    void TestReadStringAndModules()
    {
        ImageModule();
        testshim::WriteImageString(0x400300, "Hello");
        testshim::WriteImageString16(0x400400, "Hi");

        ExpectError(HandleReadString(Req("ReadStringAtAddress", ""), "7"),
            "ReadStringAtAddress address must be a non-empty printable expression");
        ExpectError(HandleReadString(Req("ReadStringAtAddress", "\"address\":\"0x400300\",\"maxBytes\":0"), "7"),
            "ReadStringAtAddress maxBytes must be between 1 and 8192.");
        ExpectError(HandleReadString(
            Req("ReadStringAtAddress", "\"address\":\"0x400300\",\"maxBytes\":8193"), "7"),
            "ReadStringAtAddress maxBytes must be between 1 and 8192.");

        const std::string ascii = HandleReadString(
            Req("ReadStringAtAddress", "\"address\":\"0x400300\""), "7");
        ExpectOk(ascii);
        Require(Contains(ascii, "\"text\":\"Hello\""), "ascii string mismatch");

        const std::string wide = HandleReadString(
            Req("ReadStringAtAddress", "\"address\":\"0x400400\",\"unicode\":true"), "7");
        ExpectOk(wide);
        Require(Contains(wide, "\"text\":\"Hi\""), "utf-16 string mismatch");

        const std::string modules = HandleModules("7", "GetAllModulesFromMemMap");
        ExpectOk(modules);
        Require(Contains(modules, "app.exe"), "module list must contain the scripted module");

        // CollectModuleRecords caches per debugger generation: retire the
        // cache before re-reading the emptied map.
        testshim::SetMemoryPages({});
        ++g_debuggerGeneration;
        Require(Contains(HandleModules("7", "GetAllModulesFromMemMap"), "No image modules found"),
            "empty map must report no image modules");
    }

    void TestGetXrefs()
    {
        ImageModule();
        ExpectError(HandleGetXrefs(Req("GetXrefs", ""), "7"),
            "GetXrefs target must be a non-empty printable expression");
        ExpectError(HandleGetXrefs(Req("GetXrefs", "\"target\":\"0x402000\",\"start\":257"), "7"),
            "GetXrefs start must be between 0 and 256.");
        ExpectError(HandleGetXrefs(Req("GetXrefs", "\"target\":\"0x402000\",\"count\":0"), "7"),
            "GetXrefs count must be between 1 and 256.");
        ExpectError(HandleGetXrefs(Req("GetXrefs", "\"target\":\"0x402000\",\"count\":257"), "7"),
            "GetXrefs count must be between 1 and 256.");

        testshim::SetXrefCount(0x402000, 1);
        testshim::SetXrefs(0x402000, {{0x401000, XrefType::Call}});
        const std::string ok = HandleGetXrefs(
            Req("GetXrefs", "\"target\":\"0x402000\",\"module\":\"all\",\"scanFallback\":false"), "7");
        ExpectOk(ok);
        Require(Contains(ok, "target=" + HexAddress(0x402000)), "xref target header missing");
        Require(Contains(ok, "from=" + HexAddress(0x401000)), "xref source address missing");
        Require(Contains(ok, "type=call"), "xref type text missing");
        Require(Contains(ok, "source=x64dbg-xref-db"), "xref source tag missing");
        Require(Contains(ok, "reportedCount=1"), "reportedCount echo missing");
    }

    void TestInspectAddress()
    {
        ImageModule();
        testshim::WriteImageBytes(0x400100, {0xCC, 0xC3, 0x90, 0x90});

        ExpectError(HandleInspectAddressStructure(Req("InspectAddressStructure", ""), "7"),
            "InspectAddressStructure address must be a non-empty printable expression");
        ExpectError(HandleInspectAddressStructure(
            Req("InspectAddressStructure", "\"address\":\"0x400100\",\"pointerCount\":65"), "7"),
            "InspectAddressStructure pointerCount must be between 0 and 64.");
        ExpectError(HandleInspectAddressStructure(
            Req("InspectAddressStructure", "\"address\":\"0x400100\",\"byteCount\":4097"), "7"),
            "InspectAddressStructure byteCount must be between 0 and 4096.");
        ExpectError(HandleInspectAddressStructure(
            Req("InspectAddressStructure", "\"address\":\"0x400100\",\"stringBytes\":15"), "7"),
            "InspectAddressStructure stringBytes must be between 16 and 1024.");
        ExpectError(HandleInspectAddressStructure(
            Req("InspectAddressStructure", "\"address\":\"0x400100\",\"maxXrefs\":257"), "7"),
            "InspectAddressStructure maxXrefs must be between 1 and 256.");
        ExpectError(HandleInspectAddressStructure(
            Req("InspectAddressStructure", "\"address\":\"0x400100\",\"maxScanBytes\":4095"), "7"),
            "InspectAddressStructure maxScanBytes must be between 4096 and 67108864.");

        const std::string ok = HandleInspectAddressStructure(
            Req("InspectAddressStructure",
                "\"address\":\"0x400100\",\"pointerCount\":0,\"byteCount\":4,\"includeXrefs\":false"),
            "7");
        ExpectOk(ok);
        Require(Contains(ok, "address=" + HexAddress(0x400100)), "inspect address header missing");
        Require(Contains(ok, "[Xrefs] included=false"), "disabled xrefs must be reported");
        Require(Contains(ok, "[Bytes] byteCount=4 read=true"), "byte section must report a clean read");
        // Compact dump: header address + length, contiguous lowercase hex.
        Require(Contains(ok, HexAddress(0x400100) + " (4 bytes)"), "dump header missing");
        Require(Contains(ok, "ccc39090"), "dump body must be contiguous lowercase hex");
        // pointerSize lives in the reply header only; the [Pointers] repeat
        // is dropped.
        Require(Contains(ok, "[Pointers] count=0 read=true"), "pointer section shape wrong");
        Require(!Contains(ok, "[Pointers] pointerSize"), "pointerSize duplicate must be dropped");
    }

    // Inspect + dump flags (both true) over a live pointer table: entry 0
    // points at an unreadable address (non-null, stringRead=false), entry 1
    // is null (no marker). This pins the null-vs-unreadable distinction and
    // the includeAscii/spacedHex rendering past the single-read path above.
    void TestInspectAddressFlags()
    {
        ImageModule();
        testshim::WriteImageBytes(0x400100,
            {0xCC, 0xC3, 0x90, 0x90, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

        const std::string ok = HandleInspectAddressStructure(
            Req("InspectAddressStructure",
                "\"address\":\"0x400100\",\"pointerCount\":2,\"byteCount\":16,"
                "\"includeXrefs\":false,\"includeAscii\":true,\"spacedHex\":true"),
            "7");
        ExpectOk(ok);
        Require(Contains(ok, "[Pointers] count=2 read=true"), "pointer section must read both entries");
        // Spaced lowercase hex plus the ASCII gutter (all 16 bytes are
        // non-printable, so the gutter is 16 dots).
        Require(Contains(ok, "cc c3 90 90"), "spacedHex must separate bytes with spaces");
        Require(!Contains(ok, "ccc39090"), "spacedHex must not render contiguous hex");
        Require(Contains(ok, "................"), "includeAscii must re-add the ASCII gutter");
        // Entry 0 is non-null but unreadable: value echo plus the marker.
        Require(Contains(ok, "value=0x9090c3cc"), "unreadable pointee value missing");
        Require(Contains(ok, "stringRead=false"), "unreadable pointee must carry stringRead=false");
        // Exactly one marker: the null entry must not carry it.
        std::size_t markers = 0;
        for (std::size_t at = ok.find("stringRead=false"); at != std::string::npos;
             at = ok.find("stringRead=false", at + 1))
            ++markers;
        Require(markers == 1, "only the unreadable entry may carry stringRead=false");

        ExpectError(HandleInspectAddressStructure(
            Req("InspectAddressStructure", "\"address\":\"0x400100\",\"includeAscii\":\"yes\""), "7"),
            "InspectAddressStructure includeAscii must be a boolean.");
        ExpectError(HandleInspectAddressStructure(
            Req("InspectAddressStructure", "\"address\":\"0x400100\",\"spacedHex\":\"yes\""), "7"),
            "InspectAddressStructure spacedHex must be a boolean.");
    }

    void TestTraceAndOpenTarget()
    {
        ImageModule();
        testshim::WriteImageString(0x400200, "trace-me");
        testshim::SetDisasm("call target", 5);

        ExpectError(HandleTraceStringReferences(Req("TraceStringReferences", ""), "7"),
            "TraceStringReferences text must be non-empty, printable, and at most 256 bytes.");
        ExpectError(HandleTraceStringReferences(
            Req("TraceStringReferences", "\"text\":\"x\",\"maxStringMatches\":0"), "7"),
            "TraceStringReferences maxStringMatches must be between 1 and 64.");
        ExpectError(HandleTraceStringReferences(
            Req("TraceStringReferences", "\"text\":\"x\",\"maxStringMatches\":65"), "7"),
            "TraceStringReferences maxStringMatches must be between 1 and 64.");

        const std::string trace = HandleTraceStringReferences(
            Req("TraceStringReferences", "\"text\":\"trace-me\",\"module\":\"app.exe\""), "7");
        ExpectOk(trace);
        Require(Contains(trace, "matches=1"), "trace must find the scripted string");

        ExpectError(HandleOpenDebugTarget(Req("OpenDebugTarget", ""), "7"),
            "path must be a non-empty string of at most 32760 bytes.");
        // NOTE: in hand-written JSON, backslash-letter sequences are JSON
        // escapes ("\t" decodes to TAB, "\a" is an invalid escape that kills
        // the whole request), so Windows-style paths can't be inlined here.
        // Forward slashes exercise the same validation branches cleanly.
        ExpectError(HandleOpenDebugTarget(Req("OpenDebugTarget", "\"path\":\"C:/test/app.txt\""), "7"),
            "path must be a .exe or .dll debug target.");
        ExpectError(HandleOpenDebugTarget(Req("OpenDebugTarget", "\"path\":\"C:/test/a\\\"b.exe\""), "7"),
            "path must be at most 32760 bytes without quotes or control characters.");
        // SEC J5: UNC / device-prefix / DOS-device targets die here, not in
        // the debugger loader. (Backslashes are JSON-escaped below, so the
        // UNC literal is written with doubled pairs.)
        ExpectError(HandleOpenDebugTarget(Req("OpenDebugTarget", "\"path\":\"//evil/share/a.exe\""), "7"),
            "path must be a local absolute drive path");
        ExpectError(HandleOpenDebugTarget(Req("OpenDebugTarget", "\"path\":\"\\\\\\\\evil\\\\share\\\\a.exe\""), "7"),
            "path must be a local absolute drive path");
        ExpectError(HandleOpenDebugTarget(Req("OpenDebugTarget", "\"path\":\"C:/test/CON.exe\""), "7"),
            "path must be a local absolute drive path");
        ExpectError(HandleOpenDebugTarget(
            Req("OpenDebugTarget", "\"path\":\"C:/test/app.exe\",\"workDir\":\"\\\\\\\\evil\\\\share\""), "7"),
            "workDir must be a local absolute drive path");
        ExpectError(HandleOpenDebugTarget(
            Req("OpenDebugTarget", "\"path\":\"C:/test/app.exe\",\"workDir\":\"relative/dir\""), "7"),
            "workDir must be a local absolute drive path");

        // The shim accepts the init command, so the success path executes
        // without spawning any process.
        testshim::ClearExecLog();
        const std::string opened = HandleOpenDebugTarget(
            Req("OpenDebugTarget",
                "\"path\":\"C:/test/app.exe\",\"arguments\":\"--x\",\"workDir\":\"C:/work\""),
            "7");
        ExpectOk(opened);
        Require(Contains(opened, "\"opened\":true"), "open must report opened");
        Require(Contains(opened, "\"path\":\"C:/test/app.exe\""), "open must echo the path");
        Require(testshim::ExecLog().back() == "init \"C:/test/app.exe\", \"--x\", \"C:/work\"",
            "init command contract broken");

        testshim::SetExecDirectResult(false);
        ExpectError(HandleOpenDebugTarget(Req("OpenDebugTarget", "\"path\":\"C:/test/app.exe\""), "7"),
            "The debugger could not open the target.");
    }

    void WriteLe16(std::vector<unsigned char>& bytes, std::size_t offset, std::uint16_t value)
    {
        bytes[offset] = static_cast<unsigned char>(value & 0xFF);
        bytes[offset + 1] = static_cast<unsigned char>((value >> 8) & 0xFF);
    }

    void WriteLe32(std::vector<unsigned char>& bytes, std::size_t offset, std::uint32_t value)
    {
        for (int i = 0; i < 4; ++i)
            bytes[offset + i] = static_cast<unsigned char>((value >> (8 * i)) & 0xFF);
    }

    void WriteAsciiZ(std::vector<unsigned char>& bytes, std::size_t offset, const char* text)
    {
        std::size_t i = 0;
        for (; text[i] != '\0'; ++i)
            bytes[offset + i] = static_cast<unsigned char>(text[i]);
        bytes[offset + i] = 0;
    }

    // w19 GetModuleFunctions export fallback over a hand-built PE32+: one valid
    // named export survives; a forwarded export (function RVA inside the export
    // block) and an out-of-module RVA are skipped.
    void TestGetModuleFunctionsExportFallback()
    {
        constexpr std::uintptr_t base = 0x400000;
        constexpr std::size_t moduleSize = 0x2000;
        constexpr std::uint32_t ntRva = 0x80;
        constexpr std::uint32_t exportRva = 0x1000;
        constexpr std::uint32_t exportSize = 0x100;
        constexpr std::uint32_t functionsRva = 0x1040;
        constexpr std::uint32_t namesRva = 0x1060;
        constexpr std::uint32_t ordinalsRva = 0x1070;
        constexpr std::uint32_t codeRva = 0x1200;

        testshim::Reset();
        testshim::SetMemoryPages({testshim::MakeImagePage(base, moduleSize, PAGE_EXECUTE_READ, "C:\\test\\app.exe")});
        testshim::SetModuleName(base, "app.exe");
        std::vector<unsigned char> image(moduleSize, 0);
        image[0] = 'M';
        image[1] = 'Z';
        WriteLe32(image, 0x3C, ntRva);
        image[ntRva] = 'P';
        image[ntRva + 1] = 'E';
        WriteLe16(image, ntRva + 24, 0x20B);            // PE32+ optional-header magic
        WriteLe32(image, ntRva + 24 + 112, exportRva);  // data directory[0] RVA
        WriteLe32(image, ntRva + 24 + 116, exportSize); // data directory[0] size
        WriteLe32(image, exportRva + 20, 3);            // NumberOfFunctions
        WriteLe32(image, exportRva + 24, 3);            // NumberOfNames
        WriteLe32(image, exportRva + 28, functionsRva);
        WriteLe32(image, exportRva + 32, namesRva);
        WriteLe32(image, exportRva + 36, ordinalsRva);
        WriteLe32(image, functionsRva + 0, codeRva);    // valid code export
        WriteLe32(image, functionsRva + 4, 0x1080);     // forwarder string inside the export block
        WriteLe32(image, functionsRva + 8, 0x3000);     // RVA outside the module
        WriteLe32(image, namesRva + 0, 0x1080);
        WriteLe32(image, namesRva + 4, 0x1090);
        WriteLe32(image, namesRva + 8, 0x10A0);
        WriteLe16(image, ordinalsRva + 0, 0);
        WriteLe16(image, ordinalsRva + 2, 1);
        WriteLe16(image, ordinalsRva + 4, 2);
        WriteAsciiZ(image, 0x1080, "FixtureCallee");
        WriteAsciiZ(image, 0x1090, "Forwarded");
        WriteAsciiZ(image, 0x10A0, "Bogus");
        image[codeRva] = 0xC3; // ret
        testshim::WriteImageBytes(base, image);

        ExpectError(HandleGetModuleFunctions(Req("GetModuleFunctions", "\"module\":\"other.exe\""), "7"),
            "no loaded module matches");

        const std::string ok = HandleGetModuleFunctions(
            Req("GetModuleFunctions", "\"module\":\"app.exe\""), "7");
        ExpectOk(ok);
        Require(Contains(ok, "\"source\":\"exports\""), "export fallback source missing");
        Require(Contains(ok, "\"returnedCount\":1"), "only the valid export must survive");
        Require(Contains(ok, "\"name\":\"FixtureCallee\""), "valid export name missing");
        Require(Contains(ok, "\"entry\":\"" + HexAddress(base + codeRva) + "\""), "valid export entry wrong");
        Require(Contains(ok, "\"rva\":\"" + HexAddress(codeRva) + "\""), "valid export rva wrong");
        Require(!Contains(ok, "Forwarded"), "forwarded export must be skipped");
        Require(!Contains(ok, "Bogus"), "out-of-module export must be skipped");
        Require(Contains(ok, "\"truncated\":false"), "full export list must not truncate");

        const std::string capped = HandleGetModuleFunctions(
            Req("GetModuleFunctions", "\"module\":\"app.exe\",\"maxItems\":1"), "7");
        ExpectOk(capped);
        Require(Contains(capped, "\"returnedCount\":1"), "maxItems=1 must return one row");
        Require(Contains(capped, "\"truncated\":true"), "maxItems=1 must report truncation");
    }

    // m4: a corrupt export directory with an unbounded NumberOfFunctions
    // must fail loudly instead of admitting ordinals up to 2^32-1.
    void TestGetModuleFunctionsImplausibleCounts()
    {
        constexpr std::uintptr_t base = 0x400000;
        constexpr std::size_t moduleSize = 0x2000;
        constexpr std::uint32_t ntRva = 0x80;
        constexpr std::uint32_t exportRva = 0x1000;

        testshim::Reset();
        testshim::SetMemoryPages({testshim::MakeImagePage(base, moduleSize, PAGE_EXECUTE_READ, "C:\\test\\app.exe")});
        testshim::SetModuleName(base, "app.exe");
        std::vector<unsigned char> image(moduleSize, 0);
        image[0] = 'M';
        image[1] = 'Z';
        WriteLe32(image, 0x3C, ntRva);
        image[ntRva] = 'P';
        image[ntRva + 1] = 'E';
        WriteLe16(image, ntRva + 24, 0x20B);
        WriteLe32(image, ntRva + 24 + 112, exportRva);
        WriteLe32(image, ntRva + 24 + 116, 0x100);
        WriteLe32(image, exportRva + 20, 2 * 1024 * 1024); // NumberOfFunctions: implausible
        WriteLe32(image, exportRva + 24, 1);               // NumberOfNames
        WriteLe32(image, exportRva + 28, 0x1040);
        WriteLe32(image, exportRva + 32, 0x1060);
        WriteLe32(image, exportRva + 36, 0x1070);
        testshim::WriteImageBytes(base, image);

        ExpectError(HandleGetModuleFunctions(Req("GetModuleFunctions", "\"module\":\"app.exe\""), "7"),
            "export function count is implausible");
    }

    void RunReadHandlerTests()
    {
        TestReadMemoryChunk();
        TestReadDisassemblyChunk();
        TestEvaluateExpression();
        TestGetMemoryMap();
        TestReadStringAndModules();
        TestGetXrefs();
        TestInspectAddress();
        TestInspectAddressFlags();
        TestTraceAndOpenTarget();
        TestGetModuleFunctionsExportFallback();
        TestGetModuleFunctionsImplausibleCounts();
    }
} // namespace dbglink_read_tests
