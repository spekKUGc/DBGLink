// NativeSearchHandlersTests.cpp — read/search handlers.
//
// Covers NativeSearchHandlers.cpp (ReadMemAtAddress, ReadDismAtAddress,
// FindBytePatternInModule) and NativeStringSearchHandlers.cpp
// (FindStringInModule, FindInterestingStrings) plus the ParseMaskedBytePattern
// units from NativeBytePatternSearch.cpp, all against scripted shim memory
// and memory-map pages.
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "../../src/native/DbgLink.Native/NativeBytePatternSearch.h"
#include "../../src/native/DbgLink.Native/NativeJsonFormatting.h"
#include "../../src/native/DbgLink.Native/NativeSearchHandlers.h"
#include "../../src/native/DbgLink.Native/NativeStringSearchHandlers.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"
#include "../../src/native/DbgLink.Native/NativeControlSupport.h"
#include "../../src/native/DbgLink.Native/X64DbgApiShim.h"

namespace dbglink_search_tests
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

    // One 4 KiB image module at 0x400000 with caller-supplied bytes at the
    // given offsets; the cheapest deterministic search fixture.
    void SetupModule(std::uintptr_t base = 0x400000, std::size_t size = 0x1000)
    {
        testshim::Reset();
        testshim::SetMemoryPages({testshim::MakeImagePage(base, size, PAGE_EXECUTE_READ, "C:\\test\\app.exe")});
        testshim::SetModuleName(base, "app.exe");
        testshim::WriteImageBytes(base, std::vector<unsigned char>(size, 0x90));
    }

    void TestParseMaskedBytePattern()
    {
        MaskedBytePattern parsed;
        std::string error;
        Require(ParseMaskedBytePattern("48 8B ??", parsed, error), "valid masked pattern was rejected");
        Require(parsed.bytes.size() == 3 && parsed.bytes[0] == 0x48 && parsed.bytes[1] == 0x8B,
            "masked pattern bytes mismatch");
        Require(parsed.exact[0] == 1 && parsed.exact[1] == 1 && parsed.exact[2] == 0,
            "masked pattern exact flags mismatch");

        Require(ParseMaskedBytePattern("0x48,0x8B-05", parsed, error), "0x/comma/dash form was rejected");
        Require(parsed.bytes.size() == 3 && parsed.bytes[2] == 0x05, "0x-prefixed token mismatch");

        Require(!ParseMaskedBytePattern("", parsed, error), "empty pattern was accepted");
        Require(!ParseMaskedBytePattern("?? ??", parsed, error) &&
            Contains(error, "at least one exact byte"), "all-wildcard pattern was accepted");
        Require(!ParseMaskedBytePattern("ZZ", parsed, error), "non-hex token was accepted");
        Require(!ParseMaskedBytePattern("4", parsed, error), "odd token was accepted");

        std::string many;
        for (int i = 0; i < 257; ++i)
        {
            if (i != 0)
                many += ' ';
            many += "41";
        }
        Require(!ParseMaskedBytePattern(many, parsed, error) &&
            Contains(error, "between 1 and 256"), "257-token pattern was accepted");
    }

    void TestReadMemory()
    {
        SetupModule();
        testshim::WriteImageBytes(0x401000, {0x48, 0x8B, 0x05, 0x00});

        ExpectError(HandleReadMemory(Req("ReadMemAtAddress", ""), "7"),
            "ReadMemAtAddress address must be a non-empty printable expression");
        ExpectError(HandleReadMemory(Req("ReadMemAtAddress", "\"address\":\"0x401000\",\"byteCount\":0"), "7"),
            "ReadMemAtAddress byteCount must be between 1 and 65536.");
        ExpectError(HandleReadMemory(Req("ReadMemAtAddress", "\"address\":\"0x401000\",\"byteCount\":65537"), "7"),
            "ReadMemAtAddress byteCount must be between 1 and 65536.");
        ExpectError(HandleReadMemory(Req("ReadMemAtAddress", "\"address\":\"0x600000\""), "7"),
            "Failed to read memory at " + HexAddress(0x600000));

        const std::string ok = HandleReadMemory(
            Req("ReadMemAtAddress", "\"address\":\"0x401000\",\"byteCount\":4"), "7");
        Require(Contains(ok, "\"ok\":true"), "expected ok:true for a readable address");
        Require(Contains(ok, "\"method\":\"ReadMemAtAddress\""), "method field missing");
        Require(Contains(ok, HexAddress(0x401000)), "dump must start at the requested address");
        Require(Contains(ok, "48"), "dump must contain the scripted bytes");

        // The 65536 ceiling passes validation, then fails against the 4 KiB
        // scripted image: validation and read errors stay distinguishable.
        ExpectError(HandleReadMemory(
            Req("ReadMemAtAddress", "\"address\":\"0x400000\",\"byteCount\":65536"), "7"),
            "Failed to read memory at " + HexAddress(0x400000));
        const std::string one = HandleReadMemory(
            Req("ReadMemAtAddress", "\"address\":\"0x400000\",\"byteCount\":1"), "7");
        ExpectOk(one);
    }

    // w17 multi-range read: address XOR ranges, 1..8 entries, per-entry and
    // total byte caps, and per-index error isolation over scripted memory.
    void TestReadMemoryRanges()
    {
        SetupModule();
        testshim::WriteImageBytes(0x401000, {0x48, 0x8B, 0x05, 0x00});
        testshim::WriteImageBytes(0x400000, {0xAA, 0xBB});

        ExpectError(HandleReadMemory(
            Req("ReadMemAtAddress",
                "\"address\":\"0x401000\",\"ranges\":[{\"address\":\"0x401000\",\"byteCount\":1}]"), "7"),
            "takes either address or ranges, not both.");
        ExpectError(HandleReadMemory(Req("ReadMemAtAddress", "\"ranges\":[]"), "7"),
            "ranges must contain 1 to 8 entries.");
        ExpectError(HandleReadMemory(
            Req("ReadMemAtAddress", "\"ranges\":[{},{},{},{},{},{},{},{},{}]"), "7"),
            "ranges must contain 1 to 8 entries.");
        const std::string badSize = HandleReadMemory(
            Req("ReadMemAtAddress", "\"ranges\":[{\"address\":\"0x401000\",\"byteCount\":4097}]"), "7");
        ExpectOk(badSize);
        Require(Contains(badSize,
            "[0] error=ReadMemAtAddress ranges[0].byteCount must be between 1 and 4096."),
            "oversized range byteCount must fail by index, not the whole request");
        ExpectError(HandleReadMemory(
            Req("ReadMemAtAddress",
                "\"ranges\":[{\"address\":\"0x401000\",\"byteCount\":4096},"
                "{\"address\":\"0x401000\",\"byteCount\":4096},"
                "{\"address\":\"0x401000\",\"byteCount\":4096},"
                "{\"address\":\"0x401000\",\"byteCount\":4096},"
                "{\"address\":\"0x401000\",\"byteCount\":4096}]"),
            "7"),
            "total byteCount across ranges must not exceed 16384.");

        const std::string mixed = HandleReadMemory(
            Req("ReadMemAtAddress",
                "\"ranges\":[{\"address\":\"0x401000\",\"byteCount\":4},"
                "{\"address\":\"0x600000\",\"byteCount\":4},"
                "{\"address\":\"0x400000\",\"byteCount\":2}]"),
            "7");
        ExpectOk(mixed);
        Require(Contains(mixed, "ranges=3"), "range count echo missing");
        Require(Contains(mixed, "[0] address=" + HexAddress(0x401000) + " byteCount=4"), "first range header wrong");
        Require(Contains(mixed, "[1] error=Failed to read memory at " + HexAddress(0x600000)),
            "bad range must fail by index");
        Require(Contains(mixed, "[2] address=" + HexAddress(0x400000) + " byteCount=2"), "third range header wrong");
        // Compact dump: single header address, contiguous lowercase hex, no
        // ASCII gutter by default.
        Require(Contains(mixed, "488b0500"), "first range bytes missing");
        Require(Contains(mixed, "aabb"), "third range bytes missing");
        Require(!Contains(mixed, "48 8B"), "dump must not use the legacy spaced uppercase shape");
    }

    // Token-light dump shape: header address + byte count, contiguous
    // lowercase rows, all-zero rows collapsed with an exact count, and the
    // includeAscii/spacedHex opt-ins restoring the legacy extras.
    void TestCompactHexDumpShape()
    {
        SetupModule();
        testshim::WriteImageBytes(0x401000, {0x48, 0x8B, 0x05, 0x00});

        const std::string compact = HandleReadMemory(
            Req("ReadMemAtAddress", "\"address\":\"0x401000\",\"byteCount\":4"), "7");
        ExpectOk(compact);
        Require(Contains(compact, HexAddress(0x401000) + " (4 bytes)"), "dump header must carry address and length");
        Require(Contains(compact, "488b0500"), "dump body must be contiguous lowercase hex");

        const std::string ascii = HandleReadMemory(
            Req("ReadMemAtAddress", "\"address\":\"0x401000\",\"byteCount\":4,\"includeAscii\":true"), "7");
        ExpectOk(ascii);
        Require(Contains(ascii, "488b0500  H..."), "includeAscii must re-add the ASCII gutter");

        const std::string spaced = HandleReadMemory(
            Req("ReadMemAtAddress", "\"address\":\"0x401000\",\"byteCount\":4,\"spacedHex\":true"), "7");
        ExpectOk(spaced);
        Require(Contains(spaced, "48 8b 05 00"), "spacedHex must re-add inter-byte spaces");

        ExpectError(HandleReadMemory(
            Req("ReadMemAtAddress", "\"address\":\"0x401000\",\"byteCount\":4,\"includeAscii\":\"yes\""), "7"),
            "ReadMemAtAddress includeAscii must be a boolean.");
        ExpectError(HandleReadMemory(
            Req("ReadMemAtAddress", "\"address\":\"0x401000\",\"byteCount\":4,\"spacedHex\":\"yes\""), "7"),
            "ReadMemAtAddress spacedHex must be a boolean.");

        // 20 bytes: one nonzero byte + 19 zeros. The first 16-byte row still
        // prints (it holds 0xCC); only the all-zero 4-byte tail collapses,
        // with an exact count so the bytes stay recoverable (16 + 4 == 20).
        // The address sits inside the 4 KiB scripted image on purpose: an
        // out-of-image address would only read via the shim's sparse-store
        // extension, not a realistic in-image read.
        std::vector<unsigned char> twenty(20, 0);
        twenty[0] = 0xCC;
        testshim::WriteImageBytes(0x400800, twenty);
        const std::string collapsed = HandleReadMemory(
            Req("ReadMemAtAddress", "\"address\":\"0x400800\",\"byteCount\":20"), "7");
        ExpectOk(collapsed);
        Require(Contains(collapsed, HexAddress(0x400800) + " (20 bytes)"), "collapsed header must report the full length");
        Require(Contains(collapsed, "* [repeated 4 zero bytes omitted]"), "zero tail must collapse with an exact count");
    }

    // Multi-range reads honour the dump flags too (read once, applied to
    // every range): spacedHex separates bytes and includeAscii re-adds the
    // gutter in each range body.
    void TestReadMemoryRangesFlags()
    {
        SetupModule();
        testshim::WriteImageBytes(0x400100, {0x48, 0x8B, 0x05, 0x00});
        testshim::WriteImageBytes(0x400200, {0xAA, 0xBB});

        const std::string flagged = HandleReadMemory(
            Req("ReadMemAtAddress",
                "\"ranges\":[{\"address\":\"0x400100\",\"byteCount\":4},"
                "{\"address\":\"0x400200\",\"byteCount\":2}],"
                "\"includeAscii\":true,\"spacedHex\":true"),
            "7");
        ExpectOk(flagged);
        Require(Contains(flagged, "ranges=2"), "range count echo missing");
        Require(Contains(flagged, "[0] address=" + HexAddress(0x400100) + " byteCount=4"),
            "first range header wrong");
        Require(Contains(flagged, "[1] address=" + HexAddress(0x400200) + " byteCount=2"),
            "second range header wrong");
        Require(Contains(flagged, "48 8b 05 00"), "first range must render spaced hex");
        Require(Contains(flagged, "aa bb"), "second range must render spaced hex");
        Require(Contains(flagged, "H..."), "first range must carry the ASCII gutter");
        Require(!Contains(flagged, "488b0500"), "flagged ranges must not render contiguous hex");

        ExpectError(HandleReadMemory(
            Req("ReadMemAtAddress",
                "\"ranges\":[{\"address\":\"0x400100\",\"byteCount\":4}],\"includeAscii\":\"yes\""), "7"),
            "ReadMemAtAddress includeAscii must be a boolean.");
        ExpectError(HandleReadMemory(
            Req("ReadMemAtAddress",
                "\"ranges\":[{\"address\":\"0x400100\",\"byteCount\":4}],\"spacedHex\":\"yes\""), "7"),
            "ReadMemAtAddress spacedHex must be a boolean.");
    }

    void TestReadDisassembly()
    {
        SetupModule();
        testshim::SetDisasm("mov eax, ebx", 3);
        testshim::WriteImageBytes(0x401000, {0x8B, 0xC3, 0x90});

        ExpectError(HandleDisassembly(Req("ReadDismAtAddress", ""), "7"),
            "ReadDismAtAddress address must be a non-empty printable expression");
        ExpectError(HandleDisassembly(Req("ReadDismAtAddress", "\"address\":\"0x401000\",\"byteCount\":0"), "7"),
            "ReadDismAtAddress byteCount must be between 1 and 65536.");

        const std::string ok = HandleDisassembly(
            Req("ReadDismAtAddress", "\"address\":\"0x401000\",\"byteCount\":3"), "7");
        Require(Contains(ok, "\"ok\":true"), "expected ok:true for disassembly");
        Require(Contains(ok, "\"method\":\"ReadDismAtAddress\""), "method field missing");
        Require(Contains(ok, "mov eax, ebx"), "scripted instruction text missing");
        Require(Contains(ok, HexAddress(0x401000)), "instruction address missing");

        testshim::SetDisasm("", 0);
        Require(Contains(HandleDisassembly(
            Req("ReadDismAtAddress", "\"address\":\"0x401000\",\"byteCount\":1"), "7"), "<undecodable>"),
            "zero-size disassembly must render <undecodable>");
    }

    void TestFindBytePattern()
    {
        SetupModule();
        testshim::WriteImageBytes(0x400100, {0x48, 0x8B, 0x05, 0xAA});

        ExpectError(HandleFindBytePatternInModule(Req("FindBytePatternInModule", ""), "7"),
            "FindBytePatternInModule pattern is required.");
        ExpectError(HandleFindBytePatternInModule(
            Req("FindBytePatternInModule", "\"pattern\":\"?? ??\""), "7"),
            "FindBytePatternInModule pattern must contain at least one exact byte.");
        ExpectError(HandleFindBytePatternInModule(
            Req("FindBytePatternInModule", "\"pattern\":\"48\",\"maxResults\":0"), "7"),
            "FindBytePatternInModule maxResults must be between 1 and 512.");
        ExpectError(HandleFindBytePatternInModule(
            Req("FindBytePatternInModule", "\"pattern\":\"48\",\"maxResults\":513"), "7"),
            "FindBytePatternInModule maxResults must be between 1 and 512.");
        ExpectError(HandleFindBytePatternInModule(
            Req("FindBytePatternInModule", "\"pattern\":\"48\",\"maxScanBytes\":4095"), "7"),
            "FindBytePatternInModule maxScanBytes must be between 4096 and 67108864.");
        ExpectError(HandleFindBytePatternInModule(
            Req("FindBytePatternInModule", "\"pattern\":\"48\",\"maxScanBytes\":67108865"), "7"),
            "FindBytePatternInModule maxScanBytes must be between 4096 and 67108864.");

        const std::string ok = HandleFindBytePatternInModule(
            Req("FindBytePatternInModule", "\"pattern\":\"48 8B ??\",\"module\":\"app.exe\""), "7");
        Require(Contains(ok, "\"ok\":true"), "expected ok:true for a matching pattern");
        Require(Contains(ok, "matches=1"), "expected exactly one match");
        Require(Contains(ok, "address=" + HexAddress(0x400100)), "match address mismatch");

        const std::string miss = HandleFindBytePatternInModule(
            Req("FindBytePatternInModule", "\"pattern\":\"00 11 22 33\",\"module\":\"app.exe\""), "7");
        Require(Contains(miss, "\"ok\":true"), "a clean miss must still be ok:true");
        Require(Contains(miss, "No matches"), "a clean miss must report No matches");

        const std::string filtered = HandleFindBytePatternInModule(
            Req("FindBytePatternInModule", "\"pattern\":\"48 8B ??\",\"module\":\"other.dll\""), "7");
        Require(Contains(filtered, "No matches"), "a non-matching module filter must yield no matches");

        // Two occurrences with maxResults=1 stop at the result limit.
        testshim::WriteImageBytes(0x400200, {0x48, 0x8B, 0x05});
        const std::string limited = HandleFindBytePatternInModule(
            Req("FindBytePatternInModule",
                "\"pattern\":\"48 8B 05\",\"module\":\"app.exe\",\"maxResults\":1"), "7");
        Require(Contains(limited, "matches=1"), "maxResults=1 must cap the matches");
        Require(Contains(limited, "resultLimitReached=true"), "limit stop must set resultLimitReached");
    }

    void TestFindString()
    {
        SetupModule();
        testshim::WriteImageString(0x400200, "hello");
        testshim::WriteImageString16(0x400300, "wide");

        ExpectError(HandleFindStringInModule(Req("FindStringInModule", ""), "7"),
            "FindStringInModule text must be non-empty, printable, and at most 256 bytes.");
        ExpectError(HandleFindStringInModule(
            Req("FindStringInModule", "\"text\":\"hi\",\"ascii\":false,\"unicode\":false"), "7"),
            "FindStringInModule enables at least one encoding.");
        ExpectError(HandleFindStringInModule(
            Req("FindStringInModule", "\"text\":\"hi\",\"maxResults\":513"), "7"),
            "FindStringInModule maxResults must be between 1 and 512.");

        const std::string ascii = HandleFindStringInModule(
            Req("FindStringInModule", "\"text\":\"hello\",\"module\":\"app.exe\""), "7");
        Require(Contains(ascii, "\"ok\":true"), "expected ok:true for an ascii hit");
        Require(Contains(ascii, "encoding=ascii"), "ascii hit must carry its encoding");
        Require(Contains(ascii, "address=" + HexAddress(0x400200)), "ascii hit address mismatch");

        const std::string wide = HandleFindStringInModule(
            Req("FindStringInModule", "\"text\":\"wide\",\"module\":\"app.exe\",\"ascii\":false"), "7");
        Require(Contains(wide, "encoding=utf-16le"), "utf-16le hit must carry its encoding");
        Require(Contains(wide, "address=" + HexAddress(0x400300)), "utf-16le hit address mismatch");
    }

    void TestFindInterestingStrings()
    {
        SetupModule();
        testshim::WriteImageString(0x400200, "an error occurred");

        ExpectError(HandleFindInterestingStrings(Req("FindInterestingStrings", "\"module\":42"), "7"),
            "FindInterestingStrings module must be a string.");

        const std::string ok = HandleFindInterestingStrings(
            Req("FindInterestingStrings", "\"module\":\"app.exe\""), "7");
        Require(Contains(ok, "\"ok\":true"), "expected ok:true for interesting strings");
        // NOTE: the envelope JSON-escapes the text body, so the wire bytes
        // carry backslash-quote sequences around the needle name.
        Require(Contains(ok, "[needle=\\\"error\\\"]"), "the error needle must group a match");
        Require(Contains(ok, "address=" + HexAddress(0x400203)), "needle hit address mismatch");
    }

    void RunSearchHandlerTests()
    {
        TestParseMaskedBytePattern();
        TestReadMemory();
        TestReadMemoryRanges();
        TestReadMemoryRangesFlags();
        TestCompactHexDumpShape();
        TestReadDisassembly();
        TestFindBytePattern();
        TestFindString();
        TestFindInterestingStrings();
    }
} // namespace dbglink_search_tests
