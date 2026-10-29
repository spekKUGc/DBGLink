#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../../src/native/DbgLink.Native/NativeHexFormat.h"
#include "../../src/native/DbgLink.Native/NativeJsonFormatting.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"

namespace dbglink
{
    // Link seam: NativeBridgeFoundation.cpp is now linked into the test
    // binary (it backs the new handler tests via X64DbgApiShim), so this
    // TU-local stub is static: internal linkage keeps the historical
    // "no debugger attached" state for the parsing tests without
    // colliding with the shim-backed definition in other TUs.
    // A module name that never exists keeps GetDebuggerBridgeFunction null,
    // i.e. "no debugger attached" — exactly the state these fast-path tests
    // target. Bridge-backed expressions (symbols, registers) are covered by
    // live/E2E suites instead.
    static const wchar_t* DebuggerBridgeModuleName()
    {
        return L"DbgLink.Tests.NoBridge.dll";
    }
}

namespace dbglink_address_parsing_tests
{
    using namespace dbglink;

    int g_checks = 0;
    const bool kIs64Bit = sizeof(std::uintptr_t) == 8;

    void Require(bool condition, const std::string& message)
    {
        ++g_checks;
        if (!condition)
            throw std::runtime_error("AddressParsing: " + message);
    }

    struct ResolveCase
    {
        const char* text;
        // Expectation on 64-bit. Values above 32 bits additionally require a
        // 64-bit build (a 32-bit bridge cannot hold them).
        bool ok;
        std::uint64_t value;
    };

    void ExpectResolve(const ResolveCase& test)
    {
        std::uintptr_t address = 0;
        const bool parsed = ResolveAddress(test.text, address);
        const bool effectiveOk = test.ok && (kIs64Bit || test.value <= 0xFFFFFFFFULL);
        Require(parsed == effectiveOk,
            std::string("ResolveAddress('") + test.text + "') ok mismatch");
        if (effectiveOk)
        {
            Require(address == static_cast<std::uintptr_t>(test.value),
                std::string("ResolveAddress('") + test.text + "') value mismatch");
        }
    }

    struct ParseCase
    {
        const char* text;
        int base;
        bool ok;
        std::uint64_t value;
    };

    void ExpectParse(const ParseCase& test)
    {
        std::uintptr_t value = 0;
        const bool parsed = TryParseUnsignedText(test.text, test.base, value);
        const bool effectiveOk = test.ok && (kIs64Bit || test.value <= 0xFFFFFFFFULL);
        Require(parsed == effectiveOk,
            std::string("TryParseUnsignedText('") + test.text + "') ok mismatch");
        if (effectiveOk)
        {
            Require(value == static_cast<std::uintptr_t>(test.value),
                std::string("TryParseUnsignedText('") + test.text + "') value mismatch");
        }
    }

    void RunAddressParsingTests()
    {
        // Bare numbers are hex (x64dbg semantics + managed parity). The
        // decimal-looking inputs below are the regression zone: base-10-first
        // parsing used to turn "401000" into decimal 401000.
        const std::vector<ResolveCase> resolveCases{
            {"0", true, 0},
            {"00", true, 0},
            {"0001", true, 1},
            {"007", true, 7},
            {"1", true, 1},
            {"9", true, 9},
            {"10", true, 0x10},
            {"11", true, 0x11},
            {"99", true, 0x99},
            {"100", true, 0x100},
            {"123", true, 0x123},
            {"1000", true, 0x1000},
            {"1234", true, 0x1234},
            {"401000", true, 0x401000},
            {"7777777", true, 0x7777777},
            {"999999", true, 0x999999},
            {"123456789", true, 0x123456789},
            {"140001000", true, 0x140001000},
            {"401abc", true, 0x401ABC},
            {"401ABC", true, 0x401ABC},
            {"abcdef12", true, 0xABCDEF12},
            {"DEADBEEF", true, 0xDEADBEEF},
            {"deadbeef", true, 0xDEADBEEF},
            {"DeadBeef", true, 0xDEADBEEF},
            {"CAFEBABE", true, 0xCAFEBABE},
            {"ff", true, 0xFF},
            {"FF", true, 0xFF},
            {"0x0", true, 0},
            {"0X0", true, 0},
            {"0x1", true, 1},
            {"0xff", true, 0xFF},
            {"0xFF", true, 0xFF},
            {"0x0001", true, 1},
            {"0x00FF", true, 0xFF},
            {"0x1234", true, 0x1234},
            {"0Xabcd", true, 0xABCD},
            {"0xABCDEF", true, 0xABCDEF},
            {"0x140001000", true, 0x140001000},
            {"0xDEADBEEF", true, 0xDEADBEEF},
            {"7ffff7dd1000", true, 0x7FFFF7DD1000},
            {"0x7ffff7dd1000", true, 0x7FFFF7DD1000},
            {"  0x1234  ", true, 0x1234},
            {"  401000 ", true, 0x401000},
            {"\t0xAB\n", true, 0xAB},
            {"\t10\t", true, 0x10},
            {"FFFFFFFF", true, 0xFFFFFFFFULL},
            {"0xFFFFFFFF", true, 0xFFFFFFFFULL},
            {"100000000", true, 0x100000000ULL},
            {"0x100000000", true, 0x100000000ULL},
            {"1FFFFFFFF", true, 0x1FFFFFFFFULL},
            {"FFFFFFFFFFFFFFFF", true, 0xFFFFFFFFFFFFFFFFULL},
            {"0xFFFFFFFFFFFFFFFF", true, 0xFFFFFFFFFFFFFFFFULL},
            {"0Xffffffffffffffff", true, 0xFFFFFFFFFFFFFFFFULL},
            {"FFFFFFFFFFFFFFFE", true, 0xFFFFFFFFFFFFFFFEULL},
            {"8000000000000000", true, 0x8000000000000000ULL},
            {"7FFFFFFFFFFFFFFF", true, 0x7FFFFFFFFFFFFFFFULL},
            // No debugger bridge is linked into the test binary, so anything
            // that is not plain hex must fail here (with x64dbg attached the
            // same inputs fall through to DbgValFromString).
            {"", false, 0},
            {"   ", false, 0},
            {"\t\n", false, 0},
            {"0x", false, 0},
            {"0X", false, 0},
            {"0xx123", false, 0},
            {"00x123", false, 0},
            {"0x 123", false, 0},
            {"hello", false, 0},
            {"cip", false, 0},
            {"eax", false, 0},
            {"cip+10", false, 0},
            {"eax==1", false, 0},
            {"123.", false, 0},
            {"0xG0", false, 0},
            {"0x12 34", false, 0},
            {"12 34", false, 0},
            {"12\n34", false, 0},
            {"-1", false, 0},
            {"-0x1", false, 0},
            {"+10", false, 0},
            {"+0x10", false, 0},
            {"--1", false, 0},
            {"1_000", false, 0},
            {"1,000", false, 0},
            {"12h", false, 0},
            {"0o17", false, 0},
            {"0n10", false, 0},
            {"1p3", false, 0},
            {"0x1p3", false, 0},
            {"0xDEADBEEFG", false, 0},
            {" x ", false, 0},
            {"!", false, 0},
            {"FFFFFFFFFFFFFFFFFF", false, 0},
            {"10000000000000000", false, 0},
            {"12345678901234567890", false, 0},
            {"0x10000000000000000", false, 0},
        };
        for (const auto& test : resolveCases)
            ExpectResolve(test);

        const std::vector<ParseCase> parseCases{
            {"0", 16, true, 0},
            {"ff", 16, true, 0xFF},
            {"FF", 16, true, 0xFF},
            {"00ff", 16, true, 0xFF},
            {"10", 16, true, 0x10},
            {"401000", 16, true, 0x401000},
            {"401abc", 16, true, 0x401ABC},
            {"DEADBEEF", 16, true, 0xDEADBEEF},
            {"FFFFFFFF", 16, true, 0xFFFFFFFFULL},
            {"100000000", 16, true, 0x100000000ULL},
            {"FFFFFFFFFFFFFFFF", 16, true, 0xFFFFFFFFFFFFFFFFULL},
            {"", 16, false, 0},
            {" ", 16, false, 0},
            {"0x10", 16, false, 0},
            {"1g", 16, false, 0},
            {" 10", 16, false, 0},
            {"10 ", 16, false, 0},
            {"+10", 16, false, 0},
            {"-10", 16, false, 0},
            {"10000000000000000", 16, false, 0},
            {"FFFFFFFFFFFFFFFFFF", 16, false, 0},
            {"10", 10, true, 10},
            {"010", 10, true, 10},
            {"0", 10, true, 0},
            {"401000", 10, true, 401000},
            {"4294967295", 10, true, 0xFFFFFFFFULL},
            {"4294967296", 10, true, 0x100000000ULL},
            {"18446744073709551615", 10, true, 0xFFFFFFFFFFFFFFFFULL},
            {"ff", 10, false, 0},
            {"", 10, false, 0},
            {" 10", 10, false, 0},
            {"10 ", 10, false, 0},
            {"+10", 10, false, 0},
            {"-10", 10, false, 0},
            {"0x10", 10, false, 0},
            {"1_0", 10, false, 0},
            {"18446744073709551616", 10, false, 0},
            {"99999999999999999999", 10, false, 0},
        };
        for (const auto& test : parseCases)
            ExpectParse(test);

        // m1/m5: full-width hex rendering and width-clamped byte decode.
        // A 64-bit RVA must survive on 32-bit builds (old code narrowed
        // through uintptr_t and truncated to 0x40001000).
        Require(HexAddress(static_cast<std::uint64_t>(0x140001000ULL)) == "0x140001000",
            "HexAddress must render full 64-bit values without narrowing");
        Require(HexAddress(static_cast<std::uint64_t>(0xFFFFFFFFFFFFFFFFULL)) == "0xffffffffffffffff",
            "HexAddress must render the 64-bit maximum");
        {
            const unsigned char low[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            unsigned char wide[9]{};
            for (int i = 0; i < 8; ++i)
                wide[i] = low[i];
            wide[8] = 0xFF;
            const std::uintptr_t expected = BytesToUintPtr(low, 8);
            Require(BytesToUintPtr(wide, 9) == expected,
                "BytesToUintPtr must ignore bytes past the pointer width");
            Require(BytesToUintPtr(nullptr, 8) == 0,
                "BytesToUintPtr must handle a null buffer");
        }

        std::cout << "AddressParsingChecks: " << g_checks << "\n";
    }
}
