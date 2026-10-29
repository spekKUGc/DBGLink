#include <algorithm>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../../src/native/DbgLink.Native/NativeJson.h"
#include "../../src/native/DbgLink.Native/NativeAnalysisData.h"
#include "../../src/native/DbgLink.Native/NativeHexFormat.h"

namespace dbglink_command_text_tests
{
    void RunNativeCommandTextTests();
    void TestCommandArgumentFieldPolicy();
}

namespace dbglink_bounded_text_tests
{
    void RunBoundedTextTests();
}

namespace dbglink_address_parsing_tests
{
    void RunAddressParsingTests();
}

namespace dbglink_input_validation_tests
{
    void RunInputValidationTests();
}

namespace dbglink_control_tests
{
    void RunControlHandlerTests();
}

namespace dbglink_search_tests
{
    void RunSearchHandlerTests();
}

namespace dbglink_state_edit_tests
{
    void RunStateEditTests();
}

namespace dbglink_thread_tests
{
    void RunThreadHandlerTests();
}

namespace dbglink_read_tests
{
    void RunReadHandlerTests();
}

namespace dbglink_request_params_tests
{
    void RunRequestParamTests();
}

namespace dbglink_coverage_tests
{
    void RunCoverageTests();
}

namespace dbglink_pipe_auth_tests
{
    void RunPipeAuthTests();
}

namespace dbglink_pipe_drain_tests
{
    void RunPipeDrainTests();
}

namespace dbglink_native_json_tests
{
    using namespace dbglink;
    constexpr std::size_t kMaxPipeRequestBytes = 64 * 1024;


    void Require(bool condition, std::string_view message)
    {
        if (!condition)
            throw std::runtime_error(std::string(message));
    }

    bool Parses(std::string request)
    {
        BeginJsonRequestParse(request);
        return IsJsonObjectRequest(request);
    }

    /// <summary>Top-level member names of the last parsed request. The
    /// product surface only exposes the validity check, so the enumeration
    /// lives here and reads the cached document.</summary>
    std::vector<std::string> TopLevelMembers(const std::string& request)
    {
        BeginJsonRequestParse(request);
        std::vector<std::string> names;
        const auto* document = CachedRequestDocument(request);
        if (document == nullptr)
            return names;
        for (auto it = document->begin(); it != document->end(); ++it)
            names.push_back(it.key());
        return names;
    }

    void ExpectInvalid(std::string request, std::string_view label)
    {
        Require(!Parses(std::move(request)), label);
    }

    void TestValidBoundaries()
    {
        std::vector<std::string> members =
            TopLevelMembers(" { \"method\" : \"tools/call\", \"params\" : { \"name\" : \"GetServerStatus\" } } \n");
        Require(members.size() == 2 && members[0] == "method" && members[1] == "params",
            "top-level member ranges were not recorded");

        const std::string unicode = R"({"params":{"text":"line\n\u0021 \uD83D\uDE00"}})";
        Require(Parses(unicode), "valid JSON escapes were rejected");
        std::string decoded;
        Require(ExtractJsonString(unicode, "text", decoded), "escaped JSON string was not extracted");
        Require(decoded == "line\n! \xF0\x9F\x98\x80", "escaped JSON string decoded incorrectly");

        const std::string atLimitPrefix = "{\"padding\":\"";
        std::string atLimit = atLimitPrefix;
        atLimit.append(kMaxPipeRequestBytes - atLimitPrefix.size() - 2, 'a');
        atLimit += "\"}";
        Require(atLimit.size() == kMaxPipeRequestBytes, "the exact request-size boundary was not constructed");
        Require(Parses(atLimit), "a valid request at the byte limit was rejected");

        std::string overLimit = atLimit;
        overLimit.insert(overLimit.size() - 2, "a");
        Require(overLimit.size() == kMaxPipeRequestBytes + 1, "the over-limit request was not constructed");
        ExpectInvalid(std::move(overLimit), "a request over the byte limit was accepted");

        std::string membersAtLimit = "{";
        for (std::size_t index = 0; index < 512; ++index)
        {
            if (index != 0)
                membersAtLimit += ',';
            membersAtLimit += "\"k" + std::to_string(index) + "\":0";
        }
        membersAtLimit += "}";
        Require(Parses(membersAtLimit), "512 object members were rejected");
        membersAtLimit.insert(membersAtLimit.size() - 1, ",\"overflow\":0");
        ExpectInvalid(std::move(membersAtLimit), "513 object members were accepted");

        std::string nested = "{";
        nested += "\"value\":";
        for (int depth = 0; depth < 16; ++depth)
            nested += "[";
        nested += '0';
        for (int depth = 0; depth < 16; ++depth)
            nested += "]";
        nested += "}";
        Require(Parses(nested), "JSON at the maximum nesting depth was rejected");
        nested.insert(nested.find('0'), "[");
        ExpectInvalid(std::move(nested), "JSON beyond the maximum nesting depth was accepted");
    }

    void TestCorruptedRequests()
    {
        const std::vector<std::pair<std::string, std::string_view>> invalid =
        {
            { "", "empty request" },
            { "[]", "array request" },
            { "{", "unterminated object" },
            { "{\"a\" 1}", "missing colon" },
            { "{\"a\":}", "missing value" },
            { "{\"a\":1,}", "trailing comma" },
            { "{\"a\":1 \"b\":2}", "missing comma" },
            { "{\"a\":\"bad\\q\"}", "invalid escape" },
            { std::string("{\"a\":\"") + std::string(1, '\x01') + "\"}", "unescaped control character" },
            { R"({"a":"\u12G4"})", "invalid unicode digit" },
            { R"({"a":"\uD800"})", "lone high surrogate" },
            { R"({"a":"\uDC00"})", "lone low surrogate" },
            { R"({"a":01})", "leading zero" },
            { R"({"a":1.})", "missing fraction digits" },
            { R"({"a":1e})", "missing exponent digits" },
            { R"({"a":truex})", "literal with suffix" },
            { R"({"a":null} trailing)", "trailing data" },
            { R"({"a":1,"a":2})", "duplicate property" },
            { R"({"x":1,"\u0078":2})", "duplicate escaped property" },
            { std::string("{\"text\":\"") + std::string("\xC0\xAF", 2) + "\"}", "invalid UTF-8" },
        };

        for (const auto& [request, label] : invalid)
            ExpectInvalid(request, label);
    }

    void TestPrimitiveExtraction()
    {
        const std::string request = R"({"id":42,"method":"test","params":{"text":"hello","number":"18446744073709551615","flag":true}})";
        Require(Parses(request), "primitive extraction fixture was rejected");

        Require(ExtractId(request) == "42", "numeric JSON-RPC id was not preserved");
        std::string text;
        Require(ExtractJsonString(request, "text", text) && text == "hello", "string member extraction failed");

        std::uint64_t number = 0;
        Require(ExtractUnsigned(request, "number", number) && number == std::numeric_limits<std::uint64_t>::max(),
            "maximum unsigned integer extraction failed");
        bool flag = false;
        Require(ExtractBoolean(request, "flag", flag) && flag, "boolean extraction failed");

        const std::vector<std::string> nonUnsigned =
        {
            R"({"value":-1})",
            R"({"value":1.0})",
            R"({"value":1e2})",
            R"({"value":18446744073709551616})",
            R"({"value":"not-a-number"})",
        };
        for (const auto& valueRequest : nonUnsigned)
        {
            Require(Parses(valueRequest), "non-unsigned extraction fixture was rejected");
            Require(!ExtractUnsigned(valueRequest, "value", number), "invalid unsigned value was accepted");
        }

        Require(ExtractId(R"({"id":{}})") == "null", "object JSON-RPC id was accepted");
        Require(!ExtractBoolean(R"({"flag":1})", "flag", flag), "numeric boolean was accepted");
    }

    void TestManagedRequestEnvelope()
    {
        const std::string request = R"({"id":7,"method":"ReadMemAtAddress","params":{"address":"0x140001000","byteCount":64}})";
        Require(Parses(request), "managed request envelope was rejected");
        std::string address;
        std::uint64_t bytes = 0;
        Require(ExtractId(request) == "7", "request id did not come from the envelope");
        Require(ExtractJsonString(request, "address", address) && address == "0x140001000", "params.address was not read");
        Require(ExtractUnsigned(request, "byteCount", bytes) && bytes == 64, "params.byteCount was not read");
        Require(!ExtractJsonString(R"({"method":"ReadMemAtAddress","address":"0x140001000"})", "address", address),
            "flat request argument was accepted");
        Require(!HasJsonProperty(request, "missing"), "missing parameter was reported as present");
        Require(ExtractId(R"({"id":7,"params":{"id":99}})") == "7", "params replaced the envelope id");
        ExpectInvalid(R"({"params":{"byteCount":1,"byteCount":2}})", "duplicate nested argument was accepted");

        std::string nested = "{\"x\":" + std::string(17, '[') + "0" + std::string(17, ']') + "}";
        ExpectInvalid(nested, "well-formed JSON exceeding the nesting limit was accepted");
        std::string array = "{\"x\":[0";
        for (int i = 1; i < 513; ++i) array += ",0";
        array += "]}";
        ExpectInvalid(array, "oversized nested array was accepted");
    }

    void TestUtf8AndTrim()
    {
        Require(IsValidUtf8("Hello world!"), "plain ASCII was rejected as invalid UTF-8");
        Require(IsValidUtf8("\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82"), "Cyrillic was rejected as invalid UTF-8");
        Require(IsValidUtf8("\xF0\x9F\x98\x80"), "4-byte emoji was rejected as invalid UTF-8");
        Require(!IsValidUtf8("\xC0\xAF"), "overlong UTF-8 was accepted");
        Require(!IsValidUtf8("\x80"), "stray UTF-8 continuation byte was accepted");
        Require(!IsValidUtf8("\xE0\x80\xAF"), "overlong 3-byte sequence was accepted");
        Require(!IsValidUtf8("trailing\xE2"), "truncated 3-byte sequence was accepted");

        Require(Trim("  hello  ") == "hello", "leading and trailing whitespace was not trimmed");
        Require(Trim("\t\r\nworld\n\r") == "world", "control whitespace was not trimmed");
        Require(Trim("   ").empty(), "all-whitespace string was not trimmed to empty");
        Require(Trim("").empty(), "empty string trim failed");
        Require(Trim("a b c") == "a b c", "internal whitespace was modified by trim");

        Require(ToLower("ABC") == "abc", "ASCII lowercase conversion failed");
        Require(ToLower("  RAX\t") == "  rax\t", "lowercase conversion altered whitespace");
        Require(ToLower("").empty(), "lowercasing an empty string failed");
        Require(ToLower("\xC3\x89X") == "\xC3\x89x", "lowercase conversion mishandled high-bit bytes");
    }
}

int main()
{
    try
    {
        using namespace dbglink;
        using dbglink_native_json_tests::Require;
        auto utf16 = [](std::u16string text)
        {
            std::vector<unsigned char> bytes;
            for (const auto unit : text)
            {
                bytes.push_back(static_cast<unsigned char>(unit & 255));
                bytes.push_back(static_cast<unsigned char>(unit >> 8));
            }
            bytes.push_back(0); bytes.push_back(0);
            return bytes;
        };
        std::string decoded;
        Require(TryDecodePrintableUtf16(utf16(u"\u041f\u0440\u0438\u0432\u0435\u0442"), decoded) &&
            decoded == "\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82", "Cyrillic UTF-16 was lost");
        Require(TryDecodePrintableUtf16(utf16(u"\u4e2d\U0001f600\n"), decoded) &&
            decoded == "\xE4\xB8\xAD\xF0\x9F\x98\x80\n", "CJK or surrogate pair was decoded incorrectly");
        for (auto bytes : std::vector<std::vector<unsigned char>>{
            {0, 0}, {0, 0xD8, 0, 0}, {0, 0xDC, 0, 0}, {65, 0}, {65, 0, 0}, {1, 0, 0, 0}})
            Require(!TryDecodePrintableUtf16(bytes, decoded) && decoded.empty(), "Invalid UTF-16 was accepted");

        // Address rendering contract: compact lowercase hex everywhere via
        // HexAddress (address fields, sizes, RVAs and offsets alike).
        const std::string compactAddress = dbglink::HexAddress(0xDEADBEEFu);
        Require(compactAddress == "0xdeadbeef",
            "HexAddress must strip leading zeros and render lowercase");
        Require(dbglink::HexAddress(0) == "0x0",
            "HexAddress must keep a single zero digit");
        Require(dbglink::HexAddress(0x1A2u) == "0x1a2",
            "HexAddress must strip leading zeros and render lowercase");

        std::vector<ModuleRecord> modules;
        for (std::uintptr_t i = 0; i < 300; ++i)
        {
            ModuleRecord module{};
            module.base = 0x100000 + i * 0x10000;
            module.end = module.base + 0x1000;
            module.name = "m" + std::to_string(i) + ".dll";
            module.path = "C:\\modules\\" + module.name;
            modules.push_back(module);
        }
        const auto selected = nlohmann::json::parse(FormatModuleRecords("7", modules, false, "C:\\other\\m299.dll", 1024));
        Require(selected["id"] == 7 && selected["result"]["modules"].size() == 1 &&
            selected["result"]["modules"][0]["name"] == "m299.dll" &&
            selected["result"]["truncated"] == false, "Late module was lost before filtering");
        const auto limited = nlohmann::json::parse(FormatModuleRecords("8", modules, false, "", 1024));
        Require(limited["result"]["truncated"] == true && limited["result"]["matchedCount"] == 300,
            "Module output truncation was not reported");
        const auto incomplete = nlohmann::json::parse(FormatModuleRecords("9", modules, true, "missing.dll"));
        Require(incomplete["result"]["modules"].empty() && incomplete["result"]["truncated"] == true,
            "Incomplete map was reported as a complete negative result");

        std::vector<ModuleRecord> lettered;
        ModuleRecord letter{};
        letter.base = 0xABCDEF00;
        letter.end = 0xABCDF000;
        letter.name = "lettered.dll";
        letter.path = "C:\\modules\\lettered.dll";
        lettered.push_back(letter);
        const auto parsedLettered =
            nlohmann::json::parse(FormatModuleRecords("12", lettered, false, ""));
        Require(parsedLettered["result"]["modules"][0]["base"] == "0xabcdef00" &&
                parsedLettered["result"]["modules"][0]["end"] == "0xabcdf000",
            "Module addresses must use the shared compact lowercase hex format");
        dbglink_native_json_tests::TestValidBoundaries();
        dbglink_native_json_tests::TestCorruptedRequests();
        dbglink_native_json_tests::TestPrimitiveExtraction();
        dbglink_native_json_tests::TestManagedRequestEnvelope();
        dbglink_native_json_tests::TestUtf8AndTrim();
        dbglink_command_text_tests::RunNativeCommandTextTests();
        dbglink_command_text_tests::TestCommandArgumentFieldPolicy();
        dbglink_bounded_text_tests::RunBoundedTextTests();
        dbglink_input_validation_tests::RunInputValidationTests();
        dbglink_address_parsing_tests::RunAddressParsingTests();
        dbglink_control_tests::RunControlHandlerTests();
        dbglink_search_tests::RunSearchHandlerTests();
        dbglink_state_edit_tests::RunStateEditTests();
        dbglink_thread_tests::RunThreadHandlerTests();
        dbglink_read_tests::RunReadHandlerTests();
        dbglink_request_params_tests::RunRequestParamTests();
        dbglink_coverage_tests::RunCoverageTests();
        dbglink_pipe_auth_tests::RunPipeAuthTests();
        dbglink_pipe_drain_tests::RunPipeDrainTests();
        std::cout << "NativeJsonParserTests: PASS\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "NativeJsonParserTests: FAIL: " << exception.what() << '\n';
        return 1;
    }
}
