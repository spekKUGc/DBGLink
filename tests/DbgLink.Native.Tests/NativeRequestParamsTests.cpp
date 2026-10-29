// NativeRequestParamsTests.cpp — request validation, address resolution and
// bridge dispatch.
//
// Covers NativeRequestParams.cpp (every RequestParams helper at its ±1
// boundaries), ResolveAddressExpression/ResolveNonZeroAddressExpression
// (including the bare-hex parity with managed AddressMapping.TryParseAddress)
// and NativePipeServer.cpp HandleRequest (unknown-method/invalid-JSON/
// missing-method envelopes, ping, and one end-to-end dispatch through the
// kBridgeMethods table).
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

#include "../../src/native/DbgLink.Native/NativeControlHandlers.h"
#include "../../src/native/DbgLink.Native/NativeJson.h"
#include "../../src/native/DbgLink.Native/NativeJsonFormatting.h"
#include "../../src/native/DbgLink.Native/NativePipeServer.h"
#include "../../src/native/DbgLink.Native/NativeRequestParams.h"
#include "../../src/native/DbgLink.Native/NativeSearchHandlers.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"
#include "../../src/native/DbgLink.Native/NativeControlSupport.h"
#include "../../src/native/DbgLink.Native/X64DbgApiShim.h"

namespace dbglink_request_params_tests
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

    // NOTE: handler arguments live inside "params" (NativeJson.cpp Find);
    // root-level keys other than id/method are invisible to the helpers.
    static std::string P(const std::string& inner)
    {
        return "{\"params\":{" + inner + "}}";
    }

    void TestRequestParamsHelpers()
    {
        {
            // NOTE: RequestParams holds its request by const reference, so the
            // backing JSON must outlive the wrapper (no temporaries here).
            const std::string keepReq = P("\"keep\":\"v\"");
            const RequestParams params(keepReq);
            Require(params.Has("keep"), "Has missed a present key");
            Require(!params.Has("missing"), "Has reported a missing key");
        }
        {
            const std::string emptyReq = P("");
            const RequestParams params(emptyReq);
            std::string out = "untouched";
            Require(params.OptionalString("absent", out, "must not fire").empty(), "absent optional must succeed");
            Require(out == "untouched", "absent optional must keep the output");
        }
        {
            const std::string nonStringReq = P("\"n\":7");
            const RequestParams params(nonStringReq);
            std::string out;
            Require(params.OptionalString("n", out, "non-string optional") == "non-string optional",
                "non-string optional must yield the call-site message");
        }
        {
            // RequiredString min/max: empty fails min=1, 3 bytes pass 1..3, 4 fail.
            const std::string emptyJson = P("\"k\":\"\"");
            const std::string okJson = P("\"k\":\"abc\"");
            const std::string longJson = P("\"k\":\"abcd\"");
            const RequestParams emptyReq(emptyJson);
            const RequestParams okReq(okJson);
            const RequestParams longReq(longJson);
            std::string out;
            Require(emptyReq.RequiredString("k", out, "need-k", 1, 3) == "need-k", "empty must fail minBytes=1");
            Require(okReq.RequiredString("k", out, "need-k", 1, 3).empty() && out == "abc",
                "3-byte value at maxBytes=3 must pass");
            Require(longReq.RequiredString("k", out, "need-k", 1, 3) == "need-k",
                "4-byte value over maxBytes=3 must fail");
            Require(RequestParams(P("")).RequiredString("k", out, "need-k", 1, 3) == "need-k",
                "missing required string must fail");
        }
        {
            // OptionalStringBounded caps inline during extraction.
            const std::string boundedOkJson = P("\"k\":\"ab\"");
            const std::string boundedLongJson = P("\"k\":\"abc\"");
            const RequestParams okReq(boundedOkJson);
            const RequestParams longReq(boundedLongJson);
            std::string out;
            Require(okReq.OptionalStringBounded("k", out, 2, "bounded") == "" && out == "ab",
                "value at the inline cap must pass");
            Require(longReq.OptionalStringBounded("k", out, 2, "bounded") == "bounded",
                "value over the inline cap must fail");
        }
        {
            // BoundedUnsigned [5,10]: 4/11 fail, 5/10 pass, absent keeps out.
            std::uint64_t value = 99;
            Require(RequestParams(P("")).BoundedUnsigned("n", value, 5, 10, "range") == "" && value == 99,
                "absent bounded value must keep the output");
            Require(RequestParams(P("\"n\":4")).BoundedUnsigned("n", value, 5, 10, "range") == "range",
                "4 below lo=5 must fail");
            Require(RequestParams(P("\"n\":11")).BoundedUnsigned("n", value, 5, 10, "range") == "range",
                "11 above hi=10 must fail");
            Require(RequestParams(P("\"n\":5")).BoundedUnsigned("n", value, 5, 10, "range") == "" && value == 5,
                "lo edge must pass");
            Require(RequestParams(P("\"n\":10")).BoundedUnsigned("n", value, 5, 10, "range") == "" && value == 10,
                "hi edge must pass");
            Require(RequestParams(P("\"n\":\"x\"")).BoundedUnsigned("n", value, 5, 10, "range") == "range",
                "non-integer bounded value must fail");
        }
        {
            std::uint64_t value = 0;
            Require(RequestParams(P("\"n\":\"x\"")).OptionalUnsigned("n", value, "uint-msg") == "uint-msg",
                "non-integer optional unsigned must fail");
            bool flag = false;
            Require(RequestParams(P("\"b\":\"yes\"")).OptionalBoolean("b", flag, "bool-msg") == "bool-msg",
                "non-boolean optional must fail");
            Require(RequestParams(P("\"b\":true")).OptionalBoolean("b", flag, "bool-msg") == "" && flag,
                "boolean true must extract");
        }
        {
            std::string out;
            Require(RequestParams(P("\"t\":\"a\"")).RequiredSearchText("t", out, "search-msg") == "" &&
                out == "a", "printable search text must pass");
            Require(RequestParams(P("\"t\":\"a\"")).RequiredSearchText("missing", out, "search-msg") == "search-msg",
                "missing search text must fail");
            Require(RequestParams(P("\"t\":\"a\\u0001b\"")).RequiredSearchText("t", out, "search-msg") ==
                "search-msg", "control byte in search text must fail");
            Require(RequestParams(P("\"t\":7")).RequiredSearchText("t", out, "search-msg") == "search-msg",
                "non-string search text must fail");
        }
        {
            std::string out = "kept";
            Require(RequestParams(P("")).OptionalModuleFilter("m", out, "str-msg", "filter-msg") == "" &&
                out == "kept", "absent module filter must keep the output");
            Require(RequestParams(P("\"m\":7")).OptionalModuleFilter("m", out, "str-msg", "filter-msg") ==
                "str-msg", "non-string module filter must yield the string message");
            Require(RequestParams(P("\"m\":\"a\\u0009b\"")).OptionalModuleFilter(
                    "m", out, "str-msg", "filter-msg") == "filter-msg",
                "control byte in module filter must yield the filter message");
        }
    }

    void TestResolveAddress()
    {
        std::uintptr_t address = 0;
        // 0x-prefixed and bare numbers both parse as hex — the bare-hex fast
        // path mirrors managed AddressMapping.TryParseAddress.
        Require(ResolveAddressExpression("0x10", address).empty() && address == 0x10,
            "0x-prefixed address mismatch");
        Require(ResolveAddressExpression("401000", address).empty() && address == 0x401000,
            "bare number must parse as hex (managed parity)");
        Require(ResolveAddressExpression("  0x20  ", address).empty() && address == 0x20,
            "surrounding whitespace must be trimmed");
        Require(ResolveAddressExpression("0", address).empty() && address == 0, "zero must resolve to 0");
        Require(ResolveAddressExpression("", address) == "Invalid address or expression: ",
            "empty expression message mismatch");
        Require(ResolveAddressExpression("!!!", address) == "Invalid address or expression: !!!",
            "invalid expression message mismatch");
        Require(!ResolveNonZeroAddressExpression("0", address).empty(), "non-zero resolution must reject 0");

        // Scripted debugger expressions go through DbgValFromString, with
        // DbgIsValidExpression disambiguating a valid zero.
        testshim::Reset();
        testshim::SetExpression("myfunc", 0x600000);
        Require(ResolveAddressExpression("myfunc", address).empty() && address == 0x600000,
            "scripted expression mismatch");
        testshim::SetExpression("zerofunc", 0);
        Require(!ResolveAddressExpression("zerofunc", address).empty(), "zero expression must fail before validity");
        testshim::SetExpressionValid("zerofunc", true);
        Require(ResolveAddressExpression("zerofunc", address).empty() && address == 0,
            "valid zero expression must resolve");
    }

    void TestErrorEnvelopeShape()
    {
        // Byte-exact error envelope: {"id",ok:false,"error":{code,message}}.
        const std::string response = HandleReadMemory("{}", "7");
        Require(response ==
            "{\"id\":7,\"ok\":false,\"error\":{\"code\":\"native_error\",\"message\":"
            "\"ReadMemAtAddress address must be a non-empty printable expression of at most 256 bytes.\"}}",
            "error envelope is not byte-exact");
    }

    void TestHandleRequestDispatch()
    {
        testshim::Reset();
        Require(HandleRequest("{") ==
            "{\"id\":null,\"ok\":false,\"error\":{\"code\":\"native_error\",\"message\":"
            "\"Native bridge request is invalid JSON.\"}}",
            "invalid-JSON envelope mismatch");
        Require(Contains(HandleRequest(R"({"id":1})"), "Native bridge request requires a method."),
            "missing-method envelope mismatch");
        Require(Contains(HandleRequest(R"({"id":9,"method":"NoSuchMethod"})"), "Unknown bridge method."),
            "unknown-method envelope mismatch");
        Require(Contains(HandleRequest(R"({"id":9,"method":"NoSuchMethod"})"), "\"id\":9"),
            "unknown-method id echo missing");

        const std::string ping = HandleRequest(R"({"id":2,"method":"ping"})");
        Require(Contains(ping, "\"ok\":true"), "ping must succeed without a session");
        Require(Contains(ping, "\"plugin\":\"DBGLink\""), "ping plugin tag missing");
        Require(Contains(ping, "\"bridge\":\"native\""), "ping bridge tag missing");
        Require(Contains(ping, "\"debugging\":false"), "ping must report debugging=false by default");

        testshim::SetDebugging(true);
        Require(Contains(HandleRequest(R"({"id":2,"method":"GetServerStatus"})"), "\"debugging\":true"),
            "status must reflect the scripted debugging flag");

        // One full dispatch through the kBridgeMethods table: the request
        // travels HandleRequest -> HandleListBreakpoints -> shim BpList.
        testshim::AddBreakpoint(1, 0x401000, "entry", false);
        const std::string dispatched =
            HandleRequest(R"({"id":7,"method":"ListBreakpoints","params":{"maxItems":5}})");
        Require(Contains(dispatched, "\"ok\":true"), "dispatched ListBreakpoints must succeed");
        Require(Contains(dispatched, "\"address\":\"" + HexAddress(0x401000) + "\""),
            "dispatched list must carry the scripted breakpoint");
    }

    void RunRequestParamTests()
    {
        TestRequestParamsHelpers();
        TestResolveAddress();
        TestErrorEnvelopeShape();
        TestHandleRequestDispatch();
    }
} // namespace dbglink_request_params_tests
