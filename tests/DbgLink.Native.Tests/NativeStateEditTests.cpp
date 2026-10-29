// NativeStateEditTests.cpp — debugger state-edit handlers.
//
// Covers NativeStateEditHandlers.cpp (SetRegister, WriteMemory, CallFunction,
// SetLabel, SetComment, SetBookmark): validation errors, the register-file
// and memory-image side effects through the shim, the CallFunction frame
// layout, and annotation command construction.
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "../../src/native/DbgLink.Native/NativeBridgeFoundation.h"
#include "../../src/native/DbgLink.Native/NativeControlHandlers.h"
#include "../../src/native/DbgLink.Native/NativePipeServer.h"
#include "../../src/native/DbgLink.Native/NativeJsonFormatting.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"
#include "../../src/native/DbgLink.Native/NativeControlSupport.h"
#include "../../src/native/DbgLink.Native/X64DbgApiShim.h"

namespace dbglink_state_edit_tests
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

    void PausedSession()
    {
        testshim::Reset();
        testshim::SetDebugging(true);
    }

    void TestSetRegister()
    {
        testshim::Reset();
        ExpectError(HandleSetRegister(Req("SetRegister", "\"register\":\"rax\",\"value\":\"0x1\""), "7"),
            "No active debug session.");
        PausedSession();
        testshim::SetRunning(true);
        ExpectError(HandleSetRegister(Req("SetRegister", "\"register\":\"rax\",\"value\":\"0x1\""), "7"),
            "Target is running. Pause it before editing registers.");

        PausedSession();
        ExpectError(HandleSetRegister(Req("SetRegister", "\"value\":\"0x1\""), "7"),
            "SetRegister register is required.");
        ExpectError(HandleSetRegister(Req("SetRegister", "\"register\":\"rax\""), "7"),
            "SetRegister value is required");
        ExpectError(HandleSetRegister(Req("SetRegister", "\"register\":\"xyz\",\"value\":\"0x1\""), "7"),
            "Unknown register.");
        ExpectError(HandleSetRegister(Req("SetRegister", "\"register\":\"rax\",\"value\":\"0xZZ\""), "7"),
            "Invalid register value: 0xZZ");
        ExpectError(HandleSetRegister(
            Req("SetRegister", "\"register\":\"" + std::string(33, 'a') + "\",\"value\":\"0x1\""), "7"),
            "SetRegister register/value are too long.");

        // Canonicalisation is case-insensitive; oldValue comes from the live
        // register file before the write lands.
        testshim::SetRegister("rax", 0x1111);
        const std::string ok = HandleSetRegister(
            Req("SetRegister", "\"register\":\"RAX\",\"value\":\"0x2222\""), "7");
        ExpectOk(ok);
        Require(Contains(ok, "\"register\":\"rax\""), "register name must canonicalise to lowercase");
        Require(Contains(ok, "\"oldValue\":\"" + HexAddress(0x1111) + "\""), "oldValue mismatch");
        Require(Contains(ok, "\"newValue\":\"" + HexAddress(0x2222) + "\""), "newValue mismatch");

        testshim::SetValToStringResult(false);
        ExpectError(HandleSetRegister(Req("SetRegister", "\"register\":\"rax\",\"value\":\"0x1\""), "7"),
            "The debugger rejected the register write.");
    }

    void TestWriteMemory()
    {
        testshim::Reset();
        ExpectError(HandleWriteMemory(Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"90\""), "7"),
            "No active debug session.");
        PausedSession();
        testshim::SetRunning(true);
        ExpectError(HandleWriteMemory(Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"90\""), "7"),
            "Target is running. Pause it before writing memory.");

        PausedSession();
        ExpectError(HandleWriteMemory(Req("WriteMemory", "\"address\":\"0x500000\""), "7"),
            "WriteMemory hexBytes must be 1..12288 chars");
        ExpectError(HandleWriteMemory(Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"\""), "7"),
            "WriteMemory hexBytes must be 1..12288 chars");
        ExpectError(HandleWriteMemory(
            Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"" + std::string(12289, '0') + "\""), "7"),
            "WriteMemory hexBytes must be 1..12288 chars");
        ExpectError(HandleWriteMemory(Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"ZZ\""), "7"),
            "WriteMemory Invalid hex digit.");
        ExpectError(HandleWriteMemory(Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"ABC\""), "7"),
            "WriteMemory Hex bytes must be an even number of hex digits.");
        ExpectError(HandleWriteMemory(
            Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"" + std::string(8194, '0') + "\""), "7"),
            "WriteMemory Too many bytes (max 4096 per call; page large patches).");

        // 4096 bytes are the accepted ceiling (8192 hex chars < 12288).
        const std::string ceiling = HandleWriteMemory(
            Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"" + std::string(8192, '0') + "\""), "7");
        ExpectOk(ceiling);
        Require(Contains(ceiling, "\"bytesWritten\":4096"), "4096-byte write must be accepted");

        // The range check permits a range whose last byte lands exactly on top
        // of the address space (byteCount-1 <= max-address); 257 bytes from
        // ...FF00 truly overflows it.
        if constexpr (sizeof(std::uintptr_t) == 8)
        {
            ExpectError(HandleWriteMemory(
                Req("WriteMemory",
                    "\"address\":\"0xFFFFFFFFFFFFFF00\",\"hexBytes\":\"" + std::string(514, '0') + "\""),
                "7"),
                "WriteMemory address range overflows.");
        }
        else
        {
            ExpectError(HandleWriteMemory(
                Req("WriteMemory",
                    "\"address\":\"0xFFFFFF00\",\"hexBytes\":\"" + std::string(514, '0') + "\""),
                "7"),
                "WriteMemory address range overflows.");
        }

        const std::string ok = HandleWriteMemory(
            Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"48 8B 05\""), "7");
        ExpectOk(ok);
        Require(Contains(ok, "\"address\":\"" + HexAddress(0x500000) + "\""), "write address mismatch");
        Require(Contains(ok, "\"bytesWritten\":3"), "bytesWritten mismatch");
        // The bytesHex echo duplicates the caller input and stays dropped by
        // default; nextAddress is always present (contractually pinned).
        Require(!Contains(ok, "\"bytesHex\""), "default write ack must not echo bytesHex");
        Require(Contains(ok, "\"nextAddress\":\"" + HexAddress(0x500003) + "\""), "write ack must carry nextAddress");
        unsigned char first = 0;
        unsigned char last = 0;
        Require(testshim::ReadImageByte(0x500000, first) && first == 0x48, "first byte did not land in the image");
        Require(testshim::ReadImageByte(0x500002, last) && last == 0x05, "last byte did not land in the image");

        // Opt-in echo for callers that verify against it.
        const std::string echo = HandleWriteMemory(
            Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"48 8B 05\",\"echoBytes\":true"), "7");
        ExpectOk(echo);
        Require(Contains(echo, "\"bytesHex\":\"48 8B 05\""), "echoBytes must restore the legacy echo");
        Require(Contains(echo, "\"nextAddress\":\"" + HexAddress(0x500003) + "\""),
            "echoBytes must keep nextAddress");
        ExpectError(HandleWriteMemory(
            Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"90\",\"echoBytes\":\"yes\""), "7"),
            "WriteMemory echoBytes must be a boolean.");

        testshim::SetMemWriteResult(false);
        ExpectError(HandleWriteMemory(Req("WriteMemory", "\"address\":\"0x500000\",\"hexBytes\":\"90\""), "7"),
            "Failed to write memory at " + HexAddress(0x500000));
    }

    void TestCallFunction()
    {
        PausedSession();
        ExpectError(HandleCallFunction(Req("CallFunction", ""), "7"),
            "CallFunction address must be a non-empty printable expression");
        ExpectError(HandleCallFunction(Req("CallFunction", "\"address\":\"0x402000\",\"arg1\":\"nope\""), "7"),
            "Invalid arg1: nope");
        ExpectError(HandleCallFunction(
            Req("CallFunction", "\"address\":\"0x402000\",\"runAfter\":\"soon\""), "7"),
            "CallFunction runAfter must be a boolean.");
        Require(!g_pendingCallRestore.armed, "pending restore must start disarmed");

        testshim::SetRegister("cip", 0x401000);
        testshim::SetRegister("csp", 0x90000);
        const std::string ok = HandleCallFunction(
            Req("CallFunction", "\"address\":\"0x402000\",\"arg1\":\"0x1\",\"arg2\":\"0x2\""), "7");
        ExpectOk(ok);
        Require(Contains(ok, "\"target\":\"" + HexAddress(0x402000) + "\""), "target mismatch");
        Require(Contains(ok, "\"oldCip\":\"" + HexAddress(0x401000) + "\""), "oldCip mismatch");
        Require(Contains(ok, "\"oldCsp\":\"" + HexAddress(0x90000) + "\""), "oldCsp mismatch");
        Require(Contains(ok, "\"newCip\":\"" + HexAddress(0x402000) + "\""), "newCip mismatch");
        Require(Contains(ok, "\"returnBreakpoint\":\"" + HexAddress(0x401000) + "\""), "return breakpoint mismatch");
        // Shared execution-control ack policy: every control ack keeps its
        // followUp hint (the convention sentence stays in the tool
        // description, so only it stays dropped from the ack).
        Require(!Contains(ok, "\"convention\""), "call ack must not repeat the static convention");
        Require(Contains(ok, "\"followUp\":\"A temporary breakpoint at oldCip restores csp"),
            "call ack must keep the return-value follow-up");
        Require(g_pendingCallRestore.armed, "call must arm the pending csp restore");
        Require(g_pendingCallRestore.returnAddress == 0x401000, "restore must target the original cip");
        Require(!testshim::ExecLog().empty() &&
            testshim::ExecLog().front() == "bp " + HexAddress(0x401000),
            "temporary return breakpoint must be armed first");

        if constexpr (sizeof(std::uintptr_t) == 8)
        {
            // Windows x64 frame below the paused rsp: entry = old - 8 - 32,
            // alignment pad keeps entry % 16 == 8.
            Require(Contains(ok, "\"newCsp\":\"" + HexAddress(0x8FFD8) + "\""), "x64 entry csp mismatch");
            Require(Contains(ok, "\"expectedCspOnReturn\":\"" + HexAddress(0x8FFE0) + "\""),
                "x64 expected csp mismatch");
            Require(g_pendingCallRestore.expectedCsp == 0x8FFE0, "restore must expect post-ret csp");
            unsigned char slot[8]{};
            for (int i = 0; i < 8; ++i)
                Require(testshim::ReadImageByte(0x8FFD8 + static_cast<std::uintptr_t>(i), slot[i]),
                    "return-address slot was not written");
            std::uintptr_t pushed = 0;
            for (int i = 0; i < 8; ++i)
                pushed |= static_cast<std::uintptr_t>(slot[i]) << (i * 8);
            Require(pushed == 0x401000, "return-address slot must hold the original cip");
        }
        else
        {
            // x86 cdecl: return address pushed below the untouched arguments.
            Require(Contains(ok, "\"newCsp\":\"" + HexAddress(0x90000 - 12) + "\""), "x86 entry csp mismatch");
            Require(Contains(ok, "\"expectedCspOnReturn\":\"" + HexAddress(0x90000 - 8) + "\""),
                "x86 expected csp mismatch");
        }
    }

    void TestCallFunctionReturnValue()
    {
        // Full wire path through HandleRequest: stage a call, simulate the
        // injected `ret` landing on the return breakpoint, then verify the
        // next response carries returnValue + registersAfter exactly once
        // while the csp restore still disarms.
        PausedSession();
        testshim::SetRegister("cip", 0x401000);
        testshim::SetRegister("csp", 0x90000);
        const std::string staged = HandleRequest(
            Req("CallFunction", "\"address\":\"0x402000\""));
        ExpectOk(staged);
        Require(!Contains(staged, "\"returnValue\":\""), "staging must not invent a return value");
        Require(g_pendingCallRestore.armed, "staging must arm the restore");

        // Post-ret state observed by the debugger: trap cip, post-ret csp,
        // callee result in rax/eax.
        std::uintptr_t postRetCsp = 0;
        const char* retReg = nullptr;
        if constexpr (sizeof(std::uintptr_t) == 8)
        {
            postRetCsp = 0x8FFE0;
            retReg = "rax";
        }
        else
        {
            postRetCsp = 0x90000;
            retReg = "eax";
        }
        testshim::SetRegister("cip", 0x401000);
        testshim::SetRegister("csp", postRetCsp);
        testshim::SetRegister(retReg, 0x1234);

        const std::string follow = HandleRequest(Req("ListBreakpoints", ""));
        ExpectOk(follow);
        Require(Contains(follow, "\"returnValue\":\"" + HexAddress(0x1234) + "\""),
            "landed call must report returnValue");
        Require(Contains(follow, "\"registersAfter\":{"), "registersAfter missing");
        // SEC N8: the structural merge keeps the historical splice position —
        // returnValue/registersAfter lead the result object byte-for-byte.
        Require(Contains(follow, "\"result\":{\"returnValue\":\""),
            "call return must lead the result object");
        if constexpr (sizeof(std::uintptr_t) == 8)
        {
            Require(Contains(follow, "\"rip\":\"" + HexAddress(0x401000) + "\""), "rip mismatch");
            Require(Contains(follow, "\"rsp\":\"" + HexAddress(postRetCsp) + "\""), "rsp must show post-ret csp");
            Require(Contains(follow, "\"rax\":\"" + HexAddress(0x1234) + "\""), "rax mismatch");
        }
        else
        {
            Require(Contains(follow, "\"eip\":\"" + HexAddress(0x401000) + "\""), "eip mismatch");
            Require(Contains(follow, "\"esp\":\"" + HexAddress(postRetCsp) + "\""), "esp must show post-ret csp");
            Require(Contains(follow, "\"eax\":\"" + HexAddress(0x1234) + "\""), "eax mismatch");
        }
        Require(!g_pendingCallRestore.armed, "landing must disarm the restore");

        // Consume-once: the value must not leak into later responses.
        const std::string third = HandleRequest(Req("ListBreakpoints", ""));
        ExpectOk(third);
        Require(!Contains(third, "\"returnValue\":\""), "return value must be reported once");
    }

    void TestAnnotations()
    {
        testshim::Reset();
        ExpectError(HandleSetLabel(Req("SetLabel", "\"address\":\"0x401000\""), "7"), "No active debug session.");
        ExpectError(HandleSetComment(Req("SetComment", "\"address\":\"0x401000\""), "7"),
            "No active debug session.");
        ExpectError(HandleSetBookmark(Req("SetBookmark", "\"address\":\"0x401000\""), "7"),
            "No active debug session.");

        PausedSession();
        ExpectError(HandleSetLabel(Req("SetLabel", ""), "7"), "SetLabel address is required.");
        ExpectError(HandleSetLabel(Req("SetLabel", "\"address\":\"0\""), "7"),
            "Invalid address or expression: 0");
        ExpectError(HandleSetLabel(Req("SetLabel", "\"address\":\"0x401000\",\"label\":\"a\\\"b\""), "7"),
            "SetLabel label must be at most 256 bytes without quotes or control characters.");
        ExpectError(HandleSetLabel(
            Req("SetLabel", "\"address\":\"0x401000\",\"label\":\"" + std::string(257, 'l') + "\""), "7"),
            "SetLabel label must be at most 256 bytes without quotes or control characters.");
        ExpectError(HandleSetComment(
            Req("SetComment", "\"address\":\"0x401000\",\"comment\":\"" + std::string(1025, 'c') + "\""), "7"),
            "SetComment comment must be at most 1024 bytes without quotes or control characters.");
        ExpectError(HandleSetBookmark(
            Req("SetBookmark", "\"address\":\"0x401000\",\"enabled\":\"yes\""), "7"),
            "SetBookmark enabled must be a boolean.");

        // 256/1024 are the accepted ceilings.
        ExpectOk(HandleSetLabel(
            Req("SetLabel", "\"address\":\"0x401000\",\"label\":\"" + std::string(256, 'l') + "\""), "7"));
        ExpectOk(HandleSetComment(
            Req("SetComment", "\"address\":\"0x401000\",\"comment\":\"" + std::string(1024, 'c') + "\""), "7"));

        testshim::ClearExecLog();
        const std::string label = HandleSetLabel(
            Req("SetLabel", "\"address\":\"0x401000\",\"label\":\"start\""), "7");
        ExpectOk(label);
        Require(Contains(label, "\"label\":\"start\""), "label echo missing");
        Require(testshim::ExecLog().back() == "lbl " + HexAddress(0x401000) + ",\"start\"",
            "lbl command contract broken");

        const std::string cleared = HandleSetLabel(Req("SetLabel", "\"address\":\"0x401000\""), "7");
        ExpectOk(cleared);
        Require(testshim::ExecLog().back() == "lblclear " + HexAddress(0x401000),
            "empty label must issue lblclear");

        const std::string bookmark = HandleSetBookmark(
            Req("SetBookmark", "\"address\":\"0x401000\",\"enabled\":false"), "7");
        ExpectOk(bookmark);
        Require(Contains(bookmark, "\"enabled\":false"), "bookmark enabled echo missing");
        Require(testshim::ExecLog().back() == "bookmark.clear " + HexAddress(0x401000),
            "disabled bookmark must issue bookmark.clear");

        testshim::SetExecDirectResult(false);
        ExpectError(HandleSetLabel(Req("SetLabel", "\"address\":\"0x401000\",\"label\":\"x\""), "7"),
            "The debugger rejected the label command.");
    }

    void RunStateEditTests()
    {
        TestSetRegister();
        TestWriteMemory();
        TestCallFunction();
        TestCallFunctionReturnValue();
        TestAnnotations();
    }
} // namespace dbglink_state_edit_tests
