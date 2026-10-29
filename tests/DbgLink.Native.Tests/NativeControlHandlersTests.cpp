// NativeControlHandlersTests.cpp — execution-control and breakpoint handlers.
//
// Covers NativeControlHandlers.cpp (StepInto/StepOver/StepOut/RunDebugger/
// PauseDebugger/ContinueDebugger) and NativeBreakpointHandlers.cpp
// (SetBreakpoint/ClearBreakpoint/ListBreakpoints) against the scripted
// X64DbgApiShim backend: no live x64dbg is required.  Every test asserts the
// shared error envelope {"id",ok:false,"error":{code,message}} on failures,
// numeric ±1 boundaries on the capped parameters, and handler<->shim side
// effects (set-then-list-then-clear roundtrips through the shim breakpoint
// store and the ExecDirect log).
#include <stdexcept>
#include <string>
#include <string_view>

#include "../../src/native/DbgLink.Native/NativeControlHandlers.h"
#include "../../src/native/DbgLink.Native/NativeJsonFormatting.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"
#include "../../src/native/DbgLink.Native/NativeControlSupport.h"
#include "../../src/native/DbgLink.Native/X64DbgApiShim.h"

namespace dbglink_control_tests
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

    void ExpectError(const std::string& response, const char* id, std::string_view fragment)
    {
        Require(Contains(response, "\"ok\":false"), "expected ok:false");
        Require(Contains(response, "\"code\":\"native_error\""), "expected native_error code");
        Require(Contains(response, std::string("\"id\":") + id), "expected id echo");
        Require(Contains(response, std::string(fragment)), "expected error fragment");
    }

    void ExpectOk(const std::string& response, const char* id = "7")
    {
        Require(Contains(response, "\"ok\":true"), "expected ok:true");
        Require(Contains(response, std::string("\"id\":") + id), "expected id echo");
    }

    void TestStepGuards()
    {
        testshim::Reset();
        ExpectError(HandleStepInto(Req("StepInto", ""), "1"), "1", "No active debug session.");
        ExpectError(HandleStepOver(Req("StepOver", ""), "1"), "1", "No active debug session.");
        ExpectError(HandleStepOut(Req("StepOut", ""), "1"), "1", "No active debug session.");
        ExpectError(HandleRunDebugger(Req("RunDebugger", ""), "1"), "1", "No active debug session.");
        ExpectError(HandlePauseDebugger(Req("PauseDebugger", ""), "1"), "1", "No active debug session.");
        ExpectError(HandleContinueDebugger(Req("ContinueDebugger", ""), "1"), "1",
            "No active debug session.");

        testshim::Reset();
        testshim::SetDebugging(true);
        testshim::SetRunning(true);
        ExpectError(HandleStepInto(Req("StepInto", ""), "7"), "7",
            "Target is running. Pause it before stepping.");
        ExpectError(HandleStepOver(Req("StepOver", ""), "7"), "7",
            "Target is running. Pause it before stepping.");
        ExpectError(HandleStepOut(Req("StepOut", ""), "7"), "7",
            "Target is running. Pause it before stepping.");
    }

    void TestStepCountBoundaries()
    {
        testshim::Reset();
        testshim::SetDebugging(true);
        ExpectError(HandleStepInto(Req("StepInto", "\"count\":0"), "7"), "7",
            "Step count must be between 1 and 100.");
        ExpectError(HandleStepInto(Req("StepInto", "\"count\":101"), "7"), "7",
            "Step count must be between 1 and 100.");
        ExpectError(HandleStepInto(Req("StepInto", "\"count\":\"many\""), "7"), "7",
            "Step count must be between 1 and 100.");

        // x64dbg parses integer command arguments as hex: the handler renders
        // the decimal count as 0x-hex so count=10 steps ten times, not sixteen.
        const std::string ok = HandleStepInto(Req("StepInto", "\"count\":10"), "7");
        ExpectOk(ok);
        Require(Contains(ok, "\"action\":\"stepInto\""), "stepInto action missing");
        Require(Contains(ok, "\"count\":10"), "stepInto count missing");
        Require(Contains(ok, "\"command\":\"sti 0xa\""), "stepInto hex command contract broken");
        Require(!testshim::ExecLog().empty() && testshim::ExecLog().back() == "sti 0xa",
            "sti command was not issued to the debugger");

        const std::string over = HandleStepOver(Req("StepOver", "\"count\":10"), "7");
        ExpectOk(over);
        Require(Contains(over, "\"command\":\"sto 0xa\""), "stepOver hex command contract broken");
        const std::string out = HandleStepOut(Req("StepOut", "\"count\":10"), "7");
        ExpectOk(out);
        Require(Contains(out, "\"command\":\"rtr 0xa\""), "stepOut hex command contract broken");

        // Default count is a single step; the upper bound stays accepted.
        testshim::ClearExecLog();
        const std::string def = HandleStepInto(Req("StepInto", ""), "7");
        ExpectOk(def);
        Require(Contains(def, "\"command\":\"sti 0x1\""), "default step command must be sti 0x1");
        ExpectOk(HandleStepInto(Req("StepInto", "\"count\":100"), "7"));

        testshim::SetExecDirectResult(false);
        ExpectError(HandleStepInto(Req("StepInto", ""), "7"), "7",
            "The debugger rejected the step command.");
    }

    void TestRunPauseContinue()
    {
        testshim::Reset();
        testshim::SetDebugging(true);
        testshim::SetRunning(true);
        Require(Contains(HandleRunDebugger(Req("RunDebugger", ""), "7"), "\"alreadyRunning\":true"),
            "run while running must report alreadyRunning");
        Require(Contains(HandleContinueDebugger(Req("ContinueDebugger", ""), "7"), "\"alreadyRunning\":true"),
            "continue while running must report alreadyRunning");

        testshim::SetRunning(false);
        Require(Contains(HandlePauseDebugger(Req("PauseDebugger", ""), "7"), "\"alreadyPaused\":true"),
            "pause while paused must report alreadyPaused");

        const std::string run = HandleRunDebugger(Req("RunDebugger", ""), "7");
        ExpectOk(run);
        Require(Contains(run, "\"resumed\":true"), "run must report resumed");
        Require(testshim::ExecLog().back() == "run", "run command missing from exec log");

        testshim::SetRunning(true);
        const std::string pause = HandlePauseDebugger(Req("PauseDebugger", ""), "7");
        ExpectOk(pause);
        Require(Contains(pause, "\"requested\":true"), "pause must report requested");

        testshim::SetRunning(false);
        const std::string cont = HandleContinueDebugger(Req("ContinueDebugger", ""), "7");
        ExpectOk(cont);
        Require(Contains(cont, "\"resumed\":true"), "continue must report resumed");

        testshim::SetExecDirectResult(false);
        ExpectError(HandleRunDebugger(Req("RunDebugger", ""), "7"), "7",
            "The debugger rejected the run command.");
        testshim::SetRunning(true);
        ExpectError(HandlePauseDebugger(Req("PauseDebugger", ""), "7"), "7",
            "The debugger rejected the pause command");
    }

    void TestBreakpointGuards()
    {
        testshim::Reset();
        ExpectError(HandleSetBreakpoint(Req("SetBreakpoint", "\"address\":\"0x401000\""), "3"), "3",
            "No active debug session. Open a target first.");
        ExpectError(HandleClearBreakpoint(Req("ClearBreakpoint", "\"address\":\"0x401000\""), "3"), "3",
            "No active debug session.");

        // ListBreakpoints has no session gate: an empty store lists cleanly.
        const std::string empty = HandleListBreakpoints(Req("ListBreakpoints", ""), "3");
        ExpectOk(empty, "3");
        Require(Contains(empty, "\"totalCount\":0"), "empty breakpoint list must report totalCount 0");
        Require(Contains(empty, "\"breakpoints\":[]"), "empty breakpoint list must be []");
    }

    void TestSetClearListRoundtrip()
    {
        testshim::Reset();
        testshim::SetDebugging(true);
        const std::string set = HandleSetBreakpoint(
            Req("SetBreakpoint", "\"address\":\"0x401000\",\"name\":\"entry\",\"singleshot\":true"), "7");
        ExpectOk(set);
        Require(Contains(set, "\"kind\":\"soft\""), "default breakpoint kind must be soft");
        Require(Contains(set, "\"address\":\"" + HexAddress(0x401000) + "\""), "set address must be compact hex");
        Require(Contains(set, "\"expression\":\"0x401000\""), "set must echo the expression");
        Require(Contains(set, "\"name\":\"entry\""), "set must echo the name");
        Require(Contains(set, "\"singleshot\":true"), "set must echo singleshot");
        Require(!testshim::ExecLog().empty() &&
            testshim::ExecLog().front().find("bp " + HexAddress(0x401000)) == 0,
            "bp command missing from exec log");

        const std::string list = HandleListBreakpoints(Req("ListBreakpoints", ""), "7");
        ExpectOk(list);
        Require(Contains(list, "\"totalCount\":1"), "list must report one breakpoint");
        Require(Contains(list, "\"type\":\"soft\""), "list item type must be soft");
        Require(Contains(list, "\"address\":\"" + HexAddress(0x401000) + "\""), "list item address mismatch");
        Require(Contains(list, "\"singleshot\":true"), "list must use the singleshot wire name");
        Require(Contains(list, "\"name\":\"entry\""), "list item name mismatch");
        Require(Contains(list, "\"hitCount\":0"), "list item hitCount missing");

        const std::string clear = HandleClearBreakpoint(
            Req("ClearBreakpoint", "\"address\":\"0x401000\""), "7");
        ExpectOk(clear);
        Require(Contains(clear, "\"kind\":\"soft\""), "clear must report the canonical kind");
        Require(Contains(HandleListBreakpoints(Req("ListBreakpoints", ""), "7"), "\"totalCount\":0"),
            "cleared breakpoint must disappear from the list");

        ExpectError(HandleClearBreakpoint(Req("ClearBreakpoint", "\"address\":\"0x401000\""), "7"), "7",
            "The debugger could not clear the breakpoint (no such breakpoint?).");
        ExpectError(HandleClearBreakpoint(Req("ClearBreakpoint", ""), "7"), "7",
            "ClearBreakpoint requires address or all=true.");
        ExpectError(HandleClearBreakpoint(Req("ClearBreakpoint", "\"all\":true,\"kind\":\"bad\""), "7"), "7",
            "ClearBreakpoint kind must be soft, hw, mem or all.");
    }

    void TestBreakpointKinds()
    {
        testshim::Reset();
        testshim::SetDebugging(true);
        const std::string hw = HandleSetBreakpoint(
            Req("SetBreakpoint", "\"address\":\"0x402000\",\"kind\":\"hw\",\"hwType\":\"x\",\"hwSize\":1"), "7");
        ExpectOk(hw);
        Require(Contains(hw, "\"kind\":\"hw\""), "hardware breakpoint kind missing");
        Require(testshim::ExecLog().back().find("bph ") == 0, "bph command missing from exec log");

        ExpectError(HandleSetBreakpoint(
            Req("SetBreakpoint", "\"address\":\"0x402001\",\"kind\":\"hw\",\"hwSize\":2"), "7"), "7",
            "Hardware breakpoint address must be aligned to hwSize.");
        ExpectError(HandleSetBreakpoint(
            Req("SetBreakpoint", "\"address\":\"0x402000\",\"kind\":\"hw\",\"hwSize\":3"), "7"), "7",
            "SetBreakpoint hwSize must be 1, 2, 4 or 8.");
        ExpectError(HandleSetBreakpoint(
            Req("SetBreakpoint", "\"address\":\"0x402000\",\"kind\":\"hw\",\"hwType\":\"z\""), "7"), "7",
            "SetBreakpoint hwType must be x, r or w.");
        ExpectError(HandleSetBreakpoint(Req("SetBreakpoint", "\"address\":\"0x402000\",\"kind\":\"laser\""), "7"),
            "7", "SetBreakpoint kind must be soft, hw or mem.");

        // Memory breakpoints live on the whole page: the handler resolves the
        // page base through DbgMemFindBaseAddr and reports it back.
        testshim::SetMemoryPages({testshim::MakeImagePage(0x400000, 0x10000, PAGE_EXECUTE_READ, "app.exe")});
        testshim::SetModuleName(0x400000, "app.exe");
        const std::string mem = HandleSetBreakpoint(
            Req("SetBreakpoint", "\"address\":\"0x401234\",\"kind\":\"mem\""), "7");
        ExpectOk(mem);
        Require(Contains(mem, "\"pageBase\":\"" + HexAddress(0x400000) + "\""), "mem breakpoint must report pageBase");
        Require(Contains(mem, "\"singleshot\":true"), "mem breakpoint without restore is singleshot");
        Require(testshim::ExecLog().back().find("bpm " + HexAddress(0x400000)) == 0,
            "bpm command must target the page base");

        testshim::ClearExecLog();
        ExpectOk(HandleClearBreakpoint(Req("ClearBreakpoint", "\"all\":true"), "7"));
        Require(Contains(HandleListBreakpoints(Req("ListBreakpoints", ""), "7"), "\"totalCount\":0"),
            "clear-all must empty every breakpoint kind");
    }

    void TestBreakpointAtomicity()
    {
        // A rejected bpc sub-command must roll the just-created breakpoint
        // back so the operation stays atomic (failure means no breakpoint).
        testshim::Reset();
        testshim::SetDebugging(true);
        testshim::SetExecRejectContains("bpc");
        ExpectError(HandleSetBreakpoint(
            Req("SetBreakpoint", "\"address\":\"0x401000\",\"condition\":\"eax==1\""), "7"), "7",
            "The debugger rejected the breakpoint condition.");
        Require(Contains(HandleListBreakpoints(Req("ListBreakpoints", ""), "7"), "\"totalCount\":0"),
            "rolled-back breakpoint must not be listed");
        const auto& log = testshim::ExecLog();
        Require(log.size() >= 3 && log[2].find("bc ") == 0, "rollback must issue bc for the new breakpoint");
    }

    void TestBreakpointBoundaries()
    {
        testshim::Reset();
        testshim::SetDebugging(true);
        ExpectError(HandleListBreakpoints(Req("ListBreakpoints", "\"maxItems\":0"), "7"), "7",
            "ListBreakpoints maxItems must be between 1 and 512.");
        ExpectError(HandleListBreakpoints(Req("ListBreakpoints", "\"maxItems\":513"), "7"), "7",
            "ListBreakpoints maxItems must be between 1 and 512.");
        ExpectOk(HandleListBreakpoints(Req("ListBreakpoints", "\"maxItems\":512"), "7"));
        ExpectError(HandleListBreakpoints(Req("ListBreakpoints", "\"offset\":\"far\""), "7"), "7",
            "ListBreakpoints offset must be an integer.");

        ExpectError(HandleSetBreakpoint(Req("SetBreakpoint", ""), "7"), "7",
            "SetBreakpoint address must be a non-empty printable expression");
        ExpectError(HandleSetBreakpoint(Req("SetBreakpoint", "\"address\":\"0\""), "7"), "7",
            "Invalid address or expression: 0");
        ExpectError(HandleSetBreakpoint(
            Req("SetBreakpoint", "\"address\":\"0x401000\",\"name\":\"9bad\""), "7"), "7",
            "SetBreakpoint name must match");

        testshim::SetExecDirectResult(false);
        ExpectError(HandleSetBreakpoint(Req("SetBreakpoint", "\"address\":\"0x401000\""), "7"), "7",
            "The debugger rejected the breakpoint command.");
    }

    void RunControlHandlerTests()
    {
        TestStepGuards();
        TestStepCountBoundaries();
        TestRunPauseContinue();
        TestBreakpointGuards();
        TestSetClearListRoundtrip();
        TestBreakpointKinds();
        TestBreakpointAtomicity();
        TestBreakpointBoundaries();
    }
} // namespace dbglink_control_tests
