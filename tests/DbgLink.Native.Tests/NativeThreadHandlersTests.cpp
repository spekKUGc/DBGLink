// NativeThreadHandlersTests.cpp — thread handlers.
//
// Covers NativeThreadHandlers.cpp (SwitchThread, ListThreads, GetBacktrace):
// paging boundaries, the thread-switch side effect on the shim thread list,
// and a deterministic rbp-chain backtrace walked out of the scripted memory
// image on both x64 and x86.
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "../../src/native/DbgLink.Native/NativeControlHandlers.h"
#include "../../src/native/DbgLink.Native/NativeJsonFormatting.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"
#include "../../src/native/DbgLink.Native/NativeControlSupport.h"
#include "../../src/native/DbgLink.Native/NativeHexFormat.h"
#include "../../src/native/DbgLink.Native/X64DbgApiShim.h"

namespace dbglink_thread_tests
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

    void TwoThreads()
    {
        testshim::Reset();
        testshim::SetThreads(
            {testshim::MakeThread(1, 0x100, 0x400000, "main"),
             testshim::MakeThread(2, 0x104, 0x500000, "worker")},
            0);
    }

    void TestListThreads()
    {
        TwoThreads();
        const std::string list = HandleListThreads(Req("ListThreads", ""), "7");
        ExpectOk(list);
        Require(Contains(list, "\"totalCount\":2"), "thread totalCount mismatch");
        Require(Contains(list, "\"threadId\":256"), "first thread id missing");
        Require(Contains(list, "\"threadId\":260"), "second thread id missing");
        Require(Contains(list, "\"entry\":\"" + HexAddress(0x400000) + "\""), "entry address format mismatch");
        Require(Contains(list, "\"name\":\"main\""), "thread name missing");
        Require(Contains(list, "\"currentThread\":0"), "currentThread echo missing");
        Require(Contains(list, "\"schemaVersion\":1"), "paged envelope schemaVersion missing");
        // Sparse items: suspendCount is 0 in the fixture, so it is omitted;
        // names are non-empty, so they stay.
        Require(!Contains(list, "\"suspendCount\""), "zero suspendCount must be omitted");

        ExpectError(HandleListThreads(Req("ListThreads", "\"maxItems\":0"), "7"),
            "ListThreads maxItems must be between 1 and 512.");
        ExpectError(HandleListThreads(Req("ListThreads", "\"maxItems\":513"), "7"),
            "ListThreads maxItems must be between 1 and 512.");
        ExpectError(HandleListThreads(Req("ListThreads", "\"offset\":\"far\""), "7"),
            "ListThreads offset must be an integer.");

        const std::string page = HandleListThreads(Req("ListThreads", "\"maxItems\":1"), "7");
        ExpectOk(page);
        Require(Contains(page, "\"returnedCount\":1"), "page must return one thread");
        Require(Contains(page, "\"truncated\":true"), "partial page must report truncated");
        Require(Contains(page, "\"nextOffset\":1"), "partial page must report nextOffset");

        const std::string tail = HandleListThreads(Req("ListThreads", "\"offset\":1,\"maxItems\":1"), "7");
        ExpectOk(tail);
        Require(Contains(tail, "\"threadId\":260"), "second page must hold the worker thread");
        Require(!Contains(tail, "\"threadId\":256"), "second page must not repeat the first thread");

        const std::string pastEnd = HandleListThreads(Req("ListThreads", "\"offset\":9"), "7");
        ExpectOk(pastEnd);
        Require(Contains(pastEnd, "\"returnedCount\":0"), "past-end page must be empty");
        Require(Contains(pastEnd, "\"nextOffset\":null"), "final page must null the nextOffset");

        TwoThreads();
        testshim::SetThreads({}, 0);
        Require(Contains(HandleListThreads(Req("ListThreads", ""), "7"), "\"totalCount\":0"),
            "empty thread store must list cleanly");
    }

    void TestSwitchThread()
    {
        testshim::Reset();
        ExpectError(HandleSwitchThread(Req("SwitchThread", "\"threadId\":256"), "7"),
            "No active debug session.");

        TwoThreads();
        testshim::SetDebugging(true);
        ExpectError(HandleSwitchThread(Req("SwitchThread", ""), "7"),
            "SwitchThread threadId must be a debugger thread id (see ListThreads).");
        ExpectError(HandleSwitchThread(Req("SwitchThread", "\"threadId\":0"), "7"),
            "SwitchThread threadId must be a debugger thread id (see ListThreads).");
        ExpectError(HandleSwitchThread(Req("SwitchThread", "\"threadId\":4294967296"), "7"),
            "SwitchThread threadId must be a debugger thread id (see ListThreads).");
        ExpectError(HandleSwitchThread(Req("SwitchThread", "\"threadId\":999"), "7"),
            "The debugger rejected the thread switch (unknown thread id?).");

        // Thread ids render as 0x-hex on the command line (x64dbg parses bare
        // integers as hex), so 0x104 travels untouched.
        const std::string ok = HandleSwitchThread(Req("SwitchThread", "\"threadId\":260"), "7");
        ExpectOk(ok);
        Require(Contains(ok, "\"threadId\":260"), "switch must echo the decimal thread id");
        // Shared execution-control ack policy: the switch ack keeps its
        // followUp like step/run/pause/continue do.
        Require(Contains(ok, "\"followUp\":\"Call GetBacktrace or GetAnalysisSnapshot"),
            "switch ack must keep the follow-up");
        Require(testshim::ExecLog().back() == "switchthread 0x104", "switchthread hex command broken");
        Require(Contains(HandleListThreads(Req("ListThreads", ""), "7"), "\"currentThread\":1"),
            "switch side effect must move currentThread");

        // A thread id with hex letters pins the lowercase 0x-hex rendering:
        // 0xABC travels as "switchthread 0xabc", never "0xABC".
        testshim::SetThreads(
            {testshim::MakeThread(1, 0x100, 0x400000, "main"),
             testshim::MakeThread(2, 0x104, 0x500000, "worker"),
             testshim::MakeThread(3, 0xABC, 0x600000, "hex")},
            0);
        testshim::SetDebugging(true);
        const std::string hex = HandleSwitchThread(Req("SwitchThread", "\"threadId\":2748"), "7");
        ExpectOk(hex);
        Require(Contains(hex, "\"threadId\":2748"), "lettered switch must echo the decimal thread id");
        Require(testshim::ExecLog().back() == "switchthread 0xabc", "switchthread must render hex letters lowercase");
    }

    void WritePtr(std::uintptr_t address, std::uintptr_t value)
    {
        unsigned char bytes[sizeof(std::uintptr_t)]{};
        for (std::size_t i = 0; i < sizeof(bytes); ++i)
            bytes[i] = static_cast<unsigned char>((value >> (i * 8)) & 0xFF);
        testshim::WriteImage(address, bytes, sizeof(bytes));
    }

    void FrameFixtures()
    {
        TwoThreads();
        testshim::SetDebugging(true);
        testshim::SetMemoryPages({testshim::MakeImagePage(0x400000, 0x10000, PAGE_EXECUTE_READ, "app.exe")});
        testshim::SetModuleName(0x400000, "app.exe");
        // Classic two-frame rbp chain: [rbp] = next, [rbp+8] = return.
        WritePtr(0x80000, 0x80100);
        WritePtr(0x80000 + sizeof(std::uintptr_t), 0x401005);
        WritePtr(0x80100, 0);
        WritePtr(0x80100 + sizeof(std::uintptr_t), 0x402005);
        if constexpr (sizeof(std::uintptr_t) == 8)
        {
            testshim::SetRegister("rbp", 0x80000);
            testshim::SetRegister("rsp", 0x7F000);
        }
        else
        {
            testshim::SetRegister("ebp", 0x80000);
            testshim::SetRegister("esp", 0x7F000);
        }
    }

    void TestBacktrace()
    {
        testshim::Reset();
        ExpectError(HandleBacktrace(Req("GetBacktrace", ""), "7"), "No active debug session.");

        FrameFixtures();
        ExpectError(HandleBacktrace(Req("GetBacktrace", "\"maxFrames\":0"), "7"),
            "GetBacktrace maxFrames must be between 1 and 128.");
        ExpectError(HandleBacktrace(Req("GetBacktrace", "\"maxFrames\":129"), "7"),
            "GetBacktrace maxFrames must be between 1 and 128.");
        ExpectError(HandleBacktrace(Req("GetBacktrace", "\"threadId\":999"), "7"),
            "Unknown threadId (see ListThreads).");

        const std::string ok = HandleBacktrace(Req("GetBacktrace", ""), "7");
        ExpectOk(ok);
        // method names the walk kind outright (rbp_frame_chain here);
        // approximate stays as the machine-readable twin.
        Require(Contains(ok, "\"method\":\"rbp_frame_chain\""), "frame-pointer walk method missing");
        Require(Contains(ok, "\"approximate\":false"), "clean chain must not be approximate");
        Require(Contains(ok, "\"walkedFrames\":2"), "both scripted frames must be walked");
        Require(Contains(ok, "\"returnAddress\":\"" + HexAddress(0x401005) + "\""), "first return address missing");
        Require(Contains(ok, "\"returnAddress\":\"" + HexAddress(0x402005) + "\""), "second return address missing");
        Require(Contains(ok, "\"frameAddress\":\"" + HexAddress(0x80000) + "\""), "frame address missing");
        // index is the absolute frame number, restored for client paging.
        Require(Contains(ok, "\"index\":0"), "first frame index missing");
        Require(Contains(ok, "\"index\":1"), "second frame index missing");

        const std::string sliced = HandleBacktrace(Req("GetBacktrace", "\"startFrame\":1,\"maxFrames\":1"), "7");
        ExpectOk(sliced);
        Require(Contains(sliced, "\"returnedCount\":1"), "slice must return one frame");
        Require(Contains(sliced, "\"returnAddress\":\"" + HexAddress(0x402005) + "\""),
            "slice must start at the second frame");
        Require(Contains(sliced, "\"index\":1"), "sliced frame must keep its absolute index");
        Require(!Contains(sliced, "\"nextFrame\""), "exhausted walk must omit nextFrame, not null it");

        // A truncated walk keeps nextFrame (load-bearing paging cursor).
        const std::string first = HandleBacktrace(Req("GetBacktrace", "\"maxFrames\":1"), "7");
        ExpectOk(first);
        Require(Contains(first, "\"truncated\":true"), "one-frame page of two must report truncated");
        Require(Contains(first, "\"nextFrame\":1"), "truncated walk must carry nextFrame");

        // Reading another thread switches there and back: the visible thread
        // is unchanged and the log shows the there-and-back pair.
        testshim::ClearExecLog();
        const std::string other = HandleBacktrace(Req("GetBacktrace", "\"threadId\":260"), "7");
        ExpectOk(other);
        Require(Contains(other, "\"threadId\":260"), "backtrace must echo the requested thread");
        Require(testshim::ExecLog().size() == 2, "threaded backtrace must switch there and back");
        Require(Contains(HandleListThreads(Req("ListThreads", ""), "7"), "\"currentThread\":0"),
            "threaded backtrace must restore the original thread");

        // m3: a huge startFrame must not narrow to a small size_t index
        // (2^32 wraps to 0 on 32-bit and would return the first page).
        const std::string pastHuge =
            HandleBacktrace(Req("GetBacktrace", "\"startFrame\":4294967296"), "7");
        ExpectOk(pastHuge);
        Require(Contains(pastHuge, "\"returnedCount\":0"), "huge startFrame must return no frames");
        Require(Contains(pastHuge, "\"truncated\":false"), "huge startFrame must not claim truncation");
        Require(!Contains(pastHuge, "\"nextFrame\""), "huge startFrame must omit nextFrame");
    }

    void RunThreadHandlerTests()
    {
        TestListThreads();
        TestSwitchThread();
        TestBacktrace();
    }
} // namespace dbglink_thread_tests
