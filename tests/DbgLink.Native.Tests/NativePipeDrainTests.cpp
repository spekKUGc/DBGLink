// NativePipeDrainTests.cpp — X1 single-instance pipe drain regression tests.
//
// Root cause: PipeLoopCore served one client at a time and, after writing a
// response, called DisconnectNamedPipe immediately. DisconnectNamedPipe
// discards any outbound bytes the client has not read yet, so:
//   (a) responses larger than the 8 KiB kernel out-buffer were lost
//       deterministically (ListBreakpoints with 60+ items, full
//       GetMemoryMap), and
//   (b) small responses were lost intermittently when the client had not
//       read yet (~100 ms of descheduling loses the read 10/10).
//
// The fix holds the instance after a successful write with a bounded
// overlapped drain read (WaitForClientDrain, reuse of
// kPipeWriteTimeoutMilliseconds) until the client consumes the message and
// closes, disconnecting anyway on timeout.
//
// These tests exercise the real single-instance PipeLoopCore (not the
// multi-instance RealNativePipeServer harness, which cannot catch this):
//   (0) negative control: a stub server with the OLD immediate-disconnect
//       semantics loses a delayed read (proves the harness reproduces X1);
//   (1) delayed read (100 ms) against the fixed loop delivers 10/10;
//   (2) large responses (128 ListBreakpoints items, 200-page GetMemoryMap,
//       both > 8 KiB) arrive intact;
//   (3) a burst of concurrent clients sees zero empty reads.
#include <atomic>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "../../src/native/DbgLink.Native/NativeBridgeFoundation.h"
#include "../../src/native/DbgLink.Native/NativePipeServer.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"
#include "../../src/native/DbgLink.Native/X64DbgApiShim.h"

namespace dbglink_pipe_drain_tests
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

    std::atomic_long s_pipeSerial{0};

    std::wstring TestPipeName(const char* tag)
    {
        std::wstring name = L"DbgLink.Test.Drain.";
        name += std::to_wstring(GetCurrentProcessId());
        name += L".";
        for (const char* p = tag; *p != '\0'; ++p)
            name.push_back(static_cast<wchar_t>(*p));
        name += L".";
        name += std::to_wstring(s_pipeSerial.fetch_add(1));
        return name;
    }

    // One request/response exchange over a message-mode client handle.
    struct ExchangeResult
    {
        std::string bytes;
        bool emptyRead = false;
        std::string failure;
    };

    ExchangeResult Exchange(
        const std::wstring& pipeName,
        const std::string& request,
        DWORD delayBeforeReadMilliseconds)
    {
        ExchangeResult result;
        const std::wstring fullName = L"\\\\.\\pipe\\" + pipeName;

        HANDLE raw = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 240; ++attempt)
        {
            raw = CreateFileW(
                fullName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr);
            if (raw != INVALID_HANDLE_VALUE)
                break;
            const DWORD error = GetLastError();
            if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND)
            {
                result.failure = "connect failed, error " + std::to_string(error);
                return result;
            }
            // Single-instance server: no free instance while another client
            // is served. Wait for the instance to be released, then retry.
            (void)WaitNamedPipeW(fullName.c_str(), 250);
        }
        if (raw == INVALID_HANDLE_VALUE)
        {
            result.failure = "connect timed out (no pipe instance became available)";
            return result;
        }
        ScopedHandle client(raw);

        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(client.get(), &mode, nullptr, nullptr))
        {
            result.failure = "could not switch the client to message mode";
            return result;
        }

        DWORD written = 0;
        if (!WriteFile(
                client.get(),
                request.data(),
                static_cast<DWORD>(request.size()),
                &written,
                nullptr) ||
            written != request.size())
        {
            result.failure = "request write failed, error " + std::to_string(GetLastError());
            return result;
        }

        if (delayBeforeReadMilliseconds != 0)
            Sleep(delayBeforeReadMilliseconds);

        // Synchronous message-mode read: a message larger than the buffer
        // reports ERROR_MORE_DATA with a partial fill; loop until the whole
        // message arrives. A teardown before any byte is read surfaces as
        // ERROR_BROKEN_PIPE or ERROR_PIPE_NOT_CONNECTED (the .NET client
        // sees Read() == 0) — the X1 empty-read signature.
        std::string collected;
        char chunk[8192]{};
        for (;;)
        {
            DWORD got = 0;
            if (ReadFile(client.get(), chunk, sizeof(chunk), &got, nullptr))
            {
                if (got == 0)
                {
                    result.emptyRead = true;
                    result.failure = "zero-byte read (server tore down before the read)";
                    return result;
                }
                collected.append(chunk, got);
                break;
            }
            const DWORD error = GetLastError();
            if (error == ERROR_MORE_DATA)
            {
                if (got > 0)
                    collected.append(chunk, got);
                continue;
            }
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED)
            {
                if (collected.empty())
                {
                    result.emptyRead = true;
                    result.failure = "pipe torn down before any byte (error " +
                        std::to_string(error) + ": server tore down before the read)";
                }
                else
                {
                    result.failure = "pipe torn down mid-message after " +
                        std::to_string(collected.size()) + " bytes (error " +
                        std::to_string(error) + ")";
                }
                return result;
            }
            result.failure = "response read failed, error " + std::to_string(error);
            return result;
        }
        result.bytes = std::move(collected);
        return result;
    }

    struct ScopedLoopServer
    {
        std::thread thread;
        bool active = false;

        void Start(const std::wstring& pipeName)
        {
            testshim::Reset();
            g_pipeName = pipeName;
            g_pipeToken.clear();
            g_stopRequested = false;
            thread = std::thread([] { PipeLoopCore(); });
            active = true;
            // Wait until the first instance exists so connects below cannot
            // race server startup (ERROR_FILE_NOT_FOUND).
            const std::wstring fullName = L"\\\\.\\pipe\\" + pipeName;
            for (int i = 0; i < 200; ++i)
            {
                if (WaitNamedPipeW(fullName.c_str(), 50))
                    break;
            }
        }

        void Stop()
        {
            if (!active)
                return;
            active = false;
            g_stopRequested = true;
            WakePipe();
            if (thread.joinable())
                thread.join();
            testshim::Reset();
        }

        // A failing Require throws with the server thread still serving; a
        // joinable std::thread would std::terminate the process during the
        // unwind and hide the failure. Stop the loop from the destructor so
        // every failure surfaces as a FAIL message instead of an abort.
        ~ScopedLoopServer() noexcept
        {
            try
            {
                Stop();
            }
            catch (...)
            {
            }
        }
    };

    // (0) Negative control with the OLD semantics: write the response and
    // disconnect immediately. A client delayed 100 ms must lose the read.
    // This passes with or without the product fix; it proves the harness
    // reproduces X1 rather than masking it.
    void TestImmediateDisconnectLosesDelayedRead()
    {
        const std::wstring pipeName = TestPipeName("neg");
        const std::wstring fullName = L"\\\\.\\pipe\\" + pipeName;
        const std::string response = "{\"id\":1,\"ok\":true}\n";
        constexpr int kAttempts = 5;
        int emptyReads = 0;

        for (int attempt = 0; attempt < kAttempts; ++attempt)
        {
            ScopedHandle server(CreateNamedPipeW(
                fullName.c_str(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                8192,
                8192,
                1000,
                nullptr));
            Require(static_cast<bool>(server), "negative-control pipe creation failed");

            std::thread clientThread([&] {
                const ExchangeResult result =
                    Exchange(pipeName, "{\"id\":1,\"method\":\"ping\"}\n", 100);
                if (result.emptyRead)
                    ++emptyReads;
            });

            const BOOL connected =
                ConnectNamedPipe(server.get(), nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
            Require(connected != FALSE, "negative-control connect failed");

            char request[1024]{};
            DWORD read = 0;
            (void)ReadFile(server.get(), request, sizeof(request), &read, nullptr);

            DWORD written = 0;
            (void)WriteFile(
                server.get(), response.data(), static_cast<DWORD>(response.size()), &written, nullptr);
            // OLD (buggy) semantics: tear down without waiting for the
            // client to read. Unread bytes are discarded here.
            (void)DisconnectNamedPipe(server.get());
            clientThread.join();
        }
        Require(emptyReads == kAttempts,
            "negative control must lose every delayed read under immediate-disconnect semantics");
    }

    void TestDelayedReadDelivers()
    {
        ScopedLoopServer server;
        server.Start(TestPipeName("delay"));
        int emptyReads = 0;
        std::string firstFailure;
        for (int i = 0; i < 10; ++i)
        {
            const ExchangeResult result =
                Exchange(g_pipeName, "{\"id\":1,\"method\":\"ping\"}\n", 100);
            if (result.emptyRead)
            {
                ++emptyReads;
                if (firstFailure.empty())
                    firstFailure = result.failure;
                continue;
            }
            Require(result.failure.empty(), result.failure.c_str());
            Require(Contains(result.bytes, "\"ok\":true"), "delayed ping lost its ok:true payload");
            Require(!result.bytes.empty() && result.bytes.back() == '\n',
                "delayed ping response must keep its framing newline");
        }
        server.Stop();
        Require(emptyReads == 0,
            ("delayed reads lost " + std::to_string(emptyReads) +
                "/10 after the drain fix" +
                (firstFailure.empty() ? "" : (": " + firstFailure)))
                .c_str());
    }

    void TestLargeResponsesDelivered()
    {
        ScopedLoopServer server;
        server.Start(TestPipeName("large"));
        // Seed after Start: Start() resets the shim, and the server is idle
        // (no request in flight) so populating the scripted backend here is
        // race-free.
        testshim::SetDebugging(true);
        // 128 soft breakpoints: the default ListBreakpoints page, well past
        // the ~60-item / ~8 KiB live failure threshold.
        for (int i = 0; i < 128; ++i)
        {
            char name[32]{};
            (void)snprintf(name, sizeof(name), "bp%d", i);
            testshim::AddBreakpoint(
                1, static_cast<std::uintptr_t>(0x401000 + i * 0x10), name, false);
        }
        std::vector<testshim::FakePage> seeded;
        // 200 memory pages for a full GetMemoryMap reply past 8 KiB.
        for (int i = 0; i < 200; ++i)
        {
            char info[32]{};
            (void)snprintf(info, sizeof(info), "mod%d", i);
            seeded.push_back(testshim::MakeImagePage(
                static_cast<std::uintptr_t>(0x10000000 + i * 0x10000),
                0x10000,
                PAGE_EXECUTE_READ,
                info));
        }
        testshim::SetMemoryPages(std::move(seeded));

        const ExchangeResult breakpoints =
            Exchange(g_pipeName, "{\"id\":2,\"method\":\"ListBreakpoints\"}\n", 0);
        Require(breakpoints.failure.empty(), breakpoints.failure.c_str());
        Require(!breakpoints.emptyRead, "large ListBreakpoints reply was an empty read");
        Require(breakpoints.bytes.size() > 8192,
            ("128-item ListBreakpoints reply must exceed the 8 KiB out-buffer to prove the fix"
                " (got " + std::to_string(breakpoints.bytes.size()) + " bytes" +
                (breakpoints.failure.empty() ? "" : ("; " + breakpoints.failure)) + ")")
                .c_str());
        Require(Contains(breakpoints.bytes, "\"totalCount\":128"),
            "large ListBreakpoints reply lost items in transit");
        Require(Contains(breakpoints.bytes, "\"ok\":true"), "large ListBreakpoints reply lost ok:true");

        const ExchangeResult memoryMap = Exchange(
            g_pipeName,
            "{\"id\":3,\"method\":\"GetMemoryMap\",\"params\":{\"maxItems\":512}}\n",
            0);
        Require(memoryMap.failure.empty(), memoryMap.failure.c_str());
        Require(!memoryMap.emptyRead, "full GetMemoryMap reply was an empty read");
        Require(memoryMap.bytes.size() > 8192,
            ("200-page GetMemoryMap reply must exceed the 8 KiB out-buffer to prove the fix"
                " (got " + std::to_string(memoryMap.bytes.size()) + " bytes" +
                (memoryMap.failure.empty() ? "" : ("; " + memoryMap.failure)) + ")")
                .c_str());
        Require(Contains(memoryMap.bytes, "\"ok\":true"), "full GetMemoryMap reply lost ok:true");

        server.Stop();
    }

    void TestBurstSeesZeroEmptyReads()
    {
        ScopedLoopServer server;
        server.Start(TestPipeName("burst"));

        // 8x20 exchanges against the single-instance loop: every client
        // except the served one waits on connect (the loop notices a
        // waiter on its ~50 ms overlapped-connect poll), so the connect
        // budget must cover the whole serialized burst, not one exchange.
        constexpr int kThreads = 8;
        constexpr int kPerThread = 20;
        std::atomic_int emptyReads{0};
        std::atomic_int failures{0};
        std::atomic_int wrongPayload{0};
        std::string firstFailure;
        std::mutex firstFailureMutex;
        std::vector<std::thread> workers;
        for (int t = 0; t < kThreads; ++t)
        {
            workers.emplace_back([&] {
                for (int i = 0; i < kPerThread; ++i)
                {
                    const ExchangeResult result =
                        Exchange(g_pipeName, "{\"id\":1,\"method\":\"ping\"}\n", 0);
                    if (result.emptyRead)
                    {
                        emptyReads.fetch_add(1);
                        continue;
                    }
                    if (!result.failure.empty())
                    {
                        failures.fetch_add(1);
                        std::lock_guard<std::mutex> lock(firstFailureMutex);
                        if (firstFailure.empty())
                            firstFailure = result.failure;
                        continue;
                    }
                    if (!Contains(result.bytes, "\"ok\":true"))
                        wrongPayload.fetch_add(1);
                }
            });
        }
        for (auto& worker : workers)
            worker.join();
        server.Stop();

        const int total = kThreads * kPerThread;
        Require(emptyReads.load() == 0,
            ("burst lost " + std::to_string(emptyReads.load()) + "/" + std::to_string(total) +
                " reads to empty disconnects after the drain fix")
                .c_str());
        Require(failures.load() == 0,
            ("burst saw " + std::to_string(failures.load()) + " transport failures" +
                (firstFailure.empty() ? "" : (" (first: " + firstFailure + ")")))
                .c_str());
        Require(wrongPayload.load() == 0, "burst response lost its ok:true payload");
    }

    void RunPipeDrainTests()
    {
        TestImmediateDisconnectLosesDelayedRead();
        TestDelayedReadDelivers();
        TestLargeResponsesDelivered();
        TestBurstSeesZeroEmptyReads();
    }
} // namespace dbglink_pipe_drain_tests
