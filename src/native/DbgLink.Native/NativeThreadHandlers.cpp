#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeControlSupport.h"
#include "NativeDebuggerQueries.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeControlHandlers.h"
#include "NativeRequestParams.h"

namespace dbglink
{
    namespace
    {
        // x64dbg parses integer command arguments as hex, so a decimal thread
        // id resolves a different thread. Every switchthread call site renders
        // the id through this helper so the three paths cannot drift apart.
        // HexAddress matches the shared compact-hex wire policy (lowercase).
        std::string SwitchThreadCommand(std::uint64_t threadId)
        {
            return "switchthread " + HexAddress(static_cast<std::uintptr_t>(threadId));
        }
    }

    std::string HandleSwitchThread(const std::string& request, const std::string& id)
    {
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        std::uint64_t tid = 0;
        if (!ExtractUnsigned(request, "threadId", tid) || tid == 0 || tid > 0xFFFFFFFFu)
            return ErrorResponse(id, "SwitchThread threadId must be a debugger thread id (see ListThreads).");
        const std::string command = SwitchThreadCommand(tid);
        if (!ExecDirect(command))
            return ErrorResponse(id, "The debugger rejected the thread switch (unknown thread id?).");
        // Shared execution-control ack policy (see NativeControlHandlers.h):
        // every control ack keeps its followUp hint; the sentence also lives
        // in the SwitchThread tool description, but scripted callers poll on
        // the ack field, so dropping it here while step/run/pause/continue
        // keep theirs would split the contract.
        nlohmann::json result{
            {"action", "switchThread"},
            {"threadId", tid},
            {"followUp", "Call GetBacktrace or GetAnalysisSnapshot to read the new thread."},
        };
        return SuccessResponse(id, result);
    }

    std::string HandleListThreads(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::uint64_t offset = 0;
        if (auto error = params.OptionalUnsigned("offset", offset, "ListThreads offset must be an integer."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t maxItems = 128;
        if (auto error = params.BoundedUnsigned("maxItems", maxItems, 1, 512,
                "ListThreads maxItems must be between 1 and 512."); !error.empty())
            return ErrorResponse(id, error);
        auto getThreadList = GetDebuggerBridgeFunction<DbgGetThreadListFunction>("DbgGetThreadList");
        auto bridgeFree = GetDebuggerBridgeFunction<BridgeFreeFunction>("BridgeFree");
        if (getThreadList == nullptr || bridgeFree == nullptr)
            return ErrorResponse(id, "Thread-list bridge is unavailable.");
        BridgeThreadListGuard threads;
        threads.freeFunction = bridgeFree;
        getThreadList(&threads.list);
        if (threads.list.count < 0 || threads.list.count > kMaxThreadEntries)
            return ErrorResponse(id, "x64dbg returned an invalid thread count.");
        if (!ValidateBridgeList(threads.list.count, threads.list.list, kMaxThreadEntries))
            return ErrorResponse(id, "x64dbg returned a null thread-list buffer.");
        const std::size_t total = static_cast<std::size_t>(threads.list.count);
        const PageWindow window = ComputePageWindow(offset, maxItems, total);
        nlohmann::json items = nlohmann::json::array();
        for (std::size_t i = 0; i < window.count; ++i)
        {
            const auto& info = threads.list.list[window.start + i].basicInfo;
            const auto& full = threads.list.list[window.start + i];
            nlohmann::json item{
                {"number", info.threadNumber},
                {"threadId", info.threadId},
                {"entry", HexAddress(info.threadStartAddress)},
                {"teb", HexAddress(info.threadLocalBase)},
                {"cip", HexAddress(full.threadCip)},
            };
            const std::string name = SingleLine(BufferText(info.threadName, sizeof(info.threadName)));
            if (!name.empty())
                item["name"] = name;
            if (full.suspendCount != 0)
                item["suspendCount"] = full.suspendCount;
            items.push_back(std::move(item));
        }
        nlohmann::json result;
        ApplyPagedEnvelope(result, window, offset);
        result["currentThread"] = threads.list.currentThread;
        result["threads"] = std::move(items);
        return SuccessResponse(id, result);
    }

    std::string HandleBacktrace(const std::string& request, const std::string& id)
    {
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        const RequestParams params(request);
        std::uint64_t maxFrames = 16;
        if (auto error = params.BoundedUnsigned("maxFrames", maxFrames, 1, 128,
                "GetBacktrace maxFrames must be between 1 and 128."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t startFrame = 0;
        if (auto error = params.OptionalUnsigned("startFrame", startFrame,
                "GetBacktrace startFrame must be an integer."); !error.empty())
            return ErrorResponse(id, error);
        const bool hasThread = params.Has("threadId");
        std::uint64_t wantedTid = 0;
        if (auto error = params.BoundedUnsigned("threadId", wantedTid, 1,
                0xFFFFFFFFull,
                "GetBacktrace threadId must be a debugger thread id."); !error.empty())
            return ErrorResponse(id, error);

        // Optionally switch to the requested thread, walk, then switch back.
        std::uint64_t previousTid = 0;
        bool switched = false;
        if (hasThread)
        {
            auto getThreadList = GetDebuggerBridgeFunction<DbgGetThreadListFunction>("DbgGetThreadList");
            auto bridgeFree = GetDebuggerBridgeFunction<BridgeFreeFunction>("BridgeFree");
            if (getThreadList == nullptr || bridgeFree == nullptr)
                return ErrorResponse(id, "Thread-list bridge is unavailable.");
            BridgeThreadListGuard threads;
            threads.freeFunction = bridgeFree;
            getThreadList(&threads.list);
            if (threads.list.count < 0 || threads.list.count > kMaxThreadEntries || threads.list.list == nullptr)
                return ErrorResponse(id, "x64dbg returned an invalid thread list.");
            bool found = false;
            for (int i = 0; i < threads.list.count; ++i)
            {
                if (threads.list.list[i].basicInfo.threadId == static_cast<DWORD>(wantedTid))
                    found = true;
                if (i == threads.list.currentThread)
                    previousTid = threads.list.list[i].basicInfo.threadId;
            }
            if (!found)
                return ErrorResponse(id, "Unknown threadId (see ListThreads).");
            if (wantedTid != previousTid)
            {
                if (!ExecDirect(SwitchThreadCommand(wantedTid)))
                    return ErrorResponse(id, "The debugger rejected the thread switch.");
                switched = true;
            }
        }

        auto valueFromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        auto memoryRead = GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead");
        std::string walkError;
        nlohmann::json frames = nlohmann::json::array();
        std::size_t walked = 0;
        std::size_t returned = 0;
        bool approximate = false;
        if (valueFromString == nullptr || memoryRead == nullptr)
        {
            walkError = "Register/memory bridge is unavailable.";
        }
        else
        {
            const char* frameReg = sizeof(std::uintptr_t) == 8 ? "rbp" : "ebp";
            const char* stackReg = sizeof(std::uintptr_t) == 8 ? "rsp" : "esp";
            std::uintptr_t rbp = valueFromString(frameReg);
            const std::uintptr_t rsp = valueFromString(stackReg);
            auto getModuleAt = GetDebuggerBridgeFunction<DbgGetModuleAtFunction>("DbgGetModuleAt");
            auto getLabelAt = GetDebuggerBridgeFunction<DbgGetLabelAtFunction>("DbgGetLabelAt");
            auto getCommentAt = GetDebuggerBridgeFunction<DbgGetCommentAtFunction>("DbgGetCommentAt");
            // m2: keep paging arithmetic in 64 bits. A size_t narrowing of a
            // huge startFrame would wrap to a small index (even 0) on 32-bit
            // and return the wrong page; the loop indexes with a
            // bounds-checked cast instead.
            const std::uint64_t wantStart = startFrame;
            const std::uint64_t wantCount = maxFrames;

            CallStackWalk walk = WalkCallStack(memoryRead, rbp, rsp, kMaxCallStackFrames);
            approximate = walk.approximate;
            walked = walk.frames.size();
            for (std::uint64_t index = wantStart;
                 index < static_cast<std::uint64_t>(walk.frames.size()) &&
                     static_cast<std::uint64_t>(returned) < wantCount;
                 ++index)
            {
                const auto& frame = walk.frames[static_cast<std::size_t>(index)];
                const auto info = GetCallStackAddressInfo(frame.returnAddress, getModuleAt, getLabelAt, getCommentAt);
                // index is the absolute frame number (startFrame + position);
                // empty module/label/comment stay omitted, but index itself is
                // restored: paging arithmetic on the client reads it.
                nlohmann::json frameJson{
                    {"index", index},
                    {"frameAddress", HexAddress(frame.frameAddress)},
                    {"returnAddress", HexAddress(frame.returnAddress)},
                };
                if (!info.module.empty())
                    frameJson["module"] = info.module;
                if (!info.label.empty())
                    frameJson["label"] = info.label;
                if (!info.comment.empty())
                    frameJson["comment"] = info.comment;
                frames.push_back(std::move(frameJson));
                ++returned;
            }

            if (walk.frames.empty())
                walkError = "Call stack could not be retrieved (check RBP validity or use debugger UI).";
        }

        if (switched && previousTid != 0)
            (void)ExecDirect(SwitchThreadCommand(previousTid));

        if (!walkError.empty() && frames.empty())
            return ErrorResponse(id, walkError);
        nlohmann::json result{
            {"schemaVersion", 1},
            {"startFrame", startFrame},
            {"returnedCount", returned},
            {"walkedFrames", walked},
            {"truncated", static_cast<std::uint64_t>(walked) > startFrame &&
                static_cast<std::uint64_t>(walked) - startFrame > static_cast<std::uint64_t>(returned)},
            // rbp_frame_chain = frame-pointer walk; stack_scan = validated
            // fallback for builds that omit frame pointers (approximate).
            // method is restored (not gated): it is one short string per call
            // and scripted consumers match on it; approximate stays as the
            // machine-readable twin.
            {"method", approximate ? "stack_scan" : "rbp_frame_chain"},
            {"approximate", approximate},
        };
        result["frames"] = std::move(frames);
        // nextFrame is the paging cursor: present while truncated, omitted
        // when the walk is exhausted (never null). Overflow-safe: only
        // computed when hasMore holds, so startFrame + returned < walked.
        if (static_cast<std::uint64_t>(walked) > startFrame &&
            static_cast<std::uint64_t>(walked) - startFrame > static_cast<std::uint64_t>(returned))
            result["nextFrame"] = startFrame + static_cast<std::uint64_t>(returned);
        if (hasThread)
            result["threadId"] = wantedTid;
        return SuccessResponse(id, result);
    }
}
