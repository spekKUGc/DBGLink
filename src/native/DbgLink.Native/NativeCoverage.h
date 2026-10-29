#pragma once
#include "NativeTypes.h"
#include "third_party/nlohmann/json.hpp"
namespace dbglink
{
    // Stack-sampling coverage (SampleCallStacks): aggregates unique
    // module+RVA frames with hit counts across bounded stack snapshots.
    //
    // Safety contract: the handler performs NO automatic run/pause
    // orchestration. Issuing Run/Pause from inside g_debuggerCallMutex (held
    // by the pipe dispatch) would deadlock or race the debugger UI thread,
    // so sampling only reads the current (paused) state with Sleep-spaced
    // snapshots. For live coverage, drive repeated short calls across
    // manual run/pause steps (ControlDebuggerExecution) instead.
    //
    // SEC N3 locking contract: HandleSampleCallStacks runs WITHOUT holding
    // g_debuggerCallMutex (the pipe dispatcher releases it for this method).
    // The handler takes the mutex per snapshot for the debugger reads only
    // and always Sleeps unlocked, so a sampling run never starves
    // Pause/WriteMemory/CallFunction. Callers must not wrap this handler in
    // the mutex (std::mutex is non-recursive: it would deadlock).
    struct CoverageFrameKey
    {
        std::string module;
        std::uint64_t rva = 0;
        bool operator==(const CoverageFrameKey& other) const
        {
            return module == other.module && rva == other.rva;
        }
    };
    struct CoverageFrameKeyHash
    {
        std::size_t operator()(const CoverageFrameKey& key) const noexcept
        {
            const std::size_t moduleHash = std::hash<std::string>{}(key.module);
            const std::size_t rvaHash = std::hash<std::uint64_t>{}(key.rva);
            return moduleHash ^ (rvaHash + 0x9E3779B9u + (moduleHash << 6) + (moduleHash >> 2));
        }
    };
    struct CoverageFrameCount
    {
        std::string module;
        std::uint64_t rva = 0;
        std::uint64_t hits = 0;
    };
    // Deduplicating hit counter: one Add per observed frame address.
    class CoverageAggregator
    {
    public:
        void Add(const std::string& module, std::uint64_t rva);
        std::size_t UniqueFrames() const;
        // Hits descending, then module ascending, then RVA ascending, so the
        // wire order is deterministic for equal hit counts.
        std::vector<CoverageFrameCount> Top(std::size_t count) const;
    private:
        std::unordered_map<CoverageFrameKey, std::uint64_t, CoverageFrameKeyHash> hits_;
    };
    // Maps an absolute address to its module+RVA key using one module-table
    // snapshot. Unmapped addresses aggregate under "<unmapped>" keyed by the
    // absolute address, so kernel/unlisted frames stay visible, not dropped.
    CoverageFrameKey CoverageKeyForAddress(
        const std::vector<ModuleRecord>& modules,
        std::uintptr_t address);
    // Pure result builder (no debugger calls): shared by the handler and the
    // regression harness, so aggregation order and truncation are pinned.
    nlohmann::json BuildCoverageResult(
        std::uint64_t samples,
        const CoverageAggregator& coverage,
        std::size_t topN);
    std::string HandleSampleCallStacks(const std::string& request, const std::string& id);
}
