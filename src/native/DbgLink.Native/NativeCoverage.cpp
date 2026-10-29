#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeCoverage.h"
#include "NativeDebuggerQueries.h"
#include "NativeInputValidation.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeRequestParams.h"

namespace dbglink
{
    namespace
    {
        constexpr std::uint64_t kDefaultSampleIntervalMs = 200;
        constexpr std::uint64_t kMinSampleIntervalMs = 50;
        constexpr std::uint64_t kMaxSampleIntervalMs = 5000;
        constexpr std::uint64_t kDefaultSampleDurationMs = 2000;
        // SEC N3: 15 s / 100 snapshots cap the worst-case pipe hold even
        // before the per-iteration mutex release below does its part.
        constexpr std::uint64_t kMaxSampleDurationMs = 15000;
        constexpr std::uint64_t kDefaultMaxSamples = 20;
        constexpr std::uint64_t kMaxSamples = 100;
        constexpr std::uint64_t kDefaultSampleFrames = 32;
        constexpr std::uint64_t kMaxSampleFrames = 128;
        constexpr std::uint64_t kDefaultTopN = 32;
        constexpr std::uint64_t kMaxTopN = 128;
    }

    void CoverageAggregator::Add(const std::string& module, std::uint64_t rva)
    {
        ++hits_[CoverageFrameKey{ module, rva }];
    }

    std::size_t CoverageAggregator::UniqueFrames() const
    {
        return hits_.size();
    }

    std::vector<CoverageFrameCount> CoverageAggregator::Top(std::size_t count) const
    {
        std::vector<CoverageFrameCount> entries;
        entries.reserve(hits_.size());
        for (const auto& [key, hits] : hits_)
            entries.push_back({ key.module, key.rva, hits });
        std::sort(entries.begin(), entries.end(), [](const CoverageFrameCount& left, const CoverageFrameCount& right)
            {
                if (left.hits != right.hits)
                    return left.hits > right.hits;
                if (left.module != right.module)
                    return left.module < right.module;
                return left.rva < right.rva;
            });
        if (entries.size() > count)
            entries.resize(count);
        return entries;
    }

    CoverageFrameKey CoverageKeyForAddress(
        const std::vector<ModuleRecord>& modules,
        std::uintptr_t address)
    {
        for (const auto& module : modules)
        {
            if (module.base < module.end && address >= module.base && address < module.end)
            {
                std::string name = module.name.empty() ? FileNameFromPath(module.path) : module.name;
                if (name.empty())
                    name = "<unknown>";
                return { name, static_cast<std::uint64_t>(address - module.base) };
            }
        }
        return { "<unmapped>", static_cast<std::uint64_t>(address) };
    }

    nlohmann::json BuildCoverageResult(
        std::uint64_t samples,
        const CoverageAggregator& coverage,
        std::size_t topN)
    {
        const auto top = coverage.Top(topN);
        nlohmann::json frames = nlohmann::json::array();
        for (const auto& entry : top)
        {
            frames.push_back(
                {
                    { "module", entry.module },
                    { "rva", HexAddress(entry.rva) },
                    { "hits", entry.hits },
                });
        }
        return nlohmann::json{
            { "samples", samples },
            { "uniqueFrames", coverage.UniqueFrames() },
            { "truncated", top.size() < coverage.UniqueFrames() },
            { "frames", std::move(frames) },
        };
    }

    std::string HandleSampleCallStacks(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::uint64_t intervalMs = kDefaultSampleIntervalMs;
        if (auto error = params.BoundedUnsigned("intervalMs", intervalMs, kMinSampleIntervalMs, kMaxSampleIntervalMs,
                "SampleCallStacks intervalMs must be between 50 and 5000."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t durationMs = kDefaultSampleDurationMs;
        if (auto error = params.BoundedUnsigned("durationMs", durationMs, 0, kMaxSampleDurationMs,
                "SampleCallStacks durationMs must be between 0 and 15000."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t maxSamples = kDefaultMaxSamples;
        if (auto error = params.BoundedUnsigned("maxSamples", maxSamples, 1, kMaxSamples,
                "SampleCallStacks maxSamples must be between 1 and 100."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t maxFrames = kDefaultSampleFrames;
        if (auto error = params.BoundedUnsigned("maxFrames", maxFrames, 1, kMaxSampleFrames,
                "SampleCallStacks maxFrames must be between 1 and 128."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t topN = kDefaultTopN;
        if (auto error = params.BoundedUnsigned("topN", topN, 1, kMaxTopN,
                "SampleCallStacks topN must be between 1 and 128."); !error.empty())
            return ErrorResponse(id, error);
        std::string moduleFilter;
        if (auto error = params.OptionalModuleFilter("module", moduleFilter,
                "SampleCallStacks module must be a string.",
                "SampleCallStacks module must be at most 256 printable bytes."); !error.empty())
            return ErrorResponse(id, error);

        // Snapshots stop at the first bound hit: (samples-1)*intervalMs never
        // exceeds durationMs, so the worst-case pipe hold stays around the
        // 15 s duration cap above. At least one snapshot always runs.
        const std::uint64_t sampleCount = (std::min)(maxSamples, durationMs / intervalMs + 1);

        // SEC N3: this handler runs WITHOUT holding g_debuggerCallMutex (the
        // dispatcher releases it for SampleCallStacks). The mutex is taken
        // per snapshot for the debugger reads only and released before Sleep,
        // so Pause/WriteMemory/CallFunction are never starved by the loop.
        auto valueFromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        if (valueFromString == nullptr)
            return ErrorResponse(id, "[SampleCallStacks] No active debug session.");
        auto memoryRead = GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead");
        if (memoryRead == nullptr)
            return ErrorResponse(id, "[SampleCallStacks] Memory-read bridge is unavailable.");
        {
            std::lock_guard<std::mutex> lock(g_debuggerCallMutex);
            ApplyPendingCallRestore();
            if (!IsDebugging())
                return ErrorResponse(id, "[SampleCallStacks] No active debug session.");
        }

        std::vector<ModuleRecord> modules;
        bool mapTruncated = false;
        std::string moduleError;
        {
            std::lock_guard<std::mutex> lock(g_debuggerCallMutex);
            ApplyPendingCallRestore();
            if (!IsDebugging())
                return ErrorResponse(id, "[SampleCallStacks] No active debug session.");
            if (!CollectModuleRecords(modules, mapTruncated, moduleError))
                return ErrorResponse(id, "SampleCallStacks: " + moduleError);
        }
        const auto selected = SelectModulesByFilter(modules, moduleFilter, true);
        const bool filtering = !moduleFilter.empty() && !EqualsInsensitive(moduleFilter, "all");

        CoverageAggregator coverage;
        const char* frameRegister = sizeof(std::uintptr_t) == 8 ? "rbp" : "ebp";
        const char* stackRegister = sizeof(std::uintptr_t) == 8 ? "rsp" : "esp";
        std::uint64_t samplesTaken = 0;
        for (std::uint64_t sample = 0; sample < sampleCount; ++sample)
        {
            if (g_stopRequested.load())
                break;
            {
                // Mutex only for the debugger reads; the Sleep below runs
                // unlocked. A session that ends mid-run stops the loop and
                // reports the snapshots taken so far (same result shape).
                std::lock_guard<std::mutex> lock(g_debuggerCallMutex);
                ApplyPendingCallRestore();
                if (!IsDebugging())
                    break;
                const std::uintptr_t rbp = valueFromString(frameRegister);
                const std::uintptr_t rsp = valueFromString(stackRegister);
                const CallStackWalk walk = WalkCallStack(memoryRead, rbp, rsp, static_cast<int>(maxFrames));
                for (const auto& frame : walk.frames)
                {
                    const auto key = CoverageKeyForAddress(selected, frame.returnAddress);
                    // Under a module filter, frames outside the selected modules
                    // (keyed "<unmapped>") are skipped instead of aggregated.
                    if (filtering && key.module == "<unmapped>")
                        continue;
                    coverage.Add(key.module, key.rva);
                }
            }
            ++samplesTaken;
            if (sample + 1 < sampleCount)
                Sleep(static_cast<DWORD>(intervalMs));
        }

        if (samplesTaken == 0)
            return ErrorResponse(id, "[SampleCallStacks] No active debug session.");
        return SuccessResponse(id, BuildCoverageResult(samplesTaken, coverage, static_cast<std::size_t>(topN)));
    }

}
