// NativeCoverageTests.cpp — stack-sampling coverage aggregation.
//
// Covers NativeCoverage.cpp without a debugger: CoverageAggregator
// dedup/ordering/truncation, CoverageKeyForAddress module+RVA mapping
// (including the end-exclusive boundary and the file-name fallback),
// BuildCoverageResult wire shape, and HandleSampleCallStacks limit
// validation plus the no-debug-session path (the test binary loads no
// debugger bridge, so IsDebugging() is false).
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "../../src/native/DbgLink.Native/NativeCoverage.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"
#include "../../src/native/DbgLink.Native/X64DbgApiShim.h"

namespace dbglink_coverage_tests
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
        return "{\"id\":9,\"method\":\"SampleCallStacks\",\"params\":{" + inner + "}}";
    }

    void RunCoverageTests()
    {
        {
            CoverageAggregator coverage;
            coverage.Add("b.exe", 0x2000);
            coverage.Add("a.exe", 0x1000);
            coverage.Add("a.exe", 0x1000);
            coverage.Add("a.exe", 0x3000);
            Require(coverage.UniqueFrames() == 3, "repeated frames were not deduplicated");
            const auto top = coverage.Top(10);
            Require(top.size() == 3, "Top returned the wrong frame count");
            Require(top[0].module == "a.exe" && top[0].rva == 0x1000 && top[0].hits == 2,
                "hits must sort before module and RVA");
            Require(top[1].module == "a.exe" && top[1].rva == 0x3000 && top[1].hits == 1,
                "equal hits must break ties by module then RVA");
            Require(top[2].module == "b.exe" && top[2].hits == 1,
                "equal hits must break ties by module then RVA");
            const auto first = coverage.Top(1);
            Require(first.size() == 1 && first[0].hits == 2, "Top must truncate to the requested count");
        }

        {
            // Addr narrows a 64-bit literal to uintptr_t explicitly: on
            // 32-bit builds the test addresses wrap (C4305/C4309 by design),
            // exactly like real truncated live addresses would.
            auto addr = [](std::uint64_t v) { return static_cast<std::uintptr_t>(v); };
            std::vector<ModuleRecord> modules;
            ModuleRecord app{};
            app.base = addr(0x140000000);
            app.end = addr(0x140010000);
            app.name = "app.exe";
            app.path = "C:\\target\\app.exe";
            modules.push_back(app);
            const auto key = CoverageKeyForAddress(modules, addr(0x140001000));
            Require(key.module == "app.exe" && key.rva == 0x1000, "in-module address must map to module+RVA");
            const auto edge = CoverageKeyForAddress(modules, addr(0x140010000));
            // NOTE: on 32-bit builds the address truncates to uintptr_t, so
            // the unmapped key carries the truncated value, not the literal.
            const auto truncatedEdge = static_cast<std::uint64_t>(addr(0x140010000));
            Require(edge.module == "<unmapped>" && edge.rva == truncatedEdge,
                "module end is exclusive: the first byte past it is unmapped");
            ModuleRecord nameless{};
            nameless.base = addr(0x200000000);
            nameless.end = addr(0x200010000);
            nameless.path = "C:\\target\\lib.dll";
            modules.push_back(nameless);
            const auto fallback = CoverageKeyForAddress(modules, addr(0x200000500));
            Require(fallback.module == "lib.dll" && fallback.rva == 0x500,
                "empty module name must fall back to the file name");
        }

        {
            CoverageAggregator coverage;
            coverage.Add("b.exe", 0x2000);
            coverage.Add("a.exe", 0x1000);
            coverage.Add("a.exe", 0x1000);
            const auto full = BuildCoverageResult(5, coverage, 32);
            Require(full["samples"] == 5, "result must report the snapshot count");
            Require(full["uniqueFrames"] == 2, "result must report the unique frame count");
            Require(full["truncated"] == false, "untruncated result must not claim truncation");
            Require(full["frames"].size() == 2, "result must carry every frame under topN");
            Require(full["frames"][0]["module"] == "a.exe" &&
                    full["frames"][0]["rva"] == "0x1000" &&
                    full["frames"][0]["hits"] == 2,
                "top frame must carry module, compact lowercase RVA and hit count");
            const auto cut = BuildCoverageResult(5, coverage, 1);
            Require(cut["frames"].size() == 1 && cut["truncated"] == true,
                "topN truncation must cap frames and report truncated=true");
        }

        {
            // m1: RVAs above 32 bits must not narrow through uintptr_t (old
            // code truncated 0x140001000 to 0x40001000 on 32-bit builds).
            CoverageAggregator wide;
            wide.Add("a.exe", 0x140001000ULL);
            const auto result = BuildCoverageResult(1, wide, 32);
            Require(result["frames"].size() == 1, "wide RVA frame missing");
            Require(result["frames"][0]["rva"] == "0x140001000",
                "wide RVA must render in full without narrowing");
        }

        {
            // The shim redirects the debugger bridge: pin it to "no session"
            // (earlier suites leave debugging enabled), so valid arguments
            // reach the no-session guard without touching Sleep or memory.
            testshim::Reset();
            testshim::SetDebugging(false);
            Require(Contains(HandleSampleCallStacks(P("\"intervalMs\":49"), "1"),
                        "intervalMs must be between 50 and 5000"),
                "intervalMs below 50 must be rejected");
            Require(Contains(HandleSampleCallStacks(P("\"intervalMs\":5001"), "1"),
                        "intervalMs must be between 50 and 5000"),
                "intervalMs above 5000 must be rejected");
            Require(Contains(HandleSampleCallStacks(P("\"durationMs\":15001"), "1"),
                        "durationMs must be between 0 and 15000"),
                "durationMs above 15000 must be rejected");
            Require(Contains(HandleSampleCallStacks(P("\"maxSamples\":0"), "1"),
                        "maxSamples must be between 1 and 100"),
                "maxSamples of 0 must be rejected");
            Require(Contains(HandleSampleCallStacks(P("\"maxSamples\":101"), "1"),
                        "maxSamples must be between 1 and 100"),
                "maxSamples above 100 must be rejected");
            Require(Contains(HandleSampleCallStacks(P("\"maxFrames\":129"), "1"),
                        "maxFrames must be between 1 and 128"),
                "maxFrames above 128 must be rejected");
            Require(Contains(HandleSampleCallStacks(P("\"topN\":0"), "1"),
                        "topN must be between 1 and 128"),
                "topN of 0 must be rejected");
            // The test binary loads no live debugger; with the shim pinned to
            // "no session" above, valid arguments fail loudly here instead of
            // sampling.
            Require(Contains(HandleSampleCallStacks(P("\"maxSamples\":1"), "3"),
                        "No active debug session"),
                "sampling without a debug session must fail loudly");
        }
    }
}
