#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeInterestingStringSearch.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"

namespace dbglink
{
    InterestingStringResult ScanInterestingStrings(
        const std::vector<ModuleRecord>& modules,
        const std::vector<InterestingSearchPattern>& patterns,
        std::size_t maxResultsPerNeedle,
        std::size_t maxScanBytes)
    {
        InterestingStringResult result;
        if (patterns.empty() || modules.empty() || maxResultsPerNeedle == 0 || maxScanBytes == 0)
            return result;
        std::size_t maxPatternLength = 0;
        std::size_t groupCount = 0;
        for (const auto& item : patterns)
        {
            maxPatternLength = std::max(maxPatternLength, item.pattern.bytes.size());
            groupCount = std::max(groupCount, item.group + 1);
        }
        if (maxPatternLength == 0 || groupCount == 0)
            return result;

        const std::size_t carryLimit = maxPatternLength - 1;
        auto memoryRead = GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead");
        if (memoryRead == nullptr)
        {
            result.readFailure = true;
            return result;
        }
        const std::size_t maxTotalResults = maxResultsPerNeedle * groupCount;
        result.matches.reserve(std::min(
            maxTotalResults,
            kMaxInterestingNeedles * kMaxInterestingResultsPerNeedle));
        std::vector<std::size_t> resultCounts(groupCount, 0);
        std::array<std::vector<std::size_t>, 256> patternBuckets;
        for (std::size_t patternIndex = 0; patternIndex < patterns.size(); ++patternIndex)
        {
            const auto& pattern = patterns[patternIndex].pattern.bytes;
            if (!pattern.empty())
                patternBuckets[pattern.front()].push_back(patternIndex);
        }
        std::size_t remainingBudget = maxScanBytes;
        std::vector<unsigned char> carry;
        carry.reserve(carryLimit);
        std::vector<unsigned char> combined;
        combined.reserve(kMaxMemoryReadBytes + carryLimit);

        for (std::size_t moduleIndex = 0;
             moduleIndex < modules.size() && remainingBudget > 0;
             ++moduleIndex)
        {
            const auto& module = modules[moduleIndex];
            if (module.base == 0 || module.end <= module.base)
                continue;

            const auto moduleSize = static_cast<std::uint64_t>(module.end - module.base);
            const std::size_t scanLimit = static_cast<std::size_t>(std::min<std::uint64_t>(
                moduleSize,
                static_cast<std::uint64_t>(remainingBudget)));
            if (scanLimit < moduleSize)
                result.scanTruncated = true;

            std::size_t moduleOffset = 0;
            carry.clear();
            combined.clear();
            while (moduleOffset < scanLimit)
            {
                const std::size_t chunkSize = std::min<std::size_t>(
                    kMaxMemoryReadBytes,
                    scanLimit - moduleOffset);
                std::uintptr_t chunkAddress = 0;
                if (!TryAddAddress(module.base, moduleOffset, chunkAddress))
                {
                    result.addressOverflow = true;
                    break;
                }

                combined.clear();
                combined.insert(combined.end(), carry.begin(), carry.end());
                const std::size_t carrySize = combined.size();
                combined.resize(carrySize + chunkSize);
                if (!ReadMemory(chunkAddress, chunkSize, combined.data() + carrySize, memoryRead))
                {
                    result.readFailure = true;
                    carry.clear();
                    moduleOffset += chunkSize;
                    result.scannedBytes += chunkSize;
                    continue;
                }

                const std::size_t dataSize = combined.size() - carrySize;
                const std::size_t combinedBaseOffset = moduleOffset >= carrySize
                    ? moduleOffset - carrySize
                    : 0;

                for (std::size_t offset = 0; offset < combined.size(); ++offset)
                {
                    const auto& candidates = patternBuckets[combined[offset]];
                    for (const auto patternIndex : candidates)
                    {
                        const auto& item = patterns[patternIndex];
                        if (item.group >= resultCounts.size() ||
                            item.pattern.bytes.empty() ||
                            offset + item.pattern.bytes.size() > combined.size() ||
                            resultCounts[item.group] >= maxResultsPerNeedle)
                        {
                            continue;
                        }

                        if (!std::equal(item.pattern.bytes.begin(), item.pattern.bytes.end(), combined.begin() +
                                static_cast<std::ptrdiff_t>(offset)))
                        {
                            continue;
                        }

                        const std::size_t globalOffset = combinedBaseOffset + offset;
                        if (globalOffset + item.pattern.bytes.size() <= moduleOffset)
                            continue;

                        std::uintptr_t matchAddress = 0;
                        if (!TryAddAddress(module.base, globalOffset, matchAddress))
                        {
                            result.addressOverflow = true;
                            break;
                        }

                        result.matches.push_back(InterestingStringMatch
                            {
                                matchAddress,
                                module.name,
                                item.needle,
                                item.pattern.encoding,
                                item.pattern.bytes.size(),
                                item.pattern.preview,
                            });
                        ++resultCounts[item.group];
                        if (std::all_of(resultCounts.begin(), resultCounts.end(),
                            [maxResultsPerNeedle](std::size_t count)
                            {
                                return count >= maxResultsPerNeedle;
                            }))
                        {
                            result.scannedBytes += dataSize;
                            result.resultLimitReached = true;
                            return result;
                        }
                        if (result.matches.size() >= maxTotalResults)
                        {
                            result.scannedBytes += dataSize;
                            result.resultLimitReached = true;
                            return result;
                        }
                    }
                    if (result.addressOverflow)
                        break;
                }
                if (result.addressOverflow)
                    break;

                const std::size_t nextCarrySize = std::min(carryLimit, dataSize);
                carry.assign(combined.end() - static_cast<std::ptrdiff_t>(nextCarrySize), combined.end());
                moduleOffset += dataSize;
                result.scannedBytes += dataSize;
                if (dataSize < chunkSize)
                {
                    result.scanTruncated = true;
                    break;
                }
            }

            if (moduleOffset < scanLimit)
                result.scanTruncated = true;
            remainingBudget -= std::min(remainingBudget, moduleOffset);
            if (moduleIndex + 1 < modules.size() && remainingBudget == 0)
                result.scanTruncated = true;

            bool allNeedlesComplete = true;
            for (const auto count : resultCounts)
            {
                if (count < maxResultsPerNeedle)
                {
                    allNeedlesComplete = false;
                    break;
                }
            }
            if (allNeedlesComplete)
            {
                result.resultLimitReached = true;
                return result;
            }
        }

        return result;
    }

    const char* XrefTypeText(XrefType type)
    {
        switch (type)
        {
        case XrefType::Data:
            return "data";
        case XrefType::Jmp:
            return "jmp";
        case XrefType::Call:
            return "call";
        default:
            return "none";
        }
    }

}
