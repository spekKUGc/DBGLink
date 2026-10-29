#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeStringSearch.h"

namespace dbglink
{
    StringSearchResult ScanStringPatterns(
        const std::vector<ModuleRecord>& modules,
        const std::vector<SearchPattern>& patterns,
        std::size_t maxResults,
        std::size_t maxScanBytes)
    {
        StringSearchResult result;
        if (patterns.empty() || modules.empty() || maxResults == 0 || maxScanBytes == 0)
            return result;

        result.matches.reserve(std::min(maxResults, kMaxSearchResults));

        std::size_t maxPatternLength = 0;
        for (const auto& pattern : patterns)
            maxPatternLength = std::max(maxPatternLength, pattern.bytes.size());
        const std::size_t carryLimit = maxPatternLength > 0 ? maxPatternLength - 1 : 0;
        auto memoryRead = GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead");
        if (memoryRead == nullptr)
        {
            result.readFailure = true;
            return result;
        }
        std::size_t remainingBudget = maxScanBytes;
        std::vector<unsigned char> carry;
        carry.reserve(carryLimit);
        std::vector<unsigned char> combined;
        combined.reserve(kMaxMemoryReadBytes + carryLimit);

        for (std::size_t moduleIndex = 0; moduleIndex < modules.size() && remainingBudget > 0; ++moduleIndex)
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

                for (const auto& pattern : patterns)
                {
                    if (pattern.bytes.empty() || pattern.bytes.size() > combined.size())
                        continue;

                    const auto lastStart = combined.end() -
                        static_cast<std::ptrdiff_t>(pattern.bytes.size()) + 1;
                    auto candidate = combined.begin();
                    while (candidate != lastStart)
                    {
                        candidate = std::find(candidate, lastStart, pattern.bytes.front());
                        if (candidate == lastStart)
                            break;

                        const auto offset = static_cast<std::size_t>(candidate - combined.begin());

                        if (!std::equal(pattern.bytes.begin(), pattern.bytes.end(), combined.begin() +
                                static_cast<std::ptrdiff_t>(offset)))
                        {
                            ++candidate;
                            continue;
                        }

                        const std::size_t globalOffset = combinedBaseOffset + offset;
                        if (globalOffset + pattern.bytes.size() <= moduleOffset)
                        {
                            ++candidate;
                            continue;
                        }

                        std::uintptr_t matchAddress = 0;
                        if (!TryAddAddress(module.base, globalOffset, matchAddress))
                        {
                            result.addressOverflow = true;
                            break;
                        }

                        result.matches.push_back(StringSearchMatch
                        {
                            matchAddress,
                            module.name,
                            pattern.encoding,
                            pattern.bytes.size(),
                            pattern.preview,
                        });
                        if (result.matches.size() >= maxResults)
                        {
                            result.scannedBytes += dataSize;
                            result.resultLimitReached = true;
                            return result;
                        }

                        ++candidate;
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
            }

            if (moduleOffset < scanLimit)
                result.scanTruncated = true;
            remainingBudget -= std::min(remainingBudget, moduleOffset);
            if (moduleIndex + 1 < modules.size() && remainingBudget == 0)
                result.scanTruncated = true;
        }

        return result;
    }

}
