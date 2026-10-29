#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeBytePatternSearch.h"
#include "NativeInputValidation.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"

namespace dbglink
{
    namespace
    {
        bool TryHexDigit(char c, std::uint16_t& value)
        {
            if (c >= '0' && c <= '9') value = c - '0';
            else if (c >= 'a' && c <= 'f') value = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') value = c - 'A' + 10;
            else return false;
            return true;
        }
    }
    bool ParseMaskedBytePattern(
        const std::string& pattern,
        MaskedBytePattern& parsed,
        std::string& error)
    {
        parsed = {};
        if (!IsBytePatternTextValid(pattern))
        {
            error = "pattern must be printable, non-empty, and at most 1024 bytes";
            return false;
        }

        std::vector<std::string> tokens;
        std::string token;
        auto flushToken = [&]()
        {
            if (!token.empty())
            {
                tokens.push_back(token);
                token.clear();
            }
        };

        for (const unsigned char character : pattern)
        {
            if (character == ' ' || character == '\t' || character == ',' || character == '-')
                flushToken();
            else
                token.push_back(static_cast<char>(character));
        }
        flushToken();

        if (tokens.empty() || tokens.size() > kMaxBytePatternTokens)
        {
            error = "pattern must contain between 1 and 256 byte tokens";
            return false;
        }

        bool hasExactByte = false;
        parsed.bytes.reserve(tokens.size());
        parsed.exact.reserve(tokens.size());
        for (const auto& rawToken : tokens)
        {
            if (rawToken == "?" || rawToken == "??")
            {
                parsed.bytes.push_back(0);
                parsed.exact.push_back(0);
                continue;
            }

            std::string value = rawToken;
            if (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X'))
                value.erase(0, 2);
            if (value.size() != 2)
            {
                error = "pattern tokens must be two hex digits or ??";
                return false;
            }

            std::uint16_t high = 0;
            std::uint16_t low = 0;
            if (!TryHexDigit(value[0], high) || !TryHexDigit(value[1], low))
            {
                error = "pattern tokens must be two hex digits or ??";
                return false;
            }

            parsed.bytes.push_back(static_cast<unsigned char>((high << 4) | low));
            parsed.exact.push_back(1);
            hasExactByte = true;
        }

        if (!hasExactByte)
        {
            error = "pattern must contain at least one exact byte";
            return false;
        }
        return true;
    }

    ByteSearchResult ScanMaskedBytePattern(
        const std::vector<ModuleRecord>& modules,
        const MaskedBytePattern& pattern,
        std::size_t maxResults,
        std::size_t maxScanBytes)
    {
        ByteSearchResult result;
        if (pattern.bytes.empty() || pattern.bytes.size() != pattern.exact.size() ||
            modules.empty() || maxResults == 0 || maxScanBytes == 0)
            return result;

        result.matches.reserve(std::min(maxResults, kMaxSearchResults));

        const std::size_t carryLimit = pattern.bytes.size() - 1;
        const auto exactAnchor = std::find(pattern.exact.begin(), pattern.exact.end(), 1);
        const std::size_t anchorIndex = exactAnchor == pattern.exact.end()
            ? pattern.exact.size()
            : static_cast<std::size_t>(std::distance(pattern.exact.begin(), exactAnchor));
        if (anchorIndex >= pattern.bytes.size())
            return result;

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
                const std::size_t requested = std::min<std::size_t>(
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
                combined.resize(carrySize + requested);
                if (!ReadMemory(chunkAddress, requested, combined.data() + carrySize, memoryRead))
                {
                    result.readFailure = true;
                    carry.clear();
                    moduleOffset += requested;
                    result.scannedBytes += requested;
                    continue;
                }

                const std::size_t dataSize = combined.size() - carrySize;
                const std::size_t combinedBaseOffset = moduleOffset >= carrySize
                    ? moduleOffset - carrySize
                    : 0;
                if (combined.size() >= pattern.bytes.size())
                {
                    const auto lastStart = combined.end() -
                        static_cast<std::ptrdiff_t>(pattern.bytes.size()) + 1;
                    const auto firstAnchor = combined.begin() +
                        static_cast<std::ptrdiff_t>(anchorIndex);
                    const auto lastAnchor = lastStart +
                        static_cast<std::ptrdiff_t>(anchorIndex);
                    auto candidate = firstAnchor;
                    while (candidate != lastAnchor)
                    {
                        candidate = std::find(candidate, lastAnchor, pattern.bytes[anchorIndex]);
                        if (candidate == lastAnchor)
                            break;

                        const std::size_t offset = static_cast<std::size_t>(candidate - combined.begin()) -
                            anchorIndex;

                        bool matches = true;
                        for (std::size_t index = 0; index < pattern.bytes.size(); ++index)
                        {
                            if (pattern.exact[index] != 0 &&
                                combined[offset + index] != pattern.bytes[index])
                            {
                                matches = false;
                                break;
                            }
                        }
                        if (!matches)
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

                        result.matches.push_back(ByteSearchMatch{ matchAddress, module.name });
                        if (result.matches.size() >= maxResults)
                        {
                            result.scannedBytes += dataSize;
                            result.resultLimitReached = true;
                            return result;
                        }

                        ++candidate;
                    }
                }

                if (result.addressOverflow)
                    break;

                const std::size_t nextCarrySize = std::min(carryLimit, dataSize);
                carry.assign(combined.end() - static_cast<std::ptrdiff_t>(nextCarrySize), combined.end());
                moduleOffset += dataSize;
                result.scannedBytes += dataSize;
                if (dataSize < requested)
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
        }

        return result;
    }

}
