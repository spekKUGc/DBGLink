#include "NativeTypes.h"
#include "NativeBoundedText.h"
#include "NativeBridgeFoundation.h"
#include "NativeBytePatternSearch.h"
#include "NativeDebuggerQueries.h"
#include "NativeDisassemblyQueries.h"
#include "NativeHexFormat.h"
#include "NativeInputValidation.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeRequestParams.h"
#include "NativeSearchHandlers.h"

namespace dbglink
{
    namespace
    {
        constexpr std::size_t kMaxReadRanges = 8;
        constexpr std::size_t kMaxRangeBytes = 4096;
        constexpr std::size_t kMaxRangesTotalBytes = 16384;
        constexpr std::uint64_t kDefaultRangeByteCount = 128;

        bool ParseRangeByteCount(const nlohmann::ordered_json& entry, std::uint64_t& out)
        {
            auto found = entry.find("byteCount");
            if (found == entry.end())
            {
                out = kDefaultRangeByteCount;
                return true;
            }
            if (found->is_number_unsigned())
            {
                out = found->get<std::uint64_t>();
                return true;
            }
            if (found->is_string())
                return ParseUnsignedText(found->get<std::string>(), out);
            return false;
        }
    }

    std::string HandleReadMemoryRanges(const std::string& request, const std::string& id)
    {
        // The request was already parsed and validated by BeginJsonRequestParse
        // (HandleRequest before dispatch); reuse the cached document instead
        // of parsing the bytes a second time.
        const auto* document = CachedRequestDocument(request);
        const nlohmann::ordered_json* ranges = nullptr;
        if (document != nullptr && document->is_object())
        {
            const auto paramsIt = document->find("params");
            if (paramsIt != document->end() && paramsIt->is_object())
            {
                const auto rangesIt = paramsIt->find("ranges");
                if (rangesIt != paramsIt->end() && rangesIt->is_array())
                    ranges = &*rangesIt;
            }
        }
        if (ranges == nullptr)
            return ErrorResponse(id, "ReadMemAtAddress ranges must be an array of 1 to 8 entries.");

        if (ranges->empty() || ranges->size() > kMaxReadRanges)
            return ErrorResponse(id, "ReadMemAtAddress ranges must contain 1 to 8 entries.");

        // Token-light dump opt-ins (default off); read once for all ranges.
        const RequestParams dumpParams(request);
        bool includeAscii = false;
        if (auto error = dumpParams.OptionalBoolean("includeAscii", includeAscii,
                "ReadMemAtAddress includeAscii must be a boolean."); !error.empty())
            return ErrorResponse(id, error);
        bool spacedHex = false;
        if (auto error = dumpParams.OptionalBoolean("spacedHex", spacedHex,
                "ReadMemAtAddress spacedHex must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        struct RangeRequest
        {
            std::string addressText;
            std::uint64_t byteCount = kDefaultRangeByteCount;
            std::string validationError;
        };
        std::vector<RangeRequest> parsed;
        parsed.reserve(ranges->size());
        std::uint64_t totalBytes = 0;
        for (std::size_t index = 0; index < ranges->size(); ++index)
        {
            RangeRequest item;
            const auto& entry = (*ranges)[index];
            const std::string tag = "ReadMemAtAddress ranges[" + std::to_string(index) + "]";
            if (!entry.is_object())
            {
                item.validationError = tag + " must be an object with address and optional byteCount.";
                parsed.push_back(std::move(item));
                continue;
            }
            auto addressIt = entry.find("address");
            if (addressIt == entry.end() || !addressIt->is_string() ||
                !IsSearchTextValid(addressIt->get<std::string>()))
            {
                item.validationError = tag +
                    ".address must be a non-empty printable expression of at most 256 bytes.";
                // Still try to account byteCount for the total cap.
                std::uint64_t size = 0;
                if (ParseRangeByteCount(entry, size) && size >= 1 && size <= kMaxRangeBytes)
                    totalBytes += size;
                parsed.push_back(std::move(item));
                continue;
            }
            item.addressText = addressIt->get<std::string>();
            std::uint64_t size = kDefaultRangeByteCount;
            if (!ParseRangeByteCount(entry, size) || size < 1 || size > kMaxRangeBytes)
            {
                item.validationError = tag + ".byteCount must be between 1 and 4096.";
                parsed.push_back(std::move(item));
                continue;
            }
            item.byteCount = size;
            totalBytes += size;
            parsed.push_back(std::move(item));
        }
        if (totalBytes > kMaxRangesTotalBytes)
            return ErrorResponse(id,
                "ReadMemAtAddress total byteCount across ranges must not exceed 16384.");

        std::string body = "[ReadMemAtAddress] ranges=" + std::to_string(parsed.size()) + "\n";
        for (std::size_t index = 0; index < parsed.size(); ++index)
        {
            const auto& item = parsed[index];
            const std::string prefix = "[" + std::to_string(index) + "] ";
            if (!item.validationError.empty())
            {
                body += prefix + "error=" + item.validationError + "\n";
                continue;
            }
            std::uintptr_t address = 0;
            if (auto error = ResolveAddressExpression(item.addressText, address); !error.empty())
            {
                body += prefix + "error=" + error + "\n";
                continue;
            }
            std::vector<unsigned char> data;
            if (!ReadMemory(address, static_cast<std::size_t>(item.byteCount), data))
            {
                body += prefix + "error=Failed to read memory at " + HexAddress(address) + "\n";
                continue;
            }
            body += prefix + "address=" + HexAddress(address) +
                " byteCount=" + std::to_string(data.size()) + "\n";
            body += FormatHexDump(address, data, includeAscii, spacedHex);
            body.push_back('\n');
        }
        if (!body.empty() && body.back() == '\n')
            body.pop_back();
        return TextResponse(id, "ReadMemAtAddress", body);
    }

    std::string HandleReadMemory(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        if (params.Has("ranges") && params.Has("address"))
            return ErrorResponse(id, "ReadMemAtAddress takes either address or ranges, not both.");
        if (params.Has("ranges"))
            return HandleReadMemoryRanges(request, id);
        std::string expression;
        if (auto error = params.RequiredSearchText("address", expression,
                "ReadMemAtAddress address must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t requestedSize = 128;
        if (auto error = params.BoundedUnsigned("byteCount", requestedSize, 1, kMaxMemoryReadBytes,
                "ReadMemAtAddress byteCount must be between 1 and 65536."); !error.empty())
            return ErrorResponse(id, error);

        bool includeAscii = false;
        if (auto error = params.OptionalBoolean("includeAscii", includeAscii,
                "ReadMemAtAddress includeAscii must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        bool spacedHex = false;
        if (auto error = params.OptionalBoolean("spacedHex", spacedHex,
                "ReadMemAtAddress spacedHex must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        std::uintptr_t address = 0;
        if (auto error = ResolveAddressExpression(expression, address); !error.empty())
            return ErrorResponse(id, error);

        std::vector<unsigned char> data;
        if (!ReadMemory(address, static_cast<std::size_t>(requestedSize), data))
            return ErrorResponse(id, "Failed to read memory at " + HexAddress(address));

        return TextResponse(id, "ReadMemAtAddress", FormatHexDump(address, data, includeAscii, spacedHex));
    }

    std::string HandleDisassembly(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string expression;
        if (auto error = params.RequiredSearchText("address", expression,
                "ReadDismAtAddress address must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t requestedBytes = 128;
        if (auto error = params.BoundedUnsigned("byteCount", requestedBytes, 1, kMaxMemoryReadBytes,
                "ReadDismAtAddress byteCount must be between 1 and 65536."); !error.empty())
            return ErrorResponse(id, error);

        std::uintptr_t address = 0;
        if (auto error = ResolveAddressExpression(expression, address); !error.empty())
            return ErrorResponse(id, error);

        return TextResponse(id, "ReadDismAtAddress", ReadDisassembly(address, static_cast<std::size_t>(requestedBytes)));
    }

    std::string FormatBytePatternSearch(
        const std::string& pattern,
        const std::string& module,
        const ByteSearchResult& search)
    {
        BoundedText body(kMaxSearchOutputChars, BoundedText::OverflowPolicy::Report);

        if (search.matches.empty())
        {
            body.Assign("[FindBytePatternInModule] No matches for \"" + SingleLine(pattern) +
                "\" in module=\"" + SingleLine(module) + "\" scannedBytes=" +
                std::to_string(search.scannedBytes));
        }
        else
        {
            body.Append("[FindBytePatternInModule] matches=" + std::to_string(search.matches.size()) +
                " pattern=\"" + SingleLine(pattern) + "\" module=\"" + SingleLine(module) +
                "\" scannedBytes=" + std::to_string(search.scannedBytes) + "\n");
            for (std::size_t index = 0; index < search.matches.size(); ++index)
            {
                const auto& match = search.matches[index];
                const std::string line = "[" + std::to_string(index) + "] address=" +
                    HexAddress(match.address) + " module=" + SingleLine(match.module) + "\n";
                if (!body.Append(line))
                {
                    body.Append("outputTruncated=true\n");
                    break;
                }
            }
            body.PopTrailingNewline();
        }

        body.AppendFlag("scanTruncated", search.scanTruncated);
        body.AppendFlag("readFailure", search.readFailure);
        body.AppendFlag("addressOverflow", search.addressOverflow);
        body.AppendFlag("resultLimitReached", search.resultLimitReached);
        body.AppendFlag("moduleMapTruncated", search.moduleMapTruncated);
        return body.Body();
    }

    std::string HandleFindBytePatternInModule(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string patternText;
        if (auto error = params.RequiredString("pattern", patternText,
                "FindBytePatternInModule pattern is required."); !error.empty())
            return ErrorResponse(id, error);

        MaskedBytePattern pattern;
        std::string parseError;
        if (!ParseMaskedBytePattern(patternText, pattern, parseError))
            return ErrorResponse(id, "FindBytePatternInModule " + parseError + ".");

        std::string module;
        if (auto error = params.OptionalModuleFilter("module", module,
                "FindBytePatternInModule module must be a string.",
                "FindBytePatternInModule module must be at most 256 printable bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxResults = 100;
        if (auto error = params.BoundedUnsigned("maxResults", maxResults, 1, kMaxSearchResults,
                "FindBytePatternInModule maxResults must be between 1 and 512."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxScanBytes = kDefaultSearchScanBytes;
        if (auto error = params.BoundedUnsigned("maxScanBytes", maxScanBytes, 4096, kMaxSearchScanBytes,
                "FindBytePatternInModule maxScanBytes must be between 4096 and 67108864."); !error.empty())
            return ErrorResponse(id, error);

        std::vector<ModuleRecord> modules;
        bool mapTruncated = false;
        std::string error;
        if (!CollectModuleRecords(modules, mapTruncated, error))
            return ErrorResponse(id, "FindBytePatternInModule: " + error);

        const auto selectedModules = SelectModulesByFilter(std::move(modules), module, false);
        auto search = ScanMaskedBytePattern(
            selectedModules,
            pattern,
            static_cast<std::size_t>(maxResults),
            static_cast<std::size_t>(maxScanBytes));
        search.moduleMapTruncated = mapTruncated;
        return TextResponse(id, "FindBytePatternInModule", FormatBytePatternSearch(patternText, module, search));
    }

    std::string FormatStringSearch(
        const std::string& text,
        const std::string& module,
        const StringSearchResult& search)
    {
        BoundedText body(kMaxSearchOutputChars, BoundedText::OverflowPolicy::Report);

        if (search.matches.empty())
        {
            body.Assign("[FindStringInModule] No matches for \"" + SingleLine(text) +
                "\" in module=\"" + SingleLine(module) + "\" scannedBytes=" +
                std::to_string(search.scannedBytes));
        }
        else
        {
            body.Append("[FindStringInModule] matches=" + std::to_string(search.matches.size()) +
                " text=\"" + SingleLine(text) + "\" module=\"" + SingleLine(module) +
                "\" scannedBytes=" + std::to_string(search.scannedBytes) + "\n");
            for (std::size_t index = 0; index < search.matches.size(); ++index)
            {
                const auto& match = search.matches[index];
                const std::string line = "[" + std::to_string(index) + "] address=" +
                    HexAddress(match.address) + " module=" + SingleLine(match.module) +
                    " encoding=" + match.encoding + " length=" + std::to_string(match.length) +
                    " text=\"" + SingleLine(match.preview) + "\"\n";
                if (!body.Append(line))
                {
                    body.Append("outputTruncated=true\n");
                    break;
                }
            }
            body.PopTrailingNewline();
        }

        body.AppendFlag("scanTruncated", search.scanTruncated);
        body.AppendFlag("readFailure", search.readFailure);
        body.AppendFlag("addressOverflow", search.addressOverflow);
        body.AppendFlag("resultLimitReached", search.resultLimitReached);
        body.AppendFlag("moduleMapTruncated", search.moduleMapTruncated);
        return body.Body();
    }

    std::string FormatInterestingStringSearch(
        const std::string& module,
        const InterestingStringResult& search)
    {
        BoundedText body(kMaxSearchOutputChars, BoundedText::OverflowPolicy::Latch);
        body.Assign("[FindInterestingStrings] matches=" + std::to_string(search.matches.size()) +
            " module=\"" + SingleLine(module) + "\" scannedBytes=" +
            std::to_string(search.scannedBytes) + " needles=" +
            std::to_string(kMaxInterestingNeedles));

        for (const char* needle : kInterestingNeedles)
        {
            std::size_t matchCount = 0;
            for (const auto& match : search.matches)
            {
                if (match.needle == needle)
                    ++matchCount;
            }
            if (matchCount == 0)
                continue;

            body.Append("\n[needle=\"" + std::string(needle) + "\"] matches=" +
                std::to_string(matchCount) + "\n");
            std::size_t index = 0;
            for (const auto& match : search.matches)
            {
                if (match.needle != needle)
                    continue;

                body.Append("[" + std::to_string(index++) + "] address=" +
                    HexAddress(match.address) + " module=" + SingleLine(match.module) +
                    " encoding=" + match.encoding + " text=\"" +
                    SingleLine(match.preview) + "\"\n");
            }
        }

        body.AppendFlag("scanTruncated", search.scanTruncated);
        body.AppendFlag("readFailure", search.readFailure);
        body.AppendFlag("addressOverflow", search.addressOverflow);
        body.AppendFlag("resultLimitReached", search.resultLimitReached);
        body.AppendFlag("moduleMapTruncated", search.moduleMapTruncated);
        body.AppendMarker("\noutputTruncated=true", 21);
        body.PopTrailingNewline();
        return body.Body();
    }

}
