#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeInterestingStringSearch.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeRequestParams.h"
#include "NativeSearchHandlers.h"
#include "NativeStringSearch.h"
#include "NativeStringSearchHandlers.h"

namespace dbglink
{
    const std::vector<InterestingSearchPattern>& BuiltInInterestingSearchPatterns()
    {
        static const std::vector<InterestingSearchPattern> patterns = []
        {
            std::vector<InterestingSearchPattern> result;
            result.reserve(kMaxInterestingNeedles * 2);
            for (std::size_t index = 0; index < kMaxInterestingNeedles; ++index)
            {
                const std::string needle = kInterestingNeedles[index];
                const std::string preview = SingleLine(needle);
                result.push_back(InterestingSearchPattern
                {
                    needle,
                    index,
                    SearchPattern{ "ascii", AsciiSearchBytes(needle), preview },
                });

                auto unicodeBytes = Utf8SearchBytes(needle);
                if (unicodeBytes.empty())
                    return std::vector<InterestingSearchPattern>{};
                result.push_back(InterestingSearchPattern
                {
                    needle,
                    index,
                    SearchPattern{ "utf-16le", std::move(unicodeBytes), preview },
                });
            }
            return result;
        }();
        return patterns;
    }

    std::string HandleFindStringInModule(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string text;
        if (auto error = params.RequiredSearchText("text", text,
                "FindStringInModule text must be non-empty, printable, and at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::string module;
        if (auto error = params.OptionalModuleFilter("module", module,
                "FindStringInModule module must be a string.",
                "FindStringInModule module must be at most 256 printable bytes."); !error.empty())
            return ErrorResponse(id, error);

        bool ascii = true;
        if (auto error = params.OptionalBoolean("ascii", ascii, "FindStringInModule ascii must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        bool unicode = true;
        if (auto error = params.OptionalBoolean("unicode", unicode, "FindStringInModule unicode must be a boolean."); !error.empty())
            return ErrorResponse(id, error);
        if (!ascii && !unicode)
            return ErrorResponse(id, "FindStringInModule enables at least one encoding.");

        std::uint64_t maxResults = 100;
        if (auto error = params.BoundedUnsigned("maxResults", maxResults, 1, kMaxSearchResults,
                "FindStringInModule maxResults must be between 1 and 512."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxScanBytes = kDefaultSearchScanBytes;
        if (auto error = params.BoundedUnsigned("maxScanBytes", maxScanBytes, 4096, kMaxSearchScanBytes,
                "FindStringInModule maxScanBytes must be between 4096 and 67108864."); !error.empty())
            return ErrorResponse(id, error);

        std::vector<SearchPattern> patterns;
        if (ascii)
        {
            auto bytes = AsciiSearchBytes(text);
            if (!bytes.empty())
                patterns.push_back(SearchPattern{ "ascii", std::move(bytes), SingleLine(text) });
        }
        if (unicode)
        {
            auto bytes = Utf8SearchBytes(text);
            if (bytes.empty())
                return ErrorResponse(id, "FindStringInModule text is not valid UTF-8 for UTF-16 search.");
            patterns.push_back(SearchPattern{ "utf-16le", std::move(bytes), SingleLine(text) });
        }
        if (patterns.empty())
            return ErrorResponse(id, "FindStringInModule text cannot be searched with the selected encoding.");

        std::vector<ModuleRecord> modules;
        bool mapTruncated = false;
        std::string error;
        if (!CollectModuleRecords(modules, mapTruncated, error))
            return ErrorResponse(id, "FindStringInModule: " + error);

        const auto selectedModules = SelectModulesByFilter(std::move(modules), module, false);
        auto search = ScanStringPatterns(
            selectedModules,
            patterns,
            static_cast<std::size_t>(maxResults),
            static_cast<std::size_t>(maxScanBytes));
        search.moduleMapTruncated = mapTruncated;
        return TextResponse(id, "FindStringInModule", FormatStringSearch(text, module, search));
    }

    std::string HandleFindInterestingStrings(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string module;
        if (auto error = params.OptionalModuleFilter("module", module,
                "FindInterestingStrings module must be a string.",
                "FindInterestingStrings module must be at most 256 printable bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxResultsPerNeedle = 16;
        if (auto error = params.BoundedUnsigned("maxResultsPerNeedle", maxResultsPerNeedle, 1,
                kMaxInterestingResultsPerNeedle,
                "FindInterestingStrings maxResultsPerNeedle must be between 1 and 32."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxScanBytes = kDefaultSearchScanBytes;
        if (auto error = params.BoundedUnsigned("maxScanBytes", maxScanBytes, 4096, kMaxSearchScanBytes,
                "FindInterestingStrings maxScanBytes must be between 4096 and 67108864."); !error.empty())
            return ErrorResponse(id, error);

        const auto& patterns = BuiltInInterestingSearchPatterns();
        if (patterns.empty())
            return ErrorResponse(id, "FindInterestingStrings failed to encode a built-in needle.");

        std::vector<ModuleRecord> modules;
        bool mapTruncated = false;
        std::string error;
        if (!CollectModuleRecords(modules, mapTruncated, error))
            return ErrorResponse(id, "FindInterestingStrings: " + error);

        const auto selectedModules = SelectModulesByFilter(std::move(modules), module, false);
        auto search = ScanInterestingStrings(
            selectedModules,
            patterns,
            static_cast<std::size_t>(maxResultsPerNeedle),
            static_cast<std::size_t>(maxScanBytes));
        search.moduleMapTruncated = mapTruncated;
        return TextResponse(id, "FindInterestingStrings", FormatInterestingStringSearch(module, search));
    }

}
