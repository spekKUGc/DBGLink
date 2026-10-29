#include "NativeTypes.h"
#include "NativeBoundedText.h"
#include "NativeBridgeFoundation.h"
#include "NativeDebuggerQueries.h"
#include "NativeDisassemblyQueries.h"
#include "NativeInspectionHandlers.h"
#include "NativeInterestingStringSearch.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeRequestParams.h"
#include "NativeStringReferenceTrace.h"
#include "NativeStringSearch.h"
#include "NativeXrefSearch.h"

namespace dbglink
{
    std::string HandleTraceStringReferences(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string text;
        if (auto error = params.RequiredSearchText("text", text,
                "TraceStringReferences text must be non-empty, printable, and at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::string module;
        if (auto error = params.OptionalModuleFilter("module", module,
                "TraceStringReferences module must be a string.",
                "TraceStringReferences module must be at most 256 printable bytes."); !error.empty())
            return ErrorResponse(id, error);

        bool ascii = true;
        if (auto error = params.OptionalBoolean("ascii", ascii, "TraceStringReferences ascii must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        bool unicode = true;
        if (auto error = params.OptionalBoolean("unicode", unicode, "TraceStringReferences unicode must be a boolean."); !error.empty())
            return ErrorResponse(id, error);
        if (!ascii && !unicode)
            return ErrorResponse(id, "TraceStringReferences enables at least one encoding.");

        std::uint64_t maxStringMatches = 16;
        if (auto error = params.BoundedUnsigned("maxStringMatches", maxStringMatches, 1,
                kMaxTraceStringMatches,
                "TraceStringReferences maxStringMatches must be between 1 and 64."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxXrefsPerMatch = 16;
        if (auto error = params.BoundedUnsigned("maxXrefsPerMatch", maxXrefsPerMatch, 1,
                kMaxTraceXrefsPerMatch,
                "TraceStringReferences maxXrefsPerMatch must be between 1 and 64."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t inspectBytes = 64;
        if (auto error = params.BoundedUnsigned("inspectBytes", inspectBytes, 0, kMaxTraceInspectBytes,
                "TraceStringReferences inspectBytes must be between 0 and 256."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxScanBytes = kDefaultSearchScanBytes;
        if (auto error = params.BoundedUnsigned("maxScanBytes", maxScanBytes, 4096, kMaxSearchScanBytes,
                "TraceStringReferences maxScanBytes must be between 4096 and 67108864."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxXrefScanBytes = kDefaultTraceXrefScanBytes;
        if (auto error = params.BoundedUnsigned("maxXrefScanBytes", maxXrefScanBytes, 4096, kMaxSearchScanBytes,
                "TraceStringReferences maxXrefScanBytes must be between 4096 and 67108864."); !error.empty())
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
                return ErrorResponse(id, "TraceStringReferences text is not valid UTF-8 for UTF-16 search.");
            patterns.push_back(SearchPattern{ "utf-16le", std::move(bytes), SingleLine(text) });
        }
        if (patterns.empty())
            return ErrorResponse(id, "TraceStringReferences text cannot be searched with the selected encoding.");

        std::vector<ModuleRecord> modules;
        bool mapTruncated = false;
        std::string error;
        if (!CollectModuleRecords(modules, mapTruncated, error))
            return ErrorResponse(id, "TraceStringReferences: " + error);

        const auto selectedModules = SelectModulesByFilter(std::move(modules), module, false);
        auto stringSearch = ScanStringPatterns(
            selectedModules,
            patterns,
            static_cast<std::size_t>(maxStringMatches),
            static_cast<std::size_t>(maxScanBytes));
        stringSearch.moduleMapTruncated = mapTruncated;

        bool evidenceLimitReached = false;
        bool xrefScanBudgetExhausted = false;
        std::size_t remainingXrefScanBytes = static_cast<std::size_t>(maxXrefScanBytes);
        std::size_t totalEvidenceItems = 0;
        const std::size_t outputLimit = kMaxSearchOutputChars - 40;
        BoundedText body(outputLimit, BoundedText::OverflowPolicy::Latch);
        body.Assign("[TraceStringReferences] text=\"" + JsonEscape(SingleLine(text)) +
            "\" module=\"" + JsonEscape(SingleLine(module)) + "\" matches=" +
            std::to_string(stringSearch.matches.size()) + " scannedBytes=" +
            std::to_string(stringSearch.scannedBytes) + " maxXrefScanBytes=" +
            std::to_string(maxXrefScanBytes));

        const bool filterDatabase = !module.empty() && !EqualsInsensitive(module, "all");
        for (std::size_t stringIndex = 0;
             stringIndex < stringSearch.matches.size() && !body.Truncated();
             ++stringIndex)
        {
            const auto& match = stringSearch.matches[stringIndex];
            body.AppendLine("[String " + std::to_string(stringIndex) + "] address=" +
                HexAddress(match.address) + " module=" + SingleLine(match.module) +
                " encoding=" + match.encoding + " length=" + std::to_string(match.length) +
                " text=\"" + JsonEscape(SingleLine(match.preview)) + "\"");

            const std::size_t remainingEvidence = kMaxTraceEvidenceItems > totalEvidenceItems
                ? kMaxTraceEvidenceItems - totalEvidenceItems
                : 0;
            if (remainingEvidence == 0)
            {
                evidenceLimitReached = true;
                body.AppendLine("[String " + std::to_string(stringIndex) +
                    " Xrefs] skipped=evidence-limit");
                continue;
            }

            const std::size_t xrefLimit = std::min<std::size_t>(
                static_cast<std::size_t>(maxXrefsPerMatch), remainingEvidence);
            const bool allowFallback = remainingXrefScanBytes >= 4096;
            const auto xrefs = ScanXrefs(
                match.address,
                selectedModules,
                filterDatabase,
                allowFallback,
                xrefLimit,
                remainingXrefScanBytes);
            totalEvidenceItems += xrefs.matches.size();
            if (xrefs.scanFallbackUsed)
                remainingXrefScanBytes -= std::min(remainingXrefScanBytes, xrefs.scannedBytes);
            if (!allowFallback)
                xrefScanBudgetExhausted = true;

            body.AppendLine("[String " + std::to_string(stringIndex) + " Xrefs] total=" +
                std::to_string(xrefs.matches.size()) + " reportedCount=" +
                std::to_string(xrefs.reportedCount) + " scannedBytes=" +
                std::to_string(xrefs.scannedBytes));
            for (std::size_t xrefIndex = 0; xrefIndex < xrefs.matches.size(); ++xrefIndex)
            {
                const auto& xref = xrefs.matches[xrefIndex];
                body.AppendLine("[String " + std::to_string(stringIndex) + " Xref " +
                    std::to_string(xrefIndex) + "] from=" + HexAddress(xref.address) +
                    " type=" + XrefTypeText(xref.type) + " source=" +
                    SingleLine(xref.source) + " instruction=\"" +
                    JsonEscape(SingleLine(xref.instruction)) + "\"");
                if (inspectBytes > 0)
                {
                    body.AppendLine("[String " + std::to_string(stringIndex) + " Xref " +
                        std::to_string(xrefIndex) + " Address] " + GetAddressInfoLine(xref.address));
                    if (AddressRangeFits(xref.address, static_cast<std::size_t>(inspectBytes)))
                    {
                        body.AppendLine("[String " + std::to_string(stringIndex) + " Xref " +
                            std::to_string(xrefIndex) + " Disassembly]");
                        body.Append(ReadDisassembly(xref.address, static_cast<std::size_t>(inspectBytes)));
                    }
                    else
                    {
                        body.AppendLine("[String " + std::to_string(stringIndex) + " Xref " +
                            std::to_string(xrefIndex) + " Disassembly] addressOverflow=true");
                    }
                }
            }

            body.AppendFlag("xrefDbAvailable", xrefs.xrefDbAvailable);
            body.AppendFlag("xrefDbMalformed", xrefs.xrefDbMalformed);
            body.AppendFlag("xrefDbTruncated", xrefs.xrefDbTruncated);
            body.AppendFlag("scanFallbackUsed", xrefs.scanFallbackUsed);
            body.AppendFlag("scanFallbackUnavailable", xrefs.scanFallbackUnavailable);
            body.AppendFlag("scanTruncated", xrefs.scanTruncated);
            body.AppendFlag("addressOverflow", xrefs.addressOverflow);
        }

        body.AppendFlag("scanTruncated", stringSearch.scanTruncated);
        body.AppendFlag("readFailure", stringSearch.readFailure);
        body.AppendFlag("addressOverflow", stringSearch.addressOverflow);
        body.AppendFlag("resultLimitReached", stringSearch.resultLimitReached);
        body.AppendFlag("moduleMapTruncated", stringSearch.moduleMapTruncated);
        body.AppendFlag("evidenceLimitReached", evidenceLimitReached);
        body.AppendFlag("xrefScanBudgetExhausted", xrefScanBudgetExhausted);
        body.AppendLine("xrefScanBytesUsed=" + std::to_string(
            static_cast<std::size_t>(maxXrefScanBytes) - remainingXrefScanBytes));
        body.AppendMarker("\noutputTruncated=true");
        return TextResponse(id, "TraceStringReferences", body.Body());
    }

}
