#include "NativeTypes.h"
#include "NativeBoundedText.h"
#include "NativeBridgeFoundation.h"
#include "NativeInterestingStringSearch.h"
#include "NativeJsonFormatting.h"
#include "NativeXrefHandlers.h"

namespace dbglink
{
    std::string FormatXrefSearch(
        const std::string& targetText,
        std::uintptr_t target,
        std::size_t start,
        std::size_t count,
        const XrefSearchResult& search)
    {
        BoundedText body(kMaxSearchOutputChars, BoundedText::OverflowPolicy::Latch);
        body.Assign("[GetXrefs] target=" + HexAddress(target) +
            " expression=\"" + SingleLine(targetText) + "\" total=" +
            std::to_string(search.matches.size()) + " reportedCount=" +
            std::to_string(search.reportedCount) + " scannedBytes=" +
            std::to_string(search.scannedBytes));

        const std::size_t safeStart = std::min(start, search.matches.size());
        const std::size_t safeEnd = std::min(search.matches.size(), safeStart + count);
        if (safeStart < safeEnd)
        {
            body.Append(" rows=" + std::to_string(safeStart) + "-" +
                std::to_string(safeEnd - 1) + "\n");
            for (std::size_t index = safeStart; index < safeEnd; ++index)
            {
                const auto& match = search.matches[index];
                body.Append("[" + std::to_string(index) + "] from=" +
                    HexAddress(match.address) + " type=" + XrefTypeText(match.type) +
                    " source=" + SingleLine(match.source) + " instruction=\"" +
                    SingleLine(match.instruction) + "\"\n");
            }
        }
        else
        {
            body.Append(" rows=none\n");
        }

        body.Append(std::string("xrefDbAvailable=") + (search.xrefDbAvailable ? "true" : "false"));
        body.AppendFlag("xrefDbMalformed", search.xrefDbMalformed);
        body.AppendFlag("xrefDbTruncated", search.xrefDbTruncated);
        body.AppendFlag("scanFallbackUsed", search.scanFallbackUsed);
        body.AppendFlag("scanFallbackUnavailable", search.scanFallbackUnavailable);
        body.AppendFlag("scanTruncated", search.scanTruncated);
        body.AppendFlag("addressOverflow", search.addressOverflow);
        body.AppendFlag("moduleMapTruncated", search.moduleMapTruncated);
        body.AppendMarker("\noutputTruncated=true", 21);
        body.PopTrailingNewline();
        return body.Body();
    }

}
