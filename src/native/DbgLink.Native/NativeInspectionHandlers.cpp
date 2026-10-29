#include "NativeTypes.h"
#include "NativeAnalysisData.h"
#include "NativeBoundedText.h"
#include "NativeBridgeFoundation.h"
#include "NativeDebuggerQueries.h"
#include "NativeInspectionHandlers.h"
#include "NativeInterestingStringSearch.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeRequestParams.h"
#include "NativeXrefSearch.h"

namespace dbglink
{
    bool TryDecodePrintableAscii(const std::vector<unsigned char>& data, std::string& value)
    {
        value.clear();
        if (data.empty())
            return false;

        std::size_t end = 0;
        for (; end < data.size() && data[end] != 0; ++end)
        {
            if (data[end] < 0x20 || data[end] >= 0x7F)
                return false;
        }

        if (end == 0 || end >= data.size())
            return false;

        value.assign(reinterpret_cast<const char*>(data.data()), end);
        return true;
    }

    bool AddressRangeFits(std::uintptr_t address, std::size_t byteCount)
    {
        if (byteCount == 0)
            return true;

        return byteCount - 1 <= std::numeric_limits<std::uintptr_t>::max() - address;
    }

    std::uintptr_t PointerValueFromBytes(
        const std::vector<unsigned char>& data,
        std::size_t offset)
    {
        if (offset > data.size() || sizeof(std::uintptr_t) > data.size() - offset)
            return 0;

        return BytesToUintPtr(data.data() + offset, sizeof(std::uintptr_t));
    }

    std::string HandleInspectAddressStructure(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string addressText;
        if (auto error = params.RequiredSearchText("address", addressText,
                "InspectAddressStructure address must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t pointerCount = 8;
        if (auto error = params.BoundedUnsigned("pointerCount", pointerCount, 0, kMaxInspectPointerCount,
                "InspectAddressStructure pointerCount must be between 0 and 64."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t byteCount = 128;
        if (auto error = params.BoundedUnsigned("byteCount", byteCount, 0, kMaxInspectByteCount,
                "InspectAddressStructure byteCount must be between 0 and 4096."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t stringBytes = 128;
        if (auto error = params.BoundedUnsigned("stringBytes", stringBytes, 16, kMaxInspectStringBytes,
                "InspectAddressStructure stringBytes must be between 16 and 1024."); !error.empty())
            return ErrorResponse(id, error);

        bool includeXrefs = true;
        if (auto error = params.OptionalBoolean("includeXrefs", includeXrefs,
                "InspectAddressStructure includeXrefs must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxXrefs = 32;
        if (auto error = params.BoundedUnsigned("maxXrefs", maxXrefs, 1, kMaxInspectXrefs,
                "InspectAddressStructure maxXrefs must be between 1 and 256."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxScanBytes = kDefaultInspectAddressScanBytes;
        if (auto error = params.BoundedUnsigned("maxScanBytes", maxScanBytes, 4096, kMaxSearchScanBytes,
                "InspectAddressStructure maxScanBytes must be between 4096 and 67108864."); !error.empty())
            return ErrorResponse(id, error);

        // Token-light dump opt-ins (default off): includeAscii re-adds the
        // ASCII gutter, spacedHex re-adds inter-byte spaces.
        bool includeAscii = false;
        if (auto error = params.OptionalBoolean("includeAscii", includeAscii,
                "InspectAddressStructure includeAscii must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        bool spacedHex = false;
        if (auto error = params.OptionalBoolean("spacedHex", spacedHex,
                "InspectAddressStructure spacedHex must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        std::uintptr_t address = 0;
        if (auto error = ResolveNonZeroAddressExpression(addressText, address); !error.empty())
            return ErrorResponse(id, error);

        const std::size_t pointerCountValue = static_cast<std::size_t>(pointerCount);
        const std::size_t byteCountValue = static_cast<std::size_t>(byteCount);
        const std::size_t stringBytesValue = static_cast<std::size_t>(stringBytes);
        const std::size_t maxXrefsValue = static_cast<std::size_t>(maxXrefs);
        const std::size_t maxScanBytesValue = static_cast<std::size_t>(maxScanBytes);
        if (pointerCountValue > std::numeric_limits<std::size_t>::max() / sizeof(std::uintptr_t))
            return ErrorResponse(id, "InspectAddressStructure pointer table size overflow.");

        const std::size_t pointerBytes = pointerCountValue * sizeof(std::uintptr_t);
        if (!AddressRangeFits(address, byteCountValue) || !AddressRangeFits(address, pointerBytes))
            return ErrorResponse(id, "InspectAddressStructure address range overflows.");

        std::vector<unsigned char> bytes;
        const bool bytesRead = byteCountValue == 0 || ReadMemory(address, byteCountValue, bytes);

        std::vector<unsigned char> pointerData;
        const bool pointersRead = pointerBytes == 0 || ReadMemory(address, pointerBytes, pointerData);

        XrefSearchResult xrefs;
        std::string xrefError;
        bool xrefsRead = false;
        if (includeXrefs)
        {
            std::vector<ModuleRecord> modules;
            bool mapTruncated = false;
            if (CollectModuleRecords(modules, mapTruncated, xrefError))
            {
                xrefs = ScanXrefs(address, modules, false, true, maxXrefsValue, maxScanBytesValue);
                xrefs.moduleMapTruncated = mapTruncated;
                xrefsRead = true;
            }
        }

        const std::size_t outputLimit = kMaxSearchOutputChars - 32;
        BoundedText body(outputLimit, BoundedText::OverflowPolicy::Latch);
        body.Assign("[InspectAddressStructure] address=" + HexAddress(address) +
            " expression=\"" + JsonEscape(SingleLine(addressText)) + "\" pointerSize=" +
            std::to_string(sizeof(std::uintptr_t)));

        body.AppendLine("[Address] " + GetAddressInfoLine(address));
        if (includeXrefs)
        {
            if (!xrefsRead)
            {
                body.AppendLine("[Xrefs] included=true error=\"" + JsonEscape(xrefError) + "\"");
            }
            else
            {
                body.AppendLine("[Xrefs] included=true total=" + std::to_string(xrefs.matches.size()) +
                    " reportedCount=" + std::to_string(xrefs.reportedCount) +
                    " scannedBytes=" + std::to_string(xrefs.scannedBytes));
                for (std::size_t index = 0; index < xrefs.matches.size(); ++index)
                {
                    const auto& match = xrefs.matches[index];
                    body.AppendLine("[" + std::to_string(index) + "] from=" + HexAddress(match.address) +
                        " type=" + XrefTypeText(match.type) + " source=" + SingleLine(match.source) +
                        " instruction=\"" + JsonEscape(SingleLine(match.instruction)) + "\"");
                }

                body.AppendFlag("xrefDbAvailable", xrefs.xrefDbAvailable);
                body.AppendFlag("xrefDbMalformed", xrefs.xrefDbMalformed);
                body.AppendFlag("xrefDbTruncated", xrefs.xrefDbTruncated);
                body.AppendFlag("scanFallbackUsed", xrefs.scanFallbackUsed);
                body.AppendFlag("scanFallbackUnavailable", xrefs.scanFallbackUnavailable);
                body.AppendFlag("scanTruncated", xrefs.scanTruncated);
                body.AppendFlag("addressOverflow", xrefs.addressOverflow);
                body.AppendFlag("moduleMapTruncated", xrefs.moduleMapTruncated);
            }
        }
        else
        {
            body.AppendLine("[Xrefs] included=false");
        }

        body.AppendLine("[Bytes] byteCount=" + std::to_string(byteCountValue) +
            " read=" + (bytesRead ? "true" : "false"));
        if (bytesRead && !bytes.empty())
            body.AppendLine(FormatHexDump(address, bytes, includeAscii, spacedHex));

        // pointerSize is already in the reply header above; repeating it here
        // wastes a token on every inspection.
        body.AppendLine("[Pointers] count=" + std::to_string(pointerCountValue) +
            " read=" + (pointersRead ? "true" : "false"));
        if (pointersRead)
        {
            auto getModuleAt = GetDebuggerBridgeFunction<DbgGetModuleAtFunction>("DbgGetModuleAt");
            std::vector<unsigned char> stringData;
            for (std::size_t index = 0; index < pointerCountValue; ++index)
            {
                const std::size_t offset = index * sizeof(std::uintptr_t);
                const auto value = PointerValueFromBytes(pointerData, offset);
                std::string line = "[" + std::to_string(index) + "] +" +
                    HexAddress(static_cast<std::uintptr_t>(offset)) + " value=" + HexAddress(value);

                if (value != 0)
                {
                    if (getModuleAt != nullptr)
                    {
                        char moduleBuffer[kMaxModuleSize]{};
                        if (getModuleAt(value, moduleBuffer))
                        {
                            const std::string module = SingleLine(BufferText(moduleBuffer, kMaxModuleSize));
                            if (!module.empty())
                                line += " module=" + module;
                        }
                    }

                    if (ReadMemory(value, stringBytesValue, stringData))
                    {
                        std::string ascii;
                        std::string unicode;
                        if (TryDecodePrintableAscii(stringData, ascii))
                            line += " ascii=\"" + JsonEscape(SingleLine(ascii)) + "\"";
                        if (TryDecodePrintableUtf16(stringData, unicode))
                            line += " utf16=\"" + JsonEscape(SingleLine(unicode)) + "\"";
                    }
                    else
                    {
                        // stringRead=false marks a non-null pointee whose bytes
                        // could not be read. It must stay: without it an
                        // unreadable pointee is indistinguishable from a null
                        // one (null entries carry no string fields and no
                        // marker).
                        line += " stringRead=false";
                    }
                }

                body.AppendLine(line);
            }
        }

        body.AppendMarker("\noutputTruncated=true");
        return TextResponse(id, "InspectAddressStructure", body.Body());
    }

}
