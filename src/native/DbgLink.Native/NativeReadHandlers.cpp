#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeControlSupport.h"
#include "NativeDebuggerQueries.h"
#include "NativeInspectionHandlers.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeControlHandlers.h"
#include "NativeRequestParams.h"

namespace dbglink
{
    std::string HandleReadMemoryChunk(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string addressText;
        if (auto error = params.RequiredSearchText("address", addressText,
                "ReadMemoryChunk address must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t offset = 0;
        if (auto error = params.OptionalUnsigned("offset", offset, "ReadMemoryChunk offset must be an integer."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t length = 256;
        if (auto error = params.BoundedUnsigned("length", length, 1, kMaxPagedReadBytes,
                "ReadMemoryChunk length must be between 1 and 8192. Page larger dumps via offset."); !error.empty())
            return ErrorResponse(id, error);
        std::uintptr_t base = 0;
        if (auto error = ResolveAddressExpression(addressText, base); !error.empty())
            return ErrorResponse(id, error);
        std::uintptr_t target = 0;
        // SEC N6: reject before the narrowing cast. On 32-bit a huge offset
        // would truncate to a small size_t (even 0) and read `base` instead
        // of failing. Same wire error as the add-overflow below.
        if (offset > static_cast<std::uint64_t>((std::numeric_limits<std::uintptr_t>::max)()) ||
            (offset > 0 && !TryAddAddress(base, static_cast<std::size_t>(offset), target)))
            return ErrorResponse(id, "ReadMemoryChunk offset overflows the address space.");
        if (offset == 0)
            target = base;
        if (!AddressRangeFits(target, static_cast<std::size_t>(length)))
            return ErrorResponse(id, "ReadMemoryChunk range overflows the address space.");
        std::vector<unsigned char> data;
        if (!ReadMemory(target, static_cast<std::size_t>(length), data))
            return ErrorResponse(id, "Failed to read memory at " + HexAddress(target));
        std::uint64_t nextOffsetValue = 0;
        bool overflow = false;
        {
            const auto maxAddr = std::numeric_limits<std::uintptr_t>::max();
            const auto baseVal = static_cast<std::uint64_t>(base);
            const auto next = static_cast<std::uint64_t>(offset) + static_cast<std::uint64_t>(length);
            if (next > static_cast<std::uint64_t>(maxAddr) - baseVal)
            {
                // nextOffset is relative to base; report the full 64-bit
                // value even if target+length wraps, the next call will fail
                // overflow cleanly. Matches the disassembly chunk shape.
                nextOffsetValue = next;
                overflow = next < offset;
            }
            else
            {
                nextOffsetValue = next;
            }
        }
        nlohmann::json result{
            {"base", HexAddress(base)},
            {"address", HexAddress(target)},
            {"offset", offset},
            {"length", data.size()},
            {"bytesHex", FormatBytes(data)},
            {"ascii", AsciiPreview(data)},
            {"nextOffset", nextOffsetValue},
            {"addressOverflow", overflow},
        };
        return SuccessResponse(id, result);
    }

    std::string HandleReadDisassemblyChunk(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string addressText;
        if (auto error = params.RequiredSearchText("address", addressText,
                "ReadDisassemblyChunk address must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t offset = 0;
        if (auto error = params.OptionalUnsigned("offset", offset,
                "ReadDisassemblyChunk offset must be an integer."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t maxInstructions = 32;
        if (auto error = params.BoundedUnsigned("maxInstructions", maxInstructions, 1, kMaxPagedInstructions,
                "ReadDisassemblyChunk maxInstructions must be between 1 and 100."); !error.empty())
            return ErrorResponse(id, error);
        std::uintptr_t base = 0;
        if (auto error = ResolveAddressExpression(addressText, base); !error.empty())
            return ErrorResponse(id, error);
        std::uintptr_t start = base;
        // SEC N6: same narrowing-cast guard as ReadMemoryChunk above.
        if (offset > static_cast<std::uint64_t>((std::numeric_limits<std::uintptr_t>::max)()) ||
            (offset > 0 && !TryAddAddress(base, static_cast<std::size_t>(offset), start)))
            return ErrorResponse(id, "ReadDisassemblyChunk offset overflows the address space.");
        auto disasm = GetDebuggerBridgeFunction<DbgDisasmFastAtFunction>("DbgDisasmFastAt");
        auto memoryRead = GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead");
        if (disasm == nullptr)
            return ErrorResponse(id, "Disassembly bridge is unavailable.");
        nlohmann::json items = nlohmann::json::array();
        std::uintptr_t cursor = start;
        std::size_t bytesTotal = 0;
        bool truncated = false;
        for (std::size_t i = 0; i < static_cast<std::size_t>(maxInstructions); ++i)
        {
            BASIC_INSTRUCTION_INFO info{};
            disasm(cursor, &info);
            if (info.size <= 0 || info.size > 64)
            {
                items.push_back({
                    {"address", HexAddress(cursor)},
                    {"size", 0},
                    {"bytesHex", ""},
                    {"instruction", "<undecodable>"},
                });
                std::uintptr_t next = 0;
                if (!TryAddAddress(cursor, 1, next))
                {
                    truncated = true;
                    break;
                }
                cursor = next;
                bytesTotal += 1;
                continue;
            }
            std::vector<unsigned char> bytes;
            const bool readable = memoryRead != nullptr &&
                ReadMemory(cursor, static_cast<std::size_t>(info.size), bytes, memoryRead);
            const std::string text = SingleLine(BufferText(info.instruction, sizeof(info.instruction)));
            items.push_back({
                {"address", HexAddress(cursor)},
                {"size", info.size},
                {"bytesHex", readable ? FormatBytes(bytes) : ""},
                {"instruction", text.empty() ? "<unknown>" : text},
            });
            std::uintptr_t next = 0;
            if (!TryAddAddress(cursor, static_cast<std::size_t>(info.size), next))
            {
                truncated = true;
                cursor = next;
                break;
            }
            cursor = next;
            bytesTotal += static_cast<std::size_t>(info.size);
            if (items.dump().size() > 180 * 1024)
            {
                truncated = true;
                break;
            }
        }
        std::uint64_t nextOffset = static_cast<std::uint64_t>(cursor >= base ? cursor - base : 0);
        nlohmann::json result{
            {"base", HexAddress(base)},
            {"startAddress", HexAddress(start)},
            {"instructionCount", items.size()},
            {"bytesTotal", bytesTotal},
            {"nextAddress", HexAddress(cursor)},
            {"nextOffset", nextOffset},
            {"truncated", truncated},
        };
        result["instructions"] = std::move(items);
        return SuccessResponse(id, result);
    }

    std::string HandleEvaluateExpression(const std::string& request, const std::string& id)
    {
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        std::string expression;
        if (!ExtractJsonString(request, "expression", expression) || Trim(expression).empty())
            return ErrorResponse(id, "EvaluateExpression expression is required.");
        if (expression.size() > 512)
            return ErrorResponse(id, "EvaluateExpression expression is too long.");

        std::uintptr_t value = 0;
        if (!ResolveAddress(Trim(expression), value) && Trim(expression) != "0")
            return ErrorResponse(id, "Could not evaluate expression: " + expression);

        nlohmann::json result{
            {"expression", expression},
            {"valueHex", HexAddress(value)},
            {"valueUnsigned", std::to_string(value)},
            {"valueSigned", std::to_string(static_cast<std::intptr_t>(value))},
        };

        auto memRead = GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead");
        if (memRead != nullptr && value != 0)
        {
            unsigned char derefBytes[8]{};
            const std::size_t readSize = sizeof(std::uintptr_t);
            if (memRead(value, derefBytes, readSize))
            {
                result["dereference"] = HexAddress(BytesToUintPtr(derefBytes, readSize));
            }
        }
        return SuccessResponse(id, result);
    }
}
