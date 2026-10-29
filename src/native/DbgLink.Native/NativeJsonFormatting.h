#pragma once
#include "NativeTypes.h"
#include "NativeHexFormat.h"
#include "third_party/nlohmann/json.hpp"
namespace dbglink
{
    std::string JsonEscape(const std::string& value);
    std::string ErrorResponse(const std::string& id, const std::string& message);
    // N1 auth rejection: same envelope as ErrorResponse but with
    // code "unauthorized". ErrorResponse (native_error) is unchanged.
    std::string UnauthorizedResponse(const std::string& id, const std::string& message);
    std::string SuccessResponse(const std::string& id, const nlohmann::json& result);
    // Shared offset/maxItems window used by the paged list replies. The
    // callers keep their own item keys and extras; only the start/count/
    // truncated arithmetic lives here so the three sites cannot drift.
    struct PageWindow
    {
        std::size_t total = 0;
        std::size_t start = 0;
        std::size_t count = 0;
        bool truncated = false;
    };
    PageWindow ComputePageWindow(std::uint64_t offset, std::uint64_t maxItems, std::size_t total);
    void ApplyPagedEnvelope(nlohmann::json& result, const PageWindow& window, std::uint64_t offset);
    std::string TextResponse(const std::string& id, const char* method, const std::string& text);
    std::string SingleLine(const std::string& value);
    std::string BufferText(const char* buffer, std::size_t capacity);
    bool TryAddAddress(std::uintptr_t base, std::size_t offset, std::uintptr_t& result);
    // Guard for bridge-returned lists (breakpoint/thread/memory maps): the
    // count must be within [0, cap] and a non-empty list needs a buffer.
    // Returns false on any violation; callers keep their own wire message.
    template <typename T>
    bool ValidateBridgeList(int count, const T* items, int cap)
    {
        if (count < 0 || count > cap)
            return false;
        return count == 0 || items != nullptr;
    }
    // Printable-ASCII gutter shared by AsciiPreview and the FormatHexDump
    // ASCII column: printable bytes pass through, everything else is '.'.
    inline char PrintableChar(unsigned char value)
    {
        return value >= 32 && value <= 126 ? static_cast<char>(value) : '.';
    }
    // Little-endian byte decode shared by PointerValueFromBytes,
    // ReadPointerValue and the EvaluateExpression dereference read.
    // m5: clamps to the pointer width so an oversized count cannot shift
    // past the value width (UB) or silently drop high bytes.
    inline std::uintptr_t BytesToUintPtr(const unsigned char* bytes, std::size_t count)
    {
        if (bytes == nullptr)
            return 0;
        const std::size_t limit = count < sizeof(std::uintptr_t) ? count : sizeof(std::uintptr_t);
        std::uintptr_t value = 0;
        for (std::size_t index = 0; index < limit; ++index)
            value |= static_cast<std::uintptr_t>(bytes[index]) << (index * 8);
        return value;
    }
    std::string FileNameFromPath(const std::string& path);
    bool EqualsInsensitive(const std::string& left, const std::string& right);
    bool ContainsInsensitive(const std::string& text, const std::string& needle);
    std::vector<unsigned char> AsciiSearchBytes(const std::string& text);
    std::vector<unsigned char> Utf8SearchBytes(const std::string& text);
    std::string Utf16BytesToUtf8(const std::vector<unsigned char>& data, std::size_t byteCount);
    bool TryParseUnsignedText(std::string_view text, int base, std::uintptr_t& value);
    bool ResolveAddress(const std::string& expression, std::uintptr_t& address);
}
