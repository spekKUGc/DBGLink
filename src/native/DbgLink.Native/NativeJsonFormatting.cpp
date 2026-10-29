#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"

namespace dbglink
{
    std::string JsonEscape(const std::string& value)
    {
        const bool validUtf8 = IsValidUtf8(value);
        constexpr char digits[] = "0123456789ABCDEF";
        std::string escaped;
        escaped.reserve(value.size());
        for (const unsigned char character : value)
        {
            switch (character)
            {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (character < 0x20)
                {
                    escaped += "\\u00";
                    escaped.push_back(digits[character >> 4]);
                    escaped.push_back(digits[character & 0x0F]);
                }
                else if (!validUtf8 && character >= 0x80)
                {
                    escaped += "\\u00";
                    escaped.push_back(digits[character >> 4]);
                    escaped.push_back(digits[character & 0x0F]);
                }
                else
                    escaped.push_back(static_cast<char>(character));
                break;
            }
        }
        return escaped;
    }
    std::string ErrorResponse(const std::string& id, const std::string& message)
    {
        const std::string escapedMessage = JsonEscape(message);
        std::string result;
        result.reserve(id.size() + escapedMessage.size() + 32);
        result = "{\"id\":";
        result += id;
        result += ",\"ok\":false,\"error\":{\"code\":\"native_error\",\"message\":\"";
        result += escapedMessage;
        result += "\"}}";
        return result;
    }

    std::string UnauthorizedResponse(const std::string& id, const std::string& message)
    {
        const std::string escapedMessage = JsonEscape(message);
        std::string result;
        result.reserve(id.size() + escapedMessage.size() + 32);
        result = "{\"id\":";
        result += id;
        result += ",\"ok\":false,\"error\":{\"code\":\"unauthorized\",\"message\":\"";
        result += escapedMessage;
        result += "\"}}";
        return result;
    }

    std::string SuccessResponse(const std::string& id, const nlohmann::json& result)
    {
        return "{\"id\":" + id + ",\"ok\":true,\"result\":" + result.dump() + "}";
    }

    PageWindow ComputePageWindow(std::uint64_t offset, std::uint64_t maxItems, std::size_t total)
    {
        PageWindow window;
        window.total = total;
        window.start = static_cast<std::size_t>(std::min<std::uint64_t>(offset, total));
        window.count = static_cast<std::size_t>(std::min<std::uint64_t>(maxItems, total - window.start));
        window.truncated = window.start + window.count < total;
        return window;
    }

    void ApplyPagedEnvelope(nlohmann::json& result, const PageWindow& window, std::uint64_t offset)
    {
        result["schemaVersion"] = 1;
        result["totalCount"] = window.total;
        result["returnedCount"] = window.count;
        result["offset"] = offset;
        result["truncated"] = window.truncated;
        if (window.truncated)
            result["nextOffset"] = window.start + window.count;
        else
            result["nextOffset"] = nullptr;
    }

    std::string TextResponse(const std::string& id, const char* method, const std::string& text)
    {
        const std::string escapedText = JsonEscape(text);
        std::string result;
        result.reserve(id.size() + std::strlen(method) + escapedText.size() + 40);
        result = "{\"id\":";
        result += id;
        result += ",\"ok\":true,\"method\":\"";
        result += method;
        result += "\",\"text\":\"";
        result += escapedText;
        result += "\"}";
        return result;
    }

    std::string SingleLine(const std::string& value)
    {
        std::string result = value;
        for (char& character : result)
        {
            if (character == '\r' || character == '\n' || character == '\t')
                character = ' ';
        }
        return Trim(result);
    }

    std::string BufferText(const char* buffer, std::size_t capacity)
    {
        std::size_t length = 0;
        while (length < capacity && buffer[length] != '\0')
            ++length;
        return std::string(buffer, length);
    }

    bool TryAddAddress(std::uintptr_t base, std::size_t offset, std::uintptr_t& result)
    {
        const auto maximum = std::numeric_limits<std::uintptr_t>::max();
        if (offset > maximum - base)
        {
            result = 0;
            return false;
        }

        result = base + static_cast<std::uintptr_t>(offset);
        return true;
    }

    std::string FileNameFromPath(const std::string& path)
    {
        const auto separator = path.find_last_of("\\/");
        return separator == std::string::npos ? path : path.substr(separator + 1);
    }

    bool EqualsInsensitive(const std::string& left, const std::string& right)
    {
        return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin(),
            [](unsigned char leftCharacter, unsigned char rightCharacter)
            {
                return std::tolower(leftCharacter) == std::tolower(rightCharacter);
            });
    }

    bool ContainsInsensitive(const std::string& text, const std::string& needle)
    {
        if (needle.empty())
            return true;

        return std::search(text.begin(), text.end(), needle.begin(), needle.end(),
            [](unsigned char textCharacter, unsigned char needleCharacter)
            {
                return std::tolower(textCharacter) == std::tolower(needleCharacter);
            }) != text.end();
    }

    std::vector<unsigned char> AsciiSearchBytes(const std::string& text)
    {
        if (std::any_of(text.begin(), text.end(), [](unsigned char character)
            {
                return character >= 0x80;
            }))
        {
            return {};
        }

        std::vector<unsigned char> bytes;
        bytes.reserve(text.size());
        for (const unsigned char character : text)
            bytes.push_back(character);
        return bytes;
    }

    std::vector<unsigned char> Utf8SearchBytes(const std::string& text)
    {
        if (text.empty() || text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
            return {};

        const int wideLength = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0);
        if (wideLength <= 0)
            return {};

        std::wstring wide(static_cast<std::size_t>(wideLength), L'\0');
        if (MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                text.data(),
                static_cast<int>(text.size()),
                wide.data(),
                wideLength) != wideLength)
            return {};

        std::vector<unsigned char> bytes;
        bytes.reserve(wide.size() * 2);
        for (const wchar_t character : wide)
        {
            const auto codeUnit = static_cast<std::uint16_t>(character);
            bytes.push_back(static_cast<unsigned char>(codeUnit & 0xFF));
            bytes.push_back(static_cast<unsigned char>((codeUnit >> 8) & 0xFF));
        }
        return bytes;
    }

    std::string Utf16BytesToUtf8(const std::vector<unsigned char>& data, std::size_t byteCount)
    {
        const std::size_t boundedByteCount = std::min(byteCount, data.size());
        const std::size_t evenByteCount = boundedByteCount - (boundedByteCount % 2);
        if (evenByteCount / 2 > static_cast<std::size_t>(std::numeric_limits<int>::max()))
            return {};

        std::wstring wide;
        wide.reserve(evenByteCount / 2);
        for (std::size_t index = 0; index < evenByteCount; index += 2)
        {
            const auto codeUnit = static_cast<wchar_t>(
                static_cast<unsigned int>(data[index]) |
                (static_cast<unsigned int>(data[index + 1]) << 8));
            wide.push_back(codeUnit);
        }

        if (wide.empty())
            return {};

        int required = WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            wide.data(),
            static_cast<int>(wide.size()),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (required <= 0)
        {
            required = WideCharToMultiByte(
                CP_UTF8,
                0,
                wide.data(),
                static_cast<int>(wide.size()),
                nullptr,
                0,
                nullptr,
                nullptr);
        }
        if (required <= 0)
            return {};

        std::string result(static_cast<std::size_t>(required), '\0');
        if (WideCharToMultiByte(
                CP_UTF8,
                0,
                wide.data(),
                static_cast<int>(wide.size()),
                result.data(),
                required,
                nullptr,
                nullptr) <= 0)
        {
            return {};
        }
        return result;
    }

    bool TryParseUnsignedText(std::string_view text, int base, std::uintptr_t& value)
    {
        if (text.empty())
            return false;

        std::uint64_t parsed = 0;
        const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed, base);
        if (result.ec != std::errc() || result.ptr != text.data() + text.size())
            return false;
        if (parsed > static_cast<std::uint64_t>(std::numeric_limits<std::uintptr_t>::max()))
            return false;

        value = static_cast<std::uintptr_t>(parsed);
        return true;
    }

    bool ResolveAddress(const std::string& expression, std::uintptr_t& address)
    {
        const std::string trimmed = Trim(expression);
        if (trimmed.empty())
            return false;

        if (trimmed.size() > 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X'))
        {
            if (TryParseUnsignedText(std::string_view(trimmed).substr(2), 16, address))
                return true;
        }
        // Bare numbers are hex: x64dbg evaluates `401000` as 0x401000 and the
        // managed AddressMapping.TryParseAddress parses the same way, so the
        // fast path must not try base 10 first (that turned `401000` into
        // decimal 401000 while `401abc` still parsed as hex). Anything that is
        // not plain hex (symbols, registers, the decimal `123.` suffix,
        // arithmetic) falls through to the debugger's DbgValFromString below.
        else if (TryParseUnsignedText(trimmed, 16, address))
        {
            return true;
        }

        auto valueFromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        if (valueFromString == nullptr)
            return false;

        address = valueFromString(trimmed.c_str());
        if (address != 0)
            return true;
        if (trimmed == "0")
            return true;
        // DbgValFromString has no error return: 0 means either "valid zero"
        // (e.g. rax == 0) or "invalid expression". Ask the debugger to
        // disambiguate instead of rejecting every zero-valued register.
        auto isValid = GetDebuggerBridgeFunction<DbgIsValidExpressionFunction>("DbgIsValidExpression");
        if (isValid != nullptr)
            return isValid(trimmed.c_str());
        return false;
    }

}
