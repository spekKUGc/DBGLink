#include "NativeRequestParams.h"
#include "NativeJsonFormatting.h"
#include "NativeInputValidation.h"

namespace dbglink
{
    bool RequestParams::Has(const char* key) const
    {
        return HasJsonProperty(request_, key);
    }

    std::string RequestParams::OptionalString(
        const char* key,
        std::string& out,
        std::string_view message) const
    {
        if (!HasJsonProperty(request_, key))
            return {};
        if (!ExtractJsonString(request_, key, out))
            return std::string(message);
        return {};
    }

    std::string RequestParams::OptionalStringBounded(
        const char* key,
        std::string& out,
        std::size_t maxBytes,
        std::string_view message) const
    {
        if (!HasJsonProperty(request_, key))
            return {};
        if (!ExtractJsonString(request_, key, out) || out.size() > maxBytes)
            return std::string(message);
        return {};
    }

    std::string RequestParams::RequiredString(
        const char* key,
        std::string& out,
        std::string_view message,
        std::size_t minBytes,
        std::size_t maxBytes) const
    {
        if (!ExtractJsonString(request_, key, out))
            return std::string(message);
        if (out.size() < minBytes || out.size() > maxBytes)
            return std::string(message);
        return {};
    }

    std::string RequestParams::OptionalUnsigned(
        const char* key,
        std::uint64_t& out,
        std::string_view message) const
    {
        if (!HasJsonProperty(request_, key))
            return {};
        if (!ExtractUnsigned(request_, key, out))
            return std::string(message);
        return {};
    }

    std::string RequestParams::BoundedUnsigned(
        const char* key,
        std::uint64_t& out,
        std::uint64_t lo,
        std::uint64_t hi,
        std::string_view message) const
    {
        if (!HasJsonProperty(request_, key))
            return {};
        std::uint64_t value = 0;
        if (!ExtractUnsigned(request_, key, value) || value < lo || value > hi)
            return std::string(message);
        out = value;
        return {};
    }

    std::string RequestParams::OptionalBoolean(
        const char* key,
        bool& out,
        std::string_view message) const
    {
        if (!HasJsonProperty(request_, key))
            return {};
        if (!ExtractBoolean(request_, key, out))
            return std::string(message);
        return {};
    }

    std::string RequestParams::RequiredSearchText(
        const char* key,
        std::string& out,
        std::string_view message) const
    {
        if (!ExtractJsonString(request_, key, out) || !IsSearchTextValid(out))
            return std::string(message);
        return {};
    }

    std::string RequestParams::OptionalModuleFilter(
        const char* key,
        std::string& out,
        std::string_view stringMessage,
        std::string_view filterMessage) const
    {
        if (const std::string error = OptionalString(key, out, stringMessage); !error.empty())
            return error;
        if (!IsSearchModuleFilterValid(out))
            return std::string(filterMessage);
        return {};
    }

    std::string ResolveAddressExpression(const std::string& text, std::uintptr_t& address)
    {
        if (!ResolveAddress(text, address))
            return "Invalid address or expression: " + text;
        return {};
    }

    std::string ResolveNonZeroAddressExpression(const std::string& text, std::uintptr_t& address)
    {
        if (!ResolveAddress(text, address) || address == 0)
            return "Invalid address or expression: " + text;
        return {};
    }

}
