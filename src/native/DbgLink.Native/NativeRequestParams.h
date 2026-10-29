#pragma once
#include "NativeJson.h"
#include "NativeTypes.h"

namespace dbglink
{
    // Validation wrapper over one parsed bridge request. Every helper returns
    // an empty string on success, or the exact call-site error message it was
    // given, so handlers keep byte-identical wire output while sharing the
    // hand-written HasJsonProperty/Extract* validation dance.
    class RequestParams
    {
    public:
        explicit RequestParams(const std::string& request) : request_(request) {}

        bool Has(const char* key) const;

        // Optional string: an absent key keeps `out` unchanged.
        std::string OptionalString(
            const char* key,
            std::string& out,
            std::string_view message) const;

        // Optional string with an inline byte cap checked during extraction.
        std::string OptionalStringBounded(
            const char* key,
            std::string& out,
            std::size_t maxBytes,
            std::string_view message) const;

        // Required string: a missing or non-string key yields `message`.
        // Optional byte bounds cover inline capacity checks; pass minBytes=1
        // for the common non-empty requirement.
        std::string RequiredString(
            const char* key,
            std::string& out,
            std::string_view message,
            std::size_t minBytes = 0,
            std::size_t maxBytes = std::numeric_limits<std::size_t>::max()) const;

        // Optional unsigned integer: an absent key keeps `out` unchanged.
        std::string OptionalUnsigned(
            const char* key,
            std::uint64_t& out,
            std::string_view message) const;

        // Optional unsigned integer constrained to [lo, hi]; non-integers and
        // out-of-range values both yield `message`.
        std::string BoundedUnsigned(
            const char* key,
            std::uint64_t& out,
            std::uint64_t lo,
            std::uint64_t hi,
            std::string_view message) const;

        // Optional boolean: an absent key keeps `out` unchanged.
        std::string OptionalBoolean(
            const char* key,
            bool& out,
            std::string_view message) const;

        // Required search/expression text: must extract as a string and pass
        // IsSearchTextValid (non-empty, <= 256 bytes, no control bytes).
        std::string RequiredSearchText(
            const char* key,
            std::string& out,
            std::string_view message) const;

        // Optional module filter: string extraction first (stringMessage),
        // then the printable-byte module policy (filterMessage).
        std::string OptionalModuleFilter(
            const char* key,
            std::string& out,
            std::string_view stringMessage,
            std::string_view filterMessage) const;

    private:
        const std::string& request_;
    };

    // Shared address resolution producing the uniform wire message
    // "Invalid address or expression: <text>". The non-zero variant rejects a
    // successfully resolved 0, matching the handlers that treat 0 as invalid.
    std::string ResolveAddressExpression(const std::string& text, std::uintptr_t& address);
    std::string ResolveNonZeroAddressExpression(const std::string& text, std::uintptr_t& address);
}
