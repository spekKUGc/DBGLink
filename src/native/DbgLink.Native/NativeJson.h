#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "third_party/nlohmann/json.hpp"

namespace dbglink
{
    void BeginJsonRequestParse(const std::string& request);
    /// <summary>True when the request parses as a JSON object. The member
    /// list is deliberately not part of the product surface: the pipe loop
    /// only needs the validity check, and the member enumeration lived in
    /// the product headers for the benefit of the test harness only.</summary>
    bool IsJsonObjectRequest(const std::string& request);
    // Cached-document access for handlers that need structured sub-objects
    // (e.g. the ReadMemAtAddress ranges array) without re-parsing the request
    // bytes. Returns nullptr when the request is not a valid JSON object.
    const nlohmann::ordered_json* CachedRequestDocument(const std::string& request);
    bool HasJsonProperty(const std::string& request, const char* key);
    std::string ExtractId(const std::string& request);
    bool ExtractJsonString(const std::string& request, const char* key, std::string& value);
    // Top-level envelope string (id/method/token scope). Unlike
    // ExtractJsonString — which reads handler arguments from "params" — this
    // reads the request root, where the N1 bridge token lives.
    bool ExtractEnvelopeString(const std::string& request, const char* key, std::string& value);
    bool ExtractUnsigned(const std::string& request, const char* key, std::uint64_t& value);
    // Shared trimmed-decimal uint64 parser (cached ExtractUnsigned and the
    // per-range byteCount parser): rejects empties, a leading '-' and any
    // trailing garbage.
    bool ParseUnsignedText(std::string_view text, std::uint64_t& value);
    bool ExtractBoolean(const std::string& request, const char* key, bool& value);
    std::string Trim(const std::string& value);
    // ASCII lowercase copy; the shared form of the register/hwType/memType/
    // memory-map-type canonicalisation (unsigned-char std::tolower).
    std::string ToLower(const std::string& value);
    bool IsValidUtf8(const std::string& text);
}
