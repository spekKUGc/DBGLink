#include "NativeJson.h"
#include "third_party/nlohmann/json.hpp"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <unordered_set>

namespace dbglink
{
namespace
{
    using Json = nlohmann::ordered_json;
    struct RequestCache
    {
        std::string source;
        Json document;
        bool valid = false;
    };
    thread_local RequestCache cache;

    bool Parse(const std::string& request)
    {
        if (request == cache.source && cache.valid) return true;
        cache = {};
        if (request.size() > 64 * 1024) return false;
        try
        {
            std::vector<std::unordered_set<std::string>> keys;
            auto validate = [&](int depth, Json::parse_event_t event, Json& value)
            {
                using Event = Json::parse_event_t;
                if (depth > 17) throw std::invalid_argument("JSON nesting limit");
                if (event == Event::object_start) keys.emplace_back();
                if (event == Event::key)
                {
                    const auto& key = value.get_ref<const std::string&>();
                    if (key.size() > 1022 || keys.back().size() >= 512 || !keys.back().insert(key).second)
                        throw std::invalid_argument("Invalid or duplicate JSON key");
                }
                if ((event == Event::object_end || event == Event::array_end) && value.size() > 512)
                    throw std::invalid_argument("JSON container limit");
                if (event == Event::object_end) keys.pop_back();
                return true;
            };
            auto document = Json::parse(request, validate);
            if (!document.is_object()) return false;
            cache.source = request;
            cache.document = std::move(document);
            cache.valid = true;
            return true;
        }
        catch (const Json::exception&) { return false; }
        catch (const std::invalid_argument&) { return false; }
    }

    const Json* Find(const std::string& request, const char* key)
    {
        if (!Parse(request)) return nullptr;
        // Arguments are carried in params by the managed client. Envelope fields
        // always come from the root.
        const Json* object = &cache.document;
        if (std::string_view(key) == "id" || std::string_view(key) == "method")
        {
            auto found = object->find(key);
            return found == object->end() ? nullptr : &*found;
        }

        auto params = object->find("params");
        if (params == object->end() || !params->is_object())
            return nullptr;
        object = &*params;
        auto found = object->find(key);
        return found == object->end() ? nullptr : &*found;
    }
}

    void BeginJsonRequestParse(const std::string& request) { cache = {}; (void)Parse(request); }

    bool IsJsonObjectRequest(const std::string& request)
    {
        return Parse(request);
    }

    bool HasJsonProperty(const std::string& request, const char* key) { return Find(request, key) != nullptr; }

    const Json* CachedRequestDocument(const std::string& request)
    {
        return Parse(request) ? &cache.document : nullptr;
    }

    std::string ExtractId(const std::string& request)
    {
        auto value = Find(request, "id");
        if (!value || !(value->is_string() || value->is_number() || value->is_null())) return "null";
        auto encoded = value->dump();
        return encoded.size() <= 128 ? encoded : "null";
    }

    bool ExtractJsonString(const std::string& request, const char* key, std::string& value)
    {
        auto field = Find(request, key);
        if (!field || !field->is_string()) return false;
        value = field->get<std::string>();
        return true;
    }

    bool ExtractEnvelopeString(const std::string& request, const char* key, std::string& value)
    {
        if (!Parse(request)) return false;
        const auto found = cache.document.find(key);
        if (found == cache.document.end() || !found->is_string()) return false;
        value = found->get<std::string>();
        return true;
    }

    bool ParseUnsignedText(std::string_view text, std::uint64_t& value)
    {
        const std::string raw = Trim(std::string(text));
        if (raw.empty() || raw.front() == '-')
            return false;
        std::uint64_t parsed = 0;
        const auto result = std::from_chars(raw.data(), raw.data() + raw.size(), parsed);
        if (result.ec != std::errc() || result.ptr != raw.data() + raw.size())
            return false;
        value = parsed;
        return true;
    }

    bool ExtractUnsigned(const std::string& request, const char* key, std::uint64_t& value)
    {
        auto field = Find(request, key);
        if (!field) return false;
        if (field->is_number_unsigned()) { value = field->get<std::uint64_t>(); return true; }
        if (!field->is_string()) return false;
        return ParseUnsignedText(field->get<std::string>(), value);
    }

    bool ExtractBoolean(const std::string& request, const char* key, bool& value)
    {
        auto field = Find(request, key);
        if (!field || !field->is_boolean()) return false;
        value = field->get<bool>();
        return true;
    }

    std::string Trim(const std::string& value)
    {
        auto first = value.begin(), last = value.end();
        while (first != last && std::isspace(static_cast<unsigned char>(*first))) ++first;
        while (first != last && std::isspace(static_cast<unsigned char>(*(last - 1)))) --last;
        return std::string(first, last);
    }

    std::string ToLower(const std::string& value)
    {
        std::string lowered = value;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(),
            [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
        return lowered;
    }

    bool IsValidUtf8(const std::string& text)
    {
        try { (void)Json(text).dump(); return true; }
        catch (const Json::exception&) { return false; }
    }
}
