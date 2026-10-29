#pragma once
#include "NativeTypes.h"
#include "NativeHexFormat.h"
#include "NativeJsonFormatting.h"
#include "third_party/nlohmann/json.hpp"

namespace dbglink
{
    // Shared by the live handler and the debugger-independent regression harness.
    inline bool TryDecodePrintableUtf16(const std::vector<unsigned char>& data, std::string& value)
    {
        value.clear();
        std::string decoded;
        auto unitAt = [&data](std::size_t offset) -> std::uint32_t
        {
            return data[offset] | (static_cast<std::uint32_t>(data[offset + 1]) << 8);
        };
        for (std::size_t offset = 0; offset + 1 < data.size(); offset += 2)
        {
            auto code = unitAt(offset);
            if (code == 0)
            {
                value = std::move(decoded);
                return !value.empty();
            }
            if ((code < 0x20 && code != '\r' && code != '\n' && code != '\t') ||
                (code >= 0x7F && code <= 0x9F) || code == 0xFFFE || code == 0xFFFF)
                return false;
            if (code >= 0xD800 && code <= 0xDBFF)
            {
                if (offset + 3 >= data.size()) return false;
                const auto low = unitAt(offset + 2);
                if (low < 0xDC00 || low > 0xDFFF) return false;
                code = 0x10000 + ((code - 0xD800) << 10) + low - 0xDC00;
                offset += 2;
            }
            else if (code >= 0xDC00 && code <= 0xDFFF) return false;

            if (code < 0x80) decoded.push_back(static_cast<char>(code));
            else
            {
                if (code >= 0x10000)
                {
                    decoded.push_back(static_cast<char>(0xF0 | (code >> 18)));
                    decoded.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
                }
                else if (code >= 0x800) decoded.push_back(static_cast<char>(0xE0 | (code >> 12)));
                else decoded.push_back(static_cast<char>(0xC0 | (code >> 6)));
                if (code >= 0x800) decoded.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                decoded.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            }
        }
        return false; // A complete NUL-terminated string is required.
    }

    inline std::string FormatModuleRecords(const std::string& id,
        const std::vector<ModuleRecord>& modules, bool mapTruncated, const std::string& modulePath,
        std::size_t maxBytes = kMaxModuleOutputChars)
    {
        const auto selectedName = FileNameFromPath(modulePath);
        std::string records;
        std::size_t matched = 0, returned = 0;
        bool outputTruncated = false;
        for (const auto& module : modules)
        {
            // Filter the complete collected map BEFORE applying the output budget.
            if (!selectedName.empty() && _stricmp(selectedName.c_str(), FileNameFromPath(module.path).c_str()) != 0)
                continue;
            ++matched;
            const auto record = nlohmann::json{{"base", HexAddress(module.base)},
                {"end", HexAddress(module.end)},
                {"name", module.name}, {"path", module.path}}.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            if (outputTruncated || records.size() + record.size() + 512 > maxBytes)
            {
                outputTruncated = true;
                continue;
            }
            if (!records.empty()) records += ',';
            records += record;
            ++returned;
        }
        return "{\"id\":" + id + ",\"ok\":true,\"result\":{\"schemaVersion\":1,\"modules\":[" + records +
            "],\"matchedCount\":" + std::to_string(matched) + ",\"returnedCount\":" + std::to_string(returned) +
            ",\"mapTruncated\":" + (mapTruncated ? "true" : "false") +
            ",\"truncated\":" + (mapTruncated || outputTruncated ? "true" : "false") + "}}";
    }
}
