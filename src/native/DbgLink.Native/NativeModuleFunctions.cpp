#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeHexFormat.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeModuleFunctions.h"
#include "NativeRequestParams.h"

namespace dbglink
{
    namespace
    {
        constexpr std::uint64_t kDefaultModuleFunctionItems = 512;
        constexpr std::uint64_t kMaxModuleFunctionItems = 4096;
        // Byte-step walk over one module with DbgFunctionGet: gaps without
        // analysis data cost one probe per byte, so a hard probe budget keeps
        // the handler bounded under the debugger mutex. Hitting it reports
        // truncated=true instead of silently returning a partial list.
        constexpr std::size_t kMaxFunctionWalkProbes = 262144;
        // Serialized function rows must stay well under the 256 KiB pipe cap
        // even at maxItems=4096 (a full page averages ~80 chars per row).
        constexpr std::size_t kFunctionOutputBudgetChars = 192 * 1024;
        constexpr std::size_t kMaxExportNameChars = 256;

        struct ModuleFunctionEntry
        {
            std::uintptr_t entry = 0;
            std::string name;
            std::uintptr_t end = 0;
            bool hasEnd = false;
        };

        std::uint16_t ReadU16(const std::vector<unsigned char>& data, std::size_t offset)
        {
            return static_cast<std::uint16_t>(data[offset] | (static_cast<std::uint16_t>(data[offset + 1]) << 8));
        }

        std::uint32_t ReadU32(const std::vector<unsigned char>& data, std::size_t offset)
        {
            return static_cast<std::uint32_t>(data[offset]) |
                (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
                (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
                (static_cast<std::uint32_t>(data[offset + 3]) << 24);
        }

        bool ReadRemoteU32(std::uintptr_t address, std::uint32_t& value)
        {
            std::vector<unsigned char> data;
            if (!ReadMemory(address, sizeof(std::uint32_t), data) || data.size() != sizeof(std::uint32_t))
                return false;
            value = ReadU32(data, 0);
            return true;
        }

        // True when [address, address+size) lies inside [base, end).
        bool RangeInModule(std::uintptr_t base, std::uintptr_t end, std::uintptr_t address, std::size_t size)
        {
            if (end <= base || address < base || address >= end)
                return false;
            const auto remaining = static_cast<std::size_t>(end - address);
            return size <= remaining;
        }

        std::string ModuleLabel(const ModuleRecord& module)
        {
            return module.name.empty() ? module.path : module.name;
        }

        void CollectWalkFunctions(
            const ModuleRecord& target,
            DbgFunctionGetFunction functionGet,
            DbgGetLabelAtFunction labelAt,
            std::size_t limit,
            std::vector<ModuleFunctionEntry>& entries,
            bool& rangeComplete)
        {
            entries.clear();
            rangeComplete = false;
            std::uintptr_t cursor = target.base;
            std::size_t probes = 0;
            while (cursor < target.end && entries.size() < limit && probes < kMaxFunctionWalkProbes)
            {
                ++probes;
                std::uintptr_t start = 0;
                std::uintptr_t end = 0;
                if (functionGet(cursor, &start, &end) && end > start &&
                    start >= target.base && start < target.end)
                {
                    std::string name;
                    if (labelAt != nullptr)
                    {
                        char buffer[kMaxModuleSize]{};
                        if (labelAt(start, 0, buffer))
                            name = Trim(SingleLine(BufferText(buffer, kMaxModuleSize)));
                    }
                    entries.push_back(ModuleFunctionEntry{start, name, end, true});
                    cursor = end > cursor ? end : cursor + 1;
                }
                else
                {
                    // A miss still advances: gaps without analysis data are
                    // skipped one byte at a time under the probe budget above.
                    // cursor < target.end <= max keeps cursor + 1 wraparound-free.
                    ++cursor;
                }
            }
            rangeComplete = cursor >= target.end;
        }

        bool CollectExportFunctions(
            const ModuleRecord& target,
            std::size_t limit,
            std::vector<ModuleFunctionEntry>& entries,
            bool& truncated,
            std::string& error)
        {
            entries.clear();
            truncated = false;
            const auto moduleSize = static_cast<std::size_t>(target.end - target.base);

            std::vector<unsigned char> dos;
            if (!ReadMemory(target.base, 64, dos) || dos.size() < 64 ||
                dos[0] != 'M' || dos[1] != 'Z')
            {
                error = "GetModuleFunctions: could not read the module DOS header.";
                return false;
            }
            const std::uint32_t e_lfanew = ReadU32(dos, 0x3C);
            if (e_lfanew > 1024 * 1024 || !RangeInModule(target.base, target.end, target.base + e_lfanew, 64))
            {
                error = "GetModuleFunctions: the module NT headers are outside the module range.";
                return false;
            }
            const std::uintptr_t ntAddress = target.base + e_lfanew;
            std::vector<unsigned char> nt;
            if (!ReadMemory(ntAddress, 64, nt) || nt.size() < 64 ||
                ReadU32(nt, 0) != 0x00004550)
            {
                error = "GetModuleFunctions: the module NT signature is unreadable.";
                return false;
            }
            const std::uint16_t magic = ReadU16(nt, 24);
            const std::size_t dataDirectoryOffset = magic == 0x20B ? 112 : magic == 0x10B ? 96 : 0;
            if (dataDirectoryOffset == 0)
            {
                error = "GetModuleFunctions: unsupported module optional-header magic.";
                return false;
            }
            std::vector<unsigned char> directory;
            if (!ReadMemory(ntAddress + 24 + dataDirectoryOffset, 8, directory) || directory.size() < 8)
            {
                error = "GetModuleFunctions: the module export directory pointer is unreadable.";
                return false;
            }
            const std::uint32_t exportRva = ReadU32(directory, 0);
            const std::uint32_t exportSize = ReadU32(directory, 4);
            if (exportRva == 0)
            {
                error = "GetModuleFunctions: the module has no export table.";
                return false;
            }
            std::uintptr_t exportAddress = 0;
            if (!TryAddAddress(target.base, exportRva, exportAddress) ||
                !RangeInModule(target.base, target.end, exportAddress, 40))
            {
                error = "GetModuleFunctions: the module export directory is outside the module range.";
                return false;
            }
            std::vector<unsigned char> exportDirectory;
            if (!ReadMemory(exportAddress, 40, exportDirectory) || exportDirectory.size() < 40)
            {
                error = "GetModuleFunctions: the module export directory is unreadable.";
                return false;
            }
            const std::uint32_t numberOfNames = ReadU32(exportDirectory, 24);
            const std::uint32_t numberOfFunctions = ReadU32(exportDirectory, 20);
            const std::uint32_t addressOfFunctions = ReadU32(exportDirectory, 28);
            const std::uint32_t addressOfNames = ReadU32(exportDirectory, 32);
            const std::uint32_t addressOfNameOrdinals = ReadU32(exportDirectory, 36);
            if (numberOfNames == 0)
                return true;
            if (numberOfNames > 1024 * 1024)
            {
                error = "GetModuleFunctions: the module export name count is implausible.";
                return false;
            }
            // m4: a corrupt numberOfFunctions would otherwise admit ordinals
            // up to 2^32-1; the functionOffset math below is ordinal-bound
            // (uint16, so no overflow), but the ordinal gate itself must not
            // trust an unbounded count. Same 1M cap as the name count.
            if (numberOfFunctions > 1024 * 1024)
            {
                error = "GetModuleFunctions: the module export function count is implausible.";
                return false;
            }
            const std::size_t namesToRead = std::min<std::size_t>(numberOfNames, limit);
            truncated = static_cast<std::uint64_t>(numberOfNames) > limit;
            std::uintptr_t namesAddress = 0;
            std::uintptr_t ordinalsAddress = 0;
            std::uintptr_t functionsAddress = 0;
            if (!TryAddAddress(target.base, addressOfNames, namesAddress) ||
                !RangeInModule(target.base, target.end, namesAddress, namesToRead * sizeof(std::uint32_t)) ||
                !TryAddAddress(target.base, addressOfNameOrdinals, ordinalsAddress) ||
                !RangeInModule(target.base, target.end, ordinalsAddress, namesToRead * sizeof(std::uint16_t)) ||
                !TryAddAddress(target.base, addressOfFunctions, functionsAddress) ||
                functionsAddress < target.base || functionsAddress >= target.end)
            {
                error = "GetModuleFunctions: the module export tables are outside the module range.";
                return false;
            }
            std::vector<unsigned char> names;
            std::vector<unsigned char> ordinals;
            if (!ReadMemory(namesAddress, namesToRead * sizeof(std::uint32_t), names) ||
                names.size() != namesToRead * sizeof(std::uint32_t) ||
                !ReadMemory(ordinalsAddress, namesToRead * sizeof(std::uint16_t), ordinals) ||
                ordinals.size() != namesToRead * sizeof(std::uint16_t))
            {
                error = "GetModuleFunctions: the module export name tables are unreadable.";
                return false;
            }
            const std::size_t functionTableBytes = moduleSize - static_cast<std::size_t>(functionsAddress - target.base);
            for (std::size_t index = 0; index < namesToRead; ++index)
            {
                const std::uint32_t nameRva = ReadU32(names, index * sizeof(std::uint32_t));
                const std::uint16_t ordinal = static_cast<std::uint16_t>(ordinals[index * 2] |
                    (static_cast<std::uint16_t>(ordinals[index * 2 + 1]) << 8));
                if (ordinal >= numberOfFunctions)
                    continue;
                // m4: ordinal is uint16 so the product cannot overflow, but
                // keep the arithmetic in 64 bits so a future widening of the
                // ordinal type cannot reintroduce a narrowing bug.
                const std::uint64_t functionOffset =
                    static_cast<std::uint64_t>(ordinal) * sizeof(std::uint32_t);
                if (functionOffset + sizeof(std::uint32_t) >
                    static_cast<std::uint64_t>(functionTableBytes))
                    continue;
                std::uint32_t functionRva = 0;
                if (!ReadRemoteU32(functionsAddress + static_cast<std::size_t>(functionOffset), functionRva))
                    continue;
                std::uintptr_t nameAddress = 0;
                if (!TryAddAddress(target.base, nameRva, nameAddress) ||
                    !RangeInModule(target.base, target.end, nameAddress, 1))
                    continue;
                const std::size_t nameLimit = std::min<std::size_t>(
                    kMaxExportNameChars, static_cast<std::size_t>(target.end - nameAddress));
                std::vector<unsigned char> nameBytes;
                if (!ReadMemory(nameAddress, nameLimit, nameBytes) || nameBytes.empty())
                    continue;
                std::size_t nameLength = 0;
                while (nameLength < nameBytes.size() && nameBytes[nameLength] != 0)
                    ++nameLength;
                if (nameLength == 0 || nameLength >= nameBytes.size())
                    continue;
                std::uintptr_t entry = 0;
                if (!TryAddAddress(target.base, functionRva, entry) ||
                    entry < target.base || entry >= target.end)
                    continue;
                // A forwarded export's RVA points at a forwarder string inside
                // the export directory block, not at code: skip it instead of
                // reporting a fake function entry. Guard on a plausible size so
                // a corrupt exportSize cannot swallow real exports.
                if (exportSize != 0 && exportSize <= moduleSize && functionRva >= exportRva &&
                    static_cast<std::uint64_t>(functionRva) <
                        static_cast<std::uint64_t>(exportRva) + exportSize)
                    continue;
                entries.push_back(ModuleFunctionEntry{
                    entry, std::string(reinterpret_cast<const char*>(nameBytes.data()), nameLength), 0, false});
            }
            return true;
        }
    }

    std::string HandleGetModuleFunctions(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string module;
        if (auto error = params.OptionalModuleFilter("module", module,
                "GetModuleFunctions module must be a string.",
                "GetModuleFunctions module must be at most 256 printable bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxItems = kDefaultModuleFunctionItems;
        if (auto error = params.BoundedUnsigned("maxItems", maxItems, 1, kMaxModuleFunctionItems,
                "GetModuleFunctions maxItems must be between 1 and 4096."); !error.empty())
            return ErrorResponse(id, error);

        std::vector<ModuleRecord> modules;
        bool mapTruncated = false;
        std::string error;
        if (!CollectModuleRecords(modules, mapTruncated, error))
            return ErrorResponse(id, std::string("GetModuleFunctions: ") + error);

        const auto selected = SelectModulesByFilter(std::move(modules), module, false);
        if (selected.empty())
            return ErrorResponse(id, "GetModuleFunctions: no loaded module matches '" +
                SingleLine(module) + "'.");
        if (selected.size() > 1)
            return ErrorResponse(id, "GetModuleFunctions: '" + SingleLine(module) +
                "' matches " + std::to_string(selected.size()) +
                " modules; specify a single module.");
        const auto& target = selected.front();
        const std::size_t limit = static_cast<std::size_t>(maxItems);

        std::vector<ModuleFunctionEntry> entries;
        std::string source;
        bool truncated = false;
        if (auto functionGet = GetDebuggerBridgeFunction<DbgFunctionGetFunction>("DbgFunctionGet"))
        {
            const auto labelAt = GetDebuggerBridgeFunction<DbgGetLabelAtFunction>("DbgGetLabelAt");
            bool rangeComplete = false;
            CollectWalkFunctions(target, functionGet, labelAt, limit, entries, rangeComplete);
            source = "x64dbg";
            truncated = !rangeComplete;
        }
        else
        {
            std::string exportError;
            if (!CollectExportFunctions(target, limit, entries, truncated, exportError))
                return ErrorResponse(id, exportError);
            source = "exports";
        }

        nlohmann::json functions = nlohmann::json::array();
        std::size_t outputChars = 0;
        for (const auto& entry : entries)
        {
            // Rows stop before the pipe cap: a full 4096-row page would
            // otherwise exceed the 256 KiB bounded response size.
            outputChars += 80 + entry.name.size();
            if (outputChars > kFunctionOutputBudgetChars)
            {
                truncated = true;
                break;
            }
            nlohmann::json item{
                {"entry", HexAddress(entry.entry)},
                {"rva", HexAddress(entry.entry - target.base)},
                {"name", entry.name},
            };
            if (entry.hasEnd)
                item["end"] = HexAddress(entry.end);
            functions.push_back(std::move(item));
        }

        const auto returnedCount = functions.size();
        // Like the sibling list handlers (FormatModuleRecords): a truncated
        // module map truncates the answer, so fold it into truncated and
        // report mapTruncated alongside instead of discarding it.
        truncated = truncated || mapTruncated;
        const nlohmann::json result{
            {"schemaVersion", 1},
            {"module",
             {{"name", ModuleLabel(target)},
              {"path", target.path},
              {"base", HexAddress(target.base)},
              {"end", HexAddress(target.end)}}},
            {"source", source},
            {"functions", std::move(functions)},
            {"returnedCount", returnedCount},
            {"truncated", truncated},
            {"mapTruncated", mapTruncated},
        };
        return SuccessResponse(id, result);
    }
}
