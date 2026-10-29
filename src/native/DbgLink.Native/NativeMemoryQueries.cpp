#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeInspectionHandlers.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeAnalysisData.h"
#include "NativeRequestParams.h"
#include <psapi.h>

namespace dbglink
{
    namespace
    {
        constexpr ULONGLONG kModuleCacheMilliseconds = 1'000;
        std::vector<ModuleRecord> g_cachedModules;
        bool g_cachedMapTruncated = false;
        std::uint64_t g_cachedGeneration = 0;
        ULONGLONG g_cachedModulesExpiresAt = 0;
        bool g_hasCachedModules = false;
    }

    std::string ProcessModulePath(std::uintptr_t moduleBase)
    {
        auto getProcessHandle = GetDebuggerBridgeFunction<DbgGetProcessHandleFunction>("DbgGetProcessHandle");
        if (getProcessHandle == nullptr || moduleBase == 0)
            return {};

        const HANDLE process = getProcessHandle();
        if (process == nullptr || process == INVALID_HANDLE_VALUE)
            return {};

        // The module path can be up to 32K wchars; keep the large scratch off
        // the thread stack (a 64 KB frame risks STATUS_STACK_OVERFLOW in
        // constrained plugin threads).
        std::vector<wchar_t> buffer(32768);
        const DWORD length = GetModuleFileNameExW(
            process,
            reinterpret_cast<HMODULE>(moduleBase),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (length == 0 || length >= buffer.size())
            return {};

        const int utf8Length = WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            buffer.data(),
            static_cast<int>(length),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (utf8Length <= 0 || utf8Length > 32760)
            return {};

        std::string result(static_cast<std::size_t>(utf8Length), '\0');
        if (WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                buffer.data(),
                static_cast<int>(length),
                result.data(),
                utf8Length,
                nullptr,
                nullptr) != utf8Length)
            return {};
        return result;
    }

    bool ReadMemory(
        std::uintptr_t address,
        std::size_t size,
        unsigned char* data,
        DbgMemReadFunction memoryRead)
    {
        if (size == 0 || size > kMaxMemoryReadBytes || data == nullptr ||
            memoryRead == nullptr || !AddressRangeFits(address, size))
            return false;

        return memoryRead(address, data, static_cast<std::uintptr_t>(size));
    }

    bool ReadMemory(std::uintptr_t address, std::size_t size, unsigned char* data)
    {
        return ReadMemory(
            address,
            size,
            data,
            GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead"));
    }

    bool ReadMemory(
        std::uintptr_t address,
        std::size_t size,
        std::vector<unsigned char>& data,
        DbgMemReadFunction memoryRead)
    {
        if (size == 0 || size > kMaxMemoryReadBytes)
            return false;

        if (data.size() != size)
            data.resize(size);
        return ReadMemory(address, size, data.data(), memoryRead);
    }

    bool ReadMemory(std::uintptr_t address, std::size_t size, std::vector<unsigned char>& data)
    {
        return ReadMemory(
            address,
            size,
            data,
            GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead"));
    }

    bool ReadPointerValue(DbgMemReadFunction memoryRead, std::uintptr_t address, std::uintptr_t& value)
    {
        if (memoryRead == nullptr || !AddressRangeFits(address, sizeof(std::uintptr_t)))
            return false;

        unsigned char bytes[sizeof(std::uintptr_t)]{};
        if (!memoryRead(address, bytes, static_cast<std::uintptr_t>(sizeof(bytes))))
            return false;

        value = BytesToUintPtr(bytes, sizeof(bytes));
        return true;
    }

    bool CollectModuleRecords(std::vector<ModuleRecord>& modules, bool& mapTruncated, std::string& error)
    {
        modules.clear();
        mapTruncated = false;
        error.clear();

        const auto generation = g_debuggerGeneration.load();
        if (g_hasCachedModules && g_cachedGeneration == generation &&
            GetTickCount64() < g_cachedModulesExpiresAt)
        {
            modules = g_cachedModules;
            mapTruncated = g_cachedMapTruncated;
            return true;
        }

        auto memoryMap = GetDebuggerBridgeFunction<DbgMemMapFunction>("DbgMemMap");
        auto bridgeFree = GetDebuggerBridgeFunction<BridgeFreeFunction>("BridgeFree");
        if (memoryMap == nullptr || bridgeFree == nullptr)
        {
            error = "x64dbg memory-map exports are unavailable.";
            return false;
        }

        BridgeMemoryMapGuard mapGuard;
        mapGuard.freeFunction = bridgeFree;
        if (!memoryMap(&mapGuard.map))
        {
            error = "x64dbg memory map request failed.";
            return false;
        }

        if (mapGuard.map.count < 0)
        {
            error = "x64dbg returned an invalid memory-map count.";
            return false;
        }
        if (mapGuard.map.count > static_cast<int>(kMaxModuleMapEntries))
            mapTruncated = true;
        if (mapGuard.map.count > 0 && mapGuard.map.page == nullptr)
        {
            error = "x64dbg returned a null memory-map buffer.";
            return false;
        }

        const std::size_t pageCount = std::min<std::size_t>(
            static_cast<std::size_t>(mapGuard.map.count), kMaxModuleMapEntries);
        const auto maxAddress = std::numeric_limits<std::uintptr_t>::max();
        const auto pageAddress = reinterpret_cast<std::uintptr_t>(mapGuard.map.page);
        if (pageCount > 0 &&
            (pageAddress == 0 ||
                pageCount > maxAddress / sizeof(BRIDGE_MEMORY_PAGE) ||
                pageAddress > maxAddress - pageCount * sizeof(BRIDGE_MEMORY_PAGE)))
        {
            error = "x64dbg returned an invalid memory-map buffer.";
            return false;
        }

        std::unordered_map<std::uintptr_t, std::size_t> moduleIndexes;
        moduleIndexes.reserve(pageCount);

        for (std::size_t index = 0; index < pageCount; ++index)
        {
            const auto& page = mapGuard.map.page[index];
            if (page.mbi.Type != MEM_IMAGE || page.mbi.RegionSize == 0)
                continue;

            const auto allocationBase = reinterpret_cast<std::uintptr_t>(page.mbi.AllocationBase);
            const auto regionBase = reinterpret_cast<std::uintptr_t>(page.mbi.BaseAddress);
            const auto regionSize = static_cast<std::uintptr_t>(page.mbi.RegionSize);
            if (allocationBase == 0 || regionSize == 0 || regionBase > maxAddress - regionSize)
                continue;

            const auto regionEnd = regionBase + regionSize;
            const auto [moduleIndex, inserted] = moduleIndexes.emplace(allocationBase, modules.size());
            if (inserted)
            {
                const std::string pageInfo = Trim(SingleLine(BufferText(page.info, kMaxModuleSize)));
                modules.push_back(ModuleRecord
                {
                    allocationBase,
                    regionEnd,
                    {},
                    pageInfo,
                });
            }
            else
            {
                auto& existing = modules[moduleIndex->second];
                existing.end = std::max(existing.end, regionEnd);
                if (existing.path.empty())
                {
                    const std::string pageInfo = Trim(SingleLine(BufferText(page.info, kMaxModuleSize)));
                    if (!pageInfo.empty())
                        existing.path = pageInfo;
                }
            }
        }

        std::sort(modules.begin(), modules.end(), [](const ModuleRecord& left, const ModuleRecord& right)
        {
            return left.base < right.base;
        });

        auto getModuleAt = GetDebuggerBridgeFunction<DbgGetModuleAtFunction>("DbgGetModuleAt");
        for (auto& module : modules)
        {
            const auto processPath = ProcessModulePath(module.base);
            if (!processPath.empty())
                module.path = processPath;
            if (getModuleAt != nullptr)
            {
                char nameBuffer[kMaxModuleSize]{};
                if (getModuleAt(module.base, nameBuffer))
                    module.name = Trim(SingleLine(BufferText(nameBuffer, kMaxModuleSize)));
            }
            if (module.name.empty())
                module.name = FileNameFromPath(module.path);
            if (module.name.empty())
                module.name = "<unknown>";
            if (module.path.empty())
                module.path = module.name;
        }

        g_cachedModules = modules;
        g_cachedMapTruncated = mapTruncated;
        g_cachedGeneration = generation;
        g_cachedModulesExpiresAt = GetTickCount64() + kModuleCacheMilliseconds;
        g_hasCachedModules = true;

        return true;
    }

    std::vector<ModuleRecord> SelectModulesByFilter(
        std::vector<ModuleRecord> modules,
        const std::string& filter,
        bool emptyMeansAll)
    {
        if (EqualsInsensitive(filter, "all"))
            return modules;

        if (filter.empty())
        {
            // Coverage aggregates across the whole module table by default;
            // search handlers resolve an omitted filter to the CIP module.
            if (emptyMeansAll)
                return modules;
            std::uintptr_t cip = 0;
            if (auto valueFromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString"))
                cip = valueFromString("cip");

            for (auto& module : modules)
            {
                if (module.base < module.end && cip >= module.base && cip < module.end)
                {
                    std::vector<ModuleRecord> selected;
                    selected.push_back(std::move(module));
                    return selected;
                }
            }

            if (!modules.empty())
            {
                std::vector<ModuleRecord> selected;
                selected.push_back(std::move(modules.front()));
                return selected;
            }
            return {};
        }

        std::vector<ModuleRecord> exact;
        for (auto& module : modules)
        {
            if (EqualsInsensitive(module.name, filter) ||
                EqualsInsensitive(FileNameFromPath(module.path), filter) ||
                EqualsInsensitive(module.path, filter))
                exact.push_back(std::move(module));
        }
        if (!exact.empty())
            return exact;

        std::vector<ModuleRecord> partial;
        for (auto& module : modules)
        {
            if (ContainsInsensitive(module.name, filter) || ContainsInsensitive(module.path, filter))
                partial.push_back(std::move(module));
        }
        return partial;
    }

    namespace
    {
        std::string FormatProtectString(DWORD protect)
        {
            std::string s;
            const DWORD base = protect & 0xFF;
            switch (base)
            {
            case PAGE_NOACCESS: s = "PAGE_NOACCESS"; break;
            case PAGE_READONLY: s = "PAGE_READONLY"; break;
            case PAGE_READWRITE: s = "PAGE_READWRITE"; break;
            case PAGE_WRITECOPY: s = "PAGE_WRITECOPY"; break;
            case PAGE_EXECUTE: s = "PAGE_EXECUTE"; break;
            case PAGE_EXECUTE_READ: s = "PAGE_EXECUTE_READ"; break;
            case PAGE_EXECUTE_READWRITE: s = "PAGE_EXECUTE_READWRITE"; break;
            case PAGE_EXECUTE_WRITECOPY: s = "PAGE_EXECUTE_WRITECOPY"; break;
            default: s = "PAGE_UNKNOWN"; break;
            }
            if (protect & PAGE_GUARD) s += "|PAGE_GUARD";
            if (protect & PAGE_NOCACHE) s += "|PAGE_NOCACHE";
            if (protect & PAGE_WRITECOMBINE) s += "|PAGE_WRITECOMBINE";
            return s;
        }

        std::string FormatTypeString(DWORD type)
        {
            switch (type)
            {
            case MEM_IMAGE: return "image";
            case MEM_MAPPED: return "mapped";
            case MEM_PRIVATE: return "private";
            default: return "unknown";
            }
        }

        std::string FormatStateString(DWORD state)
        {
            switch (state)
            {
            case MEM_COMMIT: return "commit";
            case MEM_RESERVE: return "reserve";
            case MEM_FREE: return "free";
            default: return "unknown";
            }
        }
    }

    std::string HandleGetMemoryMap(const std::string& request, const std::string& id)
    {
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");

        const RequestParams params(request);
        bool executableOnly = false;
        if (auto error = params.OptionalBoolean("executableOnly", executableOnly,
                "GetMemoryMap executableOnly must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        bool rwxOnly = false;
        if (auto error = params.OptionalBoolean("rwxOnly", rwxOnly,
                "GetMemoryMap rwxOnly must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        std::string typeFilter;
        if (auto error = params.OptionalString("type", typeFilter, "GetMemoryMap type must be a string."); !error.empty())
            return ErrorResponse(id, error);

        typeFilter = Trim(ToLower(typeFilter));

        std::uint64_t offset = 0;
        if (auto error = params.OptionalUnsigned("offset", offset,
                "GetMemoryMap offset must be an unsigned integer."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxItems = 128;
        if (auto error = params.OptionalUnsigned("maxItems", maxItems,
                "GetMemoryMap maxItems must be an unsigned integer."); !error.empty())
            return ErrorResponse(id, error);
        if (maxItems == 0) maxItems = 1;
        if (maxItems > 512) maxItems = 512;

        // Token-light protect opt-in (default off): the human-readable
        // protect string stays by default; fullProtect=true restores the
        // machine-readable protectValue/isExecutable/isRwx triple for
        // callers that filter on it.
        bool fullProtect = false;
        if (auto error = params.OptionalBoolean("fullProtect", fullProtect,
                "GetMemoryMap fullProtect must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        auto memoryMap = GetDebuggerBridgeFunction<DbgMemMapFunction>("DbgMemMap");
        auto bridgeFree = GetDebuggerBridgeFunction<BridgeFreeFunction>("BridgeFree");
        if (memoryMap == nullptr || bridgeFree == nullptr)
            return ErrorResponse(id, "x64dbg memory-map exports are unavailable.");

        BridgeMemoryMapGuard mapGuard;
        mapGuard.freeFunction = bridgeFree;
        if (!memoryMap(&mapGuard.map))
            return ErrorResponse(id, "x64dbg memory map request failed.");
        // SEC N5: same shared guard as CollectModuleRecords above — a hostile
        // or corrupt count must not become an unbounded page walk, and a null
        // page buffer must not be indexed. Wire message unchanged.
        if (!ValidateBridgeList(
                mapGuard.map.count,
                mapGuard.map.page,
                static_cast<int>(kMaxModuleMapEntries)))
            return ErrorResponse(id, "x64dbg memory map request failed.");

        const std::size_t pageCount = static_cast<std::size_t>(mapGuard.map.count);
        // Overflow-safe buffer-range math, mirroring CollectModuleRecords: the
        // count is capped above, but the base pointer itself is untrusted.
        const auto maxAddress = std::numeric_limits<std::uintptr_t>::max();
        const auto pageAddress = reinterpret_cast<std::uintptr_t>(mapGuard.map.page);
        if (pageCount > 0 &&
            (pageAddress == 0 ||
                pageCount > maxAddress / sizeof(BRIDGE_MEMORY_PAGE) ||
                pageAddress > maxAddress - pageCount * sizeof(BRIDGE_MEMORY_PAGE)))
            return ErrorResponse(id, "x64dbg memory map request failed.");
        nlohmann::json pages = nlohmann::json::array();
        std::size_t matchedCount = 0;

        for (std::size_t i = 0; i < pageCount; ++i)
        {
            const auto& page = mapGuard.map.page[i];
            const DWORD protect = page.mbi.Protect;
            const bool isExec = (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            const bool isRwx = (protect & PAGE_EXECUTE_READWRITE) != 0;

            if (executableOnly && !isExec)
                continue;
            if (rwxOnly && !isRwx)
                continue;

            const std::string typeStr = FormatTypeString(page.mbi.Type);
            if (!typeFilter.empty() && typeFilter != "all" && typeStr != typeFilter)
                continue;

            if (matchedCount >= offset && pages.size() < maxItems)
            {
                const auto baseAddr = reinterpret_cast<std::uintptr_t>(page.mbi.BaseAddress);
                const auto allocBase = reinterpret_cast<std::uintptr_t>(page.mbi.AllocationBase);
                // Single protect representation by default: the human-readable
                // string. fullProtect=true restores the machine-readable
                // triple alongside it (same keys as before the slimming).
                nlohmann::json item{
                    {"baseAddress", HexAddress(baseAddr)},
                    {"allocationBase", HexAddress(allocBase)},
                    {"regionSize", page.mbi.RegionSize},
                    {"state", FormatStateString(page.mbi.State)},
                    {"protect", FormatProtectString(protect)},
                    {"type", typeStr},
                };
                if (fullProtect)
                {
                    item["protectValue"] = protect;
                    item["isExecutable"] = isExec;
                    item["isRwx"] = isRwx;
                }
                std::string infoStr = page.info;
                if (!infoStr.empty())
                    item["info"] = infoStr;
                pages.push_back(std::move(item));
            }
            ++matchedCount;
        }

        // Truncation math matches ComputePageWindow; the memory-map reply keeps
        // its own envelope shape and only reports nextOffset when truncated.
        const PageWindow window = ComputePageWindow(offset, maxItems, matchedCount);
        const bool truncated = window.truncated;
        nlohmann::json result{
            {"pages", std::move(pages)},
            {"totalMatched", matchedCount},
            {"offset", offset},
            {"truncated", truncated},
        };
        if (truncated)
            result["nextOffset"] = offset + maxItems;

        return SuccessResponse(id, result);
    }

}
