#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeJsonFormatting.h"
#include "NativeXrefSearch.h"

namespace dbglink
{
    bool AddressInModules(std::uintptr_t address, const std::vector<ModuleRecord>& modules)
    {
        const auto candidate = std::upper_bound(
            modules.begin(),
            modules.end(),
            address,
            [](std::uintptr_t value, const ModuleRecord& module)
            {
                return value < module.base;
            });
        if (candidate == modules.begin())
            return false;

        const auto& module = *(candidate - 1);
        return module.base < module.end && address < module.end;
    }
    std::string InstructionAt(std::uintptr_t address, DbgDisasmFastAtFunction disasm)
    {
        if (disasm == nullptr)
            return {};

        BASIC_INSTRUCTION_INFO info{};
        disasm(address, &info);
        return info.size > 0 ? SingleLine(BufferText(info.instruction, sizeof(info.instruction))) : std::string{};
    }

    void AddXrefMatch(
        XrefSearchResult& result,
        std::uintptr_t address,
        XrefType type,
        const char* source,
        std::size_t maxResults,
        const std::vector<ModuleRecord>* moduleFilter,
        std::unordered_set<std::uintptr_t>& seenAddresses,
        DbgDisasmFastAtFunction disasm)
    {
        if (address == 0 || result.matches.size() >= maxResults ||
            (moduleFilter != nullptr && !AddressInModules(address, *moduleFilter)))
        {
            return;
        }

        if (!seenAddresses.insert(address).second)
        {
            return;
        }

        result.matches.push_back(XrefMatch
        {
            address,
            type,
            source == nullptr ? std::string{} : std::string(source),
            InstructionAt(address, disasm),
        });
    }

    XrefSearchResult ScanXrefs(
        std::uintptr_t target,
        const std::vector<ModuleRecord>& scanModules,
        bool filterDatabase,
        bool scanFallback,
        std::size_t maxResults,
        std::size_t maxScanBytes)
    {
        XrefSearchResult result;
        if (target == 0 || maxResults == 0)
            return result;

        result.matches.reserve(std::min(maxResults, kMaxXrefResults));
        std::unordered_set<std::uintptr_t> seenAddresses;
        seenAddresses.reserve(std::min(maxResults, kMaxXrefResults));

        const std::vector<ModuleRecord>* databaseFilter = filterDatabase ? &scanModules : nullptr;
        auto disasm = GetDebuggerBridgeFunction<DbgDisasmFastAtFunction>("DbgDisasmFastAt");
        auto xrefCountAt = GetDebuggerBridgeFunction<DbgGetXrefCountAtFunction>("DbgGetXrefCountAt");
        auto xrefGet = GetDebuggerBridgeFunction<DbgXrefGetFunction>("DbgXrefGet");
        result.xrefDbAvailable = xrefGet != nullptr;
        if (xrefCountAt != nullptr)
            result.reportedCount = static_cast<std::size_t>(std::min<std::uintptr_t>(
                xrefCountAt(target), static_cast<std::uintptr_t>(kMaxXrefResults)));

        if (xrefGet != nullptr)
        {
            XREF_INFO info{};
            if (xrefGet(target, &info))
            {
                if (info.refcount > static_cast<std::uintptr_t>(kMaxXrefResults))
                    result.xrefDbTruncated = true;

                // Inspect the bounded database window independently from the
                // result limit. Duplicate records and module filtering can
                // otherwise consume the first maxResults entries without
                // yielding maxResults usable matches.
                const std::size_t count = static_cast<std::size_t>(std::min<std::uintptr_t>(
                    info.refcount,
                    static_cast<std::uintptr_t>(kMaxXrefResults)));
                const auto referencesAddress = reinterpret_cast<std::uintptr_t>(info.references);
                const auto maxAddress = std::numeric_limits<std::uintptr_t>::max();
                const bool referencesFit = count == 0 ||
                    (referencesAddress != 0 &&
                        count <= maxAddress / sizeof(XREF_RECORD) &&
                        referencesAddress <= maxAddress - count * sizeof(XREF_RECORD));
                if ((info.refcount > 0 && info.references == nullptr) || !referencesFit)
                {
                    result.xrefDbMalformed = true;
                }
                else
                {
                    for (std::size_t index = 0; index < count; ++index)
                    {
                        const auto& reference = info.references[index];
                        AddXrefMatch(
                            result,
                            reference.address,
                            reference.type,
                            "x64dbg-xref-db",
                            maxResults,
                            databaseFilter,
                            seenAddresses,
                            disasm);
                    }
                }
            }
        }

        if (!scanFallback || result.matches.size() >= maxResults)
            return result;

        result.scanFallbackUsed = true;
        if (disasm == nullptr)
        {
            result.scanFallbackUnavailable = true;
            return result;
        }

        std::size_t remainingBudget = maxScanBytes;
        for (std::size_t moduleIndex = 0;
             moduleIndex < scanModules.size() && remainingBudget > 0 && result.matches.size() < maxResults;
             ++moduleIndex)
        {
            const auto& module = scanModules[moduleIndex];
            if (module.base == 0 || module.end <= module.base)
                continue;

            const auto moduleSize = static_cast<std::uint64_t>(module.end - module.base);
            const std::size_t scanLimit = static_cast<std::size_t>(std::min<std::uint64_t>(
                moduleSize,
                static_cast<std::uint64_t>(remainingBudget)));
            if (scanLimit < moduleSize)
                result.scanTruncated = true;

            std::size_t offset = 0;
            std::size_t badInstructionBytes = 0;
            while (offset < scanLimit && result.matches.size() < maxResults)
            {
                std::uintptr_t current = 0;
                if (!TryAddAddress(module.base, offset, current))
                {
                    result.addressOverflow = true;
                    break;
                }

                BASIC_INSTRUCTION_INFO info{};
                disasm(current, &info);
                if (info.size <= 0 || info.size > 64)
                {
                    ++badInstructionBytes;
                    if (badInstructionBytes > 4096)
                    {
                        result.scanTruncated = true;
                        break;
                    }

                    ++offset;
                    continue;
                }

                badInstructionBytes = 0;
                const bool matches =
                    ((info.type & 4u) != 0 && info.addr == target) ||
                    ((info.type & 1u) != 0 && info.value.value == target) ||
                    ((info.type & 2u) != 0 && info.memory.value == target);
                if (matches)
                {
                    AddXrefMatch(
                        result,
                        current,
                        XrefType::None,
                        "disassembly-scan",
                        maxResults,
                        nullptr,
                        seenAddresses,
                        disasm);
                }

                const std::size_t step = std::min<std::size_t>(
                    static_cast<std::size_t>(info.size),
                    scanLimit - offset);
                if (step == 0)
                    break;
                offset += step;
            }

            result.scannedBytes += offset;
            if (offset < scanLimit)
                result.scanTruncated = true;
            remainingBudget -= std::min(remainingBudget, offset);
            if (moduleIndex + 1 < scanModules.size() && remainingBudget == 0)
                result.scanTruncated = true;
        }

        return result;
    }

}
