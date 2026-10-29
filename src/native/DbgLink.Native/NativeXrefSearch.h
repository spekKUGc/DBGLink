#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    bool AddressInModules(std::uintptr_t address, const std::vector<ModuleRecord>& modules);
    std::string InstructionAt(std::uintptr_t address, DbgDisasmFastAtFunction disasm);
    void AddXrefMatch(
        XrefSearchResult& result,
        std::uintptr_t address,
        XrefType type,
        const char* source,
        std::size_t maxResults,
        const std::vector<ModuleRecord>* moduleFilter,
        std::unordered_set<std::uintptr_t>& seenAddresses,
        DbgDisasmFastAtFunction disasm);
    XrefSearchResult ScanXrefs(
        std::uintptr_t target,
        const std::vector<ModuleRecord>& scanModules,
        bool filterDatabase,
        bool scanFallback,
        std::size_t maxResults,
        std::size_t maxScanBytes);
}
