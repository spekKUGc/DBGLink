#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    bool ReadMemory(
        std::uintptr_t address,
        std::size_t size,
        unsigned char* data,
        DbgMemReadFunction memoryRead);
    bool ReadMemory(std::uintptr_t address, std::size_t size, unsigned char* data);
    bool ReadMemory(
        std::uintptr_t address,
        std::size_t size,
        std::vector<unsigned char>& data,
        DbgMemReadFunction memoryRead);
    bool ReadMemory(std::uintptr_t address, std::size_t size, std::vector<unsigned char>& data);
    bool ReadPointerValue(DbgMemReadFunction memoryRead, std::uintptr_t address, std::uintptr_t& value);
    bool CollectModuleRecords(std::vector<ModuleRecord>& modules, bool& mapTruncated, std::string& error);
    // Shared module-table filter: exact matches first, then case-insensitive
    // substring matches. emptyMeansAll=false resolves an empty filter to the
    // CIP module (search handlers); true keeps every module (coverage).
    // "all" always keeps every module.
    std::vector<ModuleRecord> SelectModulesByFilter(
        std::vector<ModuleRecord> modules,
        const std::string& filter,
        bool emptyMeansAll);
    std::string HandleGetMemoryMap(const std::string& request, const std::string& id);
}
