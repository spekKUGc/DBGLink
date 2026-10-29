#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    bool ParseMaskedBytePattern(
        const std::string& pattern,
        MaskedBytePattern& parsed,
        std::string& error);
    ByteSearchResult ScanMaskedBytePattern(
        const std::vector<ModuleRecord>& modules,
        const MaskedBytePattern& pattern,
        std::size_t maxResults,
        std::size_t maxScanBytes);
}
