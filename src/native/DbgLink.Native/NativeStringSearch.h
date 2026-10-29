#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    StringSearchResult ScanStringPatterns(
        const std::vector<ModuleRecord>& modules,
        const std::vector<SearchPattern>& patterns,
        std::size_t maxResults,
        std::size_t maxScanBytes);
}
