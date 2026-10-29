#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    InterestingStringResult ScanInterestingStrings(
        const std::vector<ModuleRecord>& modules,
        const std::vector<InterestingSearchPattern>& patterns,
        std::size_t maxResultsPerNeedle,
        std::size_t maxScanBytes);
    const char* XrefTypeText(XrefType type);
}
