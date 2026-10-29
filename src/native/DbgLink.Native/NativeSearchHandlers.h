#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    std::string HandleReadMemory(const std::string& request, const std::string& id);
    std::string HandleDisassembly(const std::string& request, const std::string& id);
    std::string FormatBytePatternSearch(
        const std::string& pattern,
        const std::string& module,
        const ByteSearchResult& search);
    std::string HandleFindBytePatternInModule(const std::string& request, const std::string& id);
    std::string FormatStringSearch(
        const std::string& text,
        const std::string& module,
        const StringSearchResult& search);
    std::string FormatInterestingStringSearch(
        const std::string& module,
        const InterestingStringResult& search);
}
