#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    const std::vector<InterestingSearchPattern>& BuiltInInterestingSearchPatterns();
    std::string HandleFindStringInModule(const std::string& request, const std::string& id);
    std::string HandleFindInterestingStrings(const std::string& request, const std::string& id);
}
