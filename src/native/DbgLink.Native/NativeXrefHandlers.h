#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    std::string FormatXrefSearch(
        const std::string& targetText,
        std::uintptr_t target,
        std::size_t start,
        std::size_t count,
        const XrefSearchResult& search);
}
