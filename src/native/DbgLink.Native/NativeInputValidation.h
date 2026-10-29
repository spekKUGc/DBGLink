#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    // Request-field text policy shared by the search text, module filter and
    // byte-pattern arguments: a byte-length cap plus no control bytes; the
    // search text and byte pattern additionally require at least one byte.
    // The wire error messages stay at the call sites, so only the three
    // checks live here.
    bool IsSearchTextValid(const std::string& text);
    bool IsSearchModuleFilterValid(const std::string& module);
    bool IsBytePatternTextValid(const std::string& pattern);
}
