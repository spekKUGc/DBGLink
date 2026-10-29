#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    // Lists the functions of one loaded module: entry/RVA/name triples from
    // the x64dbg function database (DbgFunctionGet) when that export exists,
    // otherwise from the module's PE export table parsed out of debuggee
    // memory. The reply always carries an honest source field so callers can
    // tell analysis data ("x64dbg") apart from plain exports ("exports").
    std::string HandleGetModuleFunctions(const std::string& request, const std::string& id);
}
