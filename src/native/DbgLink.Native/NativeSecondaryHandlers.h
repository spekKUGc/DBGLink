#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    std::string HandleModuleRecords(const std::string& request, const std::string& id);
    std::string HandleAnalysisSnapshot(const std::string& request, const std::string& id);
    std::string HandleSnapshotState(const std::string& id);
    std::string HandleGetXrefs(const std::string& request, const std::string& id);
    std::string HandleReadString(const std::string& request, const std::string& id);
    std::string HandleOpenDebugTarget(const std::string& request, const std::string& id);
    std::string HandleModules(const std::string& id, const char* method);
    std::string HandleCurrentContext(const std::string& request, const std::string& id);
    std::string HandleAllRegisters(const std::string& id);
    std::string HandleAllActiveThreads(const std::string& id);
    std::string HandleCallStack(const std::string& request, const std::string& id);
}
