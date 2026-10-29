#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    // Execution-control ack policy (shared by NativeControlHandlers.cpp,
    // NativeThreadHandlers.cpp and NativeStateEditHandlers.cpp): every
    // control ack (step/run/pause/continue/switchThread/callFunction) keeps
    // its followUp hint. Either all keep it or all drop it — a split
    // contract breaks scripted callers that poll the ack field. The sentence
    // also lives in each tool description (static prose); the ack repeats it
    // because the follow-up is per-call navigation, not decoration.
    std::string HandleSetBreakpoint(const std::string& request, const std::string& id);
    std::string HandleClearBreakpoint(const std::string& request, const std::string& id);
    std::string HandleListBreakpoints(const std::string& request, const std::string& id);
    std::string HandleStepInto(const std::string& request, const std::string& id);
    std::string HandleStepOver(const std::string& request, const std::string& id);
    std::string HandleStepOut(const std::string& request, const std::string& id);
    std::string HandleRunDebugger(const std::string& request, const std::string& id);
    std::string HandlePauseDebugger(const std::string& request, const std::string& id);
    std::string HandleContinueDebugger(const std::string& request, const std::string& id);
    std::string HandleSetRegister(const std::string& request, const std::string& id);
    std::string HandleWriteMemory(const std::string& request, const std::string& id);
    std::string HandleCallFunction(const std::string& request, const std::string& id);
    std::string HandleSwitchThread(const std::string& request, const std::string& id);
    std::string HandleListThreads(const std::string& request, const std::string& id);
    std::string HandleBacktrace(const std::string& request, const std::string& id);
    std::string HandleReadMemoryChunk(const std::string& request, const std::string& id);
    std::string HandleReadDisassemblyChunk(const std::string& request, const std::string& id);
    std::string HandleEvaluateExpression(const std::string& request, const std::string& id);
    std::string HandleSetLabel(const std::string& request, const std::string& id);
    std::string HandleSetComment(const std::string& request, const std::string& id);
    std::string HandleSetBookmark(const std::string& request, const std::string& id);
}
