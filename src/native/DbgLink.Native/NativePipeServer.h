#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    std::string HandleRequest(const std::string& request);
    void WakePipe() noexcept;
    void PipeLoopCore();
    void PipeLoop() noexcept;
    std::wstring ModuleDirectory();
    std::wstring ServerPort();
    bool EnvironmentFlagEnabled(const wchar_t* name);
    void StartServerProcess();
}
