#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    // Helpers shared by the themed control-handler TUs (breakpoints, state
    // edits, thread/stack, chunk reads, annotations). They were file-local in
    // NativeControlHandlers.cpp before it was split by theme.
    bool IsBreakpointNameValid(const std::string& name);
    bool IsRegisterNameValid(const std::string& name, std::string& canonical);
    bool ParseHexBytes(const std::string& text, std::vector<unsigned char>& out, std::string& error);
    std::string AsciiPreview(const std::vector<unsigned char>& data);
    // x64dbg keys memory breakpoints by page base (MemFindBaseAddr), not by
    // the requested address: resolve the base so set/clear/list agree.
    bool FindPageBase(std::uintptr_t address, std::uintptr_t& base, std::uintptr_t& size);
}
