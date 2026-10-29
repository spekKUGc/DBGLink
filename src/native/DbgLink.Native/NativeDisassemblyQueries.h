#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    std::string ReadDisassembly(std::uintptr_t start, std::size_t byteCount);
    std::string CurrentContextText(std::size_t beforeBytes, std::size_t instructionBytes, std::size_t stackBytes);
}
