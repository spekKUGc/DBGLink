#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    bool TryDecodePrintableAscii(const std::vector<unsigned char>& data, std::string& value);
    bool AddressRangeFits(std::uintptr_t address, std::size_t byteCount);
    std::uintptr_t PointerValueFromBytes(
        const std::vector<unsigned char>& data,
        std::size_t offset);
    std::string HandleInspectAddressStructure(const std::string& request, const std::string& id);
}
