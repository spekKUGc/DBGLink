#pragma once
#include "NativeTypes.h"
#include <type_traits>
namespace dbglink
{
    // Address rendering lives in its own translation unit so the regression
    // harness can link it without dragging in the debugger bridge. Every hex
    // address on the wire uses the compact lowercase form (no zero padding,
    // "0x401000") via HexAddress: JSON address fields, thread entry/teb/cip
    // fields, sizes, RVAs and offsets in text replies alike. Matches the
    // managed CompactTraceAddress policy (lowercase, no zero padding).

    // "0x" plus lowercase digits with no leading zeros ("0x0", "0xdeadbeef").
    std::string HexAddress(std::uintptr_t address);
    // Full-width overload for 64-bit quantities (coverage RVAs, absolute
    // addresses) that must not narrow through uintptr_t on 32-bit builds.
    // Constrained to 8-byte integrals (uint64_t/int64_t): a concrete
    // HexAddress(uint64_t) overload would make every HexAddress(int-literal)
    // call site ambiguous on 32-bit (int converts equally to uint32_t and
    // uint64_t; verified by the Win32 build), while this template leaves
    // 4-byte arguments to the uintptr_t overload above. On 64-bit uintptr_t
    // already is 64 bits and both overloads render identically.
    template <typename T, std::enable_if_t<std::is_integral_v<T> && sizeof(T) == 8, int> = 0>
    inline std::string HexAddress(T address)
    {
        const auto value = static_cast<std::uint64_t>(address);
        constexpr char digits[] = "0123456789abcdef";
        constexpr std::size_t digitCount = sizeof(std::uint64_t) * 2;
        std::size_t firstDigit = 0;
        while (firstDigit + 1 < digitCount &&
            ((value >> ((digitCount - firstDigit - 1) * 4)) & 0x0F) == 0)
        {
            ++firstDigit;
        }
        std::string result;
        result.reserve(2 + digitCount - firstDigit);
        result = "0x";
        for (std::size_t index = firstDigit; index < digitCount; ++index)
        {
            const std::size_t shift = (digitCount - index - 1) * 4;
            result.push_back(digits[(value >> shift) & 0x0F]);
        }
        return result;
    }
}
