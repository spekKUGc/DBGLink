#include "NativeHexFormat.h"

namespace dbglink
{
    namespace
    {
        // Lowercase compact rendering for HexAddress: "0x" plus hex digits
        // with leading zeros stripped (a single "0" survives for the zero
        // value). Matches the managed CompactTraceAddress policy
        // (lowercase, no zero padding).
        std::string CompactLowercase(std::uint64_t numeric)
        {
            constexpr char digits[] = "0123456789abcdef";
            constexpr std::size_t digitCount = sizeof(std::uint64_t) * 2;
            std::size_t firstDigit = 0;
            while (firstDigit + 1 < digitCount &&
                ((numeric >> ((digitCount - firstDigit - 1) * 4)) & 0x0F) == 0)
            {
                ++firstDigit;
            }

            std::string result;
            result.reserve(2 + digitCount - firstDigit);
            result = "0x";
            for (std::size_t index = firstDigit; index < digitCount; ++index)
            {
                const std::size_t shift = (digitCount - index - 1) * 4;
                result.push_back(digits[(numeric >> shift) & 0x0F]);
            }
            return result;
        }
    }

    std::string HexAddress(std::uintptr_t address)
    {
        return CompactLowercase(static_cast<std::uint64_t>(address));
    }
}
