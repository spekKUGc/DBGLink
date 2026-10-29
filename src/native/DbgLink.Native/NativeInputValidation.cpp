#include "NativeInputValidation.h"

namespace dbglink
{
    namespace
    {
        // One bounded-printable check behind the three request validators:
        // [minBytes, maxBytes] inclusive plus no byte below 0x20. minBytes is
        // 1 for the fields that must not be empty and 0 for the optional
        // module filter.
        bool IsBoundedPrintableText(const std::string& text, std::size_t minBytes, std::size_t maxBytes)
        {
            if (text.size() < minBytes || text.size() > maxBytes)
                return false;
            return std::none_of(text.begin(), text.end(), [](unsigned char character)
            {
                return character < 0x20;
            });
        }
    }

    bool IsSearchTextValid(const std::string& text)
    {
        return IsBoundedPrintableText(text, 1, kMaxSearchTextBytes);
    }

    bool IsSearchModuleFilterValid(const std::string& module)
    {
        return IsBoundedPrintableText(module, 0, kMaxModuleSize);
    }

    bool IsBytePatternTextValid(const std::string& pattern)
    {
        return IsBoundedPrintableText(pattern, 1, kMaxBytePatternChars);
    }
}
