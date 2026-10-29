#include <stdexcept>
#include <string>
#include <string_view>

#include "../../src/native/DbgLink.Native/NativeInputValidation.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"

namespace dbglink_input_validation_tests
{
    using namespace dbglink;

    void Require(bool condition, std::string_view message)
    {
        if (!condition)
            throw std::runtime_error(std::string(message));
    }

    void RunInputValidationTests()
    {
        // Search text: non-empty, at most kMaxSearchTextBytes, no control bytes.
        Require(!IsSearchTextValid(""), "empty search text was accepted");
        Require(IsSearchTextValid("x"), "single printable byte was rejected");
        Require(IsSearchTextValid(std::string(kMaxSearchTextBytes, 'a')),
            "search text at the byte cap was rejected");
        Require(!IsSearchTextValid(std::string(kMaxSearchTextBytes + 1, 'a')),
            "search text over the byte cap was accepted");
        Require(!IsSearchTextValid(std::string("\x01")), "control byte in search text was accepted");

        // Module filter: the same policy but an empty filter means "all".
        Require(IsSearchModuleFilterValid(""), "empty module filter was rejected");
        Require(IsSearchModuleFilterValid(std::string(kMaxModuleSize, 'm')),
            "module filter at the byte cap was rejected");
        Require(!IsSearchModuleFilterValid(std::string(kMaxModuleSize + 1, 'm')),
            "module filter over the byte cap was accepted");
        Require(!IsSearchModuleFilterValid(std::string("\t")), "control byte in the module filter was accepted");

        // Byte pattern: non-empty, at most kMaxBytePatternChars, no control bytes.
        Require(!IsBytePatternTextValid(""), "empty byte pattern was accepted");
        Require(IsBytePatternTextValid("48 8B 05 ??"), "printable byte pattern was rejected");
        Require(IsBytePatternTextValid(std::string(kMaxBytePatternChars, '0')),
            "byte pattern at the byte cap was rejected");
        Require(!IsBytePatternTextValid(std::string(kMaxBytePatternChars + 1, '0')),
            "byte pattern over the byte cap was accepted");
        Require(!IsBytePatternTextValid(std::string("\n")), "control byte in the byte pattern was accepted");

        // High-bit bytes are not control bytes: the scan reads unsigned char.
        std::string highBit = "a";
        highBit.push_back(static_cast<char>(0x80));
        Require(IsSearchTextValid(highBit), "a high-bit byte was treated as a control byte");
    }
}
