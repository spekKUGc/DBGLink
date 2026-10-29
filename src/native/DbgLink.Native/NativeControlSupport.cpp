#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeDebuggerQueries.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeControlSupport.h"

namespace dbglink
{
    bool IsBreakpointNameValid(const std::string& name)
    {
        if (name.empty() || name.size() > kMaxBreakpointNameChars)
            return false;
        auto isFirst = [](char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                c == '_' || c == '$' || c == '?' || c == '.';
        };
        auto isRest = [&isFirst](char c)
        {
            return isFirst(c) || (c >= '0' && c <= '9');
        };
        if (!isFirst(name[0]))
            return false;
        for (char c : name)
        {
            if (!isRest(c))
                return false;
        }
        return true;
    }

    bool IsRegisterNameValid(const std::string& name, std::string& canonical)
    {
        static const char* const kRegisters[] = {
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "rip", "eflags", "rflags", "cflags",
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
            "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "ip",
            "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
            "sil", "dil", "bpl", "spl",
            "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
            "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
            "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
            "cip", "csp", "cbp", "cax", "cbx", "ccx", "cdx", "csi", "cdi",
            "gs", "fs", "es", "ds", "cs", "ss",
            "dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
        };
        // Original order: lower first, then trim.
        const std::string lowered = Trim(ToLower(name));
        for (const char* candidate : kRegisters)
        {
            if (lowered == candidate)
            {
                canonical = lowered;
                return true;
            }
        }
        return false;
    }

    bool ParseHexBytes(const std::string& text, std::vector<unsigned char>& out, std::string& error)
    {
        // Accept "48 8B 05", "0x48,0x8B", "488B05".
        std::string working;
        working.reserve(text.size());
        for (std::size_t i = 0; i < text.size();)
        {
            if (text[i] == '0' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X'))
            {
                i += 2;
                continue;
            }
            char c = text[i++];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';' || c == '-')
                continue;
            working.push_back(c);
        }
        if (working.empty())
        {
            error = "No hex bytes found.";
            return false;
        }
        if (working.size() % 2 != 0)
        {
            error = "Hex bytes must be an even number of hex digits.";
            return false;
        }
        if (working.size() / 2 > kMaxControlWriteBytes)
        {
            error = "Too many bytes (max 4096 per call; page large patches).";
            return false;
        }
        auto hexVal = [](char c) -> int
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        out.clear();
        out.reserve(working.size() / 2);
        for (std::size_t i = 0; i < working.size(); i += 2)
        {
            int hi = hexVal(working[i]);
            int lo = hexVal(working[i + 1]);
            if (hi < 0 || lo < 0)
            {
                error = "Invalid hex digit.";
                return false;
            }
            out.push_back(static_cast<unsigned char>((hi << 4) | lo));
        }
        if (out.empty())
        {
            error = "No hex bytes found.";
            return false;
        }
        return true;
    }

    std::string AsciiPreview(const std::vector<unsigned char>& data)
    {
        std::string out;
        out.reserve(data.size());
        for (unsigned char c : data)
            out.push_back(PrintableChar(c));
        return out;
    }

    bool FindPageBase(std::uintptr_t address, std::uintptr_t& base, std::uintptr_t& size)
    {
        base = 0;
        size = 0;
        auto findBase = GetDebuggerBridgeFunction<DbgMemFindBaseAddrFunction>("DbgMemFindBaseAddr");
        if (findBase == nullptr || address == 0)
            return false;
        base = findBase(address, &size);
        return base != 0;
    }
}
