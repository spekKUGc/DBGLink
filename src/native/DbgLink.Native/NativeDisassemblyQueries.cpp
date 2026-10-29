#include "NativeTypes.h"
#include "NativeBoundedText.h"
#include "NativeBridgeFoundation.h"
#include "NativeDebuggerQueries.h"
#include "NativeDisassemblyQueries.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"

namespace dbglink
{
    std::string ReadDisassembly(std::uintptr_t start, std::size_t byteCount)
    {
        auto disasm = GetDebuggerBridgeFunction<DbgDisasmFastAtFunction>("DbgDisasmFastAt");
        if (disasm == nullptr)
            return "<disassembly unavailable>";
        auto memoryRead = GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead");
        BoundedText body(kMaxDisassemblyOutputChars, BoundedText::OverflowPolicy::Report);
        std::uintptr_t address = start;
        std::size_t bytesRead = 0;
        int instructionCount = 0;
        std::vector<unsigned char> bytes;
        auto appendMarker = [&body](const char* marker)
        {
            body.Append(std::string(marker) + "\n");
        };
        while (bytesRead < byteCount && instructionCount < kMaxDisassemblyInstructions)
        {
            BASIC_INSTRUCTION_INFO info{};
            disasm(address, &info);
            if (info.size <= 0 || info.size > 64)
            {
                const std::string lineText = HexAddress(address) + "  <undecodable>\n";
                if (!body.Append(lineText))
                {
                    appendMarker("outputTruncated=true");
                    break;
                }
                std::uintptr_t nextAddress = 0;
                if (!TryAddAddress(address, 1, nextAddress))
                {
                    appendMarker("addressOverflow=true");
                    break;
                }
                address = nextAddress;
                ++bytesRead;
                ++instructionCount;
                continue;
            }

            const std::size_t remainingBytes = byteCount - bytesRead;
            if (static_cast<std::size_t>(info.size) > remainingBytes)
            {
                const std::string lineText = HexAddress(address) + "  <instruction exceeds byte window>\n";
                if (!body.Append(lineText))
                    appendMarker("outputTruncated=true");
                break;
            }

            const bool readable = ReadMemory(
                address,
                static_cast<std::size_t>(info.size),
                bytes,
                memoryRead);
            const std::string instruction = BufferText(info.instruction, sizeof(info.instruction));
            std::string lineText = HexAddress(address) + "  ";
            lineText += readable ? FormatBytes(bytes) : "<unreadable>";
            lineText += "  ";
            lineText += instruction.empty() ? "<unknown>" : SingleLine(instruction);
            lineText.push_back('\n');
            if (!body.Append(lineText))
            {
                appendMarker("outputTruncated=true");
                break;
            }

            std::uintptr_t nextAddress = 0;
            if (!TryAddAddress(address, static_cast<std::size_t>(info.size), nextAddress))
            {
                appendMarker("addressOverflow=true");
                break;
            }
            address = nextAddress;
            bytesRead += static_cast<std::size_t>(info.size);
            ++instructionCount;
        }

        body.PopTrailingNewline();
        return body.Body();
    }

    std::string CurrentContextText(std::size_t beforeBytes, std::size_t instructionBytes, std::size_t stackBytes)
    {
        auto valueFromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        if (valueFromString == nullptr || !IsDebugging())
            return "[GetCurrentContext] No active debug session.";

        const std::uintptr_t cip = valueFromString("cip");
        const std::uintptr_t csp = valueFromString("csp");
        const std::uintptr_t disasmStart = cip > beforeBytes ? cip - static_cast<std::uintptr_t>(beforeBytes) : cip;

        std::string output = "[GetCurrentContext]\n";
        output += GetAddressInfoLine(cip);
        output += "\n\n[Registers]\n";
        output += GetRegisters();
        output += "\n\n[Disassembly]\n";
        output += ReadDisassembly(disasmStart, instructionBytes + beforeBytes);

        if (stackBytes > 0 && csp != 0)
        {
            std::vector<unsigned char> stack;
            output += "\n\n[Stack]\n";
            if (ReadMemory(csp, stackBytes, stack))
                output += FormatHexDump(csp, stack);
            else
            {
                output += "Failed to read memory at ";
                output += HexAddress(csp);
            }
        }

        return output;
    }

}
