#include "NativeTypes.h"
#include "NativeBoundedText.h"
#include "NativeBridgeFoundation.h"
#include "NativeDebuggerQueries.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"

namespace dbglink
{
    std::string FormatModuleList(const char* method, const std::vector<ModuleRecord>& modules, bool mapTruncated)
    {
        std::string header = "[" + std::string(method) + "] Found " + std::to_string(modules.size()) + " image modules:";
        if (mapTruncated)
            header += " mapTruncated=true";
        header.push_back('\n');

        BoundedText body(kMaxModuleOutputChars, BoundedText::OverflowPolicy::Report);
        body.Assign(header);

        for (const auto& module : modules)
        {
            const auto size = module.end > module.base ? module.end - module.base : 0;
            std::string line = "base=" + HexAddress(module.base) +
                " end=" + HexAddress(module.end) +
                " size=" + HexAddress(size) +
                " name=" + SingleLine(module.name) +
                " path=" + SingleLine(module.path) + "\n";
            if (!body.Append(line))
            {
                body.AppendMarker("outputTruncated=true\n", 21);
                break;
            }
        }

        body.PopTrailingNewline();
        return body.Body();
    }

    std::string FormatBytes(const unsigned char* data, std::size_t size)
    {
        if (size == 0 || data == nullptr)
            return {};

        constexpr char digits[] = "0123456789ABCDEF";
        std::string result;
        result.reserve(size * 3 - 1);
        for (std::size_t index = 0; index < size; ++index)
        {
            if (index != 0)
                result.push_back(' ');
            result.push_back(digits[data[index] >> 4]);
            result.push_back(digits[data[index] & 0x0F]);
        }
        return result;
    }

    std::string FormatBytes(const std::vector<unsigned char>& data)
    {
        return FormatBytes(data.data(), data.size());
    }

    std::string FormatHexDump(
        std::uintptr_t address,
        const std::vector<unsigned char>& data,
        bool includeAscii,
        bool spacedHex)
    {
        if (data.empty())
            return {};

        constexpr char digits[] = "0123456789abcdef";
        std::string result = HexAddress(address) + " (" + std::to_string(data.size()) + " bytes)";
        std::size_t zeroRun = 0;
        const auto flushZeroRun = [&result, &zeroRun]()
        {
            if (zeroRun == 0)
                return;
            result += "\n* [repeated " + std::to_string(zeroRun) + " zero bytes omitted]";
            zeroRun = 0;
        };
        for (std::size_t offset = 0; offset < data.size(); offset += 16)
        {
            const std::size_t count = std::min<std::size_t>(16, data.size() - offset);
            const unsigned char* chunk = data.data() + offset;

            bool allZero = true;
            for (std::size_t index = 0; index < count; ++index)
            {
                if (chunk[index] != 0)
                {
                    allZero = false;
                    break;
                }
            }
            if (allZero)
            {
                zeroRun += count;
                continue;
            }
            flushZeroRun();

            result.push_back('\n');
            for (std::size_t index = 0; index < count; ++index)
            {
                if (spacedHex && index != 0)
                    result.push_back(' ');
                result.push_back(digits[chunk[index] >> 4]);
                result.push_back(digits[chunk[index] & 0x0F]);
            }
            if (includeAscii)
            {
                result += "  ";
                for (std::size_t index = 0; index < count; ++index)
                    result.push_back(PrintableChar(chunk[index]));
            }
        }
        flushZeroRun();
        return result;
    }

    std::string GetAddressInfoLine(std::uintptr_t address)
    {
        // Module/label/comment resolution is shared with GetCallStackAddressInfo
        // (same bridge lookups, same SingleLine canonicalisation); only the
        // disassembly suffix is line-specific.
        const CallStackAddressInfo info = GetCallStackAddressInfo(
            address,
            GetDebuggerBridgeFunction<DbgGetModuleAtFunction>("DbgGetModuleAt"),
            GetDebuggerBridgeFunction<DbgGetLabelAtFunction>("DbgGetLabelAt"),
            GetDebuggerBridgeFunction<DbgGetCommentAtFunction>("DbgGetCommentAt"));

        std::string instruction;
        if (auto disasm = GetDebuggerBridgeFunction<DbgDisasmFastAtFunction>("DbgDisasmFastAt"))
        {
            BASIC_INSTRUCTION_INFO disasmInfo{};
            disasm(address, &disasmInfo);
            if (disasmInfo.size > 0)
                instruction = BufferText(disasmInfo.instruction, sizeof(disasmInfo.instruction));
        }

        std::string line = HexAddress(address);
        if (!info.module.empty())
            line += " module=" + info.module;
        if (!info.label.empty())
            line += " label=" + info.label;
        if (!info.comment.empty())
            line += " comment=" + info.comment;
        if (!instruction.empty())
            line += " instruction=" + SingleLine(instruction);
        return line;
    }



    RegisterNameList GetRegisterNames()
    {
        static constexpr const char* x64Names[] =
        {
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"
        };
        static constexpr const char* x86Names[] =
        {
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"
        };

        if constexpr (sizeof(std::uintptr_t) == 8)
        {
            return { x64Names, sizeof(x64Names) / sizeof(x64Names[0]) };
        }
        else
        {
            return { x86Names, sizeof(x86Names) / sizeof(x86Names[0]) };
        }
    }

    namespace
    {
        // Shared register renderer: GetRegisters uses lowercase names padded
        // to 7, AllRegistersText uses uppercase names padded to 4. The value
        // lookup and line joining are identical.
        std::string FormatRegisterLines(
            DbgValFromStringFunction valueFromString,
            bool upperCase,
            std::size_t padWidth)
        {
            const auto registerNames = GetRegisterNames();

            std::string output;
            for (std::size_t index = 0; index < registerNames.count; ++index)
            {
                const char* name = registerNames.names[index];
                std::string displayName(name);
                if (upperCase)
                {
                    std::transform(displayName.begin(), displayName.end(), displayName.begin(), [](unsigned char character)
                    {
                        return static_cast<char>(std::toupper(character));
                    });
                }
                output += displayName;
                if (displayName.size() < padWidth)
                    output.append(padWidth - displayName.size(), ' ');
                output += ": ";
                output += HexAddress(valueFromString(name));
                output.push_back('\n');
            }

            if (!output.empty())
                output.pop_back();
            return output;
        }
    }

    std::string GetRegisters()
    {
        auto valueFromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        if (valueFromString == nullptr)
            return "<unavailable>";

        return FormatRegisterLines(valueFromString, false, 7);
    }

    std::string AllRegistersText()
    {
        if (!IsDebugging())
            return "[GetAllRegisters] No active debug session.";

        auto valueFromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        if (valueFromString == nullptr)
            return "[GetAllRegisters] Register bridge is unavailable.";

        return FormatRegisterLines(valueFromString, true, 4);
    }

    std::string ActiveThreadsText()
    {
        if (!IsDebugging())
            return "[GetAllActiveThreads] No active debug session.";

        auto getThreadList = GetDebuggerBridgeFunction<DbgGetThreadListFunction>("DbgGetThreadList");
        auto bridgeFree = GetDebuggerBridgeFunction<BridgeFreeFunction>("BridgeFree");
        if (getThreadList == nullptr || bridgeFree == nullptr)
            return "[GetAllActiveThreads] Thread-list bridge is unavailable.";

        BridgeThreadListGuard threadList;
        threadList.freeFunction = bridgeFree;
        getThreadList(&threadList.list);

        if (threadList.list.count < 0)
            return "[GetAllActiveThreads] x64dbg returned an invalid thread count.";
        if (threadList.list.count > kMaxThreadEntries)
            return "[GetAllActiveThreads] x64dbg returned too many threads.";
        if (!ValidateBridgeList(threadList.list.count, threadList.list.list, kMaxThreadEntries))
            return "[GetAllActiveThreads] x64dbg returned a null thread-list buffer.";

        const auto listAddress = reinterpret_cast<std::uintptr_t>(threadList.list.list);
        const auto maxAddress = std::numeric_limits<std::uintptr_t>::max();
        const auto byteCount = static_cast<std::size_t>(threadList.list.count) * sizeof(BRIDGE_THREAD_ALL_INFO);
        if (byteCount > 0 && (listAddress == 0 || listAddress > maxAddress - byteCount))
            return "[GetAllActiveThreads] x64dbg returned an invalid thread-list pointer.";

        std::string header = "[GetAllActiveThreads] Found " + std::to_string(threadList.list.count) + " active threads:\n";
        BoundedText body(kMaxThreadOutputChars, BoundedText::OverflowPolicy::Report);
        body.Assign(header);
        const auto appendRightAligned = [](std::string& target, const std::string& value, std::size_t width)
        {
            if (value.size() < width)
                target.append(width - value.size(), ' ');
            target += value;
        };
        for (int index = 0; index < threadList.list.count; ++index)
        {
            const auto& info = threadList.list.list[index].basicInfo;
            const std::string name = SingleLine(BufferText(info.threadName, sizeof(info.threadName)));
            std::string text = "Num: ";
            appendRightAligned(text, std::to_string(info.threadNumber), 3);
            text += " | TID: ";
            appendRightAligned(text, std::to_string(static_cast<unsigned long long>(info.threadId)), 6);
            text += " | EntryPoint: ";
            text += HexAddress(info.threadStartAddress);
            text += " | TEB: ";
            text += HexAddress(info.threadLocalBase);
            text += " | Name: ";
            text += name;
            text.push_back('\n');
            if (!body.Append(text))
            {
                body.AppendMarker("outputTruncated=true", 21);
                break;
            }
        }

        body.PopTrailingNewline();
        return body.Body();
    }





    CallStackAddressInfo GetCallStackAddressInfo(
        std::uintptr_t address,
        DbgGetModuleAtFunction getModuleAt,
        DbgGetLabelAtFunction getLabelAt,
        DbgGetCommentAtFunction getCommentAt)
    {
        CallStackAddressInfo result;
        char buffer[512]{};

        if (getModuleAt != nullptr && getModuleAt(address, buffer))
        {
            const std::string module = SingleLine(BufferText(buffer, 256));
            if (!module.empty())
                result.module = module;
        }

        std::memset(buffer, 0, sizeof(buffer));
        if (getLabelAt != nullptr)
        {
            if (getLabelAt(address, 0, buffer))
            {
                const std::string label = SingleLine(BufferText(buffer, 256));
                if (!label.empty())
                    result.label = label;
            }
        }

        std::memset(buffer, 0, sizeof(buffer));
        if (getCommentAt != nullptr)
        {
            if (getCommentAt(address, buffer))
            {
                result.comment = BufferText(buffer, 512);
                if (!result.comment.empty() && result.comment.front() == '\x01')
                    result.comment.erase(result.comment.begin());
                result.comment = SingleLine(result.comment);
            }
        }

        return result;
    }

    namespace
    {
        // A plausible return address is the instruction after a call: a direct
        // near call (E8 rel32) or an indirect FF /2 call (modrm.reg == 2).
        bool LooksLikeCallReturn(DbgMemReadFunction memoryRead, std::uintptr_t candidate)
        {
            if (candidate < 0x10000 + 6)
                return false;

            unsigned char window[6]{};
            if (memoryRead(candidate - 6, window, sizeof(window)))
            {
                // window[1] is at candidate-5 (E8), window[4..5] at candidate-2.
                if (window[1] == 0xE8)
                    return true;
                if (window[4] == 0xFF && (window[5] & 0x38) == 0x10)
                    return true;
                return false;
            }

            // The six-byte window may straddle an unreadable page; retry with
            // smaller tails before giving up.
            unsigned char tail[5]{};
            if (memoryRead(candidate - 5, tail, sizeof(tail)) && tail[0] == 0xE8)
                return true;

            unsigned char pair[2]{};
            return memoryRead(candidate - 2, pair, sizeof(pair)) &&
                pair[0] == 0xFF && (pair[1] & 0x38) == 0x10;
        }

        bool InsideLoadedModule(const std::vector<ModuleRecord>& modules, std::uintptr_t address)
        {
            for (const auto& module : modules)
            {
                if (module.base < module.end && address >= module.base && address < module.end)
                    return true;
            }
            return false;
        }
    }

    CallStackWalk WalkCallStack(
        DbgMemReadFunction memoryRead,
        std::uintptr_t rbp,
        std::uintptr_t rsp,
        int maxFrames)
    {
        CallStackWalk walk;
        if (memoryRead == nullptr || rsp == 0)
            return walk;

        const std::size_t pointerSize = sizeof(std::uintptr_t);
        const int frameLimit = std::clamp(maxFrames, 1, kMaxCallStackFrames);

        // Phase 1: classic frame-pointer chain ([rbp] -> next, [rbp+8] -> ret).
        // Valid on x86 builds and on x64 code compiled with frame pointers.
        std::uintptr_t currentRbp = rbp;
        std::uintptr_t previousRbp = 0;
        if (rbp != 0 && rbp >= rsp && (rbp % pointerSize) == 0)
        {
            for (int index = 0; index < frameLimit; ++index)
            {
                std::uintptr_t returnAddressSlot = 0;
                if (!TryAddAddress(currentRbp, pointerSize, returnAddressSlot))
                    break;

                std::uintptr_t returnAddress = 0;
                if (!ReadPointerValue(memoryRead, returnAddressSlot, returnAddress) ||
                    returnAddress < 0x10000)
                    break;

                std::uintptr_t nextRbp = 0;
                if (!ReadPointerValue(memoryRead, currentRbp, nextRbp))
                    break;
                if (nextRbp != 0 && (nextRbp % pointerSize) != 0)
                    break;

                const std::uintptr_t frameSize = previousRbp > 0 && currentRbp > previousRbp
                    ? currentRbp - previousRbp
                    : 0;
                walk.frames.push_back({ currentRbp, returnAddress, frameSize });

                previousRbp = currentRbp;
                currentRbp = nextRbp;
                if (currentRbp == 0 || currentRbp < rsp || currentRbp <= previousRbp)
                    break;
            }
        }

        if (walk.frames.size() >= 2 || walk.frames.size() >= static_cast<std::size_t>(frameLimit))
            return walk;

        // Phase 2: frame pointers were omitted (FPO — the normal case for
        // MSVC/x64 releases). Scan the live stack for pointer-sized words that
        // fall inside a loaded module and are preceded by a call opcode.
        walk.frames.clear();
        walk.approximate = true;

        std::vector<ModuleRecord> modules;
        bool mapTruncated = false;
        std::string moduleError;
        const bool haveModules = CollectModuleRecords(modules, mapTruncated, moduleError);

        constexpr std::uintptr_t kScanWindowBytes = 16384;
        std::uintptr_t previousSlot = 0;
        // Start at the first pointer-aligned address at or above rsp.
        std::uintptr_t slot = rsp + (pointerSize - (rsp % pointerSize)) % pointerSize;
        for (; walk.frames.size() < static_cast<std::size_t>(frameLimit);
             slot += pointerSize)
        {
            if (slot < rsp || slot - rsp >= kScanWindowBytes)
                break;

            std::uintptr_t value = 0;
            if (!ReadPointerValue(memoryRead, slot, value))
                break; // guard page or unreadable stack: stop scanning
            if (value < 0x10000)
                continue;
            if (haveModules && !InsideLoadedModule(modules, value))
                continue;
            if (!LooksLikeCallReturn(memoryRead, value))
                continue;

            const std::uintptr_t frameSize = previousSlot != 0 && slot > previousSlot
                ? slot - previousSlot
                : 0;
            walk.frames.push_back({ slot, value, frameSize });
            previousSlot = slot;
        }

        return walk;
    }

    std::string CallStackText(int maxFrames)
    {
        auto valueFromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        if (valueFromString == nullptr || !IsDebugging())
            return "[GetCallStack] No active debug session.";

        auto memoryRead = GetDebuggerBridgeFunction<DbgMemReadFunction>("DbgMemRead");
        if (memoryRead == nullptr)
            return "[GetCallStack] Memory-read bridge is unavailable.";

        const char* frameRegister = sizeof(std::uintptr_t) == 8 ? "rbp" : "ebp";
        const char* stackRegister = sizeof(std::uintptr_t) == 8 ? "rsp" : "esp";
        const std::uintptr_t rbp = valueFromString(frameRegister);
        const std::uintptr_t rsp = valueFromString(stackRegister);

        CallStackWalk walk = WalkCallStack(memoryRead, rbp, rsp, maxFrames);
        const std::vector<CallStackFrame>& frames = walk.frames;

        if (frames.empty())
            return "[GetCallStack] Call stack could not be retrieved (check RBP validity or use debugger UI).";

        const auto appendLeftAligned = [](std::string& target, const std::string& value, std::size_t width)
        {
            target += value;
            if (value.size() < width)
                target.append(width - value.size(), ' ');
        };

        std::string header = "[GetCallStack] Retrieved ";
        header += std::to_string(frames.size());
        header += walk.approximate
            ? " frames (stack scan, approximate):\n"
            : " frames (RBP frame chain):\n";
        appendLeftAligned(header, "Frame", 5);
        header += ' ';
        appendLeftAligned(header, "Frame Addr", 18);
        header += ' ';
        appendLeftAligned(header, "Return Addr", 18);
        header += ' ';
        appendLeftAligned(header, "Size", 10);
        header += ' ';
        appendLeftAligned(header, "Module", 25);
        header += ' ';
        appendLeftAligned(header, "Label/Symbol", 40);
        header += " Comment\n";
        header += std::string(130, '-');
        auto getModuleAt = GetDebuggerBridgeFunction<DbgGetModuleAtFunction>("DbgGetModuleAt");
        auto getLabelAt = GetDebuggerBridgeFunction<DbgGetLabelAtFunction>("DbgGetLabelAt");
        auto getCommentAt = GetDebuggerBridgeFunction<DbgGetCommentAtFunction>("DbgGetCommentAt");

        BoundedText body(kMaxCallStackOutputChars, BoundedText::OverflowPolicy::Report);
        body.Assign(header);

        for (std::size_t index = 0; index < frames.size(); ++index)
        {
            const CallStackFrame& frame = frames[index];
            const CallStackAddressInfo info = GetCallStackAddressInfo(
                frame.returnAddress,
                getModuleAt,
                getLabelAt,
                getCommentAt);
            std::string text;
            appendLeftAligned(text, "[" + std::to_string(index) + "]", 5);
            text += ' ';
            text += HexAddress(frame.frameAddress);
            text += ' ';
            text += HexAddress(frame.returnAddress);
            text += ' ';
            appendLeftAligned(text, HexAddress(frame.frameSize), 10);
            text += ' ';
            appendLeftAligned(text, info.module, 25);
            text += ' ';
            appendLeftAligned(text, info.label, 40);
            text += ' ';
            text += info.comment;
            if (!body.AppendLine(text))
            {
                body.AppendMarker("\noutputTruncated=true", 22);
                break;
            }
        }

        return body.Body();
    }

}
