#pragma once
#include "NativeTypes.h"
namespace dbglink
{
    struct RegisterNameList
    {
        const char* const* names;
        std::size_t count;
    };
    struct CallStackFrame
    {
        std::uintptr_t frameAddress = 0;
        std::uintptr_t returnAddress = 0;
        std::uintptr_t frameSize = 0;
    };
    struct CallStackWalk
    {
        std::vector<CallStackFrame> frames;
        // True when the frames came from the validated stack scan because the
        // frame-pointer chain was unusable (frame pointers omitted/FPO).
        bool approximate = false;
    };
    // Walks the stack of the paused thread: first the classic rbp/ebp chain,
    // then (when that yields fewer than two frames) a bounded scan of the live
    // stack for values that look like call return addresses inside loaded
    // modules. Never fails with an exception; an empty result means the stack
    // could not be reconstructed.
    CallStackWalk WalkCallStack(
        DbgMemReadFunction memoryRead,
        std::uintptr_t rbp,
        std::uintptr_t rsp,
        int maxFrames);
    struct CallStackAddressInfo
    {
        std::string module;
        std::string label;
        std::string comment;
    };
    std::string FormatModuleList(const char* method, const std::vector<ModuleRecord>& modules, bool mapTruncated);
    std::string FormatBytes(const unsigned char* data, std::size_t size);
    std::string FormatBytes(const std::vector<unsigned char>& data);
    // Compact hex dump: one header line carrying the (compact lowercase)
    // start address plus the total byte count, then one contiguous-lowercase
    // hex line per 16-byte row with no per-line addresses and no inter-byte
    // spaces. All-zero rows collapse into a single
    // "* [repeated N zero bytes omitted]" marker (N is exact, so the bytes
    // stay exactly recoverable). Opt-ins: includeAscii re-adds the legacy
    // ASCII gutter per row, spacedHex re-adds inter-byte spaces. Both
    // default off (token-light); empty input still yields an empty string.
    std::string FormatHexDump(
        std::uintptr_t address,
        const std::vector<unsigned char>& data,
        bool includeAscii = false,
        bool spacedHex = false);
    std::string GetAddressInfoLine(std::uintptr_t address);
    RegisterNameList GetRegisterNames();
    std::string GetRegisters();
    std::string AllRegistersText();
    std::string ActiveThreadsText();
    CallStackAddressInfo GetCallStackAddressInfo(
        std::uintptr_t address,
        DbgGetModuleAtFunction getModuleAt,
        DbgGetLabelAtFunction getLabelAt,
        DbgGetCommentAtFunction getCommentAt);
    std::string CallStackText(int maxFrames);
}
