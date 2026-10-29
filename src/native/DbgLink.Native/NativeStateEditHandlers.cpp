#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeCommandText.h"
#include "NativeControlSupport.h"
#include "NativeDebuggerQueries.h"
#include "NativeInspectionHandlers.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeControlHandlers.h"
#include "NativeRequestParams.h"

namespace dbglink
{
    std::string HandleSetRegister(const std::string& request, const std::string& id)
    {
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        if (IsRunning())
            return ErrorResponse(id, "Target is running. Pause it before editing registers.");
        const RequestParams params(request);
        std::string regText;
        if (auto error = params.RequiredString("register", regText, "SetRegister register is required."); !error.empty())
            return ErrorResponse(id, error);
        std::string valueText;
        if (auto error = params.RequiredString("value", valueText,
                "SetRegister value is required (hex like 0x140001000 or decimal)."); !error.empty())
            return ErrorResponse(id, error);
        if (regText.size() > 32 || valueText.size() > 64)
            return ErrorResponse(id, "SetRegister register/value are too long.");
        std::string canonical;
        if (!IsRegisterNameValid(regText, canonical))
            return ErrorResponse(id, "Unknown register. Use rax..r15/rip/eflags (x64) or eax..edi/eip/eflags (x86), cip/csp.");
        std::uintptr_t value = 0;
        if (!ResolveAddress(Trim(valueText), value) && Trim(valueText) != "0")
            return ErrorResponse(id, "Invalid register value: " + valueText);
        auto fromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        auto toString = GetDebuggerBridgeFunction<DbgValToStringFunction>("DbgValToString");
        if (fromString == nullptr || toString == nullptr)
            return ErrorResponse(id, "Register bridge is unavailable.");
        const std::uintptr_t oldValue = fromString(canonical.c_str());
        if (!toString(canonical.c_str(), value))
            return ErrorResponse(id, "The debugger rejected the register write.");
        nlohmann::json result{
            {"action", "setRegister"},
            {"register", canonical},
            {"oldValue", HexAddress(oldValue)},
            {"newValue", HexAddress(value)},
        };
        return SuccessResponse(id, result);
    }

    std::string HandleWriteMemory(const std::string& request, const std::string& id)
    {
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        if (IsRunning())
            return ErrorResponse(id, "Target is running. Pause it before writing memory.");
        const RequestParams params(request);
        std::string addressText;
        if (auto error = params.RequiredSearchText("address", addressText,
                "WriteMemory address must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);
        std::string hexText;
        if (auto error = params.RequiredString("hexBytes", hexText,
                "WriteMemory hexBytes must be 1..12288 chars, e.g. \"48 8B 05\".", 1, kMaxControlHexChars); !error.empty())
            return ErrorResponse(id, error);
        std::vector<unsigned char> bytes;
        std::string parseError;
        if (!ParseHexBytes(hexText, bytes, parseError))
            return ErrorResponse(id, "WriteMemory " + parseError);
        std::uintptr_t address = 0;
        if (auto error = ResolveNonZeroAddressExpression(addressText, address); !error.empty())
            return ErrorResponse(id, error);
        if (!AddressRangeFits(address, bytes.size()))
            return ErrorResponse(id, "WriteMemory address range overflows.");
        auto memWrite = GetDebuggerBridgeFunction<DbgMemWriteFunction>("DbgMemWrite");
        if (memWrite == nullptr)
            return ErrorResponse(id, "Memory-write bridge is unavailable.");
        if (!memWrite(address, bytes.data(), static_cast<std::uintptr_t>(bytes.size())))
            return ErrorResponse(id, "Failed to write memory at " + HexAddress(address));
        // The bytesHex echo duplicates the caller input (up to ~6k tokens on
        // large writes) and stays dropped by default; echoBytes=true restores
        // it for callers that verify against it. nextAddress is always
        // present: it is contractually pinned (Live15) and the .NET echo gate
        // (SlimWriteMemoryAck) preserves it, so dropping it here would break
        // the ack contract for no meaningful saving.
        bool echoBytes = false;
        if (auto error = params.OptionalBoolean("echoBytes", echoBytes,
                "WriteMemory echoBytes must be a boolean."); !error.empty())
            return ErrorResponse(id, error);
        std::uintptr_t next = 0;
        (void)TryAddAddress(address, bytes.size(), next);
        nlohmann::json result{
            {"action", "writeMemory"},
            {"address", HexAddress(address)},
            {"bytesWritten", bytes.size()},
            {"nextAddress", HexAddress(next)},
        };
        if (echoBytes)
            result["bytesHex"] = FormatBytes(bytes);
        return SuccessResponse(id, result);
    }

    std::string HandleCallFunction(const std::string& request, const std::string& id)
    {
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        if (IsRunning())
            return ErrorResponse(id, "Target is running. Pause it before injecting a call.");
        const RequestParams params(request);
        std::string addressText;
        if (auto error = params.RequiredSearchText("address", addressText,
                "CallFunction address must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);
        std::uintptr_t target = 0;
        if (auto error = ResolveNonZeroAddressExpression(addressText, target); !error.empty())
            return ErrorResponse(id, error);
        // Optional first four integer arguments (x64 fastcall rcx/rdx/r8/r9; x86 cdecl pushed).
        const char* argKeys[] = {"arg1", "arg2", "arg3", "arg4"};
        std::vector<std::uintptr_t> args;
        for (const char* key : argKeys)
        {
            if (!HasJsonProperty(request, key))
                break;
            std::string text;
            if (!ExtractJsonString(request, key, text) || text.empty() || text.size() > 64)
                return ErrorResponse(id, std::string("CallFunction ") + key + " must be a short numeric expression.");
            std::uintptr_t value = 0;
            if (!ResolveAddress(Trim(text), value) && Trim(text) != "0")
                return ErrorResponse(id, std::string("Invalid ") + key + ": " + text);
            args.push_back(value);
        }
        bool runAfter = false;
        if (auto error = params.OptionalBoolean("runAfter", runAfter, "CallFunction runAfter must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        auto fromString = GetDebuggerBridgeFunction<DbgValFromStringFunction>("DbgValFromString");
        auto toString = GetDebuggerBridgeFunction<DbgValToStringFunction>("DbgValToString");
        auto memWrite = GetDebuggerBridgeFunction<DbgMemWriteFunction>("DbgMemWrite");
        if (fromString == nullptr || toString == nullptr || memWrite == nullptr)
            return ErrorResponse(id, "Call-injection bridge is unavailable.");
        const std::uintptr_t oldCip = fromString("cip");
        const std::uintptr_t oldCsp = fromString("csp");
        if (oldCip == 0 || oldCsp == 0)
            return ErrorResponse(id, "Could not read cip/csp. Is the target paused?");

        const std::size_t ptrSize = sizeof(std::uintptr_t);
        nlohmann::json result{
            {"action", "callFunction"},
            {"target", HexAddress(target)},
            {"oldCip", HexAddress(oldCip)},
            {"oldCsp", HexAddress(oldCsp)},
        };

        // A stale restore from an earlier injection targets a different return
        // point; drop it (and its temporary breakpoint) before staging this one.
        if (g_pendingCallRestore.armed &&
            g_pendingCallRestore.returnAddress != oldCip)
        {
            if (g_pendingCallRestore.ownsBreakpoint)
                (void)ExecDirect("bc " + HexAddress(g_pendingCallRestore.returnAddress));
            g_pendingCallRestore = {};
        }
        const bool hadReturnBreakpoint = SoftBreakpointExists(oldCip);
        // Restaging at the same cip keeps ownership of our own leftover
        // breakpoint; otherwise a pre-existing breakpoint belongs to the user
        // and must survive the restore untouched.
        const bool ownsReturnBreakpoint = hadReturnBreakpoint
            ? g_pendingCallRestore.armed && g_pendingCallRestore.ownsBreakpoint
            : true;

        std::uintptr_t entryCsp = 0;    // callee entry rsp/esp (return-address slot)
        std::uintptr_t expectedCsp = 0; // csp right after the callee executes `ret`
        if constexpr (sizeof(std::uintptr_t) == 8)
        {
            const char* regs[] = {"rcx", "rdx", "r8", "r9"};
            for (std::size_t i = 0; i < args.size() && i < 4; ++i)
            {
                if (!toString(regs[i], args[i]))
                    return ErrorResponse(id, std::string("Failed to set ") + regs[i] + ".");
            }
            // Windows x64 ABI frame, built below the paused rsp so everything
            // the callee may write stays in dead stack:
            //   entry rsp (ret slot) = oldCsp - 8 (ret) - 32 (shadow) - pad
            //   [entry+8, entry+40)  = 32-byte shadow/home space (callee scratch)
            //   entry rsp % 16 == 8  = alignment required at function entry
            // After `ret`, csp is pad+32 bytes below oldCsp; the temporary
            // breakpoint on oldCip restores it before the original code runs.
            if (oldCsp < ptrSize + 32)
                return ErrorResponse(id, "Stack pointer underflows.");
            std::uintptr_t entry = oldCsp - ptrSize - 32;
            const std::uintptr_t alignmentPad = ((entry % 16) + 8) % 16;
            if (alignmentPad > entry)
                return ErrorResponse(id, "Stack pointer underflows.");
            entry -= alignmentPad;

            unsigned char retBytes[8]{};
            for (std::size_t i = 0; i < ptrSize; ++i)
                retBytes[i] = static_cast<unsigned char>((oldCip >> (i * 8)) & 0xFF);
            if (!memWrite(entry, retBytes, static_cast<std::uintptr_t>(ptrSize)))
                return ErrorResponse(id, "Failed to push the return address.");

            entryCsp = entry;
            expectedCsp = entry + ptrSize;
            result["shadowSpace"] = 32;
            result["alignmentPad"] = alignmentPad;
        }
        else
        {
            // x86 cdecl: push args reversed, then push the return address.
            // The callee leaves the arguments on the stack (caller cleanup),
            // so csp lands 4*args bytes below oldCsp and the restore hook
            // puts it back when the temporary breakpoint fires.
            std::uintptr_t csp = oldCsp;
            for (std::size_t i = args.size(); i > 0; --i)
            {
                std::uintptr_t v = args[i - 1];
                if (csp < ptrSize)
                    return ErrorResponse(id, "Stack pointer underflows.");
                csp -= static_cast<std::uintptr_t>(ptrSize);
                unsigned char b[4]{};
                for (std::size_t k = 0; k < ptrSize; ++k)
                    b[k] = static_cast<unsigned char>((v >> (k * 8)) & 0xFF);
                if (!memWrite(csp, b, static_cast<std::uintptr_t>(ptrSize)))
                    return ErrorResponse(id, "Failed to push call arguments.");
            }
            if (csp < ptrSize)
                return ErrorResponse(id, "Stack pointer underflows.");
            csp -= static_cast<std::uintptr_t>(ptrSize);

            unsigned char retBytes[4]{};
            for (std::size_t k = 0; k < ptrSize; ++k)
                retBytes[k] = static_cast<unsigned char>((oldCip >> (k * 8)) & 0xFF);
            if (!memWrite(csp, retBytes, static_cast<std::uintptr_t>(ptrSize)))
                return ErrorResponse(id, "Failed to push the return address.");

            entryCsp = csp;
            expectedCsp = csp + ptrSize;
        }

        // Arm the temporary return breakpoint before rewriting cip/csp so a
        // failure here leaves the thread exactly where it was.
        if (!hadReturnBreakpoint && !ExecDirect("bp " + HexAddress(oldCip)))
            return ErrorResponse(id, "Could not arm the temporary return breakpoint at the original cip.");
        if (!toString("csp", entryCsp) || !toString("cip", target))
        {
            if (!hadReturnBreakpoint)
                (void)ExecDirect("bc " + HexAddress(oldCip));
            return ErrorResponse(id, "Failed to redirect cip/csp to the injected call.");
        }
        g_pendingCallRestore = PendingCallRestore{
            true, ownsReturnBreakpoint, oldCip, oldCsp, expectedCsp};

        result["newCsp"] = HexAddress(entryCsp);
        result["newCip"] = HexAddress(target);
        result["returnBreakpoint"] = HexAddress(oldCip);
        result["expectedCspOnReturn"] = HexAddress(expectedCsp);
        if (runAfter && !ExecDirect("run"))
            return ErrorResponse(id, "Call was staged but the debugger rejected run.");
        result["running"] = runAfter;
        // Shared execution-control ack policy (see NativeControlHandlers.h):
        // every control ack keeps its followUp hint — the return-value
        // mechanics below are dynamic per call, not static prose.
        result["followUp"] = "A temporary breakpoint at oldCip restores csp when the call returns; the next bridge response then carries returnValue (rax/eax) and registersAfter. Volatile registers (rcx, rdx, r8, r9) are not preserved.";
        return SuccessResponse(id, result);
    }

    namespace
    {
        // Shared implementation for SetLabel/SetComment/SetBookmark: the three
        // methods validate the same address, then differ only in their value
        // field and x64dbg command pair.
        enum class AnnotationKind
        {
            Label,
            Comment,
            Bookmark,
        };

        std::string HandleSetAnnotation(
            const std::string& request,
            const std::string& id,
            AnnotationKind kind)
        {
            const char* method = kind == AnnotationKind::Label ? "SetLabel"
                : kind == AnnotationKind::Comment ? "SetComment" : "SetBookmark";
            const bool isLabel = kind == AnnotationKind::Label;
            if (!IsDebugging())
                return ErrorResponse(id, "No active debug session.");
            std::string addressText;
            if (!ExtractJsonString(request, "address", addressText) || Trim(addressText).empty())
                return ErrorResponse(id, std::string(method) + " address is required.");
            std::uintptr_t address = 0;
            if (!ResolveAddress(addressText, address) || address == 0)
                return ErrorResponse(id, "Invalid address or expression: " + addressText);

            nlohmann::json result;
            if (kind == AnnotationKind::Bookmark)
            {
                bool enabled = true;
                if (HasJsonProperty(request, "enabled") && !ExtractBoolean(request, "enabled", enabled))
                    return ErrorResponse(id, "SetBookmark enabled must be a boolean.");
                const std::string cmd = (enabled ? "bookmark.set " : "bookmark.clear ") + HexAddress(address);
                if (!ExecDirect(cmd))
                    return ErrorResponse(id, "The debugger rejected the bookmark command.");
                result = {
                    {"action", "setBookmark"},
                    {"address", HexAddress(address)},
                    {"enabled", enabled},
                };
            }
            else
            {
                const char* field = isLabel ? "label" : "comment";
                const std::size_t maxBytes = isLabel ? kMaxLabelText : kMaxCommentText;
                std::string value;
                if (HasJsonProperty(request, field) && !ExtractJsonString(request, field, value))
                    return ErrorResponse(id, isLabel
                        ? "SetLabel label must be a string."
                        : "SetComment comment must be a string.");
                if (!IsQuotedArgumentWithinLimit(value, maxBytes))
                    return ErrorResponse(id, isLabel
                        ? "SetLabel label must be at most 256 bytes without quotes or control characters."
                        : "SetComment comment must be at most 1024 bytes without quotes or control characters.");

                std::string cmd;
                if (Trim(value).empty())
                    cmd = (isLabel ? "lblclear " : "cmtclear ") + HexAddress(address);
                else
                    cmd = (isLabel ? "lbl " : "cmt ") + HexAddress(address) + ",\"" + value + "\"";
                if (!ExecDirect(cmd))
                    return ErrorResponse(id, isLabel
                        ? "The debugger rejected the label command."
                        : "The debugger rejected the comment command.");
                result = {
                    {"action", isLabel ? "setLabel" : "setComment"},
                    {"address", HexAddress(address)},
                    {field, value},
                };
            }
            return SuccessResponse(id, result);
        }
    }

    std::string HandleSetLabel(const std::string& request, const std::string& id)
    {
        return HandleSetAnnotation(request, id, AnnotationKind::Label);
    }

    std::string HandleSetComment(const std::string& request, const std::string& id)
    {
        return HandleSetAnnotation(request, id, AnnotationKind::Comment);
    }

    std::string HandleSetBookmark(const std::string& request, const std::string& id)
    {
        return HandleSetAnnotation(request, id, AnnotationKind::Bookmark);
    }
}
