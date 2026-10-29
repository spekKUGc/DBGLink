#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeCommandText.h"
#include "NativeControlSupport.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeInputValidation.h"
#include "NativeControlHandlers.h"
#include "NativeRequestParams.h"

namespace dbglink
{
    std::string HandleSetBreakpoint(const std::string& request, const std::string& id)
    {
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session. Open a target first.");
        const RequestParams params(request);
        std::string addressText;
        if (auto error = params.RequiredSearchText("address", addressText,
                "SetBreakpoint address must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);
        std::string kind = "soft";
        if (auto error = params.OptionalString("kind", kind, "SetBreakpoint kind must be a string."); !error.empty())
            return ErrorResponse(id, error);
        std::string name;
        if (auto error = params.OptionalString("name", name, "SetBreakpoint name must be a string."); !error.empty())
            return ErrorResponse(id, error);
        if (!name.empty() && !IsBreakpointNameValid(name))
            return ErrorResponse(id, "SetBreakpoint name must match [A-Za-z_$.?][A-Za-z0-9_$.?]* (max 64).");
        bool singleshot = false;
        if (auto error = params.OptionalBoolean("singleshot", singleshot,
                "SetBreakpoint singleshot must be a boolean."); !error.empty())
            return ErrorResponse(id, error);
        std::string condition;
        if (auto error = params.OptionalString("condition", condition, "SetBreakpoint condition must be a string."); !error.empty())
            return ErrorResponse(id, error);
        std::string logText;
        if (auto error = params.OptionalString("logText", logText, "SetBreakpoint logText must be a string."); !error.empty())
            return ErrorResponse(id, error);
        std::string logCondition;
        if (auto error = params.OptionalString("logCondition", logCondition,
                "SetBreakpoint logCondition must be a string."); !error.empty())
            return ErrorResponse(id, error);
        if (!IsQuotedArgumentWithinLimit(condition, kMaxConditionalExprText))
            return ErrorResponse(id, "SetBreakpoint condition must be at most 256 bytes without quotes or control characters.");
        if (!IsQuotedArgumentWithinLimit(logText, kMaxConditionalLogText))
            return ErrorResponse(id, "SetBreakpoint logText must be at most 256 bytes without quotes or control characters.");
        if (!IsQuotedArgumentWithinLimit(logCondition, kMaxConditionalExprText))
            return ErrorResponse(id, "SetBreakpoint logCondition must be at most 256 bytes without quotes or control characters.");

        std::uintptr_t address = 0;
        if (auto error = ResolveNonZeroAddressExpression(addressText, address); !error.empty())
            return ErrorResponse(id, error);

        std::string command;
        std::string typeLabel = kind;
        // Address the debugger stores for this breakpoint: memory breakpoints
        // live on the whole page, so x64dbg keys them by page base. Conditions
        // and log statements (bpc/bpl/bplc) must use the same address or they
        // are silently ignored.
        std::uintptr_t breakpointAddress = address;
        // Effective singleshoot as stored by x64dbg (memory: !restore).
        bool effectiveSingleshot = singleshot;
        if (EqualsInsensitive(kind, "soft") || EqualsInsensitive(kind, "normal") || kind.empty())
        {
            typeLabel = "soft";
            command = "bp " + HexAddress(address);
            if (!name.empty())
                command += "," + name;
            if (singleshot)
                command += ",ss";
        }
        else if (EqualsInsensitive(kind, "hw") || EqualsInsensitive(kind, "hardware"))
        {
            typeLabel = "hw";
            std::string hwType = "x";
            if (auto error = params.OptionalString("hwType", hwType, "SetBreakpoint hwType must be a string."); !error.empty())
                return ErrorResponse(id, error);
            std::uint64_t hwSize = 1;
            if (auto error = params.OptionalUnsigned("hwSize", hwSize, "SetBreakpoint hwSize must be an integer."); !error.empty())
                return ErrorResponse(id, error);
            if (!EqualsInsensitive(hwType, "x") && !EqualsInsensitive(hwType, "r") && !EqualsInsensitive(hwType, "w"))
                return ErrorResponse(id, "SetBreakpoint hwType must be x, r or w.");
            if (hwSize != 1 && hwSize != 2 && hwSize != 4 && hwSize != 8)
                return ErrorResponse(id, "SetBreakpoint hwSize must be 1, 2, 4 or 8.");
            if (sizeof(std::uintptr_t) == 4 && hwSize == 8)
                return ErrorResponse(id, "SetBreakpoint hwSize 8 requires the x64 debugger.");
            if (address % static_cast<std::uintptr_t>(hwSize) != 0)
                return ErrorResponse(id, "Hardware breakpoint address must be aligned to hwSize.");
            const std::string lowered = ToLower(hwType);
            command = "bph " + HexAddress(address) + "," + lowered + "," + std::to_string(hwSize);
        }
        else if (EqualsInsensitive(kind, "mem") || EqualsInsensitive(kind, "memory"))
        {
            typeLabel = "mem";
            std::string memType = "a";
            if (auto error = params.OptionalString("memType", memType, "SetBreakpoint memType must be a string."); !error.empty())
                return ErrorResponse(id, error);
            bool restore = false;
            if (auto error = params.OptionalBoolean("restore", restore, "SetBreakpoint restore must be a boolean."); !error.empty())
                return ErrorResponse(id, error);
            if (!EqualsInsensitive(memType, "a") && !EqualsInsensitive(memType, "r") &&
                !EqualsInsensitive(memType, "w") && !EqualsInsensitive(memType, "x"))
                return ErrorResponse(id, "SetBreakpoint memType must be a, r, w or x.");
            const std::string lowered = ToLower(memType);
            std::uintptr_t pageBase = 0;
            std::uintptr_t pageSize = 0;
            // Memory breakpoints live on the whole page: arm the page base so
            // the stored address matches what ListBreakpoints reports.
            if (FindPageBase(address, pageBase, pageSize))
            {
                command = "bpm " + HexAddress(pageBase) + "," + (restore ? "1" : "0") + "," + lowered;
                breakpointAddress = pageBase;
            }
            else
                command = "bpm " + HexAddress(address) + "," + (restore ? "1" : "0") + "," + lowered;
            effectiveSingleshot = !restore;
        }
        else
        {
            return ErrorResponse(id, "SetBreakpoint kind must be soft, hw or mem.");
        }

        if (!ExecDirect(command))
            return ErrorResponse(id, "The debugger rejected the breakpoint command.");
        nlohmann::json result{
            {"action", "setBreakpoint"},
            {"kind", typeLabel},
            {"address", HexAddress(address)},
            {"expression", addressText},
            {"command", command},
        };
        if (typeLabel == "mem")
        {
            std::uintptr_t pageBase = 0;
            std::uintptr_t pageSize = 0;
            if (FindPageBase(address, pageBase, pageSize))
            {
                result["pageBase"] = HexAddress(pageBase);
                result["pageSize"] = pageSize;
                result["note"] = "Memory breakpoints cover the whole page starting at pageBase.";
            }
        }
        if (!name.empty())
            result["name"] = name;
        // The bpc/bpl/bplc sub-commands must be checked: an invalid
        // expression would otherwise be echoed back as applied. On failure
        // remove the breakpoint just created so the operation stays atomic
        // (failure means no breakpoint), then report which field the
        // debugger rejected.
        const auto rollbackBreakpoint = [&]()
        {
            if (typeLabel == "hw")
                (void)ExecDirect("bphc " + HexAddress(breakpointAddress));
            else if (typeLabel == "mem")
                (void)ExecDirect("bpmc " + HexAddress(breakpointAddress));
            else
                (void)ExecDirect("bc " + HexAddress(breakpointAddress));
        };
        if (!condition.empty())
        {
            if (!ExecDirect("bpc " + HexAddress(breakpointAddress) + ",\"" + condition + "\""))
            {
                rollbackBreakpoint();
                return ErrorResponse(id, "The debugger rejected the breakpoint condition.");
            }
            result["condition"] = condition;
        }
        if (!logText.empty())
        {
            if (!ExecDirect("bpl " + HexAddress(breakpointAddress) + ",\"" + logText + "\""))
            {
                rollbackBreakpoint();
                return ErrorResponse(id, "The debugger rejected the breakpoint log text.");
            }
            result["logText"] = logText;
        }
        if (!logCondition.empty())
        {
            if (!ExecDirect("bplc " + HexAddress(breakpointAddress) + ",\"" + logCondition + "\""))
            {
                rollbackBreakpoint();
                return ErrorResponse(id, "The debugger rejected the breakpoint log condition.");
            }
            result["logCondition"] = logCondition;
        }
        // Memory breakpoints are singleshoot unless restore=true (x64dbg semantics).
        result["singleshot"] = effectiveSingleshot;
        return SuccessResponse(id, result);
    }

    std::string HandleClearBreakpoint(const std::string& request, const std::string& id)
    {
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        const RequestParams params(request);
        bool clearAll = false;
        if (auto error = params.OptionalBoolean("all", clearAll, "ClearBreakpoint all must be a boolean."); !error.empty())
            return ErrorResponse(id, error);
        std::string kind;
        if (auto error = params.OptionalString("kind", kind, "ClearBreakpoint kind must be a string."); !error.empty())
            return ErrorResponse(id, error);
        std::string addressText;
        const bool hasAddress = params.Has("address");
        if (auto error = params.OptionalString("address", addressText, "ClearBreakpoint address must be a string."); !error.empty())
            return ErrorResponse(id, error);
        if (!hasAddress && !clearAll)
            return ErrorResponse(id, "ClearBreakpoint requires address or all=true.");
        if (hasAddress && !IsSearchTextValid(addressText))
            return ErrorResponse(id, "ClearBreakpoint address must be printable (max 256 bytes).");

        std::uintptr_t address = 0;
        if (hasAddress)
        {
            if (auto error = ResolveNonZeroAddressExpression(addressText, address); !error.empty())
                return ErrorResponse(id, error);
        }

        auto clearOne = [](const std::string& k, std::uintptr_t addr, bool all) -> bool
        {
            std::string cmd;
            if (EqualsInsensitive(k, "hw") || EqualsInsensitive(k, "hardware"))
                cmd = all ? "bphc" : "bphc " + HexAddress(addr);
            else if (EqualsInsensitive(k, "mem") || EqualsInsensitive(k, "memory"))
                cmd = all ? "bpmc" : "bpmc " + HexAddress(addr);
            else
                cmd = all ? "bc" : "bc " + HexAddress(addr);
            return ExecDirect(cmd);
        };

        nlohmann::json result{
            {"action", "clearBreakpoint"},
        };
        if (clearAll)
        {
            std::vector<std::string> kinds;
            if (kind.empty() || EqualsInsensitive(kind, "all"))
                kinds = {"soft", "hw", "mem"};
            else if (EqualsInsensitive(kind, "soft") || EqualsInsensitive(kind, "normal"))
                kinds = {"soft"};
            else if (EqualsInsensitive(kind, "hw") || EqualsInsensitive(kind, "hardware"))
                kinds = {"hw"};
            else if (EqualsInsensitive(kind, "mem") || EqualsInsensitive(kind, "memory"))
                kinds = {"mem"};
            else
                return ErrorResponse(id, "ClearBreakpoint kind must be soft, hw, mem or all.");
            bool ok = true;
            for (auto& k : kinds)
                ok = clearOne(k, 0, true) && ok;
            // Deleting when none exist still succeeds in x64dbg ("No breakpoints to delete!" returns true).
            if (!ok)
                return ErrorResponse(id, "The debugger could not clear breakpoints.");
            result["cleared"] = "all";
            result["kinds"] = kinds;
        }
        else
        {
            std::string k = kind.empty() ? "soft" : kind;
            if (!EqualsInsensitive(k, "soft") && !EqualsInsensitive(k, "normal") &&
                !EqualsInsensitive(k, "hw") && !EqualsInsensitive(k, "hardware") &&
                !EqualsInsensitive(k, "mem") && !EqualsInsensitive(k, "memory"))
                return ErrorResponse(id, "ClearBreakpoint kind must be soft, hw or mem.");
            std::string canonical = EqualsInsensitive(k, "hw") || EqualsInsensitive(k, "hardware") ? "hw"
                : EqualsInsensitive(k, "mem") || EqualsInsensitive(k, "memory") ? "mem" : "soft";
            // Memory breakpoints are keyed by page base: clear the containing
            // page so an address inside the page resolves to the stored entry.
            std::uintptr_t clearAddress = address;
            std::uintptr_t pageBase = 0;
            std::uintptr_t pageSize = 0;
            if (canonical == "mem" && FindPageBase(address, pageBase, pageSize))
                clearAddress = pageBase;
            if (!clearOne(canonical, clearAddress, false))
                return ErrorResponse(id, "The debugger could not clear the breakpoint (no such breakpoint?).");
            result["address"] = HexAddress(address);
            if (canonical == "mem" && clearAddress != address)
                result["pageBase"] = HexAddress(clearAddress);
            result["kind"] = canonical;
        }
        return SuccessResponse(id, result);
    }

    std::string HandleListBreakpoints(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::uint64_t offset = 0;
        if (auto error = params.OptionalUnsigned("offset", offset, "ListBreakpoints offset must be an integer."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t maxItems = 128;
        if (auto error = params.BoundedUnsigned("maxItems", maxItems, 1, 512,
                "ListBreakpoints maxItems must be between 1 and 512."); !error.empty())
            return ErrorResponse(id, error);
        auto getList = GetDebuggerBridgeFunction<DbgGetBpListFunction>("DbgGetBpList");
        auto bridgeFree = GetDebuggerBridgeFunction<BridgeFreeFunction>("BridgeFree");
        if (getList == nullptr || bridgeFree == nullptr)
            return ErrorResponse(id, "Breakpoint-list bridge is unavailable.");

        struct Entry
        {
            std::string type;
            std::uintptr_t addr = 0;
            bool enabled = false;
            bool singleshoot = false;
            bool active = false;
            std::string name;
            std::string mod;
            unsigned int hitCount = 0;
        };
        std::vector<Entry> all;
        const std::pair<int, const char*> types[] = {
            {static_cast<int>(BpListType::Normal), "soft"},
            {static_cast<int>(BpListType::Hardware), "hw"},
            {static_cast<int>(BpListType::Memory), "mem"},
        };
        for (auto [typeId, label] : types)
        {
            NativeBreakpointMapGuard guard;
            guard.freeFunction = bridgeFree;
            int count = getList(typeId, &guard.map);
            if (count < 0)
                return ErrorResponse(id, "x64dbg returned an invalid breakpoint count.");
            if (guard.map.count < 0 || guard.map.count > 4096)
                return ErrorResponse(id, "x64dbg returned an invalid breakpoint list.");
            if (!ValidateBridgeList(guard.map.count, guard.map.bp, 4096))
                return ErrorResponse(id, "x64dbg returned a null breakpoint buffer.");
            for (int i = 0; i < guard.map.count && all.size() < kMaxBreakpointRecords; ++i)
            {
                const auto& bp = guard.map.bp[i];
                Entry e;
                e.type = label;
                e.addr = bp.addr;
                e.enabled = bp.enabled;
                e.singleshoot = bp.singleshoot;
                e.active = bp.active;
                e.name = SingleLine(BufferText(bp.name, sizeof(bp.name)));
                e.mod = SingleLine(BufferText(bp.mod, sizeof(bp.mod)));
                e.hitCount = bp.hitCount;
                all.push_back(std::move(e));
            }
        }
        std::sort(all.begin(), all.end(), [](const Entry& a, const Entry& b) { return a.addr < b.addr; });
        const PageWindow window = ComputePageWindow(offset, maxItems, all.size());
        nlohmann::json items = nlohmann::json::array();
        for (std::size_t i = 0; i < window.count; ++i)
        {
            const auto& e = all[window.start + i];
            items.push_back({
                {"type", e.type},
                {"address", HexAddress(e.addr)},
                {"enabled", e.enabled},
                // Wire name follows the advertised SetBreakpoint "singleshot"
                // schema; x64dbg itself calls the flag singleshoot.
                {"singleshot", e.singleshoot},
                {"active", e.active},
                {"name", e.name},
                {"module", e.mod},
                {"hitCount", e.hitCount},
            });
        }
        nlohmann::json result;
        ApplyPagedEnvelope(result, window, offset);
        result["breakpoints"] = std::move(items);
        return SuccessResponse(id, result);
    }
}
