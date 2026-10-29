#include "NativeTypes.h"
#include "NativeBridgeFoundation.h"
#include "NativeJsonFormatting.h"
#include "NativeControlHandlers.h"
#include "NativeRequestParams.h"

// Execution control (step/run/pause/continue). Breakpoint, state-edit,
// thread/backtrace, chunk-read and annotation methods live in their own
// themed TUs; the helpers they share are in NativeControlSupport.
namespace dbglink
{
    namespace
    {
        std::string HandleStep(const std::string& request, const std::string& id, const char* action, const char* cmd)
        {
            if (!IsDebugging())
                return ErrorResponse(id, "No active debug session.");
            if (IsRunning())
                return ErrorResponse(id, "Target is running. Pause it before stepping.");
            const RequestParams params(request);
            std::uint64_t count = 1;
            if (auto error = params.BoundedUnsigned("count", count, 1, 100,
                    "Step count must be between 1 and 100."); !error.empty())
                return ErrorResponse(id, error);
            // x64dbg parses integer constants as hex: format the decimal
            // count as compact hex so count=10 steps 10 times, not 16.
            // HexAddress matches the shared compact-hex wire policy.
            std::string command = std::string(cmd) + " " + HexAddress(static_cast<std::uintptr_t>(count));
            if (!ExecDirect(command))
                return ErrorResponse(id, "The debugger rejected the step command.");
            // Stepping resumes the target asynchronously; the caller should poll
            // GetAnalysisSnapshot until consistency==unchanged.
            nlohmann::json result{
                {"action", action},
                {"count", count},
                {"command", command},
                {"followUp", "Poll GetAnalysisSnapshot until the target pauses again."},
            };
            return SuccessResponse(id, result);
        }
    }

    std::string HandleStepInto(const std::string& request, const std::string& id)
    {
        return HandleStep(request, id, "stepInto", "sti");
    }

    std::string HandleStepOver(const std::string& request, const std::string& id)
    {
        return HandleStep(request, id, "stepOver", "sto");
    }

    std::string HandleStepOut(const std::string& request, const std::string& id)
    {
        return HandleStep(request, id, "stepOut", "rtr");
    }

    std::string HandleRunDebugger(const std::string& request, const std::string& id)
    {
        (void)request;
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        if (IsRunning())
            return SuccessResponse(id, {{"action", "run"}, {"alreadyRunning", true}});
        if (!ExecDirect("run"))
            return ErrorResponse(id, "The debugger rejected the run command.");
        return SuccessResponse(id, {{"action", "run"}, {"resumed", true},
            {"followUp", "Poll GetAnalysisSnapshot for the new stop reason."}});
    }

    std::string HandlePauseDebugger(const std::string& request, const std::string& id)
    {
        (void)request;
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        if (!IsRunning())
            return SuccessResponse(id, {{"action", "pause"}, {"alreadyPaused", true}});
        // x64dbg arms a one-shot int3 at the current CIP: if the thread is
        // blocked inside a syscall that never returns to that address, the
        // pause never lands (and a later attempt is rejected while it is
        // still armed). Surface that explicitly so the caller retries.
        if (!ExecDirect("pause"))
            return ErrorResponse(id, "The debugger rejected the pause command (a previous pause attempt may still be armed; poll GetAnalysisSnapshot and retry PauseDebugger).");
        return SuccessResponse(id, {{"action", "pause"}, {"requested", true},
            {"followUp", "Poll GetAnalysisSnapshot until consistency==unchanged; if still running after a few seconds, repeat PauseDebugger."}});
    }

    std::string HandleContinueDebugger(const std::string& request, const std::string& id)
    {
        (void)request;
        if (!IsDebugging())
            return ErrorResponse(id, "No active debug session.");
        if (IsRunning())
            return SuccessResponse(id, {{"action", "continue"}, {"alreadyRunning", true}});
        // Continue after a pause/breakpoint is x64dbg `run`.
        if (!ExecDirect("run"))
            return ErrorResponse(id, "The debugger rejected the continue command.");
        return SuccessResponse(id, {{"action", "continue"}, {"resumed", true},
            {"followUp", "Poll GetAnalysisSnapshot for the new stop reason."}});
    }
}
