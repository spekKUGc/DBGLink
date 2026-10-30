#include "NativeTypes.h"
#include "NativeAnalysisData.h"
#include "NativeBridgeFoundation.h"
#include "NativeCommandText.h"
#include "NativeDebuggerQueries.h"
#include "NativeDisassemblyQueries.h"
#include "NativeJson.h"
#include "NativeJsonFormatting.h"
#include "NativeMemoryQueries.h"
#include "NativeRequestParams.h"
#include "NativeSecondaryHandlers.h"
#include "NativeXrefHandlers.h"
#include "NativeXrefSearch.h"

namespace dbglink
{
    namespace
    {
        bool TryReadSnapshotBoolean(
            const std::string& request,
            const char* name,
            bool fallback,
            std::string& error)
        {
            if (!HasJsonProperty(request, name))
                return fallback;

            bool value = false;
            if (!ExtractBoolean(request, name, value))
            {
                error = std::string(name) + " must be a boolean.";
                return fallback;
            }
            return value;
        }

        bool TryReadEnvelopePayload(const std::string& raw, nlohmann::json& payload)
        {
            try
            {
                const auto envelope = nlohmann::json::parse(raw);
                if (!envelope.is_object() ||
                    !envelope.contains("ok") || !envelope["ok"].is_boolean() ||
                    !envelope["ok"].get<bool>())
                    return false;

                if (envelope.contains("result"))
                {
                    payload = envelope["result"];
                    return true;
                }
                if (envelope.contains("text"))
                {
                    payload = envelope["text"];
                    return true;
                }
            }
            catch (const nlohmann::json::exception&)
            {
            }
            return false;
        }
    }

    std::string HandleModuleRecords(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string path;
        if (auto error = params.OptionalStringBounded("modulePath", path, 32760,
                "modulePath must be a string of at most 32760 bytes."); !error.empty())
            return ErrorResponse(id, error);
        std::vector<ModuleRecord> modules;
        bool truncated = false;
        std::string error;
        if (!CollectModuleRecords(modules, truncated, error)) return ErrorResponse(id, error);
        return FormatModuleRecords(id, modules, truncated, path);
    }

    std::string HandleAnalysisSnapshot(const std::string& request, const std::string& id)
    {
        std::string error;
        const bool includeThreads = TryReadSnapshotBoolean(request, "includeThreads", false, error);
        if (!error.empty())
            return ErrorResponse(id, error);
        const bool includeModules = TryReadSnapshotBoolean(request, "includeModules", true, error);
        if (!error.empty())
            return ErrorResponse(id, error);

        nlohmann::json stateBefore;
        if (!TryReadEnvelopePayload(HandleSnapshotState(id), stateBefore) || !stateBefore.is_object())
            return ErrorResponse(id, "Debugger state bridge is unavailable.");

        nlohmann::json stateAfter;
        nlohmann::json sections = nlohmann::json::object();
        sections["status"] = nlohmann::json
        {
            {"plugin", "DBGLink"},
            {"bridge", "native"},
            {"pid", GetCurrentProcessId()},
            {"debugging", stateBefore.value("debugging", false)},
            {"capabilities", nlohmann::json{{"analysisSnapshot", true}}}
        };

        nlohmann::json payload;
        if (!TryReadEnvelopePayload(HandleCurrentContext(request, id), payload))
            return ErrorResponse(id, "Current debugger context could not be collected.");
        sections["context"] = std::move(payload);

        if (!TryReadEnvelopePayload(HandleCallStack(request, id), payload))
            return ErrorResponse(id, "The debugger call stack could not be collected.");
        sections["callStack"] = std::move(payload);

        if (includeThreads)
        {
            if (!TryReadEnvelopePayload(HandleAllActiveThreads(id), payload))
                return ErrorResponse(id, "The debugger thread list could not be collected.");
            sections["threads"] = std::move(payload);
        }

        if (includeModules)
        {
            if (!TryReadEnvelopePayload(HandleModuleRecords(request, id), payload))
                return ErrorResponse(id, "The debugger module map could not be collected.");
            sections["modules"] = std::move(payload);
        }

        if (!TryReadEnvelopePayload(HandleSnapshotState(id), stateAfter) || !stateAfter.is_object())
            return ErrorResponse(id, "Debugger state bridge is unavailable.");

        const nlohmann::json result
        {
            {"schemaVersion", 1},
            {"bridgeCalls", 1},
            {"stateBefore", std::move(stateBefore)},
            {"stateAfter", std::move(stateAfter)},
            {"sections", std::move(sections)}
        };
        return SuccessResponse(id, result);
    }

    std::string HandleSnapshotState(const std::string& id)
    {
        const auto generation = g_debuggerGeneration.load();
        auto isDebugging = GetDebuggerBridgeFunction<DbgIsDebuggingFunction>("DbgIsDebugging");
        auto isRunning = GetDebuggerBridgeFunction<DbgIsDebuggingFunction>("DbgIsRunning");
        auto getThreadList = GetDebuggerBridgeFunction<DbgGetThreadListFunction>("DbgGetThreadList");
        auto bridgeFree = GetDebuggerBridgeFunction<BridgeFreeFunction>("BridgeFree");
        if (!isDebugging || !isRunning || !getThreadList || !bridgeFree)
            return ErrorResponse(id, "Debugger state bridge is unavailable.");
        const bool debugging = isDebugging();
        const bool running = isRunning();
        nlohmann::json state{{"debuggerPid", GetCurrentProcessId()}, {"debugging", debugging},
            {"running", running}, {"generation", std::to_string(generation)}, {"threadId", nullptr}};
        if (debugging && !running)
        {
            BridgeThreadListGuard threads;
            threads.freeFunction = bridgeFree;
            getThreadList(&threads.list);
            if (threads.list.list && threads.list.count > 0 && threads.list.count <= kMaxThreadEntries &&
                threads.list.currentThread >= 0 && threads.list.currentThread < threads.list.count)
                state["threadId"] = threads.list.list[threads.list.currentThread].basicInfo.threadId;
        }
        state["stableRead"] = generation == g_debuggerGeneration.load();
        return SuccessResponse(id, state);
    }

    std::string HandleGetXrefs(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string targetText;
        if (auto error = params.RequiredSearchText("target", targetText,
                "GetXrefs target must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);
        std::uint64_t start = 0;
        if (auto error = params.BoundedUnsigned("start", start, 0, 256,
                "GetXrefs start must be between 0 and 256."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t count = 100;
        if (auto error = params.BoundedUnsigned("count", count, 1, 256,
                "GetXrefs count must be between 1 and 256."); !error.empty())
            return ErrorResponse(id, error);

        bool scanFallback = true;
        if (auto error = params.OptionalBoolean("scanFallback", scanFallback,
                "GetXrefs scanFallback must be a boolean."); !error.empty())
            return ErrorResponse(id, error);

        std::string module;
        if (auto error = params.OptionalModuleFilter("module", module,
                "GetXrefs module must be a string.",
                "GetXrefs module must be at most 256 printable bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t maxScanBytes = kDefaultSearchScanBytes;
        if (auto error = params.BoundedUnsigned("maxScanBytes", maxScanBytes, 4096, kMaxSearchScanBytes,
                "GetXrefs maxScanBytes must be between 4096 and 67108864."); !error.empty())
            return ErrorResponse(id, error);

        std::uintptr_t target = 0;
        if (auto error = ResolveNonZeroAddressExpression(targetText, target); !error.empty())
            return ErrorResponse(id, error);

        std::vector<ModuleRecord> modules;
        bool mapTruncated = false;
        std::string error;
        if (!CollectModuleRecords(modules, mapTruncated, error))
            return ErrorResponse(id, "GetXrefs: " + error);

        const auto selectedModules = SelectModulesByFilter(std::move(modules), module, false);
        const std::size_t maxResults = static_cast<std::size_t>(start + count);
        auto search = ScanXrefs(
            target,
            selectedModules,
            !module.empty() && !EqualsInsensitive(module, "all"),
            scanFallback,
            maxResults,
            static_cast<std::size_t>(maxScanBytes));
        search.moduleMapTruncated = mapTruncated;
        return TextResponse(id, "GetXrefs", FormatXrefSearch(
            targetText,
            target,
            static_cast<std::size_t>(start),
            static_cast<std::size_t>(count),
            search));
    }

    std::string HandleReadString(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string expression;
        if (auto error = params.RequiredSearchText("address", expression,
                "ReadStringAtAddress address must be a non-empty printable expression of at most 256 bytes."); !error.empty())
            return ErrorResponse(id, error);

        std::uint64_t requestedBytes = 512;
        if (auto error = params.BoundedUnsigned("maxBytes", requestedBytes, 1, kMaxStringReadBytes,
                "ReadStringAtAddress maxBytes must be between 1 and 8192."); !error.empty())
            return ErrorResponse(id, error);

        bool unicode = false;
        if (auto error = params.OptionalBoolean("unicode", unicode,
                "ReadStringAtAddress unicode must be a boolean."); !error.empty())
            return ErrorResponse(id, error);
        if (unicode)
            requestedBytes = std::max<std::uint64_t>(requestedBytes, 2);

        std::uintptr_t address = 0;
        if (auto error = ResolveAddressExpression(expression, address); !error.empty())
            return ErrorResponse(id, error);

        std::vector<unsigned char> data;
        if (!ReadMemory(address, static_cast<std::size_t>(requestedBytes), data))
            return ErrorResponse(id, "Failed to read memory at " + HexAddress(address));

        std::size_t byteCount = data.size();
        if (unicode)
        {
            byteCount = 0;
            while (byteCount + 1 < data.size() && (data[byteCount] != 0 || data[byteCount + 1] != 0))
                byteCount += 2;
            return TextResponse(id, "ReadStringAtAddress", Utf16BytesToUtf8(data, byteCount));
        }

        std::string text;
        text.reserve(data.size());
        for (const unsigned char character : data)
        {
            if (character == 0)
                break;
            text.push_back(character < 0x80 ? static_cast<char>(character) : '?');
        }
        return TextResponse(id, "ReadStringAtAddress", text);
    }

    std::string HandleModules(const std::string& id, const char* method)
    {
        std::vector<ModuleRecord> modules;
        bool mapTruncated = false;
        std::string error;
        if (!CollectModuleRecords(modules, mapTruncated, error))
            return ErrorResponse(id, std::string(method) + ": " + error);
        if (modules.empty())
            return TextResponse(id, method, "[" + std::string(method) + "] No image modules found in memory map.");
        return TextResponse(id, method, FormatModuleList(method, modules, mapTruncated));
    }

    std::string HandleCurrentContext(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::uint64_t beforeBytes = 32;
        std::uint64_t instructionBytes = 160;
        std::uint64_t stackBytes = 128;
        if (auto error = params.BoundedUnsigned("beforeBytes", beforeBytes, 0, 512,
                "GetCurrentContext beforeBytes must be between 0 and 512."); !error.empty())
            return ErrorResponse(id, error);
        if (auto error = params.BoundedUnsigned("instructionBytes", instructionBytes, 1, 4096,
                "GetCurrentContext instructionBytes must be between 1 and 4096."); !error.empty())
            return ErrorResponse(id, error);
        if (auto error = params.BoundedUnsigned("stackBytes", stackBytes, 0, 4096,
                "GetCurrentContext stackBytes must be between 0 and 4096."); !error.empty())
            return ErrorResponse(id, error);

        return TextResponse(id, "GetCurrentContext", CurrentContextText(
            static_cast<std::size_t>(beforeBytes),
            static_cast<std::size_t>(instructionBytes),
            static_cast<std::size_t>(stackBytes)));
    }

    std::string HandleAllRegisters(const std::string& id)
    {
        return TextResponse(id, "GetAllRegisters", AllRegistersText());
    }

    std::string HandleAllActiveThreads(const std::string& id)
    {
        return TextResponse(id, "GetAllActiveThreads", ActiveThreadsText());
    }

    std::string HandleCallStack(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::uint64_t requestedFrames = kDefaultCallStackFrames;
        if (auto error = params.BoundedUnsigned("maxFrames", requestedFrames, 1, kMaxCallStackFrames,
                "GetCallStack maxFrames must be between 1 and 256."); !error.empty())
            return ErrorResponse(id, error);

        return TextResponse(id, "GetCallStack", CallStackText(static_cast<int>(requestedFrames)));
    }

    std::string HandleOpenDebugTarget(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::string path;
        if (auto error = params.RequiredString("path", path,
                "path must be a non-empty string of at most 32760 bytes.", 1); !error.empty())
            return ErrorResponse(id, error);
        std::string arguments;
        if (auto error = params.OptionalString("arguments", arguments,
                "arguments must be a string of at most 4096 bytes."); !error.empty())
            return ErrorResponse(id, error);
        std::string workDir;
        if (auto error = params.OptionalString("workDir", workDir,
                "workDir must be a string of at most 32760 bytes."); !error.empty())
            return ErrorResponse(id, error);
        if (!IsQuotedArgumentWithinLimit(path, kMaxTargetPathText))
            return ErrorResponse(id, "path must be at most 32760 bytes without quotes or control characters.");
        // SEC J5: direct-pipe callers bypass the managed ValidateDebugTarget
        // gate, so UNC (`\\host\...`), NT device prefixes (`\\?\`, `\\.`)
        // and DOS device targets must die here, not in x64dbg's loader.
        if (!IsLocalAbsoluteDrivePath(path))
            return ErrorResponse(id, "path must be a local absolute drive path (for example C:\\target\\app.exe).");
        // Defense in depth for direct-pipe callers that bypass the managed
        // ValidateDebugTarget gate: only executable images may become a
        // debug target.
        if (path.size() < 4 ||
            (!EqualsInsensitive(path.substr(path.size() - 4), ".exe") &&
             !EqualsInsensitive(path.substr(path.size() - 4), ".dll")))
            return ErrorResponse(id, "path must be a .exe or .dll debug target.");
        if (!IsQuotedArgumentWithinLimit(arguments, kMaxTargetArgumentsText))
            return ErrorResponse(id, "arguments must be at most 4096 bytes without quotes or control characters.");
        if (!IsQuotedArgumentWithinLimit(workDir, kMaxTargetWorkDirText))
            return ErrorResponse(id, "workDir must be at most 32760 bytes without quotes or control characters.");
        if (!workDir.empty() && !IsLocalAbsoluteDrivePath(workDir))
            return ErrorResponse(id, "workDir must be a local absolute drive path (for example C:\\work).");
        const auto execute = GetDebuggerBridgeFunction<DbgCmdExecDirectFunction>("DbgCmdExecDirect");
        if (execute == nullptr)
            return ErrorResponse(id, "The debugger command interface is unavailable.");
        // Mirrors x64dbg's own startup path: init "file"[, "cmdline"[, "workdir"]].
        // Opening a target replaces any current debug session first.
        std::string command = "init \"" + path + "\"";
        if (!arguments.empty())
            command += ", \"" + arguments + "\"";
        else if (!workDir.empty())
            command += ", \"\"";
        if (!workDir.empty())
            command += ", \"" + workDir + "\"";
        const bool opened = execute(command.c_str());
        if (!opened)
            return ErrorResponse(id, "The debugger could not open the target.");
        const nlohmann::json result{{"opened", opened}, {"path", path}};
        return SuccessResponse(id, result);
    }

    std::string HandleAttachDebugger(const std::string& request, const std::string& id)
    {
        const RequestParams params(request);
        std::uint64_t pid = 0;
        if (!HasJsonProperty(request, "pid"))
            return ErrorResponse(id, "pid must be an integer between 1 and 2147483647.");
        if (auto error = params.BoundedUnsigned("pid", pid, 1, 2147483647,
                "pid must be an integer between 1 and 2147483647."); !error.empty())
            return ErrorResponse(id, error);
        const auto execute = GetDebuggerBridgeFunction<DbgCmdExecDirectFunction>("DbgCmdExecDirect");
        if (execute == nullptr)
            return ErrorResponse(id, "The debugger command interface is unavailable.");
        // Mirrors the debugger's own attach path: attaching replaces any
        // current debug session first, like init does for a fresh target.
        // The pid is decimal (x64dbg plain numbers are hex; "." forces
        // decimal, matching the debugger's own command line handling).
        const std::string command = "attach ." + std::to_string(pid);
        const bool attached = execute(command.c_str());
        if (!attached)
            return ErrorResponse(id, "The debugger could not attach to the target process.");
        const nlohmann::json result{{"attached", true}, {"pid", pid}};
        return SuccessResponse(id, result);
    }

}
