// NativePipeAuthTests.cpp — N1 native pipe authentication.
//
// Covers the native side of N1 native pipe authentication:
// session-token generation (OS CSPRNG, 64 lowercase hex), the constant-time
// request gate in HandleRequest (accept/reject, top-level-only envelope,
// nothing executes on rejection), and the atomic rendezvous-file publish.
#include <cctype>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <aclapi.h>

#include "../../src/native/DbgLink.Native/NativeBridgeFoundation.h"
#include "../../src/native/DbgLink.Native/NativeJson.h"
#include "../../src/native/DbgLink.Native/NativeJsonFormatting.h"
#include "../../src/native/DbgLink.Native/NativePipeServer.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"
#include "../../src/native/DbgLink.Native/X64DbgApiShim.h"

namespace dbglink_pipe_auth_tests
{
    using namespace dbglink;

    void Require(bool condition, std::string_view message)
    {
        if (!condition)
            throw std::runtime_error(std::string(message));
    }

    bool Contains(const std::string& haystack, const std::string& needle)
    {
        return haystack.find(needle) != std::string::npos;
    }

    bool IsLowerHex(std::string_view text)
    {
        if (text.empty())
            return false;
        for (const char c : text)
        {
            const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex)
                return false;
        }
        return true;
    }

    bool IsLowerHex(std::wstring_view text)
    {
        if (text.empty())
            return false;
        for (const wchar_t c : text)
        {
            const bool hex = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
            if (!hex)
                return false;
        }
        return true;
    }

    // Fixed 64-hex session token for deterministic gate tests.
    const std::string kTestToken =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    std::string PingRequest(const std::string& tokenFragment, const char* id = "5")
    {
        return std::string("{\"id\":") + id + ",\"method\":\"ping\"" + tokenFragment + "}";
    }

    void TestSessionTokenShape()
    {
        std::string first, second;
        Require(GenerateSessionToken(first), "session token generation failed");
        Require(GenerateSessionToken(second), "session token generation failed");
        Require(first.size() == 64 && IsLowerHex(first), "session token must be 64 lowercase hex");
        Require(second.size() == 64 && IsLowerHex(second), "session token must be 64 lowercase hex");
        Require(first != second, "back-to-back session tokens must differ (CSPRNG)");
    }

    void TestPipeNameShape()
    {
        std::wstring suffix;
        Require(GeneratePipeSuffix(suffix), "pipe suffix generation failed");
        Require(suffix.size() == 8 && IsLowerHex(suffix), "pipe suffix must be 8 lowercase hex");
        Require(BuildPipeName(1234, L"deadbeef") == L"DbgLink.Control.1234.deadbeef",
            "pipe name must keep the DbgLink.Control. prefix with pid and suffix");
    }

    void TestConstantTimeEquals()
    {
        Require(ConstantTimeEquals("abc", "abc"), "equal strings must compare equal");
        Require(!ConstantTimeEquals("abc", "abd"), "differing strings must compare unequal");
        Require(!ConstantTimeEquals("abc", "abcd"), "length mismatch must compare unequal");
        Require(ConstantTimeEquals("", ""), "empty strings must compare equal");
        Require(ConstantTimeEquals(kTestToken, kTestToken), "token self-compare must hold");
    }

    void TestTokenGate()
    {
        testshim::Reset();
        // No token configured: legacy token-free requests keep working, so
        // every pre-existing HandleRequest test below stays green.
        Require(Contains(HandleRequest(PingRequest("")), "\"ok\":true"),
            "token-free request must pass while no token is configured");

        g_pipeToken = kTestToken;
        const std::string withToken = ",\"token\":\"" + kTestToken + "\"";

        // Byte-exact unauthorized envelope for the missing-token case.
        Require(HandleRequest(PingRequest("")) ==
            "{\"id\":5,\"ok\":false,\"error\":{\"code\":\"unauthorized\",\"message\":"
            "\"Missing or invalid bridge token.\"}}",
            "missing-token envelope mismatch");

        Require(Contains(HandleRequest(PingRequest(",\"token\":\"wrong\"")), "\"code\":\"unauthorized\""),
            "wrong token must be rejected");
        Require(Contains(HandleRequest(PingRequest(",\"token\":7")), "\"code\":\"unauthorized\""),
            "non-string token must be rejected");
        // The token lives at the envelope top level: a params-scoped token
        // must not authorize (NativeJson routes handler args to params).
        Require(Contains(
                HandleRequest("{\"id\":5,\"method\":\"ping\",\"params\":{\"token\":\"" + kTestToken + "\"}}"),
                "\"code\":\"unauthorized\""),
            "params-scoped token must not authorize");
        Require(Contains(HandleRequest(PingRequest("", "9")), "\"id\":9"),
            "unauthorized rejection must echo the request id");

        // Correct token authorizes, including non-ping methods.
        Require(Contains(HandleRequest(PingRequest(withToken)), "\"ok\":true"),
            "correct token must authorize ping");
        Require(Contains(HandleRequest(PingRequest(withToken)), "\"bridge\":\"native\""),
            "authorized ping lost its payload");
        Require(Contains(HandleRequest("{\"id\":6,\"method\":\"GetServerStatus\"" + withToken + "}"),
                "\"ok\":true"),
            "correct token must authorize GetServerStatus");

        // Rejection executes nothing: StepInto would issue "sti 0x1" through
        // ExecDirect on a paused session, so an empty log proves the gate ran
        // before dispatch.
        testshim::SetDebugging(true);
        testshim::ClearExecLog();
        const std::string denied =
            HandleRequest("{\"id\":7,\"method\":\"StepInto\",\"params\":{\"count\":1}}");
        Require(Contains(denied, "\"code\":\"unauthorized\""), "unguarded StepInto must be rejected");
        Require(testshim::ExecLog().empty(), "rejected request must not reach the debugger");

        const std::string allowed = HandleRequest(
            "{\"id\":7,\"method\":\"StepInto\",\"params\":{\"count\":1}" + withToken + "}");
        Require(Contains(allowed, "\"ok\":true"), "guarded StepInto with token must execute");
        Require(!testshim::ExecLog().empty() && testshim::ExecLog().back() == "sti 0x1",
            "authorized StepInto must reach the debugger");

        testshim::Reset();
    }

    std::string ReadFileBytes(const std::wstring& path)
    {
        ScopedHandle file(CreateFileW(
            path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
        Require(static_cast<bool>(file), "rendezvous file must exist after publish");
        std::string bytes;
        char chunk[4096]{};
        for (;;)
        {
            DWORD read = 0;
            Require(ReadFile(file.get(), chunk, sizeof(chunk), &read, nullptr) != FALSE,
                "rendezvous file must be readable");
            if (read == 0)
                break;
            bytes.append(chunk, read);
        }
        return bytes;
    }

    void RequireDaclProtected(const std::wstring& path)
    {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        PACL dacl = nullptr;
        const DWORD status = GetNamedSecurityInfoW(
            path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &dacl, nullptr, &descriptor);
        Require(status == ERROR_SUCCESS && descriptor != nullptr, "rendezvous ACL must be readable");
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        Require(GetSecurityDescriptorControl(descriptor, &control, &revision) != FALSE,
            "rendezvous security control must be readable");
        LocalFree(descriptor);
        Require((control & SE_DACL_PRESENT) != 0, "rendezvous file must carry an explicit DACL");
        Require((control & SE_DACL_PROTECTED) != 0,
            "rendezvous DACL must be protected (user-only, no inheritance)");
    }

    void TestRendezvousWrite()
    {
        testshim::Reset();
        g_pipeToken = kTestToken;
        g_pipeName = L"DbgLink.Control.4321.abcdef01";

        wchar_t tempDir[MAX_PATH]{};
        const DWORD tempLength = GetTempPathW(MAX_PATH, tempDir);
        Require(tempLength > 0 && tempLength < MAX_PATH, "temp path must resolve");
        const std::wstring path = std::wstring(tempDir) +
            L"dbglink-n1-test-" + std::to_wstring(GetCurrentProcessId()) + L".json";
        const std::wstring tmpPath =
            path + L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
        g_rendezvousPathOverride = path;

        Require(WriteRendezvousFile(), "rendezvous publish must succeed");
        Require(GetFileAttributesW(tmpPath.c_str()) == INVALID_FILE_ATTRIBUTES,
            "rendezvous tmp file must not linger after the atomic move");
        RequireDaclProtected(path);

        const auto published = nlohmann::ordered_json::parse(ReadFileBytes(path));
        Require(published["schemaVersion"] == 1, "rendezvous schemaVersion must be 1");
        Require(published["pid"] == GetCurrentProcessId(), "rendezvous pid must match");
        Require(published["pipeName"] == "\\\\.\\pipe\\DbgLink.Control.4321.abcdef01",
            "rendezvous pipeName mismatch");
        Require(published["token"] == kTestToken, "rendezvous token mismatch");
        Require(published["debugger"] == "x64dbg", "rendezvous debugger mismatch");
        Require(published["imagePath"].is_string(), "rendezvous imagePath must be a string");

        RemoveRendezvousFile();
        Require(GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES,
            "rendezvous file must be gone after removal");

        testshim::Reset();
    }

    void TestRendezvousPerPid()
    {
        // N1 per-PID rendezvous (B4/B5): the default path carries the own
        // pid so concurrent debugger instances never share one file.
        testshim::Reset();
        Require(g_rendezvousPathOverride.empty(), "override must start empty");
        const std::wstring path = RendezvousPath();
        Require(!path.empty(), "default rendezvous path must resolve");
        const std::wstring expected = L"native-endpoint-" +
            std::to_wstring(GetCurrentProcessId()) + L".json";
        Require(path.size() >= expected.size() &&
                path.compare(path.size() - expected.size(), expected.size(), expected) == 0,
            "default rendezvous path must end with native-endpoint-<pid>.json");
        testshim::Reset();
    }

    void RunPipeAuthTests()
    {
        TestSessionTokenShape();
        TestPipeNameShape();
        TestConstantTimeEquals();
        TestTokenGate();
        TestRendezvousWrite();
        TestRendezvousPerPid();
    }
} // namespace dbglink_pipe_auth_tests
