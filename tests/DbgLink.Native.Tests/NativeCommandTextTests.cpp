#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

#include "../../src/native/DbgLink.Native/NativeCommandText.h"
#include "../../src/native/DbgLink.Native/NativeTypes.h"

namespace dbglink_command_text_tests
{
    using namespace dbglink;

    void Require(bool condition, std::string_view message)
    {
        if (!condition)
            throw std::runtime_error(std::string(message));
    }

    void TestCommandArgumentFieldPolicy()
    {
        // 1. OpenDebugTarget path (kMaxTargetPathText = 32760)
        Require(IsQuotedArgumentWithinLimit("C:\\target\\app.exe", kMaxTargetPathText), "valid target path was rejected");
        Require(!IsQuotedArgumentWithinLimit("C:\\target\\app.exe\" --injected", kMaxTargetPathText), "target path with quote was accepted");
        Require(!IsQuotedArgumentWithinLimit("C:\\target\\app.exe\ncalc.exe", kMaxTargetPathText), "target path with newline was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("C:\\target\\app.exe\0calc", 23), kMaxTargetPathText), "target path with null byte was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string(32761, 'a'), kMaxTargetPathText), "target path exceeding cap was accepted");

        // 2. OpenDebugTarget arguments (kMaxTargetArgumentsText = 4096)
        Require(IsQuotedArgumentWithinLimit("--flag --value=123", kMaxTargetArgumentsText), "valid target arguments were rejected");
        Require(!IsQuotedArgumentWithinLimit("--flag\" --injected", kMaxTargetArgumentsText), "target arguments with quote were accepted");
        Require(!IsQuotedArgumentWithinLimit("--flag\r\n--injected", kMaxTargetArgumentsText), "target arguments with CRLF were accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("--flag\0--injected", 17), kMaxTargetArgumentsText), "target arguments with null byte were accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string(4097, 'a'), kMaxTargetArgumentsText), "target arguments exceeding cap were accepted");

        // 3. OpenDebugTarget workDir (kMaxTargetWorkDirText = 32760)
        Require(IsQuotedArgumentWithinLimit("C:\\target\\working", kMaxTargetWorkDirText), "valid workDir was rejected");
        Require(!IsQuotedArgumentWithinLimit("C:\\target\\working\" evil", kMaxTargetWorkDirText), "workDir with quote was accepted");
        Require(!IsQuotedArgumentWithinLimit("C:\\target\\working\n", kMaxTargetWorkDirText), "workDir with newline was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("C:\\target\\working\0dir", 21), kMaxTargetWorkDirText), "workDir with null byte was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string(32761, 'a'), kMaxTargetWorkDirText), "workDir exceeding cap was accepted");

        // 4. SetBreakpoint condition (kMaxConditionalExprText = 256)
        Require(IsQuotedArgumentWithinLimit("rax == 0x140001000", kMaxConditionalExprText), "valid condition was rejected");
        Require(!IsQuotedArgumentWithinLimit("rax == \"1\"", kMaxConditionalExprText), "condition with quote was accepted");
        Require(!IsQuotedArgumentWithinLimit("rax == 1\n", kMaxConditionalExprText), "condition with newline was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("rax == 1\0", 10), kMaxConditionalExprText), "condition with null byte was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string(257, 'a'), kMaxConditionalExprText), "condition exceeding cap was accepted");

        // 5. SetBreakpoint logText (kMaxConditionalLogText = 256)
        Require(IsQuotedArgumentWithinLimit("CIP={cip} RAX={rax}", kMaxConditionalLogText), "valid logText was rejected");
        Require(!IsQuotedArgumentWithinLimit("CIP=\"{cip}\"", kMaxConditionalLogText), "logText with quote was accepted");
        Require(!IsQuotedArgumentWithinLimit("CIP={cip}\n", kMaxConditionalLogText), "logText with newline was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("CIP={cip}\0", 10), kMaxConditionalLogText), "logText with null byte was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string(257, 'a'), kMaxConditionalLogText), "logText exceeding cap was accepted");

        // 6. SetBreakpoint logCondition (kMaxConditionalExprText = 256)
        Require(IsQuotedArgumentWithinLimit("rbx != 0", kMaxConditionalExprText), "valid logCondition was rejected");
        Require(!IsQuotedArgumentWithinLimit("rbx != \"0\"", kMaxConditionalExprText), "logCondition with quote was accepted");
        Require(!IsQuotedArgumentWithinLimit("rbx != 0\r", kMaxConditionalExprText), "logCondition with CR was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("rbx != 0\0", 10), kMaxConditionalExprText), "logCondition with null byte was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string(257, 'a'), kMaxConditionalExprText), "logCondition exceeding cap was accepted");

        // 7. SetLabel label (kMaxLabelText = 256)
        Require(IsQuotedArgumentWithinLimit("MainLoop_Entry", kMaxLabelText), "valid label was rejected");
        Require(!IsQuotedArgumentWithinLimit("Main\"Loop", kMaxLabelText), "label with quote was accepted");
        Require(!IsQuotedArgumentWithinLimit("Main\nLoop", kMaxLabelText), "label with newline was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("Main\0Loop", 9), kMaxLabelText), "label with null byte was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string(257, 'a'), kMaxLabelText), "label exceeding cap was accepted");

        // 8. SetComment comment (kMaxCommentText = 1024)
        Require(IsQuotedArgumentWithinLimit("Decrypted payload entry point", kMaxCommentText), "valid comment was rejected");
        Require(!IsQuotedArgumentWithinLimit("Decrypted \"payload\" entry", kMaxCommentText), "comment with quote was accepted");
        Require(!IsQuotedArgumentWithinLimit("Decrypted\nentry", kMaxCommentText), "comment with newline was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("Decrypted\0entry", 15), kMaxCommentText), "comment with null byte was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string(1025, 'a'), kMaxCommentText), "comment exceeding cap was accepted");
    }

    // SEC J5: local absolute drive-path gate for debug-target paths.
    void TestLocalAbsoluteDrivePath()
    {
        // Accepted: drive-letter absolute, both separators, forward slashes
        // (existing OpenDebugTarget callers/tests use C:/...).
        Require(IsLocalAbsoluteDrivePath("C:\\target\\app.exe"), "backslash drive path was rejected");
        Require(IsLocalAbsoluteDrivePath("C:/test/app.exe"), "forward-slash drive path was rejected");
        Require(IsLocalAbsoluteDrivePath("d:/work"), "lowercase drive path was rejected");
        Require(IsLocalAbsoluteDrivePath("C:/"), "drive root was rejected");

        // Rejected: relative paths and bare filenames.
        Require(!IsLocalAbsoluteDrivePath("target\\app.exe"), "relative path was accepted");
        Require(!IsLocalAbsoluteDrivePath("app.exe"), "bare filename was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:app.exe"), "drive-relative path was accepted");
        Require(!IsLocalAbsoluteDrivePath(""), "empty path was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:"), "bare drive was accepted");

        // Rejected: UNC and NT device prefixes.
        Require(!IsLocalAbsoluteDrivePath("\\\\evil\\share\\a.exe"), "UNC path was accepted");
        Require(!IsLocalAbsoluteDrivePath("//evil/share/a.exe"), "forward-slash UNC was accepted");
        Require(!IsLocalAbsoluteDrivePath("\\\\?\\C:\\x\\a.exe"), "extended-length prefix was accepted");
        Require(!IsLocalAbsoluteDrivePath("\\\\.\\C:\\x\\a.exe"), "device-namespace prefix was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:\\x\\\\evil"), "doubled separator was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:\\x?\\a.exe"), "question-mark path was accepted");

        // M1/G1/G2: ADS colons (any `:` past the drive colon) mirror the
        // managed DbgLinkConfigPath.IsSafePath colon rule.
        Require(!IsLocalAbsoluteDrivePath("C:\\x\\evil:stream.exe"), "ADS file stream was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:\\work:stream"), "ADS directory stream was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:\\x\\evil.exe:stream"), "ADS suffix stream was accepted");
        // Mixed doubled separators (`\/`, `/\`) are UNC smuggling, not just
        // `\\` / `//`.
        Require(!IsLocalAbsoluteDrivePath("C:\\/x\\a.exe"), "mixed backslash-slash was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:/\\x\\a.exe"), "mixed slash-backslash was accepted");

        // Rejected: DOS device components (any position, any case, with or
        // without extension).
        Require(!IsLocalAbsoluteDrivePath("C:\\test\\CON.exe"), "CON component was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:/test/nul"), "lowercase nul was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:\\COM1\\a.exe"), "COM1 directory was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:\\x\\lpt9.txt"), "LPT9 file was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:\\AUX"), "AUX was accepted");
        Require(!IsLocalAbsoluteDrivePath("C:\\x\\conout$.log"), "CONOUT$ was accepted");
        Require(IsLocalAbsoluteDrivePath("C:\\x\\console.exe"), "console.exe was rejected");
        Require(IsLocalAbsoluteDrivePath("C:\\x\\nullified.dll"), "nullified.dll was rejected");
        Require(IsLocalAbsoluteDrivePath("C:\\COMPILE\\a.exe"), "COMPILE directory was rejected");

        // Wide-char overload mirrors the narrow verdicts (IsSafeLocalPath).
        Require(IsLocalAbsoluteDrivePath(L"C:\\target\\app.exe"), "wide drive path was rejected");
        Require(!IsLocalAbsoluteDrivePath(L"\\\\evil\\share\\a.exe"), "wide UNC was accepted");
        Require(!IsLocalAbsoluteDrivePath(L"C:\\test\\NUL"), "wide NUL was accepted");
        Require(!IsLocalAbsoluteDrivePath(L"C:\\x\\evil.exe:stream"), "wide ADS stream was accepted");
        Require(!IsLocalAbsoluteDrivePath(L"C:\\/x\\a.exe"), "wide mixed separator was accepted");

        // Shared component scan used by IsSafeLocalPath.
        Require(PathHasDosDeviceComponent(std::string_view("C:\\x\\prn\\a.exe")), "prn component was missed");
        Require(!PathHasDosDeviceComponent(std::string_view("C:\\x\\printer\\a.exe")), "printer false positive");
        Require(PathHasDosDeviceComponent(std::wstring_view(L"C:\\x\\aux")), "wide aux was missed");
    }

    void RunNativeCommandTextTests()
    {
        // No length concern here: pass an unbounded cap so only the character
        // policy is exercised (length caps are covered below and in the field
        // policy).
        constexpr std::size_t kNoCap = std::numeric_limits<std::size_t>::max();
        // Safe text: plain expressions, format placeholders, UTF-8 high bytes.
        Require(IsQuotedArgumentWithinLimit("eax == 1", kNoCap), "plain condition was rejected");
        Require(IsQuotedArgumentWithinLimit("CIP={cip} RAX={rax}", kNoCap), "log format placeholders were rejected");
        Require(IsQuotedArgumentWithinLimit("", kNoCap), "empty text was rejected");
        Require(IsQuotedArgumentWithinLimit("\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82", kNoCap),
            "valid UTF-8 text was rejected");

        // Quotes and control characters must be rejected, never escaped.
        Require(!IsQuotedArgumentWithinLimit("a\"b", kNoCap), "literal quote was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("a\nb"), kNoCap), "newline was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("a\rb"), kNoCap), "carriage return was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("a\tb"), kNoCap), "tab was accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("a\x01\x02\x1F"), kNoCap), "control bytes were accepted");
        Require(!IsQuotedArgumentWithinLimit(std::string("a\x7F"), kNoCap), "DEL byte was accepted");

        // Length cap composes with the character policy.
        Require(IsQuotedArgumentWithinLimit("abcd", 4), "text at the cap was rejected");
        Require(!IsQuotedArgumentWithinLimit("abcde", 4), "text over the cap was accepted");
        Require(IsQuotedArgumentWithinLimit("", 0), "empty text at a zero cap was rejected");
        Require(!IsQuotedArgumentWithinLimit(std::string(4096, 'a'), 1024),
            "oversized plain text was accepted");
        Require(!IsQuotedArgumentWithinLimit("a\"b", 1024),
            "quote rejection was skipped for short text");
        Require(!IsQuotedArgumentWithinLimit(std::string("bad\n"), 4),
            "control rejection was skipped when the text fits the cap");

        TestCommandArgumentFieldPolicy();

        TestLocalAbsoluteDrivePath();
    }
}
