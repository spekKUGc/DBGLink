extern alias Server;
using DbgLink.Server;
using ConfigPath = Server::DbgLink.Shared.DbgLinkConfigPath;
using Xunit;

namespace DbgLink.Tests;

public sealed class NativePipeAndPathSecurityTests
{
    // ========================================================================================
    // GROUP 1: NATIVE PIPE NAME POLICY VALIDATION (25 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("DbgLink.Control", true)]
    [InlineData("DbgLink.Control.1", true)]
    [InlineData("DbgLink.Control.42", true)]
    [InlineData("DbgLink.Control.1000", true)]
    [InlineData("DbgLink.Control.65535", true)]
    [InlineData("DbgLink.Control.2147483647", true)] // int.MaxValue
    [InlineData("DbgLink.Control.0", false)] // PID must be positive
    [InlineData("DbgLink.Control.01", false)] // leading zero rejected
    [InlineData("DbgLink.Control.007", false)] // leading zero rejected
    [InlineData("DbgLink.Control.-1", false)] // negative rejected
    [InlineData("DbgLink.Control.2147483648", false)] // overflow > int.MaxValue
    [InlineData("DbgLink.Control.999999999999", false)] // overflow
    [InlineData("DbgLink.Control.abc", false)] // non-digit
    [InlineData("DbgLink.Control.12a", false)] // non-digit
    [InlineData("DbgLink.Control.", false)] // missing suffix
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("DbgLink.Control\0", false)] // control char
    [InlineData("OtherPipe.1", false)] // wrong prefix
    [InlineData("DbgLink", false)]
    [InlineData("DbgLink.Control. 1", false)] // space inside
    [InlineData("DbgLink.Control.1 ", false)] // trailing space
    [InlineData("dbglink.control.1", false)] // case sensitive prefix
    [InlineData("DBGLINK.CONTROL", false)] // case sensitive prefix
    public void NativePipeNamePolicy_ValidatesPipeNames(string? pipeName, bool expectedValid)
    {
        var valid = NativePipeNamePolicy.IsValid(pipeName);
        Assert.Equal(expectedValid, valid);
    }

    [Fact]
    public void NativePipeNamePolicy_OversizedPipeName_ReturnsFalse()
    {
        var longPipe = "DbgLink.Control." + new string('9', 250);
        Assert.False(NativePipeNamePolicy.IsValid(longPipe));
    }

    // ========================================================================================
    // GROUP 2: BEARER TOKEN FORMAT & TOKEN68 VALIDATION (25 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("12345678901234567890123456789012", true)] // 32 chars
    [InlineData("abcdefghijklmnopqrstuvwxyz012345", true)] // 32 chars
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", true)] // 32 chars
    [InlineData("1234567890123456789012345678901234567890123456789012345678901234", true)] // 64 chars
    [InlineData("abcdefghijklmnopqrstuvwxyz012345-._~+/", true)] // token68 valid chars
    [InlineData("abcdefghijklmnopqrstuvwxyz012345=", true)] // valid padding at end
    [InlineData("abcdefghijklmnopqrstuvwxyz012345==", true)] // valid padding at end
    [InlineData("abcdefghijklmnopqrstuvwxyz012345===", true)] // valid padding at end
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("1234567890123456789012345678901", false)] // 31 chars (too short)
    [InlineData("short-token", false)]
    [InlineData("abcdefghijklmnopqrstuvwxyz012345=extra", false)] // padding in middle
    [InlineData("abcdefghijklmnopqrstuvwxyz012345=123", false)] // padding followed by text
    [InlineData("================================", false)] // valueEnd == 0
    [InlineData("abcdefghijklmnopqrstuvwxyz012345 with spaces", false)] // spaces
    [InlineData("abcdefghijklmnopqrstuvwxyz012345@domain", false)] // '@' invalid
    [InlineData("abcdefghijklmnopqrstuvwxyz012345#hash", false)] // '#' invalid
    [InlineData("abcdefghijklmnopqrstuvwxyz012345$dollar", false)] // '$' invalid
    [InlineData("abcdefghijklmnopqrstuvwxyz012345!bang", false)] // '!' invalid
    [InlineData("abcdefghijklmnopqrstuvwxyz012345:colon", false)] // ':' invalid
    [InlineData("abcdefghijklmnopqrstuvwxyz012345\nnewline", false)] // newline
    [InlineData("abcdefghijklmnopqrstuvwxyz012345\0nullbyte", false)] // null byte
    [InlineData("abcdefghijklmnopqrstuvwxyz012345;semi", false)] // ';' invalid
    public void IsValidBearerToken_ValidatesLengthAndToken68Charset(string? token, bool expectedValid)
    {
        var valid = ConfigPath.IsValidBearerToken(token);
        Assert.Equal(expectedValid, valid);
    }

    [Fact]
    public void IsValidBearerToken_MaximumLength512_Accepted()
    {
        var token512 = new string('A', 512);
        Assert.True(ConfigPath.IsValidBearerToken(token512));
    }

    [Fact]
    public void IsValidBearerToken_OverLength513_Rejected()
    {
        var token513 = new string('A', 513);
        Assert.False(ConfigPath.IsValidBearerToken(token513));
    }

    // ========================================================================================
    // GROUP 3: SAFE PATH TRAVERSAL & ALTERNATE DATA STREAM GUARDS (15 Tests)
    // ========================================================================================

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("C:\\test\\file.txt:stream", false)] // Alternate data stream
    [InlineData("C:\\test\\file.txt:stream:$DATA", false)] // Alternate data stream
    [InlineData("C:\\a:b", false)] // Extra colon
    [InlineData("1:\\test", false)] // Invalid drive letter
    [InlineData("::\\test", false)] // Malformed colon
    [InlineData("C:\\test\\file.txt:", false)] // Trailing colon
    [InlineData("?:\\test", false)] // Invalid drive symbol
    [InlineData("\\\\?\\C:\\test:stream", false)] // Long path prefix with ADS
    [InlineData("C:\\Windows\\System32\\notepad.exe", true)] // Standard absolute path
    [InlineData("C:\\Temp", true)] // Standard absolute directory
    [InlineData("C:\\", true)] // Drive root
    [InlineData("D:\\tools\\x64dbg", true)] // Secondary drive path
    public void IsSafePath_DetectsAlternateDataStreamsAndInvalidColons(string? path, bool expectedSafe)
    {
        var safe = ConfigPath.IsSafePath(path!);
        Assert.Equal(expectedSafe, safe);
    }

    // ========================================================================================
    // GROUP 4: ANALYSIS ID & DOS DEVICE RESERVATIONS (20 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("session-1", true)]
    [InlineData("session_alpha_123", true)]
    [InlineData("a-b_c", true)]
    [InlineData("A1B2C3", true)]
    [InlineData("run-100", true)]
    [InlineData("test_session", true)]
    [InlineData("my-target-process_42", true)]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("CON", false)] // DOS reserved
    [InlineData("con", false)] // DOS reserved case-insensitive
    [InlineData("PRN", false)] // DOS reserved
    [InlineData("aux", false)] // DOS reserved
    [InlineData("NUL", false)] // DOS reserved
    [InlineData("COM1", false)] // DOS reserved
    [InlineData("com9", false)] // DOS reserved
    [InlineData("LPT1", false)] // DOS reserved
    [InlineData("lpt8", false)] // DOS reserved
    [InlineData("CONIN$", false)] // DOS reserved
    public void IsValidAnalysisId_RejectsDosDevicesAndValidatesIdentifiers(string? id, bool expectedValid)
    {
        var valid = AnalysisSessionRegistry.IsValidAnalysisId(id!);
        Assert.Equal(expectedValid, valid);
    }

    [Theory]
    [InlineData("session.1")] // Dot not allowed
    [InlineData("session/1")] // Slash not allowed
    [InlineData("session\\1")] // Backslash not allowed
    [InlineData("session:1")] // Colon not allowed
    [InlineData("session 1")] // Space not allowed
    [InlineData("session@1")] // At not allowed
    public void IsValidAnalysisId_RejectsSpecialCharacters(string id)
    {
        var valid = AnalysisSessionRegistry.IsValidAnalysisId(id);
        Assert.False(valid);
    }

    [Fact]
    public void IsValidAnalysisId_OversizedId_ReturnsFalse()
    {
        var longId = new string('a', 129);
        Assert.False(AnalysisSessionRegistry.IsValidAnalysisId(longId));

        var maxId = new string('a', 128);
        Assert.True(AnalysisSessionRegistry.IsValidAnalysisId(maxId));
    }
}
