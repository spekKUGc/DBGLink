using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

public sealed class AddressMappingAndModuleParsingTests
{
    // ========================================================================================
    // GROUP 1: TRYPARSEADDRESS VALID HEX INPUTS (20 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("0x0", 0UL)]
    [InlineData("0X0", 0UL)]
    [InlineData("0", 0UL)]
    [InlineData("0x1", 1UL)]
    [InlineData("0x10", 16UL)]
    [InlineData("0x7FFF", 32767UL)]
    [InlineData("0x10000000", 268435456UL)]
    [InlineData("0x7FFFFFFF", 2147483647UL)]
    [InlineData("0x80000000", 2147483648UL)]
    [InlineData("0xFFFFFFFF", 4294967295UL)]
    [InlineData("0x100000000", 4294967296UL)]
    [InlineData("0x7FFFFFFFFFFFFFFF", 9223372036854775807UL)]
    [InlineData("0xFFFFFFFFFFFFFFFF", 18446744073709551615UL)]
    [InlineData("0Xffffffffffffffff", 18446744073709551615UL)]
    [InlineData("401000", 4198400UL)]
    [InlineData("DEADBEEF", 3735928559UL)]
    [InlineData("deadbeef", 3735928559UL)]
    [InlineData("  0x1234  ", 4660UL)]
    [InlineData("  0Xabcd  ", 43981UL)]
    [InlineData("7ffff7dd1000", 140737351847936UL)]
    public void TryParseAddress_ValidHexInputs_ParsesExpectedValue(string input, ulong expected)
    {
        var success = AddressMapping.TryParseAddress(input, out var address);
        Assert.True(success);
        Assert.Equal(expected, address);
    }

    // ========================================================================================
    // GROUP 2: TRYPARSEADDRESS INVALID INPUTS (15 Tests)
    // ========================================================================================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    [InlineData("hello")]
    [InlineData("0x")]
    [InlineData("0X")]
    [InlineData("0xG0")]
    [InlineData("0x12 34")]
    [InlineData("-0x1")]
    [InlineData("-1")]
    [InlineData("+0x10")]
    [InlineData("0x10000000000000000")] // 65-bit overflow
    [InlineData("0xDEADBEEFG")]
    [InlineData("!@#$")]
    public void TryParseAddress_InvalidInputs_ReturnsFalse(string? input)
    {
        var success = AddressMapping.TryParseAddress(input, out var address);
        Assert.False(success);
        Assert.Equal(0UL, address);
    }

    // ========================================================================================
    // GROUP 3: FORMATADDRESS ROUND-TRIP (10 Tests)
    // ========================================================================================

    [Theory]
    [InlineData(0UL, "0x0")]
    [InlineData(1UL, "0x1")]
    [InlineData(15UL, "0xF")]
    [InlineData(16UL, "0x10")]
    [InlineData(255UL, "0xFF")]
    [InlineData(4096UL, "0x1000")]
    [InlineData(0xDEADBEEFUL, "0xDEADBEEF")]
    [InlineData(0x7FFFFFFFFFFFFFFFUL, "0x7FFFFFFFFFFFFFFF")]
    [InlineData(0xFFFFFFFFFFFFFFFFUL, "0xFFFFFFFFFFFFFFFF")]
    [InlineData(0x140001000UL, "0x140001000")]
    public void FormatAddress_MatchesExpectedHexRepresentation(ulong value, string expected)
    {
        var formatted = AddressMapping.FormatAddress(value);
        Assert.Equal(expected, formatted);

        var parsed = AddressMapping.TryParseAddress(formatted, out var roundtrip);
        Assert.True(parsed);
        Assert.Equal(value, roundtrip);
    }

    // ========================================================================================
    // GROUP 4: NORMALIZEIDENTITYPATH (15 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("c:\\app\\test.exe", "C:\\APP\\TEST.EXE")]
    [InlineData("C:/app/test.exe", "C:\\APP\\TEST.EXE")]
    [InlineData("\"C:\\app\\test.exe\"", "C:\\APP\\TEST.EXE")]
    [InlineData("  \"C:/app/test.exe\"  ", "C:\\APP\\TEST.EXE")]
    [InlineData("\\C:\\app\\test.exe", "C:\\APP\\TEST.EXE")]
    [InlineData("C:\\app\\bin\\", "C:\\APP\\BIN")]
    [InlineData("C:/app/bin/", "C:\\APP\\BIN")]
    [InlineData("D:\\GAMES\\DOOM\\DOOM.EXE", "D:\\GAMES\\DOOM\\DOOM.EXE")]
    [InlineData("e:\\tools\\x64dbg\\x64dbg.exe", "E:\\TOOLS\\X64DBG\\X64DBG.EXE")]
    [InlineData("\\D:\\target\\payload.dll", "D:\\TARGET\\PAYLOAD.DLL")]
    [InlineData("app.exe", "APP.EXE")]
    [InlineData("sub\\module.dll", "SUB\\MODULE.DLL")]
    [InlineData("sub/module.dll", "SUB\\MODULE.DLL")]
    [InlineData("\"path with spaces/binary.dll\"", "PATH WITH SPACES\\BINARY.DLL")]
    [InlineData("C:\\a\\b\\c\\\\", "C:\\A\\B\\C")]
    public void NormalizeIdentityPath_FormatsAndNormalizesConsistently(string input, string expected)
    {
        var normalized = AddressMapping.NormalizeIdentityPath(input);
        Assert.Equal(expected, normalized);
    }

    // ========================================================================================
    // GROUP 5: FILENAME EXTRACTION (10 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("C:\\Windows\\System32\\ntdll.dll", "ntdll.dll")]
    [InlineData("C:/Windows/System32/kernel32.dll", "kernel32.dll")]
    [InlineData("/usr/lib/libc.so.6", "libc.so.6")]
    [InlineData("target.exe", "target.exe")]
    [InlineData("C:\\app\\", "")]
    [InlineData("C:/app/", "")]
    [InlineData("D:\\Games\\Game.x86_64", "Game.x86_64")]
    [InlineData("\\\\server\\share\\tool.exe", "tool.exe")]
    [InlineData("foo/bar/baz.dll", "baz.dll")]
    [InlineData("single", "single")]
    public void FileName_ExtractsTrailingComponent(string path, string expected)
    {
        var fileName = AddressMapping.FileName(path);
        Assert.Equal(expected, fileName);
    }

    // ========================================================================================
    // GROUP 6: NORMALIZESHA256 VALIDATION & SANITIZATION (10 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85", null)] // 63 chars
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555", null)] // 65 chars
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85z", null)] // 'z' non-hex
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85 ", null)] // space inside
    [InlineData("12345", null)]
    public void NormalizeSha256_Enforces64HexDigitFormat(string? input, string? expected)
    {
        var normalized = AddressMapping.NormalizeSha256(input);
        Assert.Equal(expected, normalized);
    }

    // ========================================================================================
    // GROUP 7: PARSELIVEMODULES TEXT PARSING & EDGE CASES (15 Tests)
    // ========================================================================================

    [Fact]
    public void ParseLiveModules_SingleValidModule_ParsesCorrectly()
    {
        var text = "base=0x1000 end=0x5000 name=test.dll path=C:\\test.dll\n";
        var modules = AddressMapping.ParseLiveModules(text);
        Assert.Single(modules);
        Assert.Equal(0x1000UL, modules[0].Base);
        Assert.Equal(0x5000UL, modules[0].End);
        Assert.Equal("test.dll", modules[0].Name);
        Assert.Equal("C:\\test.dll", modules[0].Path);
    }

    [Fact]
    public void ParseLiveModules_MultipleModules_ParsesAll()
    {
        var text = "base=0x1000 end=0x5000 name=mod1 path=C:\\mod1.dll\nbase=0x6000 end=0x9000 name=mod2 path=C:\\mod2.dll\n";
        var modules = AddressMapping.ParseLiveModules(text);
        Assert.Equal(2, modules.Count);
        Assert.Equal("mod1", modules[0].Name);
        Assert.Equal("mod2", modules[1].Name);
    }

    [Fact]
    public void ParseLiveModules_InvertedBaseEnd_DiscardsModuleAndMarksTruncated()
    {
        var text = "base=0x5000 end=0x1000 name=bad.dll path=C:\\bad.dll\n";
        var modules = (AddressMapping.LiveModuleCollection)AddressMapping.ParseLiveModules(text);
        Assert.Empty(modules);
        Assert.True(modules.Truncated);
    }

    [Fact]
    public void ParseLiveModules_EqualBaseEnd_DiscardsModuleAndMarksTruncated()
    {
        var text = "base=0x1000 end=0x1000 name=bad.dll path=C:\\bad.dll\n";
        var modules = (AddressMapping.LiveModuleCollection)AddressMapping.ParseLiveModules(text);
        Assert.Empty(modules);
        Assert.True(modules.Truncated);
    }

    [Theory]
    [InlineData("mapTruncated=true\nbase=0x1000 end=0x2000 name=a path=b\n")]
    [InlineData("outputTruncated=true\nbase=0x1000 end=0x2000 name=a path=b\n")]
    [InlineData("...[truncated]\nbase=0x1000 end=0x2000 name=a path=b\n")]
    public void ParseLiveModules_TruncationMarker_SetsTruncatedFlag(string text)
    {
        var modules = (AddressMapping.LiveModuleCollection)AddressMapping.ParseLiveModules(text);
        Assert.True(modules.Truncated);
        Assert.Single(modules);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   \n\r\n")]
    [InlineData("some random debugger log output\n")]
    [InlineData("base=invalid end=0x2000 name=a path=b\n")]
    [InlineData("base=0x1000 end=invalid name=a path=b\n")]
    [InlineData("base=0x1000 end=0x2000 no_name no_path\n")]
    [InlineData("base=0x1000 end=0x2000 path=C:\\test.dll\n")] // missing name=
    [InlineData("base=0x1000 end=0x2000 name=test.dll\n")] // missing path=
    public void ParseLiveModules_MalformedLines_IgnoredCleanly(string text)
    {
        var modules = AddressMapping.ParseLiveModules(text);
        Assert.Empty(modules);
    }

    // ========================================================================================
    // GROUP 8: TRYREADHEXFIELD PARSING (5 Tests)
    // ========================================================================================

    [Theory]
    [InlineData("base=0x1000 end=0x2000", "base", true, 0x1000UL)]
    [InlineData("base=0x1000 end=0x2000", "end", true, 0x2000UL)]
    [InlineData("base=0x1000 end=0x2000", "missing", false, 0UL)]
    [InlineData("start=0xABCD", "start", true, 0xABCDUL)]
    [InlineData("rva=0x400 size=0x1000", "rva", true, 0x400UL)]
    public void TryReadHexField_ExtractsCorrectField(string line, string field, bool expectedSuccess, ulong expectedVal)
    {
        var success = AddressMapping.TryReadHexField(line, field, out var value);
        Assert.Equal(expectedSuccess, success);
        Assert.Equal(expectedVal, value);
    }
}
