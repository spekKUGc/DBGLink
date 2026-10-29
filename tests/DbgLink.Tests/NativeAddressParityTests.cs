using DbgLink.Server;
using Xunit;

namespace DbgLink.Tests;

// Parity contract between the native ResolveAddress fast path
// (src/native/DbgLink.Native/NativeJsonFormatting.cpp) and the managed
// AddressMapping.TryParseAddress: bare numbers are hexadecimal, an optional
// 0x/0X prefix is accepted, surrounding whitespace is ignored, and anything
// else is rejected by the parsers (the native side additionally consults
// x64dbg's DbgValFromString for symbols/registers when attached).
public sealed class NativeAddressParityTests
{
    [Theory]
    [InlineData("0", 0UL)]
    [InlineData("1", 1UL)]
    [InlineData("2", 2UL)]
    [InlineData("3", 3UL)]
    [InlineData("4", 4UL)]
    [InlineData("5", 5UL)]
    [InlineData("6", 6UL)]
    [InlineData("7", 7UL)]
    [InlineData("8", 8UL)]
    [InlineData("9", 9UL)]
    [InlineData("10", 16UL)]
    [InlineData("11", 17UL)]
    [InlineData("12", 18UL)]
    [InlineData("20", 32UL)]
    [InlineData("99", 153UL)]
    [InlineData("100", 256UL)]
    [InlineData("101", 257UL)]
    [InlineData("123", 291UL)]
    [InlineData("999", 2457UL)]
    [InlineData("1000", 4096UL)]
    [InlineData("1234", 4660UL)]
    [InlineData("7777", 30583UL)]
    [InlineData("9999", 39321UL)]
    [InlineData("401000", 4198400UL)]
    [InlineData("7777777", 125269879UL)]
    [InlineData("999999", 10066329UL)]
    [InlineData("123456", 1193046UL)]
    [InlineData("654321", 6636321UL)]
    [InlineData("1000000", 16777216UL)]
    [InlineData("123456789", 4886718345UL)]
    [InlineData("007", 7UL)]
    [InlineData("000", 0UL)]
    [InlineData("0001", 1UL)]
    [InlineData("0010", 16UL)]
    public void BareDecimalLookingStrings_ParseAsHex(string input, ulong expected)
    {
        Assert.True(AddressMapping.TryParseAddress(input, out var address));
        Assert.Equal(expected, address);
    }

    [Theory]
    [InlineData("0x0", 0UL)]
    [InlineData("0x1", 1UL)]
    [InlineData("0x2", 2UL)]
    [InlineData("0x3", 3UL)]
    [InlineData("0x4", 4UL)]
    [InlineData("0x5", 5UL)]
    [InlineData("0x6", 6UL)]
    [InlineData("0x7", 7UL)]
    [InlineData("0x8", 8UL)]
    [InlineData("0x9", 9UL)]
    [InlineData("0xa", 10UL)]
    [InlineData("0xb", 11UL)]
    [InlineData("0xc", 12UL)]
    [InlineData("0xd", 13UL)]
    [InlineData("0xe", 14UL)]
    [InlineData("0xf", 15UL)]
    [InlineData("0X0", 0UL)]
    [InlineData("0X1", 1UL)]
    [InlineData("0X2", 2UL)]
    [InlineData("0X3", 3UL)]
    [InlineData("0X4", 4UL)]
    [InlineData("0X5", 5UL)]
    [InlineData("0X6", 6UL)]
    [InlineData("0X7", 7UL)]
    [InlineData("0X8", 8UL)]
    [InlineData("0X9", 9UL)]
    [InlineData("0XA", 10UL)]
    [InlineData("0XB", 11UL)]
    [InlineData("0XC", 12UL)]
    [InlineData("0XD", 13UL)]
    [InlineData("0XE", 14UL)]
    [InlineData("0XF", 15UL)]
    [InlineData("a", 10UL)]
    [InlineData("b", 11UL)]
    [InlineData("c", 12UL)]
    [InlineData("d", 13UL)]
    [InlineData("e", 14UL)]
    [InlineData("f", 15UL)]
    [InlineData("A", 10UL)]
    [InlineData("B", 11UL)]
    [InlineData("C", 12UL)]
    [InlineData("D", 13UL)]
    [InlineData("E", 14UL)]
    [InlineData("F", 15UL)]
    public void SingleDigits_AllPrefixForms_ParseAsHex(string input, ulong expected)
    {
        Assert.True(AddressMapping.TryParseAddress(input, out var address));
        Assert.Equal(expected, address);
    }

    [Theory]
    [InlineData("ab", 171UL)]
    [InlineData("AB", 171UL)]
    [InlineData("aB", 171UL)]
    [InlineData("Ab", 171UL)]
    [InlineData("ff", 255UL)]
    [InlineData("FF", 255UL)]
    [InlineData("Ff", 255UL)]
    [InlineData("fF", 255UL)]
    [InlineData("00", 0UL)]
    [InlineData("0a", 10UL)]
    [InlineData("0A", 10UL)]
    [InlineData("A0", 160UL)]
    [InlineData("a0", 160UL)]
    [InlineData("1f", 31UL)]
    [InlineData("F1", 241UL)]
    [InlineData("9a", 154UL)]
    public void TwoDigit_CaseCombinations_ParseAsHex(string input, ulong expected)
    {
        Assert.True(AddressMapping.TryParseAddress(input, out var address));
        Assert.Equal(expected, address);
    }

    [Theory]
    [InlineData("deadbeef", 3735928559UL)]
    [InlineData("DEADBEEF", 3735928559UL)]
    [InlineData("DeadBeef", 3735928559UL)]
    [InlineData("dEaDbEeF", 3735928559UL)]
    [InlineData("cafebabe", 3405691582UL)]
    [InlineData("CAFEBABE", 3405691582UL)]
    [InlineData("0xDeadBeef", 3735928559UL)]
    [InlineData("0XCAFEBABE", 3405691582UL)]
    [InlineData("401abc", 4201148UL)]
    [InlineData("401ABC", 4201148UL)]
    [InlineData("abc123", 11256099UL)]
    [InlineData("123abc", 1194684UL)]
    [InlineData("0b101", 45313UL)]
    [InlineData("face", 64206UL)]
    [InlineData("FACE", 64206UL)]
    [InlineData("beef", 48879UL)]
    [InlineData("1e3", 483UL)]
    [InlineData("1E3", 483UL)]
    [InlineData("8BADF00D", 2343432205UL)]
    [InlineData("CAFE", 51966UL)]
    public void LetteredWords_ParseAsHex(string input, ulong expected)
    {
        Assert.True(AddressMapping.TryParseAddress(input, out var address));
        Assert.Equal(expected, address);
    }

    [Theory]
    [InlineData("140001000", 5368713216UL)]
    [InlineData("0x140001000", 5368713216UL)]
    [InlineData("7ffff7dd1000", 140737351847936UL)]
    [InlineData("0x7ffff7dd1000", 140737351847936UL)]
    [InlineData("7FF7DD1000", 549619306496UL)]
    [InlineData("0x7FF7DD1000", 549619306496UL)]
    [InlineData("10000", 65536UL)]
    [InlineData("0x10000", 65536UL)]
    [InlineData("100000", 1048576UL)]
    [InlineData("FFFF", 65535UL)]
    [InlineData("0xFFFF", 65535UL)]
    [InlineData("BABE", 47806UL)]
    public void RealWorldAddresses_ParseAsHex(string input, ulong expected)
    {
        Assert.True(AddressMapping.TryParseAddress(input, out var address));
        Assert.Equal(expected, address);
    }

    [Theory]
    [InlineData("FFFFFFFFFFFFFFFF", 18446744073709551615UL)]
    [InlineData("ffffffffffffffff", 18446744073709551615UL)]
    [InlineData("0xFFFFFFFFFFFFFFFF", 18446744073709551615UL)]
    [InlineData("0Xffffffffffffffff", 18446744073709551615UL)]
    [InlineData("FFFFFFFFFFFFFFFE", 18446744073709551614UL)]
    [InlineData("8000000000000000", 9223372036854775808UL)]
    [InlineData("7FFFFFFFFFFFFFFF", 9223372036854775807UL)]
    [InlineData("FFFFFFFF", 4294967295UL)]
    [InlineData("0xFFFFFFFF", 4294967295UL)]
    [InlineData("100000000", 4294967296UL)]
    [InlineData("0x100000000", 4294967296UL)]
    [InlineData("1FFFFFFFF", 8589934591UL)]
    [InlineData("0x1FFFFFFFF", 8589934591UL)]
    [InlineData("0x0", 0UL)]
    public void Boundaries_ParseExpectedValues(string input, ulong expected)
    {
        Assert.True(AddressMapping.TryParseAddress(input, out var address));
        Assert.Equal(expected, address);
    }

    [Theory]
    [InlineData("  0x1234  ", 4660UL)]
    [InlineData("  0Xabcd  ", 43981UL)]
    [InlineData("0x00FF", 255UL)]
    [InlineData("0x00000001", 1UL)]
    [InlineData("00", 0UL)]
    [InlineData("0000", 0UL)]
    [InlineData("\t0xAB\n", 171UL)]
    [InlineData(" 401000 ", 4198400UL)]
    [InlineData("\t10\t", 16UL)]
    [InlineData("0xab", 171UL)]
    [InlineData("0XAB", 171UL)]
    [InlineData("0xaB", 171UL)]
    [InlineData("0xAb", 171UL)]
    [InlineData("  ff  ", 255UL)]
    [InlineData("0x0F", 15UL)]
    [InlineData("0X0f", 15UL)]
    public void PrefixAndWhitespaceForms_ParseAsHex(string input, ulong expected)
    {
        Assert.True(AddressMapping.TryParseAddress(input, out var address));
        Assert.Equal(expected, address);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    [InlineData("0x")]
    [InlineData("0X")]
    [InlineData("0xx123")]
    [InlineData("00x123")]
    [InlineData("0x 123")]
    [InlineData("0xG0")]
    [InlineData("0x12 34")]
    [InlineData("12 34")]
    [InlineData("-1")]
    [InlineData("-0x1")]
    [InlineData("+0x10")]
    [InlineData("+10")]
    [InlineData(".")]
    [InlineData("hello")]
    [InlineData("G")]
    [InlineData("xyz")]
    [InlineData("0xDEADBEEFG")]
    [InlineData("FFFFFFFFFFFFFFFFFF")]
    [InlineData("10000000000000000")]
    [InlineData("12345678901234567890")]
    [InlineData("0x10000000000000000")]
    [InlineData("1_000")]
    [InlineData("12h")]
    [InlineData("0o17")]
    [InlineData("1,000")]
    [InlineData("0n10")]
    [InlineData("1 2")]
    [InlineData("0x 1")]
    [InlineData(" x ")]
    [InlineData("0x\n")]
    [InlineData("12\n34")]
    [InlineData("12\t34")]
    [InlineData("--1")]
    [InlineData("0x-1")]
    [InlineData("0XX1")]
    [InlineData("0x1p3")]
    [InlineData("1p3")]
    [InlineData("0d9*")]
    [InlineData("0x!")]
    [InlineData("!")]
    [InlineData("@@")]
    [InlineData("0x_1")]
    [InlineData("_1")]
    [InlineData("1__2")]
    public void NonHexInputs_AreRejected(string? input)
    {
        Assert.False(AddressMapping.TryParseAddress(input, out var address));
        Assert.Equal(0UL, address);
    }
}
