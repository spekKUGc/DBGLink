using DbgLink.Launcher.Core;
using Xunit;

namespace DbgLink.Tests;

public sealed class LauncherPlanAndGhidraPolicyTests : IDisposable
{
    private readonly string _tempDirectory;

    public LauncherPlanAndGhidraPolicyTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), "dbglink_launcher_tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDirectory))
                Directory.Delete(_tempDirectory, recursive: true);
        }
        catch
        {
        }
    }

    private string CreateSyntheticPe(ushort machine, bool validMz = true, bool validPeSig = true, int peOffset = 0x80, bool writePe = true)
    {
        var filePath = Path.Combine(_tempDirectory, $"test_pe_{Guid.NewGuid():N}.bin");
        using var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write);
        using var writer = new BinaryWriter(stream);

        // MZ Header
        writer.Write((ushort)(validMz ? 0x5A4D : 0x1234));
        // Fill up to 0x3C
        for (var i = 2; i < 0x3C; i++)
            writer.Write((byte)0);

        // Offset to PE Header at 0x3C
        writer.Write(peOffset);

        if (writePe)
        {
            // Pad until PE offset
            while (stream.Position < peOffset)
                writer.Write((byte)0);

            // PE Signature
            writer.Write((uint)(validPeSig ? 0x00004550 : 0x11223344));

            // Machine Architecture
            writer.Write(machine);

            // Pad additional header bytes
            for (var i = 0; i < 64; i++)
                writer.Write((byte)0);
        }

        return filePath;
    }

    // ========================================================================================
    // GROUP 1: DEBUGGER ARCHITECTURE PE DETECTION (25 Tests)
    // ========================================================================================

    [Fact]
    public void Detect_ValidX86Binary_ReturnsX86()
    {
        var path = CreateSyntheticPe(0x014c); // IMAGE_FILE_MACHINE_I386
        var arch = DebuggerArchitectureDetector.Detect(path, DebuggerArchitecture.Auto);
        Assert.Equal(DebuggerArchitecture.X86, arch);
    }

    [Fact]
    public void Detect_ValidX64Binary_ReturnsX64()
    {
        var path = CreateSyntheticPe(0x8664); // IMAGE_FILE_MACHINE_AMD64
        var arch = DebuggerArchitectureDetector.Detect(path, DebuggerArchitecture.Auto);
        Assert.Equal(DebuggerArchitecture.X64, arch);
    }

    [Theory]
    [InlineData(0xAA64)] // ARM64
    [InlineData(0x01c0)] // ARM
    [InlineData(0x0200)] // IA64
    [InlineData(0x0000)] // Unknown
    [InlineData(0xFFFF)] // Invalid
    public void Detect_NonX86OrX64Machine_ReturnsFallback(ushort machine)
    {
        var path = CreateSyntheticPe(machine);
        var arch = DebuggerArchitectureDetector.Detect(path, DebuggerArchitecture.Auto);
        Assert.Equal(DebuggerArchitecture.Auto, arch);
    }

    [Fact]
    public void Detect_InvalidMzHeader_ReturnsFallback()
    {
        var path = CreateSyntheticPe(0x8664, validMz: false);
        var arch = DebuggerArchitectureDetector.Detect(path, DebuggerArchitecture.X86);
        Assert.Equal(DebuggerArchitecture.X86, arch);
    }

    [Fact]
    public void Detect_InvalidPeSignature_ReturnsFallback()
    {
        var path = CreateSyntheticPe(0x8664, validPeSig: false);
        var arch = DebuggerArchitectureDetector.Detect(path, DebuggerArchitecture.Auto);
        Assert.Equal(DebuggerArchitecture.Auto, arch);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-100)]
    public void Detect_InvalidPeOffset_ReturnsFallback(int invalidOffset)
    {
        var path = CreateSyntheticPe(0x8664, peOffset: invalidOffset);
        var arch = DebuggerArchitectureDetector.Detect(path, DebuggerArchitecture.Auto);
        Assert.Equal(DebuggerArchitecture.Auto, arch);
    }

    [Fact]
    public void Detect_PeOffsetBeyondFileLength_ReturnsFallback()
    {
        var path = CreateSyntheticPe(0x8664, peOffset: 0x400, writePe: false);
        var arch = DebuggerArchitectureDetector.Detect(path, DebuggerArchitecture.Auto);
        Assert.Equal(DebuggerArchitecture.Auto, arch);
    }

    [Fact]
    public void Detect_ZeroByteFile_ReturnsFallback()
    {
        var filePath = Path.Combine(_tempDirectory, "empty.exe");
        File.WriteAllBytes(filePath, []);
        var arch = DebuggerArchitectureDetector.Detect(filePath, DebuggerArchitecture.Auto);
        Assert.Equal(DebuggerArchitecture.Auto, arch);
    }

    [Fact]
    public void Detect_TruncatedFile_ReturnsFallback()
    {
        var filePath = Path.Combine(_tempDirectory, "truncated.exe");
        File.WriteAllBytes(filePath, [0x4D, 0x5A]); // MZ only
        var arch = DebuggerArchitectureDetector.Detect(filePath, DebuggerArchitecture.Auto);
        Assert.Equal(DebuggerArchitecture.Auto, arch);
    }

    [Fact]
    public void Detect_NonExistentFile_ReturnsFallback()
    {
        var missingPath = Path.Combine(_tempDirectory, "does_not_exist.exe");
        var arch = DebuggerArchitectureDetector.Detect(missingPath, DebuggerArchitecture.Auto);
        Assert.Equal(DebuggerArchitecture.Auto, arch);
    }

    // ========================================================================================
    // GROUP 2: LAUNCHER PLAN & PIPE NAME INVARIANTS (20 Tests)
    // ========================================================================================

    [Theory]
    [InlineData(1, "DbgLink.Control.1")]
    [InlineData(2, "DbgLink.Control.2")]
    [InlineData(42, "DbgLink.Control.42")]
    [InlineData(100, "DbgLink.Control.100")]
    [InlineData(1337, "DbgLink.Control.1337")]
    [InlineData(65535, "DbgLink.Control.65535")]
    [InlineData(100000, "DbgLink.Control.100000")]
    [InlineData(2147483647, "DbgLink.Control.2147483647")]
    public void PipeNameFor_PositiveProcessIds_GeneratesCorrectPipeName(int pid, string expectedPipe)
    {
        var plan = CreatePlan();
        var pipe = plan.PipeNameFor(pid);
        Assert.Equal(expectedPipe, pipe);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    [InlineData(-2147483648)]
    public void PipeNameFor_NonPositiveProcessIds_ThrowsArgumentOutOfRangeException(int invalidPid)
    {
        var plan = CreatePlan();
        Assert.Throws<ArgumentOutOfRangeException>(() => plan.PipeNameFor(invalidPid));
    }

    // ========================================================================================
    // GROUP 3: LAUNCHER PLANNER SETTINGS & PORT VALIDATION (15 Tests)
    // ========================================================================================

    [Theory]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    [InlineData(65536, false)]
    [InlineData(100000, false)]
    [InlineData(1, true)]
    [InlineData(LauncherDefaults.DefaultPort, true)]
    [InlineData(65535, true)]
    [InlineData(8080, true)]
    public void LauncherPlanner_PortRangeValidation(int port, bool expectedValidPort)
    {
        var settings = new LauncherSettings(
            X64DbgPath: "",
            X32DbgPath: "",
            GhidraHome: "",
            Mode: ReverseMode.LetLlmChoose,
            InputFile: null,
            Port: port);

        var result = LauncherPlanner.Plan(settings);
        var hasPortIssue = result.Issues.Any(i => i.Code == "invalid_port");
        Assert.Equal(!expectedValidPort, hasPortIssue);
    }

    [Theory]
    [InlineData((ReverseMode)99, false)]
    [InlineData(ReverseMode.ChooseFile, true)]
    [InlineData(ReverseMode.LetLlmChoose, true)]
    public void LauncherPlanner_ReverseModeValidation(ReverseMode mode, bool expectedValidMode)
    {
        var settings = new LauncherSettings(
            X64DbgPath: "",
            X32DbgPath: "",
            GhidraHome: "",
            Mode: mode,
            InputFile: mode == ReverseMode.ChooseFile ? "test.exe" : null);

        var result = LauncherPlanner.Plan(settings);
        var hasModeIssue = result.Issues.Any(i => i.Code == "invalid_reverse_mode");
        Assert.Equal(!expectedValidMode, hasModeIssue);
    }

    [Theory]
    [InlineData((DebuggerArchitecture)99, false)]
    [InlineData(DebuggerArchitecture.Auto, true)]
    [InlineData(DebuggerArchitecture.X64, true)]
    [InlineData(DebuggerArchitecture.X86, true)]
    public void LauncherPlanner_DebuggerArchitectureValidation(DebuggerArchitecture arch, bool expectedValidArch)
    {
        var settings = new LauncherSettings(
            X64DbgPath: "",
            X32DbgPath: "",
            GhidraHome: "",
            Mode: ReverseMode.LetLlmChoose,
            InputFile: null,
            Debugger: arch);

        var result = LauncherPlanner.Plan(settings);
        var hasArchIssue = result.Issues.Any(i => i.Code == "invalid_debugger_architecture");
        Assert.Equal(!expectedValidArch, hasArchIssue);
    }

    // ========================================================================================
    // GROUP 4: GHIDRA TARGET POLICY EXTENSION & VALIDATION GUARDS (15 Tests)
    // ========================================================================================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("relative\\path.exe")]
    [InlineData("C:\\target\\file\0.exe")] // Null character
    public void GhidraTargetPolicy_InvalidPaths_ThrowInvalidDataException(string? invalidPath)
    {
        Assert.Throws<InvalidDataException>(() => GhidraTargetPolicy.Validate(invalidPath!));
    }

    [Theory]
    [InlineData(".txt")]
    [InlineData(".py")]
    [InlineData(".bat")]
    [InlineData(".cmd")]
    [InlineData(".ps1")]
    [InlineData(".zip")]
    [InlineData(".sh")]
    [InlineData(".json")]
    [InlineData(".xml")]
    public void GhidraTargetPolicy_DisallowedExtensions_ThrowInvalidDataException(string ext)
    {
        var testFile = Path.Combine(_tempDirectory, "sample" + ext);
        File.WriteAllBytes(testFile, [1, 2, 3]);

        var ex = Assert.Throws<InvalidDataException>(() => GhidraTargetPolicy.Validate(testFile));
        Assert.Contains("not allowlisted", ex.Message);
    }

    [Theory]
    [InlineData("target%test.exe")] // Percent sign
    [InlineData("target!test.exe")] // Exclamation mark
    public void GhidraTargetPolicy_UnsafeCharacters_ThrowInvalidDataException(string unsafeFilename)
    {
        var testFile = Path.Combine(_tempDirectory, unsafeFilename);
        File.WriteAllBytes(testFile, [1, 2, 3]);

        var ex = Assert.Throws<InvalidDataException>(() => GhidraTargetPolicy.Validate(testFile));
        Assert.Contains("percent signs or exclamation marks", ex.Message);
    }

    // ========================================================================================
    // GROUP 5: PERMISSION PROFILE & TOOLKIT PATHS (6 Tests)
    // ========================================================================================

    [Fact]
    public void LauncherPermissionProfile_Default_EnablesBothPermissions()
    {
        var profile = LauncherPermissionProfile.Default;
        Assert.True(profile.AllowGhidraAnnotation);
        Assert.True(profile.AllowGhidraMutation);
    }

    [Fact]
    public void LauncherPermissionProfile_ReadOnly_DisablesBothPermissions()
    {
        var profile = LauncherPermissionProfile.ReadOnly;
        Assert.False(profile.AllowGhidraAnnotation);
        Assert.False(profile.AllowGhidraMutation);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void LauncherPermissionProfile_CustomCombinations_ReflectValues(bool annotation, bool mutation)
    {
        var profile = new LauncherPermissionProfile(annotation, mutation);
        Assert.Equal(annotation, profile.AllowGhidraAnnotation);
        Assert.Equal(mutation, profile.AllowGhidraMutation);
    }

    [Fact]
    public void LauncherPlan_ExposesSettingsAndPathsCorrectly()
    {
        var plan = CreatePlan();
        Assert.NotNull(plan.Settings);
        Assert.NotNull(plan.Paths);
        Assert.Equal(@"C:\ghidra", plan.Paths.GhidraHome);
        Assert.Equal(@"C:\jdk", plan.Paths.JavaHome);
    }

    [Fact]
    public void ToolkitPaths_ValuesRetainedProperly()
    {
        var plan = CreatePlan();
        Assert.Equal("dbglink.dp64", plan.Paths.PluginFileName);
        Assert.Equal(@"C:\plugins", plan.Paths.PluginDirectory);
        Assert.Equal(@"C:\server\DbgLink.Server.exe", plan.Paths.ServerPath);
    }

    private static LauncherPlan CreatePlan()
    {
        var settings = new LauncherSettings(
            X64DbgPath: @"C:\x64dbg\release\x64\x64dbg.exe",
            X32DbgPath: @"C:\x64dbg\release\x32\x32dbg.exe",
            GhidraHome: @"C:\ghidra",
            Mode: ReverseMode.LetLlmChoose,
            InputFile: null);

        var paths = new ToolkitPaths(
            X64DbgPath: settings.X64DbgPath,
            X32DbgPath: settings.X32DbgPath,
            DebuggerPath: settings.X64DbgPath,
            GhidraHome: settings.GhidraHome,
            GhidraLauncherPath: @"C:\ghidra\ghidraRun.bat",
            GhidraHeadlessPath: @"C:\ghidra\support\analyzeHeadless.bat",
            PluginDirectory: @"C:\plugins",
            ServerPath: @"C:\server\DbgLink.Server.exe",
            PluginFileName: "dbglink.dp64",
            GhidraExtensionZip: @"C:\ghidra\extension.zip",
            JavaHome: @"C:\jdk");

        return new LauncherPlan(settings, paths);
    }
}
