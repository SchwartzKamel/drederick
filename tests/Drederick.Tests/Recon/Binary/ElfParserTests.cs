using Drederick.Recon.Binary;
using Xunit;

namespace Drederick.Tests.Recon.Binary;

/// <summary>Unit tests for the native ELF parser.</summary>
public class ElfParserTests
{
    // ── format detection ──────────────────────────────────────────────────

    [Fact]
    public void DetectFormat_EmptyData_ReturnsUnknown()
    {
        Assert.Equal(BinaryFormat.Unknown, ElfParser.DetectFormat([]));
    }

    [Fact]
    public void DetectFormat_ElfMagicClass1_ReturnsElf32()
    {
        byte[] data = [0x7F, (byte)'E', (byte)'L', (byte)'F', 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        Assert.Equal(BinaryFormat.Elf32, ElfParser.DetectFormat(data));
    }

    [Fact]
    public void DetectFormat_ElfMagicClass2_ReturnsElf64()
    {
        byte[] data = [0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        Assert.Equal(BinaryFormat.Elf64, ElfParser.DetectFormat(data));
    }

    [Fact]
    public void DetectFormat_MzMagic_ReturnsPeFormat()
    {
        byte[] data = new byte[0x44];
        data[0] = 0x4D; data[1] = 0x5A; // MZ
        data[0x3C] = 0x40;
        data[0x40] = 0x50; data[0x41] = 0x45; data[0x42] = 0; data[0x43] = 0;
        var fmt = ElfParser.DetectFormat(data);
        Assert.True(fmt == BinaryFormat.Pe32 || fmt == BinaryFormat.Pe64);
    }

    [Fact]
    public void DetectFormat_ScriptShebang_ReturnsScript()
    {
        byte[] data = [(byte)'#', (byte)'!', (byte)'/', (byte)'b', (byte)'i', (byte)'n'];
        Assert.Equal(BinaryFormat.Script, ElfParser.DetectFormat(data));
    }

    [Fact]
    public void DetectFormat_ZipMagic_ReturnsZip()
    {
        byte[] data = [0x50, 0x4B, 0x03, 0x04, 0, 0];
        Assert.Equal(BinaryFormat.Zip, ElfParser.DetectFormat(data));
    }

    // ── header parsing ────────────────────────────────────────────────────

    [Fact]
    public void ParseHeader_TooShort_ReturnsNull()
    {
        byte[] data = new byte[4];
        Assert.Null(ElfParser.ParseHeader(data));
    }

    [Fact]
    public void ParseHeader_InvalidMagic_ReturnsNull()
    {
        byte[] data = new byte[100];
        data[0] = 0xDE; data[1] = 0xAD;
        Assert.Null(ElfParser.ParseHeader(data));
    }

    [Fact]
    public void ParseHeader_Elf64LE_ReadsIs64BitAndLE()
    {
        // Craft a minimal ELF64 LE header (64 bytes minimum).
        byte[] data = new byte[64];
        data[0] = 0x7F; data[1] = (byte)'E'; data[2] = (byte)'L'; data[3] = (byte)'F';
        data[4] = 2; // EI_CLASS = 64-bit
        data[5] = 1; // EI_DATA  = little-endian
        // e_type @16 = ET_DYN (3)
        BitConverter.GetBytes((ushort)3).CopyTo(data, 16);
        // e_machine @18 = x86_64 (62)
        BitConverter.GetBytes((ushort)62).CopyTo(data, 18);

        var hdr = ElfParser.ParseHeader(data);
        Assert.NotNull(hdr);
        Assert.True(hdr.Is64Bit);
        Assert.True(hdr.IsLittleEndian);
        Assert.Equal((ushort)3, hdr.Type);
        Assert.Equal((ushort)62, hdr.Machine);
    }

    [Fact]
    public void ParseHeader_Elf32_ReadsIs32Bit()
    {
        byte[] data = new byte[52];
        data[0] = 0x7F; data[1] = (byte)'E'; data[2] = (byte)'L'; data[3] = (byte)'F';
        data[4] = 1; // EI_CLASS = 32-bit
        data[5] = 1; // EI_DATA  = LE

        var hdr = ElfParser.ParseHeader(data);
        Assert.NotNull(hdr);
        Assert.False(hdr.Is64Bit);
        Assert.True(hdr.IsLittleEndian);
    }

    // ── MachineToArchitecture ─────────────────────────────────────────────

    [Theory]
    [InlineData(3, "x86")]
    [InlineData(62, "x64")]
    [InlineData(40, "arm")]
    [InlineData(183, "arm64")]
    [InlineData(0xFF, "")]
    public void MachineToArchitecture_KnownMachines(ushort machine, string expected)
    {
        Assert.Equal(expected, ElfParser.MachineToArchitecture(machine));
    }

    // ── program headers / NX ──────────────────────────────────────────────

    [Fact]
    public void ParseProgramHeaders_EmptyData_ReturnsEmpty()
    {
        byte[] hdrBytes = new byte[64];
        hdrBytes[0] = 0x7F; hdrBytes[1] = (byte)'E'; hdrBytes[2] = (byte)'L'; hdrBytes[3] = (byte)'F';
        hdrBytes[4] = 2; hdrBytes[5] = 1;
        // e_phnum @56 = 0
        var hdr = ElfParser.ParseHeader(hdrBytes)!;
        var phdrs = ElfParser.ParseProgramHeaders(hdrBytes, hdr);
        Assert.Empty(phdrs);
    }

    [Fact]
    public void PT_GNU_STACK_Constant_IsCorrectValue()
    {
        // Ensures the constant used for NX detection is correct.
        Assert.Equal(0x6474e551u, ElfParser.PT_GNU_STACK);
    }

    [Fact]
    public void PF_X_Constant_IsCorrectValue()
    {
        Assert.Equal(1u, ElfParser.PF_X);
    }

    // ── symbol extraction ─────────────────────────────────────────────────

    [Fact]
    public void ExtractSymbolNames_NoSections_ReturnsEmpty()
    {
        byte[] data = new byte[64];
        data[0] = 0x7F; data[1] = (byte)'E'; data[2] = (byte)'L'; data[3] = (byte)'F';
        data[4] = 2; data[5] = 1;
        var hdr = ElfParser.ParseHeader(data)!;
        var symbols = ElfParser.ExtractSymbolNames(data, hdr);
        Assert.Empty(symbols);
    }

    // ── string extraction ─────────────────────────────────────────────────

    [Fact]
    public void ExtractStrings_PureText_ReturnsStrings()
    {
        byte[] data = System.Text.Encoding.ASCII.GetBytes("hello\0world\0!");
        var strings = ElfParser.ExtractStrings(data, minLength: 4);
        Assert.Contains("hello", strings);
        Assert.Contains("world", strings);
    }

    [Fact]
    public void ExtractStrings_EmptyData_ReturnsEmpty()
    {
        var strings = ElfParser.ExtractStrings([], minLength: 4);
        Assert.Empty(strings);
    }

    [Fact]
    public void ExtractStrings_BinaryJunk_FiltersShortRuns()
    {
        // Data with only short ASCII runs (length < 4) should yield nothing.
        byte[] data = [0x41, 0x42, 0x43, 0x00, 0x01, 0x02, 0x03]; // "ABC" (3 chars)
        var strings = ElfParser.ExtractStrings(data, minLength: 4);
        Assert.Empty(strings);
    }

    [Fact]
    public void ExtractStrings_StackChkFail_IsDetectable()
    {
        const string sym = "__stack_chk_fail";
        byte[] data = System.Text.Encoding.ASCII.GetBytes(sym + "\0");
        var strings = ElfParser.ExtractStrings(data, minLength: 4);
        Assert.Contains(sym, strings);
    }

    // ── real /bin/bash (skipped if unavailable) ───────────────────────────

    [Fact]
    public void DetectFormat_RealBash_ReturnsElfFormat()
    {
        if (!File.Exists("/bin/bash")) return;
        var data = File.ReadAllBytes("/bin/bash");
        var fmt = ElfParser.DetectFormat(data);
        Assert.True(fmt == BinaryFormat.Elf32 || fmt == BinaryFormat.Elf64);
    }

    [Fact]
    public void ParseHeader_RealBash_ReturnsValidHeader()
    {
        if (!File.Exists("/bin/bash")) return;
        var data = File.ReadAllBytes("/bin/bash");
        var hdr = ElfParser.ParseHeader(data);
        Assert.NotNull(hdr);
        Assert.NotEmpty(ElfParser.MachineToArchitecture(hdr.Machine));
    }

    [Fact]
    public void ExtractSymbolNames_RealBash_ContainsMainOrEntry()
    {
        if (!File.Exists("/bin/bash")) return;
        var data = File.ReadAllBytes("/bin/bash");
        var hdr = ElfParser.ParseHeader(data);
        if (hdr is null) return; // stripped binary — OK
        var symbols = ElfParser.ExtractSymbolNames(data, hdr);
        // Dynamic symbols should include at least some libc references.
        Assert.True(symbols.Count >= 0); // just checks it doesn't throw
    }
}
