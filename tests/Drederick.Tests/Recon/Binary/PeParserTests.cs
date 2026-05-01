using Drederick.Recon.Binary;
using Xunit;

namespace Drederick.Tests.Recon.Binary;

/// <summary>Unit tests for the native PE parser.</summary>
public class PeParserTests
{
    // ── helper: build a minimal valid PE32 header in a byte array ─────────

    /// <summary>
    /// Constructs the minimal DOS header + PE signature needed for tests.
    /// Returns a 512-byte buffer with a valid MZ magic, e_lfanew pointing to
    /// offset 0x40, a PE signature, a COFF header, and a minimal optional
    /// header (PE32 magic = 0x010b). Sections start at 0xD8.
    /// </summary>
    private static byte[] MakeMinimalPe(
        ushort machine = 0x8664,         // AMD64
        ushort dllChars = 0x0140,        // NX_COMPAT | DYNAMIC_BASE
        int numSections = 0,
        Action<byte[]>? customize = null)
    {
        var data = new byte[512];

        // DOS header
        data[0] = 0x4D; data[1] = 0x5A; // MZ
        BitConverter.GetBytes(0x40).CopyTo(data, 0x3C);  // e_lfanew = 0x40

        // PE signature at 0x40
        data[0x40] = 0x50; data[0x41] = 0x45; data[0x42] = 0x00; data[0x43] = 0x00;

        // COFF header at 0x44
        BitConverter.GetBytes(machine).CopyTo(data, 0x44);           // Machine
        BitConverter.GetBytes((ushort)numSections).CopyTo(data, 0x46); // NumSections
        // SizeOfOptionalHeader at coffOff+16 = 0x44+16 = 0x54
        BitConverter.GetBytes((ushort)0x70).CopyTo(data, 0x54);      // 112 bytes opt hdr

        // Optional header at 0x44 + 20 = 0x58
        int optOff = 0x58;
        BitConverter.GetBytes((ushort)0x010b).CopyTo(data, optOff);  // PE32 magic
        // AddressOfEntryPoint at optOff+16
        BitConverter.GetBytes(0x1000u).CopyTo(data, optOff + 16);
        // DllCharacteristics at optOff+70
        BitConverter.GetBytes(dllChars).CopyTo(data, optOff + 70);

        customize?.Invoke(data);
        return data;
    }

    // ── MZ magic detection ────────────────────────────────────────────────

    [Fact]
    public void HasNXBit_EmptyData_ReturnsFalse()
        => Assert.False(PeParser.HasNXBit([]));

    [Fact]
    public void HasASLR_EmptyData_ReturnsFalse()
        => Assert.False(PeParser.HasASLR([]));

    // ── DllCharacteristics flags ──────────────────────────────────────────

    [Fact]
    public void HasNXBit_FlagSet_ReturnsTrue()
    {
        var data = MakeMinimalPe(dllChars: 0x0100); // NX only
        Assert.True(PeParser.HasNXBit(data));
    }

    [Fact]
    public void HasNXBit_FlagClear_ReturnsFalse()
    {
        var data = MakeMinimalPe(dllChars: 0x0040); // ASLR only, no NX
        Assert.False(PeParser.HasNXBit(data));
    }

    [Fact]
    public void HasASLR_FlagSet_ReturnsTrue()
    {
        var data = MakeMinimalPe(dllChars: 0x0040); // ASLR only
        Assert.True(PeParser.HasASLR(data));
    }

    [Fact]
    public void HasASLR_FlagClear_ReturnsFalse()
    {
        var data = MakeMinimalPe(dllChars: 0x0100); // NX only, no ASLR
        Assert.False(PeParser.HasASLR(data));
    }

    [Fact]
    public void HasNXBit_BothFlags_ReturnsTrue()
    {
        var data = MakeMinimalPe(dllChars: 0x0140);
        Assert.True(PeParser.HasNXBit(data));
        Assert.True(PeParser.HasASLR(data));
    }

    // ── architecture detection ────────────────────────────────────────────

    [Theory]
    [InlineData(0x014c, "x86")]
    [InlineData(0x8664, "x64")]
    [InlineData(0x01c4, "arm")]
    [InlineData(0xaa64, "arm64")]
    [InlineData(0xDEAD, "")]
    public void DetectArchitecture_KnownMachines(int machine, string expected)
    {
        var data = MakeMinimalPe(machine: (ushort)machine);
        Assert.Equal(expected, PeParser.DetectArchitecture(data));
    }

    [Fact]
    public void DetectArchitecture_EmptyData_ReturnsEmpty()
        => Assert.Equal("", PeParser.DetectArchitecture([]));

    // ── entry point ───────────────────────────────────────────────────────

    [Fact]
    public void GetEntryPoint_Returns_AddressOfEntryPoint()
    {
        var data = MakeMinimalPe();
        Assert.Equal(0x1000ul, PeParser.GetEntryPoint(data));
    }

    [Fact]
    public void GetEntryPoint_EmptyData_ReturnsZero()
        => Assert.Equal(0ul, PeParser.GetEntryPoint([]));

    // ── section names ─────────────────────────────────────────────────────

    [Fact]
    public void GetSectionNames_NoSections_ReturnsEmpty()
    {
        var data = MakeMinimalPe(numSections: 0);
        Assert.Empty(PeParser.GetSectionNames(data));
    }

    [Fact]
    public void GetSectionNames_OneSection_ReturnsName()
    {
        var data = MakeMinimalPe(numSections: 1, customize: d =>
        {
            // Section table starts at optOff(0x58) + sizeOfOptHdr(0x70) = 0xC8.
            int sectOff = 0xC8;
            // Write ".text\0\0\0" (8 bytes).
            var name = System.Text.Encoding.ASCII.GetBytes(".text\0\0\0");
            name.CopyTo(d, sectOff);
        });
        var names = PeParser.GetSectionNames(data);
        Assert.Contains(".text", names);
    }

    // ── import directory ──────────────────────────────────────────────────

    [Fact]
    public void ParseImportedDlls_EmptyData_ReturnsEmpty()
        => Assert.Empty(PeParser.ParseImportedDlls([]));

    [Fact]
    public void ParseImportedDlls_NoImportDirectory_ReturnsEmpty()
    {
        // Import RVA = 0 in the data directory means no imports.
        var data = MakeMinimalPe();
        // Import data directory is at optOff+104 for PE32; it defaults to 0 in MakeMinimalPe.
        Assert.Empty(PeParser.ParseImportedDlls(data));
    }

    [Fact]
    public void ParseImportedDlls_WithOneImport_ReturnsLibraryName()
    {
        // Build a PE with one import descriptor pointing to "KERNEL32.DLL".
        const string dllName = "KERNEL32.DLL";
        var data = new byte[1024];

        // DOS header
        data[0] = 0x4D; data[1] = 0x5A;
        BitConverter.GetBytes(0x40).CopyTo(data, 0x3C);

        // PE signature
        data[0x40] = 0x50; data[0x41] = 0x45;

        // COFF (machine=x64, numSections=1, sizeOfOptHdr=0x70)
        BitConverter.GetBytes((ushort)0x8664).CopyTo(data, 0x44);
        BitConverter.GetBytes((ushort)1).CopyTo(data, 0x46);
        BitConverter.GetBytes((ushort)0x70).CopyTo(data, 0x54);

        int optOff = 0x58;
        // PE32 magic
        BitConverter.GetBytes((ushort)0x010b).CopyTo(data, optOff);

        // Section table at optOff+0x70 = 0xC8
        int sectOff = 0xC8;

        // We place actual import data at raw file offset 0x200.
        // Map it to RVA 0x2000 in section ".idata".
        uint importRva = 0x2000;
        uint importRawOff = 0x200;

        // Write section header for ".idata"
        var sName = System.Text.Encoding.ASCII.GetBytes(".idat\0\0\0");
        sName.CopyTo(data, sectOff);
        BitConverter.GetBytes(0x100u).CopyTo(data, sectOff + 8);   // VirtualSize
        BitConverter.GetBytes(importRva).CopyTo(data, sectOff + 12); // VirtualAddress
        BitConverter.GetBytes(0x100u).CopyTo(data, sectOff + 16);   // SizeOfRawData
        BitConverter.GetBytes(importRawOff).CopyTo(data, sectOff + 20); // PointerToRawData

        // Import data directory at optOff+104
        BitConverter.GetBytes(importRva).CopyTo(data, optOff + 104);
        BitConverter.GetBytes(0x14u).CopyTo(data, optOff + 108); // size = 20

        // One import descriptor at raw 0x200 (20 bytes)
        // Name RVA = 0x2020 (raw = 0x220)
        uint nameRva = importRva + 0x20;
        BitConverter.GetBytes(nameRva).CopyTo(data, (int)importRawOff + 12);

        // Write DLL name at raw 0x220
        System.Text.Encoding.ASCII.GetBytes(dllName + "\0").CopyTo(data, 0x220);

        // Second descriptor is all zeros (terminator) — already zero.

        var dlls = PeParser.ParseImportedDlls(data);
        Assert.Contains(dllName, dlls);
    }
}
