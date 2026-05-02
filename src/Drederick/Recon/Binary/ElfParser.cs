using System.Text;

namespace Drederick.Recon.Binary;

/// <summary>Binary format detected from leading magic bytes.</summary>
public enum BinaryFormat
{
    Unknown,
    Elf32,
    Elf64,
    Pe32,
    Pe64,
    MachO,
    Script,
    Zip,
}

/// <summary>Parsed ELF file header fields.</summary>
public sealed record ElfHeader(
    bool Is64Bit,
    bool IsLittleEndian,
    ushort Type,      // ET_EXEC=2, ET_DYN=3
    ushort Machine,   // EM_386=3, EM_ARM=40, EM_X86_64=62, EM_AARCH64=183
    ulong EntryPoint,
    ulong PhOffset,
    ulong ShOffset,
    ushort PhEntSize,
    ushort PhNum,
    ushort ShEntSize,
    ushort ShNum,
    ushort ShStrNdx);

/// <summary>Parsed ELF program header (PT_* entry).</summary>
public sealed record ElfProgramHeader(
    uint Type,
    uint Flags,
    ulong Offset,
    ulong FileSize);

/// <summary>Parsed ELF section header.</summary>
public sealed record ElfSectionHeader(
    uint NameOffset,
    uint Type,
    ulong Offset,
    ulong Size,
    uint Link,
    ulong EntSize);

/// <summary>
/// Native .NET ELF binary parser — no external tools required.
/// All methods are pure, stateless, and thread-safe.
/// </summary>
public static class ElfParser
{
    // PT_* constants
    internal const uint PT_GNU_STACK = 0x6474e551;

    // PF_* flags
    internal const uint PF_X = 1;

    // SHT_* type constants
    internal const uint SHT_SYMTAB = 2;
    internal const uint SHT_STRTAB = 3;
    internal const uint SHT_DYNAMIC = 6;
    internal const uint SHT_DYNSYM = 11;

    // DT_* dynamic-section tag constants
    private const long DT_NULL = 0;
    private const long DT_NEEDED = 1;
    private const long DT_RPATH = 15;
    private const long DT_RUNPATH = 29;

    // EM_* machine constants
    private const ushort EM_386 = 3;
    private const ushort EM_MIPS = 8;
    private const ushort EM_PPC = 20;
    private const ushort EM_PPC64 = 21;
    private const ushort EM_ARM = 40;
    private const ushort EM_X86_64 = 62;
    private const ushort EM_AARCH64 = 183;
    private const ushort EM_RISCV = 243;

    // ──────────────────────────────────────────────────────────────────────

    /// <summary>Detect binary format from leading magic bytes.</summary>
    public static BinaryFormat DetectFormat(byte[] data)
    {
        if (data.Length < 4)
            return BinaryFormat.Unknown;

        // ELF: 0x7F 'E' 'L' 'F'
        if (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46)
            return data.Length > 4 && data[4] == 2 ? BinaryFormat.Elf64 : BinaryFormat.Elf32;

        // MZ / PE
        if (data[0] == 0x4D && data[1] == 0x5A)
        {
            if (data.Length >= 0x40)
            {
                int peOff = BitConverter.ToInt32(data, 0x3C);
                if (peOff >= 0 && peOff + 28 <= data.Length &&
                    data[peOff] == 0x50 && data[peOff + 1] == 0x45 &&
                    data[peOff + 2] == 0x00 && data[peOff + 3] == 0x00)
                {
                    int optOff = peOff + 24;
                    if (optOff + 2 <= data.Length)
                        return BitConverter.ToUInt16(data, optOff) == 0x020b
                            ? BinaryFormat.Pe64 : BinaryFormat.Pe32;
                }
            }
            return BinaryFormat.Pe32;
        }

        // Mach-O: big-endian 32/64 and little-endian 32/64 magics
        if ((data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA &&
             (data[3] == 0xCE || data[3] == 0xCF)) ||
            (data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE) ||
            (data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE))
            return BinaryFormat.MachO;

        // Shell script: '#!'
        if (data.Length >= 2 && data[0] == 0x23 && data[1] == 0x21)
            return BinaryFormat.Script;

        // ZIP/JAR: PK\x03\x04
        if (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04)
            return BinaryFormat.Zip;

        return BinaryFormat.Unknown;
    }

    /// <summary>
    /// Parse the ELF file header. Returns <see langword="null"/> if data is
    /// too short, magic is wrong, or EI_CLASS is not 1 or 2.
    /// </summary>
    public static ElfHeader? ParseHeader(byte[] data)
    {
        if (data.Length < 16)
            return null;

        if (data[0] != 0x7F || data[1] != 0x45 || data[2] != 0x4C || data[3] != 0x46)
            return null;

        bool is64 = data[4] == 2;
        bool is32 = data[4] == 1;
        if (!is64 && !is32)
            return null;

        bool isLE = data[5] == 1;
        int minSize = is64 ? 64 : 52;
        if (data.Length < minSize)
            return null;

        ushort type = ReadU16(data, 16, isLE);
        ushort machine = ReadU16(data, 18, isLE);

        if (is64)
        {
            return new ElfHeader(
                Is64Bit: true,
                IsLittleEndian: isLE,
                Type: type,
                Machine: machine,
                EntryPoint: ReadU64(data, 24, isLE),
                PhOffset: ReadU64(data, 32, isLE),
                ShOffset: ReadU64(data, 40, isLE),
                PhEntSize: ReadU16(data, 54, isLE),
                PhNum: ReadU16(data, 56, isLE),
                ShEntSize: ReadU16(data, 58, isLE),
                ShNum: ReadU16(data, 60, isLE),
                ShStrNdx: ReadU16(data, 62, isLE));
        }
        else
        {
            return new ElfHeader(
                Is64Bit: false,
                IsLittleEndian: isLE,
                Type: type,
                Machine: machine,
                EntryPoint: ReadU32(data, 24, isLE),
                PhOffset: ReadU32(data, 28, isLE),
                ShOffset: ReadU32(data, 32, isLE),
                PhEntSize: ReadU16(data, 42, isLE),
                PhNum: ReadU16(data, 44, isLE),
                ShEntSize: ReadU16(data, 46, isLE),
                ShNum: ReadU16(data, 48, isLE),
                ShStrNdx: ReadU16(data, 50, isLE));
        }
    }

    /// <summary>Map ELF e_machine value to an architecture label string.</summary>
    public static string MachineToArchitecture(ushort machine) => machine switch
    {
        EM_386 => "x86",
        EM_MIPS => "mips",
        EM_PPC => "powerpc",
        EM_PPC64 => "powerpc64",
        EM_ARM => "arm",
        EM_X86_64 => "x64",
        EM_AARCH64 => "arm64",
        EM_RISCV => "riscv",
        _ => "",
    };

    /// <summary>Parse the ELF program header table.</summary>
    public static IReadOnlyList<ElfProgramHeader> ParseProgramHeaders(byte[] data, ElfHeader header)
    {
        var result = new List<ElfProgramHeader>();
        if (header.PhOffset == 0 || header.PhNum == 0 || header.PhEntSize == 0)
            return result;

        long baseOff = (long)header.PhOffset;
        int expectedSize = header.Is64Bit ? 56 : 32;

        for (int i = 0; i < header.PhNum; i++)
        {
            long off = baseOff + (long)i * header.PhEntSize;
            if (off + expectedSize > data.Length)
                break;

            uint type, flags;
            ulong fileSize, offset;

            if (header.Is64Bit)
            {
                // 64-bit: type@0, flags@4, offset@8, filesz@32
                type = ReadU32(data, off, header.IsLittleEndian);
                flags = ReadU32(data, off + 4, header.IsLittleEndian);
                offset = ReadU64(data, off + 8, header.IsLittleEndian);
                fileSize = ReadU64(data, off + 32, header.IsLittleEndian);
            }
            else
            {
                // 32-bit: type@0, offset@4, filesz@16, flags@24
                type = ReadU32(data, off, header.IsLittleEndian);
                offset = ReadU32(data, off + 4, header.IsLittleEndian);
                fileSize = ReadU32(data, off + 16, header.IsLittleEndian);
                flags = ReadU32(data, off + 24, header.IsLittleEndian);
            }

            result.Add(new ElfProgramHeader(type, flags, offset, fileSize));
        }

        return result;
    }

    /// <summary>Parse the ELF section header table.</summary>
    public static IReadOnlyList<ElfSectionHeader> ParseSectionHeaders(byte[] data, ElfHeader header)
    {
        var result = new List<ElfSectionHeader>();
        if (header.ShOffset == 0 || header.ShNum == 0 || header.ShEntSize == 0)
            return result;

        long baseOff = (long)header.ShOffset;
        int expectedSize = header.Is64Bit ? 64 : 40;

        for (int i = 0; i < header.ShNum; i++)
        {
            long off = baseOff + (long)i * header.ShEntSize;
            if (off + expectedSize > data.Length)
                break;

            uint nameOffset, type, link;
            ulong offset, size, entSize;

            if (header.Is64Bit)
            {
                // name@0, type@4, flags@8(8), addr@16(8), offset@24(8), size@32(8), link@40, info@44, align@48(8), entsize@56(8)
                nameOffset = ReadU32(data, off, header.IsLittleEndian);
                type = ReadU32(data, off + 4, header.IsLittleEndian);
                offset = ReadU64(data, off + 24, header.IsLittleEndian);
                size = ReadU64(data, off + 32, header.IsLittleEndian);
                link = ReadU32(data, off + 40, header.IsLittleEndian);
                entSize = ReadU64(data, off + 56, header.IsLittleEndian);
            }
            else
            {
                // name@0, type@4, flags@8(4), addr@12(4), offset@16(4), size@20(4), link@24, info@28, align@32(4), entsize@36(4)
                nameOffset = ReadU32(data, off, header.IsLittleEndian);
                type = ReadU32(data, off + 4, header.IsLittleEndian);
                offset = ReadU32(data, off + 16, header.IsLittleEndian);
                size = ReadU32(data, off + 20, header.IsLittleEndian);
                link = ReadU32(data, off + 24, header.IsLittleEndian);
                entSize = ReadU32(data, off + 36, header.IsLittleEndian);
            }

            result.Add(new ElfSectionHeader(nameOffset, type, offset, size, link, entSize));
        }

        return result;
    }

    /// <summary>
    /// Returns section names from the ELF section-name string table (.shstrtab).
    /// Returns empty strings for entries whose name offset is out of range.
    /// </summary>
    public static IReadOnlyList<string> GetSectionNames(byte[] data, ElfHeader header)
    {
        var names = new List<string>();
        var sections = ParseSectionHeaders(data, header);

        if (sections.Count == 0 || header.ShStrNdx >= sections.Count)
        {
            for (int i = 0; i < sections.Count; i++)
                names.Add("");
            return names;
        }

        var shstrtab = sections[header.ShStrNdx];
        long strBase = (long)shstrtab.Offset;
        long strEnd = strBase + (long)shstrtab.Size;

        bool strtabValid = strBase >= 0 && strEnd <= data.Length && shstrtab.Size > 0;

        foreach (var sec in sections)
        {
            if (!strtabValid)
            {
                names.Add("");
                continue;
            }

            long nameOff = strBase + sec.NameOffset;
            if (nameOff < strBase || nameOff >= strEnd)
            {
                names.Add("");
                continue;
            }

            int end = (int)nameOff;
            while (end < strEnd && end < data.Length && data[end] != 0)
                end++;
            names.Add(Encoding.ASCII.GetString(data, (int)nameOff, end - (int)nameOff));
        }

        return names;
    }

    /// <summary>
    /// Extracts symbol names from .dynsym and .symtab sections.
    /// </summary>
    public static IReadOnlyList<string> ExtractSymbolNames(byte[] data, ElfHeader header)
    {
        var symbols = new List<string>();
        var sections = ParseSectionHeaders(data, header);
        if (sections.Count == 0)
            return symbols;

        foreach (var section in sections)
        {
            if (section.Type != SHT_SYMTAB && section.Type != SHT_DYNSYM)
                continue;
            if (section.EntSize == 0 || section.Size == 0)
                continue;
            if (section.Link >= (uint)sections.Count)
                continue;

            var strSection = sections[(int)section.Link];
            if (strSection.Type != SHT_STRTAB)
                continue;

            long strBase = (long)strSection.Offset;
            long strEnd = strBase + (long)strSection.Size;
            long symBase = (long)section.Offset;
            long symEnd = symBase + (long)section.Size;

            if (strBase < 0 || strEnd > data.Length || symBase < 0 || symEnd > data.Length)
                continue;

            int symEntSize = header.Is64Bit ? 24 : 16;
            long count = (long)section.Size / symEntSize;

            for (long i = 0; i < count; i++)
            {
                long entOff = symBase + i * symEntSize;
                if (entOff + symEntSize > data.Length)
                    break;

                uint nameIdx = ReadU32(data, entOff, header.IsLittleEndian);
                long nameOff = strBase + nameIdx;

                if (nameOff < strBase || nameOff >= strEnd)
                    continue;

                int end = (int)nameOff;
                while (end < strEnd && end < data.Length && data[end] != 0)
                    end++;

                if (end > (int)nameOff)
                    symbols.Add(Encoding.ASCII.GetString(data, (int)nameOff, end - (int)nameOff));
            }
        }

        return symbols;
    }

    /// <summary>
    /// Extracts DT_NEEDED library names, DT_RPATH, and DT_RUNPATH from the ELF
    /// dynamic section (.dynamic), resolving strings via the linked .dynstr section.
    /// </summary>
    public static (IReadOnlyList<string> Needed, string? Rpath, string? Runpath)
        ExtractDynamicEntries(byte[] data, ElfHeader header)
    {
        var needed = new List<string>();
        string? rpath = null;
        string? runpath = null;

        var sections = ParseSectionHeaders(data, header);
        if (sections.Count == 0)
            return (needed, rpath, runpath);

        ElfSectionHeader? dynSection = null;
        foreach (var s in sections)
        {
            if (s.Type == SHT_DYNAMIC) { dynSection = s; break; }
        }

        if (dynSection is null || dynSection.Link >= (uint)sections.Count)
            return (needed, rpath, runpath);

        var dynstrSection = sections[(int)dynSection.Link];
        long strBase = (long)dynstrSection.Offset;
        long strEnd = strBase + (long)dynstrSection.Size;
        long dynBase = (long)dynSection.Offset;
        long dynEnd = dynBase + (long)dynSection.Size;

        if (strBase < 0 || strEnd > data.Length || dynBase < 0 || dynEnd > data.Length)
            return (needed, rpath, runpath);

        int entSize = header.Is64Bit ? 16 : 8;
        long count = (long)dynSection.Size / entSize;

        for (long i = 0; i < count; i++)
        {
            long off = dynBase + i * entSize;
            if (off + entSize > data.Length)
                break;

            long tag = header.Is64Bit
                ? (long)ReadU64(data, off, header.IsLittleEndian)
                : (long)ReadU32(data, off, header.IsLittleEndian);
            ulong val = header.Is64Bit
                ? ReadU64(data, off + 8, header.IsLittleEndian)
                : ReadU32(data, off + 4, header.IsLittleEndian);

            if (tag == DT_NULL)
                break;

            if (tag != DT_NEEDED && tag != DT_RPATH && tag != DT_RUNPATH)
                continue;

            long nameOff = strBase + (long)val;
            if (nameOff < strBase || nameOff >= strEnd)
                continue;

            int end = (int)nameOff;
            while (end < strEnd && end < data.Length && data[end] != 0)
                end++;

            string name = Encoding.ASCII.GetString(data, (int)nameOff, end - (int)nameOff);
            if (tag == DT_NEEDED) needed.Add(name);
            else if (tag == DT_RPATH) rpath = name;
            else runpath = name;
        }

        return (needed, rpath, runpath);
    }

    /// <summary>
    /// Native string extraction: yields all ASCII printable runs of at least
    /// <paramref name="minLength"/> bytes (same output semantics as the
    /// <c>strings(1)</c> utility).
    /// </summary>
    public static IReadOnlyList<string> ExtractStrings(byte[] data, int minLength = 4)
    {
        var result = new List<string>();
        var sb = new StringBuilder();

        foreach (byte b in data)
        {
            if (b >= 0x20 && b < 0x7F)
            {
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minLength)
                    result.Add(sb.ToString());
                sb.Clear();
            }
        }

        if (sb.Length >= minLength)
            result.Add(sb.ToString());

        return result;
    }

    // ── internal read helpers ──────────────────────────────────────────────

    internal static ushort ReadU16(byte[] data, long off, bool isLE)
    {
        if (off < 0 || off + 2 > data.Length) return 0;
        int i = (int)off;
        return isLE
            ? BitConverter.ToUInt16(data, i)
            : (ushort)((data[i] << 8) | data[i + 1]);
    }

    internal static uint ReadU32(byte[] data, long off, bool isLE)
    {
        if (off < 0 || off + 4 > data.Length) return 0;
        int i = (int)off;
        return isLE
            ? BitConverter.ToUInt32(data, i)
            : ((uint)data[i] << 24) | ((uint)data[i + 1] << 16) |
              ((uint)data[i + 2] << 8) | data[i + 3];
    }

    internal static ulong ReadU64(byte[] data, long off, bool isLE)
    {
        if (off < 0 || off + 8 > data.Length) return 0;
        int i = (int)off;
        return isLE
            ? BitConverter.ToUInt64(data, i)
            : ((ulong)data[i] << 56) | ((ulong)data[i + 1] << 48) |
              ((ulong)data[i + 2] << 40) | ((ulong)data[i + 3] << 32) |
              ((ulong)data[i + 4] << 24) | ((ulong)data[i + 5] << 16) |
              ((ulong)data[i + 6] << 8) | data[i + 7];
    }
}
