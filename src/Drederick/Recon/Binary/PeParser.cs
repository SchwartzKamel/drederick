using System.Text;

namespace Drederick.Recon.Binary;

/// <summary>
/// Native .NET PE (Portable Executable) binary parser — no external tools required.
/// Parses MZ/PE headers, DLL characteristics, import directory, and section names.
/// All methods are pure, stateless, and thread-safe.
/// </summary>
public static class PeParser
{
    // IMAGE_DLLCHARACTERISTICS flags (OptionalHeader.DllCharacteristics)
    private const ushort IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040; // ASLR
    private const ushort IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;    // DEP/NX

    // DllCharacteristics is at offset +70 from the start of the optional header
    // for BOTH PE32 (0x010b) and PE32+ (0x020b).
    private const int DLLCHARACTERISTICS_OFFSET_FROM_OPT = 70;

    // Import data directory entry indices
    private const int DATA_DIR_IMPORT_PE32 = 104;   // offset from opt header start
    private const int DATA_DIR_IMPORT_PE64 = 120;   // offset from opt header start

    // ──────────────────────────────────────────────────────────────────────

    /// <summary>Returns true if the NX-Compat (DEP) flag is set in DllCharacteristics.</summary>
    public static bool HasNXBit(byte[] data)
        => (GetDllCharacteristics(data) & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;

    /// <summary>Returns true if the Dynamic Base (ASLR) flag is set in DllCharacteristics.</summary>
    public static bool HasASLR(byte[] data)
        => (GetDllCharacteristics(data) & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;

    /// <summary>
    /// Returns the architecture label string from the COFF machine type field.
    /// </summary>
    public static string DetectArchitecture(byte[] data)
    {
        if (!TryGetPeHeaderOffset(data, out int peOff))
            return "";

        int coffOff = peOff + 4;
        if (coffOff + 2 > data.Length)
            return "";

        ushort machine = BitConverter.ToUInt16(data, coffOff);
        return machine switch
        {
            0x014c => "x86",    // IMAGE_FILE_MACHINE_I386
            0x8664 => "x64",    // IMAGE_FILE_MACHINE_AMD64
            0x01c4 => "arm",    // IMAGE_FILE_MACHINE_ARMNT
            0xaa64 => "arm64",  // IMAGE_FILE_MACHINE_ARM64
            0x0200 => "ia64",
            _ => "",
        };
    }

    /// <summary>Returns the AddressOfEntryPoint from the optional header.</summary>
    public static ulong GetEntryPoint(byte[] data)
    {
        if (!TryGetPeHeaderOffset(data, out int peOff))
            return 0;

        int optOff = peOff + 24;
        if (optOff + 20 > data.Length)
            return 0;

        ushort magic = BitConverter.ToUInt16(data, optOff);
        if (magic != 0x010b && magic != 0x020b)
            return 0;

        // AddressOfEntryPoint is at offset +16 from the optional header start.
        return BitConverter.ToUInt32(data, optOff + 16);
    }

    /// <summary>
    /// Returns the names of all PE sections (e.g. ".text", ".data", ".rdata").
    /// </summary>
    public static IReadOnlyList<string> GetSectionNames(byte[] data)
    {
        var names = new List<string>();
        if (!TryGetSectionTableOffset(data, out int sectOff, out int numSections))
            return names;

        for (int i = 0; i < numSections; i++)
        {
            int secOff = sectOff + i * 40;
            if (secOff + 8 > data.Length)
                break;

            // Section name: 8 bytes, ASCII, null-padded.
            int nullIdx = Array.IndexOf(data, (byte)0, secOff, 8);
            int len = nullIdx >= 0 ? nullIdx - secOff : 8;
            if (len < 0) len = 0;
            names.Add(Encoding.ASCII.GetString(data, secOff, len));
        }

        return names;
    }

    /// <summary>
    /// Parses the PE import directory and returns the list of imported DLL names.
    /// </summary>
    public static IReadOnlyList<string> ParseImportedDlls(byte[] data)
    {
        var dlls = new List<string>();
        if (!TryGetPeHeaderOffset(data, out int peOff))
            return dlls;

        int optOff = peOff + 24;
        if (optOff + 2 > data.Length)
            return dlls;

        ushort magic = BitConverter.ToUInt16(data, optOff);
        bool isPe64 = magic == 0x020b;

        int importDirOff = optOff + (isPe64 ? DATA_DIR_IMPORT_PE64 : DATA_DIR_IMPORT_PE32);
        if (importDirOff + 8 > data.Length)
            return dlls;

        uint importRva = BitConverter.ToUInt32(data, importDirOff);
        if (importRva == 0)
            return dlls;

        if (!TryRvaToFileOffset(data, peOff, importRva, out int importFileOff))
            return dlls;

        // Walk the IMAGE_IMPORT_DESCRIPTOR table; each entry is 20 bytes.
        // The table ends with an all-zero entry.
        while (importFileOff + 20 <= data.Length)
        {
            bool allZero = true;
            for (int j = 0; j < 20 && allZero; j++)
                allZero = data[importFileOff + j] == 0;
            if (allZero)
                break;

            // Name RVA is at offset +12 within the descriptor.
            uint nameRva = BitConverter.ToUInt32(data, importFileOff + 12);
            if (nameRva != 0 && TryRvaToFileOffset(data, peOff, nameRva, out int nameFileOff))
            {
                int end = nameFileOff;
                while (end < data.Length && data[end] != 0)
                    end++;
                string dllName = Encoding.ASCII.GetString(data, nameFileOff, end - nameFileOff);
                if (!string.IsNullOrEmpty(dllName))
                    dlls.Add(dllName);
            }

            importFileOff += 20;
        }

        return dlls;
    }

    // ── private helpers ────────────────────────────────────────────────────

    private static ushort GetDllCharacteristics(byte[] data)
    {
        if (!TryGetPeHeaderOffset(data, out int peOff))
            return 0;

        int optOff = peOff + 24;
        if (optOff + DLLCHARACTERISTICS_OFFSET_FROM_OPT + 2 > data.Length)
            return 0;

        ushort magic = BitConverter.ToUInt16(data, optOff);
        if (magic != 0x010b && magic != 0x020b)
            return 0;

        return BitConverter.ToUInt16(data, optOff + DLLCHARACTERISTICS_OFFSET_FROM_OPT);
    }

    private static bool TryGetPeHeaderOffset(byte[] data, out int peOff)
    {
        peOff = 0;
        if (data.Length < 0x40)
            return false;
        if (data[0] != 0x4D || data[1] != 0x5A) // MZ
            return false;

        peOff = BitConverter.ToInt32(data, 0x3C);
        if (peOff < 0 || peOff + 4 > data.Length)
            return false;

        return data[peOff] == 0x50 && data[peOff + 1] == 0x45 &&
               data[peOff + 2] == 0x00 && data[peOff + 3] == 0x00;
    }

    internal static bool TryGetSectionTableOffset(byte[] data, out int sectOff, out int numSections)
    {
        sectOff = 0;
        numSections = 0;

        if (!TryGetPeHeaderOffset(data, out int peOff))
            return false;

        int coffOff = peOff + 4;
        if (coffOff + 20 > data.Length)
            return false;

        numSections = BitConverter.ToUInt16(data, coffOff + 2);
        ushort sizeOfOptHdr = BitConverter.ToUInt16(data, coffOff + 16);

        sectOff = coffOff + 20 + sizeOfOptHdr;
        return sectOff + (long)numSections * 40 <= data.Length;
    }

    internal static bool TryRvaToFileOffset(byte[] data, int peOff, uint rva, out int fileOff)
    {
        fileOff = 0;
        if (!TryGetSectionTableOffset(data, out int sectOff, out int numSections))
            return false;

        for (int i = 0; i < numSections; i++)
        {
            int sOff = sectOff + i * 40;
            if (sOff + 40 > data.Length)
                break;

            uint virtualSize = BitConverter.ToUInt32(data, sOff + 8);
            uint virtualAddr = BitConverter.ToUInt32(data, sOff + 12);
            uint rawSize = BitConverter.ToUInt32(data, sOff + 16);
            uint rawAddr = BitConverter.ToUInt32(data, sOff + 20);

            uint mappedSize = Math.Max(virtualSize, rawSize);
            if (rva >= virtualAddr && rva < virtualAddr + mappedSize)
            {
                fileOff = (int)(rawAddr + (rva - virtualAddr));
                return fileOff >= 0 && fileOff < data.Length;
            }
        }

        return false;
    }
}
