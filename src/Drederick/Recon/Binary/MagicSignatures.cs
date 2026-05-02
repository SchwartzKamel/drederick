namespace Drederick.Recon.Binary;

/// <summary>
/// Native magic-byte signature table. Implements <c>docs/PLUGIN_STRATEGY.md</c>
/// Pattern 2 (embedded community data) for binary file-type identification —
/// replaces the need for a hard <c>file(1)</c> dependency. <c>file(1)</c> remains
/// a Pattern 1 graceful-enrichment fallback in <see cref="BinaryAnalyzer"/>.
/// </summary>
/// <remarks>
/// References (no upstream <c>magic</c> file content was copied verbatim — only
/// the well-known signature constants, which are facts about each format):
/// <list type="bullet">
///   <item>libmagic project (BSD-licensed, https://github.com/file/file)</item>
///   <item>Wikipedia: "List of file signatures"</item>
///   <item>https://www.garykessler.net/library/file_sigs.html</item>
///   <item>https://en.wikipedia.org/wiki/Executable_and_Linkable_Format</item>
///   <item>Microsoft PE/COFF specification (PE/PE32+/COFF)</item>
///   <item>Apple Mach-O reference (MH_MAGIC*, FAT_MAGIC*)</item>
///   <item>Apache OpenOffice OLE2 / Compound File Binary Format spec</item>
///   <item>ECMA-119 (ISO 9660) — "CD001" volume descriptor at offset 0x8001</item>
///   <item>SQLite file format spec — "SQLite format 3\0"</item>
///   <item>RFC 1952 (gzip), RFC 1951 (deflate), RFC 8478 (zstd)</item>
///   <item>Java VM spec (CAFEBABE class file magic)</item>
///   <item>CPython marshal / .pyc magic numbers (Python source: Lib/importlib/_bootstrap_external.py)</item>
/// </list>
/// </remarks>
public static class MagicSignatures
{
    /// <summary>Maximum head length we ever need to read (covers ISO 9660 at 0x8001 + 5 bytes).</summary>
    public const int MaxScanLength = 0x8006;

    /// <summary>Single magic-byte signature with optional offset and free-form label.</summary>
    public sealed record MagicSignature(
        byte[] Signature,
        int Offset,
        string MimeType,
        string Description,
        string Format);

    /// <summary>Result of a successful identification.</summary>
    public sealed record MagicMatch(
        string MimeType,
        string Description,
        string Format,
        int Offset,
        int SignatureLength);

    /// <summary>
    /// Curated signature table. The longest matching prefix
    /// (greatest <c>Offset + SignatureLength</c>) wins, so longer / more specific
    /// signatures (e.g. ISO 9660 at 0x8001) naturally beat short ones.
    /// </summary>
    public static readonly IReadOnlyList<MagicSignature> Signatures = BuildSignatures();

    private static MagicSignature[] BuildSignatures()
    {
        static byte[] B(params byte[] xs) => xs;
        static byte[] A(string ascii) => System.Text.Encoding.ASCII.GetBytes(ascii);

        return new[]
        {
            // ── Executables ────────────────────────────────────────────────
            new MagicSignature(B(0x7F, 0x45, 0x4C, 0x46), 0, "application/x-elf", "ELF executable / object", "ELF"),
            new MagicSignature(B(0x4D, 0x5A), 0, "application/vnd.microsoft.portable-executable", "MS-DOS / PE executable", "PE"),
            new MagicSignature(B(0xCA, 0xFE, 0xBA, 0xBE), 0, "application/java-vm", "Java class file", "JAVACLASS"),
            new MagicSignature(B(0xFE, 0xED, 0xFA, 0xCE), 0, "application/x-mach-binary", "Mach-O 32-bit (BE)", "MACHO"),
            new MagicSignature(B(0xFE, 0xED, 0xFA, 0xCF), 0, "application/x-mach-binary", "Mach-O 64-bit (BE)", "MACHO"),
            new MagicSignature(B(0xCE, 0xFA, 0xED, 0xFE), 0, "application/x-mach-binary", "Mach-O 32-bit (LE)", "MACHO"),
            new MagicSignature(B(0xCF, 0xFA, 0xED, 0xFE), 0, "application/x-mach-binary", "Mach-O 64-bit (LE)", "MACHO"),
            new MagicSignature(B(0xCA, 0xFE, 0xBA, 0xBF), 0, "application/x-mach-binary", "Mach-O FAT (32-bit)", "MACHO"),
            new MagicSignature(B(0xCA, 0xFE, 0xD0, 0x0D), 0, "application/x-mach-binary", "Mach-O FAT 64-bit", "MACHO"),
            new MagicSignature(B(0x00, 0x61, 0x73, 0x6D), 0, "application/wasm", "WebAssembly module", "WASM"),
            new MagicSignature(A("#!"), 0, "text/x-script", "Shebang script", "SCRIPT"),
            new MagicSignature(B(0x4D, 0x53, 0x43, 0x46), 0, "application/vnd.ms-cab-compressed", "Microsoft CAB", "ARCHIVE"),

            // ── Compound / OLE2 ────────────────────────────────────────────
            new MagicSignature(B(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1), 0,
                "application/x-ole-storage", "Microsoft OLE2 compound document (legacy DOC/XLS/MSI)", "OLE2"),

            // ── Archives & compression ─────────────────────────────────────
            new MagicSignature(B(0x50, 0x4B, 0x03, 0x04), 0, "application/zip", "ZIP / JAR / APK / DOCX (PK\\x03\\x04)", "ZIP"),
            new MagicSignature(B(0x50, 0x4B, 0x05, 0x06), 0, "application/zip", "ZIP empty archive", "ZIP"),
            new MagicSignature(B(0x50, 0x4B, 0x07, 0x08), 0, "application/zip", "ZIP spanned archive", "ZIP"),
            new MagicSignature(B(0x1F, 0x8B), 0, "application/gzip", "gzip", "ARCHIVE"),
            new MagicSignature(B(0x42, 0x5A, 0x68), 0, "application/x-bzip2", "bzip2", "ARCHIVE"),
            new MagicSignature(B(0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00), 0, "application/x-xz", "xz", "ARCHIVE"),
            new MagicSignature(B(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C), 0, "application/x-7z-compressed", "7-Zip", "ARCHIVE"),
            new MagicSignature(B(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00), 0, "application/x-rar-compressed", "RAR v1.5+", "ARCHIVE"),
            new MagicSignature(B(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00), 0, "application/x-rar-compressed", "RAR v5+", "ARCHIVE"),
            new MagicSignature(B(0x28, 0xB5, 0x2F, 0xFD), 0, "application/zstd", "Zstandard", "ARCHIVE"),
            new MagicSignature(B(0x04, 0x22, 0x4D, 0x18), 0, "application/x-lz4", "LZ4 frame", "ARCHIVE"),
            new MagicSignature(B(0x5D, 0x00, 0x00), 0, "application/x-lzma", "LZMA (raw, heuristic)", "ARCHIVE"),
            new MagicSignature(A("ustar\x00"), 257, "application/x-tar", "POSIX tar (ustar)", "ARCHIVE"),
            new MagicSignature(A("ustar  \x00"), 257, "application/x-tar", "GNU tar (ustar)", "ARCHIVE"),
            new MagicSignature(A("!<arch>\n"), 0, "application/x-archive", "Unix ar archive (DEB / .a static lib)", "ARCHIVE"),
            new MagicSignature(B(0xED, 0xAB, 0xEE, 0xDB), 0, "application/x-rpm", "RPM package", "ARCHIVE"),
            new MagicSignature(A("xar!"), 0, "application/x-xar", "Apple XAR archive", "ARCHIVE"),

            // ── ISO / disk images ──────────────────────────────────────────
            new MagicSignature(A("CD001"), 0x8001, "application/x-iso9660-image", "ISO 9660 CD/DVD image", "DISKIMAGE"),
            new MagicSignature(A("CD001"), 0x8801, "application/x-iso9660-image", "ISO 9660 CD/DVD (alternate)", "DISKIMAGE"),
            new MagicSignature(A("CD001"), 0x9001, "application/x-iso9660-image", "ISO 9660 CD/DVD (Joliet)", "DISKIMAGE"),
            new MagicSignature(A("KDMV"), 0, "application/x-vmdk", "VMware VMDK", "DISKIMAGE"),
            new MagicSignature(A("conectix"), 0, "application/x-vhd", "Microsoft VHD footer", "DISKIMAGE"),
            new MagicSignature(A("vhdxfile"), 0, "application/x-vhdx", "Microsoft VHDX", "DISKIMAGE"),
            new MagicSignature(A("QFI\xFB"), 0, "application/x-qemu-disk", "QEMU QCOW2 image", "DISKIMAGE"),

            // ── Documents ──────────────────────────────────────────────────
            new MagicSignature(A("%PDF-"), 0, "application/pdf", "PDF", "DOCUMENT"),
            new MagicSignature(A("{\\rtf"), 0, "application/rtf", "Rich Text Format", "DOCUMENT"),
            new MagicSignature(A("<?xml"), 0, "application/xml", "XML document", "DOCUMENT"),
            new MagicSignature(A("<!DOCTYPE"), 0, "text/html", "HTML document (DOCTYPE)", "DOCUMENT"),
            new MagicSignature(A("<html"), 0, "text/html", "HTML document", "DOCUMENT"),

            // ── Images ─────────────────────────────────────────────────────
            new MagicSignature(B(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A), 0, "image/png", "PNG", "IMAGE"),
            new MagicSignature(A("GIF87a"), 0, "image/gif", "GIF87a", "IMAGE"),
            new MagicSignature(A("GIF89a"), 0, "image/gif", "GIF89a", "IMAGE"),
            new MagicSignature(B(0xFF, 0xD8, 0xFF, 0xDB), 0, "image/jpeg", "JPEG (raw)", "IMAGE"),
            new MagicSignature(B(0xFF, 0xD8, 0xFF, 0xE0), 0, "image/jpeg", "JPEG/JFIF", "IMAGE"),
            new MagicSignature(B(0xFF, 0xD8, 0xFF, 0xE1), 0, "image/jpeg", "JPEG/EXIF", "IMAGE"),
            new MagicSignature(B(0xFF, 0xD8, 0xFF, 0xEE), 0, "image/jpeg", "JPEG (Adobe)", "IMAGE"),
            new MagicSignature(B(0x42, 0x4D), 0, "image/bmp", "BMP", "IMAGE"),
            new MagicSignature(B(0x49, 0x49, 0x2A, 0x00), 0, "image/tiff", "TIFF (little-endian)", "IMAGE"),
            new MagicSignature(B(0x4D, 0x4D, 0x00, 0x2A), 0, "image/tiff", "TIFF (big-endian)", "IMAGE"),
            new MagicSignature(A("RIFF"), 0, "application/x-riff", "RIFF container (WAV/WEBP/AVI)", "CONTAINER"),
            new MagicSignature(A("WEBP"), 8, "image/webp", "WebP", "IMAGE"),
            new MagicSignature(A("WAVE"), 8, "audio/wav", "WAV audio", "AUDIO"),
            new MagicSignature(A("AVI "), 8, "video/x-msvideo", "AVI video", "VIDEO"),
            new MagicSignature(B(0x00, 0x00, 0x01, 0x00), 0, "image/x-icon", "Windows ICO", "IMAGE"),
            new MagicSignature(B(0x00, 0x00, 0x02, 0x00), 0, "image/x-icon", "Windows CUR", "IMAGE"),
            new MagicSignature(B(0x38, 0x42, 0x50, 0x53), 0, "image/vnd.adobe.photoshop", "Adobe Photoshop PSD", "IMAGE"),

            // ── Audio / video ──────────────────────────────────────────────
            new MagicSignature(A("ID3"), 0, "audio/mpeg", "MP3 with ID3 tag", "AUDIO"),
            new MagicSignature(B(0xFF, 0xFB), 0, "audio/mpeg", "MP3 frame (MPEG-1 Layer III)", "AUDIO"),
            new MagicSignature(B(0xFF, 0xF3), 0, "audio/mpeg", "MP3 frame (MPEG-2 Layer III)", "AUDIO"),
            new MagicSignature(B(0xFF, 0xF2), 0, "audio/mpeg", "MP3 frame (MPEG-2.5 Layer III)", "AUDIO"),
            new MagicSignature(A("OggS"), 0, "application/ogg", "Ogg container", "AUDIO"),
            new MagicSignature(A("fLaC"), 0, "audio/flac", "FLAC", "AUDIO"),
            new MagicSignature(A("ftyp"), 4, "video/mp4", "MP4 / QuickTime / 3GP / HEIF (ftyp box)", "VIDEO"),
            new MagicSignature(A("moov"), 4, "video/quicktime", "QuickTime moov atom", "VIDEO"),
            new MagicSignature(A("mdat"), 4, "video/quicktime", "QuickTime mdat atom", "VIDEO"),
            new MagicSignature(B(0x1A, 0x45, 0xDF, 0xA3), 0, "video/x-matroska", "Matroska / WebM (EBML)", "VIDEO"),
            new MagicSignature(B(0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11), 0, "video/x-ms-asf", "ASF / WMV / WMA", "VIDEO"),

            // ── Databases / config ─────────────────────────────────────────
            new MagicSignature(A("SQLite format 3\0"), 0, "application/vnd.sqlite3", "SQLite 3 database", "DATABASE"),
            new MagicSignature(A("REGEDIT4"), 0, "application/x-registry", "Windows Registry export (REGEDIT4)", "CONFIG"),
            new MagicSignature(A("regf"), 0, "application/x-ms-regf", "Windows Registry hive (regf)", "DATABASE"),

            // ── Python pyc (multiple versions; magic in low 2 bytes + \r\n) ──
            new MagicSignature(B(0x42, 0x0D, 0x0D, 0x0A), 0, "application/x-python-bytecode", "Python 3.7 .pyc", "BYTECODE"),
            new MagicSignature(B(0x33, 0x0D, 0x0D, 0x0A), 0, "application/x-python-bytecode", "Python 3.6 .pyc", "BYTECODE"),
            new MagicSignature(B(0x16, 0x0D, 0x0D, 0x0A), 0, "application/x-python-bytecode", "Python 3.5 .pyc", "BYTECODE"),
            new MagicSignature(B(0x55, 0x0D, 0x0D, 0x0A), 0, "application/x-python-bytecode", "Python 3.8 .pyc", "BYTECODE"),
            new MagicSignature(B(0x61, 0x0D, 0x0D, 0x0A), 0, "application/x-python-bytecode", "Python 3.9 .pyc", "BYTECODE"),
            new MagicSignature(B(0x6F, 0x0D, 0x0D, 0x0A), 0, "application/x-python-bytecode", "Python 3.10 .pyc", "BYTECODE"),
            new MagicSignature(B(0xA7, 0x0D, 0x0D, 0x0A), 0, "application/x-python-bytecode", "Python 3.11 .pyc", "BYTECODE"),
            new MagicSignature(B(0xCB, 0x0D, 0x0D, 0x0A), 0, "application/x-python-bytecode", "Python 3.12 .pyc", "BYTECODE"),

            // ── Keys, certs, secrets stores ────────────────────────────────
            new MagicSignature(B(0xFE, 0xED, 0xFE, 0xED), 0, "application/x-java-keystore", "Java KeyStore (JKS)", "KEY"),
            new MagicSignature(B(0xCE, 0xCE, 0xCE, 0xCE), 0, "application/x-java-keystore", "Java KeyStore (JCEKS)", "KEY"),
            new MagicSignature(A("-----BEGIN CERTIFICATE-----"), 0, "application/x-pem-file", "PEM certificate", "KEY"),
            new MagicSignature(A("-----BEGIN RSA PRIVATE KEY-----"), 0, "application/x-pem-file", "PEM RSA private key", "KEY"),
            new MagicSignature(A("-----BEGIN OPENSSH PRIVATE KEY-----"), 0, "application/x-pem-file", "OpenSSH private key", "KEY"),
            new MagicSignature(A("-----BEGIN PGP "), 0, "application/pgp", "PGP armored data", "KEY"),
            new MagicSignature(A("ssh-rsa "), 0, "application/x-ssh-key", "OpenSSH public key (RSA)", "KEY"),
            new MagicSignature(A("ssh-ed25519 "), 0, "application/x-ssh-key", "OpenSSH public key (ed25519)", "KEY"),
            new MagicSignature(A("ecdsa-sha2-"), 0, "application/x-ssh-key", "OpenSSH public key (ECDSA)", "KEY"),

            // ── Hash / password DB markers ─────────────────────────────────
            new MagicSignature(A("$2a$"), 0, "application/x-bcrypt-hash", "bcrypt hash ($2a$)", "HASH"),
            new MagicSignature(A("$2b$"), 0, "application/x-bcrypt-hash", "bcrypt hash ($2b$)", "HASH"),
            new MagicSignature(A("$2y$"), 0, "application/x-bcrypt-hash", "bcrypt hash ($2y$)", "HASH"),
            new MagicSignature(A("$argon2"), 0, "application/x-argon2-hash", "Argon2 hash", "HASH"),
            new MagicSignature(A("$6$"), 0, "application/x-sha512-crypt-hash", "SHA-512 crypt hash", "HASH"),

            // ── Misc binary containers ─────────────────────────────────────
            new MagicSignature(A("PAR1"), 0, "application/x-parquet", "Apache Parquet", "CONTAINER"),
            new MagicSignature(A("Obj\x01"), 0, "application/avro", "Apache Avro", "CONTAINER"),
            new MagicSignature(A("dex\n"), 0, "application/x-dex", "Android DEX", "BYTECODE"),
            new MagicSignature(A("dey\n"), 0, "application/x-dey", "Android optimized DEX (dey)", "BYTECODE"),
        };
    }

    /// <summary>
    /// Identify the file type from a head buffer. Best-effort, longest specific
    /// match wins (signature offset + length).
    /// </summary>
    public static MagicMatch? Identify(ReadOnlySpan<byte> head)
    {
        MagicMatch? best = null;
        int bestSpecificity = -1;

        foreach (var sig in Signatures)
        {
            int end = sig.Offset + sig.Signature.Length;
            if (end > head.Length)
                continue;
            if (!head.Slice(sig.Offset, sig.Signature.Length).SequenceEqual(sig.Signature))
                continue;

            int specificity = sig.Offset + sig.Signature.Length;
            if (specificity > bestSpecificity)
            {
                bestSpecificity = specificity;
                best = new MagicMatch(sig.MimeType, sig.Description, sig.Format, sig.Offset, sig.Signature.Length);
            }
        }

        return best;
    }

    /// <summary>Identify the file type from a stream (reads up to <see cref="MaxScanLength"/> bytes).</summary>
    public static MagicMatch? Identify(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var buffer = new byte[MaxScanLength];
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer, total, buffer.Length - total);
            if (read <= 0)
                break;
            total += read;
        }

        return Identify(buffer.AsSpan(0, total));
    }

    /// <summary>Identify the file type by path. Returns null on read errors or no match.</summary>
    public static MagicMatch? Identify(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        try
        {
            using var fs = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 4096, useAsync: false);
            return Identify(fs);
        }
        catch (Exception)
        {
            return null;
        }
    }
}
