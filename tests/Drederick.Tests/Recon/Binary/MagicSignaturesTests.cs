using System.IO.Compression;
using Drederick.Recon.Binary;
using Xunit;

namespace Drederick.Tests.Recon.Binary;

/// <summary>
/// Unit tests for <see cref="MagicSignatures"/>. Generates tiny in-process
/// fixtures rather than shipping binary blobs.
/// </summary>
public sealed class MagicSignaturesTests
{
    [Fact]
    public void Identify_Elf_DetectsByMagic()
    {
        // /bin/bash on Linux is the canonical real-world ELF binary.
        if (File.Exists("/bin/bash"))
        {
            var match = MagicSignatures.Identify("/bin/bash");
            Assert.NotNull(match);
            Assert.Equal("ELF", match!.Format);
        }

        var synthetic = new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00 };
        var m = MagicSignatures.Identify(synthetic);
        Assert.NotNull(m);
        Assert.Equal("ELF", m!.Format);
        Assert.Equal("application/x-elf", m.MimeType);
    }

    [Fact]
    public void Identify_Pe_DosStub()
    {
        var m = MagicSignatures.Identify(new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
        Assert.NotNull(m);
        Assert.Equal("PE", m!.Format);
    }

    [Theory]
    [InlineData(new byte[] { 0xFE, 0xED, 0xFA, 0xCE }, "MACHO")]
    [InlineData(new byte[] { 0xFE, 0xED, 0xFA, 0xCF }, "MACHO")]
    [InlineData(new byte[] { 0xCE, 0xFA, 0xED, 0xFE }, "MACHO")]
    [InlineData(new byte[] { 0xCF, 0xFA, 0xED, 0xFE }, "MACHO")]
    [InlineData(new byte[] { 0xCA, 0xFE, 0xBA, 0xBF }, "MACHO")]
    public void Identify_MachO_AllVariants(byte[] head, string expectedFormat)
    {
        var m = MagicSignatures.Identify(head);
        Assert.NotNull(m);
        Assert.Equal(expectedFormat, m!.Format);
    }

    [Fact]
    public void Identify_JavaClass()
    {
        var m = MagicSignatures.Identify(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34 });
        Assert.NotNull(m);
        // CAFEBABE collides between Mach-O FAT and Java class — either resolution is acceptable.
        Assert.Contains(m!.Format, new[] { "JAVACLASS", "MACHO" });
    }

    [Fact]
    public void Identify_Zip_FromGeneratedArchive()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("hello.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write("hi");
        }
        ms.Position = 0;

        var m = MagicSignatures.Identify(ms);
        Assert.NotNull(m);
        Assert.Equal("ZIP", m!.Format);
    }

    [Theory]
    [InlineData(new byte[] { 0x1F, 0x8B, 0x08 }, "application/gzip")]
    [InlineData(new byte[] { 0x42, 0x5A, 0x68, 0x39 }, "application/x-bzip2")]
    [InlineData(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, "application/x-xz")]
    [InlineData(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, "application/x-7z-compressed")]
    [InlineData(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 }, "application/x-rar-compressed")]
    [InlineData(new byte[] { 0x28, 0xB5, 0x2F, 0xFD }, "application/zstd")]
    [InlineData(new byte[] { 0x04, 0x22, 0x4D, 0x18 }, "application/x-lz4")]
    public void Identify_CompressionFormats(byte[] head, string expectedMime)
    {
        var m = MagicSignatures.Identify(head);
        Assert.NotNull(m);
        Assert.Equal(expectedMime, m!.MimeType);
    }

    [Fact]
    public void Identify_DebArchive()
    {
        var m = MagicSignatures.Identify(System.Text.Encoding.ASCII.GetBytes("!<arch>\ndebian-binary"));
        Assert.NotNull(m);
        Assert.Equal("application/x-archive", m!.MimeType);
    }

    [Fact]
    public void Identify_Rpm()
    {
        var m = MagicSignatures.Identify(new byte[] { 0xED, 0xAB, 0xEE, 0xDB, 0x03, 0x00 });
        Assert.NotNull(m);
        Assert.Equal("application/x-rpm", m!.MimeType);
    }

    [Fact]
    public void Identify_Tar_AtOffset257()
    {
        var buf = new byte[512];
        var ustar = System.Text.Encoding.ASCII.GetBytes("ustar\x00");
        Array.Copy(ustar, 0, buf, 257, ustar.Length);
        var m = MagicSignatures.Identify(buf);
        Assert.NotNull(m);
        Assert.Equal("application/x-tar", m!.MimeType);
        Assert.Equal(257, m.Offset);
    }

    [Fact]
    public void Identify_Iso9660_AtOffset0x8001()
    {
        var buf = new byte[0x8006];
        var cd = System.Text.Encoding.ASCII.GetBytes("CD001");
        Array.Copy(cd, 0, buf, 0x8001, cd.Length);
        var m = MagicSignatures.Identify(buf);
        Assert.NotNull(m);
        Assert.Equal("DISKIMAGE", m!.Format);
        Assert.Equal(0x8001, m.Offset);
    }

    [Fact]
    public void Identify_Ole2()
    {
        var m = MagicSignatures.Identify(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00 });
        Assert.NotNull(m);
        Assert.Equal("OLE2", m!.Format);
    }

    [Fact]
    public void Identify_Pdf()
    {
        var m = MagicSignatures.Identify(System.Text.Encoding.ASCII.GetBytes("%PDF-1.7\n"));
        Assert.NotNull(m);
        Assert.Equal("application/pdf", m!.MimeType);
    }

    [Theory]
    [InlineData("image/png", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A })]
    [InlineData("image/gif", new byte[] { (byte)'G', (byte)'I', (byte)'F', (byte)'8', (byte)'9', (byte)'a' })]
    [InlineData("image/jpeg", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 })]
    [InlineData("image/bmp", new byte[] { 0x42, 0x4D, 0x36, 0x00 })]
    [InlineData("image/tiff", new byte[] { 0x49, 0x49, 0x2A, 0x00 })]
    public void Identify_Images(string expectedMime, byte[] head)
    {
        var m = MagicSignatures.Identify(head);
        Assert.NotNull(m);
        Assert.Equal(expectedMime, m!.MimeType);
    }

    [Fact]
    public void Identify_WebP_RiffContainer()
    {
        var head = new byte[] { (byte)'R', (byte)'I', (byte)'F', (byte)'F', 0x10, 0, 0, 0,
                                (byte)'W', (byte)'E', (byte)'B', (byte)'P' };
        var m = MagicSignatures.Identify(head);
        Assert.NotNull(m);
        // WEBP at offset 8 is more specific than RIFF at offset 0.
        Assert.Equal("image/webp", m!.MimeType);
    }

    [Fact]
    public void Identify_Mp3_Id3()
    {
        var m = MagicSignatures.Identify(System.Text.Encoding.ASCII.GetBytes("ID3\x03\x00\x00"));
        Assert.NotNull(m);
        Assert.Equal("audio/mpeg", m!.MimeType);
    }

    [Fact]
    public void Identify_Mp4_Ftyp()
    {
        var head = new byte[] { 0, 0, 0, 0x18, (byte)'f', (byte)'t', (byte)'y', (byte)'p',
                                (byte)'i', (byte)'s', (byte)'o', (byte)'m' };
        var m = MagicSignatures.Identify(head);
        Assert.NotNull(m);
        Assert.Equal("video/mp4", m!.MimeType);
    }

    [Fact]
    public void Identify_Sqlite3()
    {
        var m = MagicSignatures.Identify(System.Text.Encoding.ASCII.GetBytes("SQLite format 3\0"));
        Assert.NotNull(m);
        Assert.Equal("application/vnd.sqlite3", m!.MimeType);
    }

    [Fact]
    public void Identify_JavaKeystore()
    {
        var m = MagicSignatures.Identify(new byte[] { 0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00 });
        Assert.NotNull(m);
        Assert.Equal("application/x-java-keystore", m!.MimeType);
    }

    [Fact]
    public void Identify_PythonBytecode()
    {
        var m = MagicSignatures.Identify(new byte[] { 0xA7, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0 });
        Assert.NotNull(m);
        Assert.Equal("BYTECODE", m!.Format);
    }

    [Fact]
    public void Identify_PemCertificate()
    {
        var m = MagicSignatures.Identify(System.Text.Encoding.ASCII.GetBytes("-----BEGIN CERTIFICATE-----\n"));
        Assert.NotNull(m);
        Assert.Equal("KEY", m!.Format);
    }

    [Fact]
    public void Identify_BcryptHash()
    {
        var m = MagicSignatures.Identify(System.Text.Encoding.ASCII.GetBytes("$2a$12$abcdefghijklmnop"));
        Assert.NotNull(m);
        Assert.Equal("HASH", m!.Format);
    }

    [Fact]
    public void Identify_Wasm()
    {
        var m = MagicSignatures.Identify(new byte[] { 0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00 });
        Assert.NotNull(m);
        Assert.Equal("application/wasm", m!.MimeType);
    }

    [Fact]
    public void Identify_Returns_Null_ForUnknown()
    {
        var m = MagicSignatures.Identify(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 });
        Assert.Null(m);
    }

    [Fact]
    public void Identify_FromPath_RoundTrip()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, $"magic-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var p = Path.Combine(dir, "sample.png");
            File.WriteAllBytes(p, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0 });
            var m = MagicSignatures.Identify(p);
            Assert.NotNull(m);
            Assert.Equal("image/png", m!.MimeType);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SignatureTable_HasExpectedCoverage()
    {
        // Signature inventory floor — keep the table dense.
        Assert.True(MagicSignatures.Signatures.Count >= 50,
            $"Expected >= 50 signatures, got {MagicSignatures.Signatures.Count}");
    }
}
