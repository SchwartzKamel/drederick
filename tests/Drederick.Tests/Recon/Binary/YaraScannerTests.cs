using Drederick.Audit;
using Drederick.Recon.Binary;
using Xunit;

namespace Drederick.Tests.Recon.Binary;

public sealed class YaraScannerTests : IDisposable
{
    private readonly string _scratch;
    private readonly AuditLog _audit;

    public YaraScannerTests()
    {
        _scratch = Path.Combine(Path.GetTempPath(), "drederick-yara-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_scratch);
        _audit = new AuditLog(Path.Combine(_scratch, "audit.jsonl"));
    }

    public void Dispose()
    {
        try { _audit.Dispose(); } catch { }
        try { Directory.Delete(_scratch, recursive: true); } catch { }
    }

    [Fact]
    public void Loads_BundledRules_Count_AtLeast_15()
    {
        var s = new YaraScanner(_audit);
        Assert.True(s.RuleCount >= 15, $"expected >= 15 rules, got {s.RuleCount}");
        Assert.Contains("packer_upx", s.RuleNames);
        Assert.Contains("malware_mimikatz_strings", s.RuleNames);
    }

    [Fact]
    public void Detects_UPX_Strings()
    {
        var s = new YaraScanner(_audit);
        var buf = System.Text.Encoding.ASCII.GetBytes("....UPX0........UPX1.........");
        var hits = s.Scan(buf);
        Assert.Contains(hits, m => m.RuleName == "packer_upx");
    }

    [Fact]
    public void Detects_Mimikatz_Banner_NoCase()
    {
        var s = new YaraScanner(_audit);
        var buf = System.Text.Encoding.ASCII.GetBytes("xxx MIMIKATZ banner here xxx");
        var hits = s.Scan(buf);
        Assert.Contains(hits, m => m.RuleName == "malware_mimikatz_strings");
    }

    [Fact]
    public void Detects_Hex_Pattern_With_Wildcards()
    {
        var s = new YaraScanner(_audit);
        // EB 05 E8 00 00 00 00 58 — matches shellcode_x86_jmp_call_pop
        var buf = new byte[] { 0x90, 0x90, 0xEB, 0x05, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x90 };
        var hits = s.Scan(buf);
        Assert.Contains(hits, m => m.RuleName == "shellcode_x86_jmp_call_pop");
    }

    [Fact]
    public void Empty_Buffer_No_Matches()
    {
        var s = new YaraScanner(_audit);
        var hits = s.Scan(ReadOnlySpan<byte>.Empty);
        Assert.Empty(hits);
    }

    [Fact]
    public void Benign_Buffer_No_FalsePositives_ForMalwareRules()
    {
        var s = new YaraScanner(_audit);
        // Random innocuous string — must not trigger malware-family matches.
        var buf = System.Text.Encoding.ASCII.GetBytes(
            "The quick brown fox jumps over the lazy dog 0123456789");
        var hits = s.Scan(buf);
        Assert.DoesNotContain(hits, m => m.RuleName == "malware_mimikatz_strings");
        Assert.DoesNotContain(hits, m => m.RuleName == "malware_meterpreter_strings");
        Assert.DoesNotContain(hits, m => m.RuleName == "packer_upx");
    }

    [Fact]
    public void Stringmatch_OffsetIsRecorded()
    {
        var s = new YaraScanner(_audit);
        // mimikatz starts at offset 4
        var buf = System.Text.Encoding.ASCII.GetBytes("....mimikatz banner");
        var hits = s.Scan(buf);
        var hit = Assert.Single(hits, m => m.RuleName == "malware_mimikatz_strings");
        Assert.NotEmpty(hit.StringMatches);
        Assert.Equal(4, hit.StringMatches[0].Offset);
    }
}
