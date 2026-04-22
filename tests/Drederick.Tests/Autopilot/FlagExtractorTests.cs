using System.Collections.Concurrent;
using Drederick.Audit;
using Drederick.Autopilot;
using Xunit;

namespace Drederick.Tests.Autopilot;

public class FlagExtractorTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"flag-ex-{Guid.NewGuid():N}.jsonl");

    private static string NewDir() =>
        Path.Combine(Path.GetTempPath(), $"flag-scan-{Guid.NewGuid():N}");

    [Fact]
    public void Detects_Common_Ctf_Patterns()
    {
        using var audit = new AuditLog(NewAuditPath());
        var dir = NewDir();
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "loot1.txt"),
                "Access granted. Your reward: flag{tatum_knocks_them_down}");
            File.WriteAllText(Path.Combine(dir, "loot2.txt"),
                "root.txt says: HTB{corner_man_scored_the_knockout}");
            File.WriteAllText(Path.Combine(dir, "loot3.txt"),
                "picoCTF{heavyweight_champion_of_the_world}");

            var ex = new FlagExtractor(audit);
            var matches = ex.ScanDirectory(dir);
            Assert.Contains(matches, m => m.Value.Contains("tatum_knocks_them_down"));
            Assert.Contains(matches, m => m.Value.StartsWith("HTB{"));
            Assert.Contains(matches, m => m.Value.StartsWith("picoCTF{"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Dedupes_By_Sha256()
    {
        using var audit = new AuditLog(NewAuditPath());
        var dir = NewDir();
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "a.txt"), "flag{same}");
            File.WriteAllText(Path.Combine(dir, "b.txt"), "flag{same}");
            File.WriteAllText(Path.Combine(dir, "c.txt"), "flag{different}");

            var ex = new FlagExtractor(audit);
            var matches = ex.ScanDirectory(dir);
            // flag{same} + flag{different} + possibly a 32-hex false positive
            // from a sha in b.txt? none present → expect 2.
            Assert.Equal(2, matches.Count(m => m.Value.StartsWith("flag{")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Skips_Binary_Files()
    {
        using var audit = new AuditLog(NewAuditPath());
        var dir = NewDir();
        Directory.CreateDirectory(dir);
        try
        {
            // File with NUL byte → treated as binary and skipped.
            File.WriteAllBytes(Path.Combine(dir, "bin.bin"),
                new byte[] { 0x00, (byte)'f', (byte)'l', (byte)'a', (byte)'g', (byte)'{', (byte)'x', (byte)'}' });
            var ex = new FlagExtractor(audit);
            var matches = ex.ScanDirectory(dir);
            Assert.Empty(matches);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ScanText_Merges_Into_Seen()
    {
        using var audit = new AuditLog(NewAuditPath());
        var ex = new FlagExtractor(audit);
        var seen = new ConcurrentDictionary<string, FlagMatch>();
        ex.ScanText("you win: FLAG{heavyweight}", source: "test:stdout", seen);
        Assert.Single(seen);
        Assert.Contains(seen.Values, m => m.Value == "FLAG{heavyweight}");
    }

    [Fact]
    public void Empty_Or_Nonexistent_Directory_Returns_Empty()
    {
        using var audit = new AuditLog(NewAuditPath());
        var ex = new FlagExtractor(audit);
        Assert.Empty(ex.ScanDirectory("/nonexistent/path/for/tatum"));
    }
}
