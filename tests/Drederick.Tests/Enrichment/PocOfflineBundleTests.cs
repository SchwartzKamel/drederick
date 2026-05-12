using System.Text.Json;
using Drederick.Audit;
using Drederick.Enrichment;
using Xunit;

namespace Drederick.Tests.Enrichment;

/// <summary>
/// GAP-053 — tests for <see cref="PocOfflineBundle"/>. Verifies bundle
/// lookup semantics and the <c>poc.fetch.offline_hit</c> audit event
/// shape. The bundle resolver is operator-supplied for airgapped /
/// CTF-VPN runs where outbound HTTPS to github.com is blocked.
/// </summary>
public sealed class PocOfflineBundleTests
{
    private static (string work, AuditLog audit) NewAudit(string suffix)
    {
        var work = Path.Combine(Path.GetTempPath(), $"drederick-pocbundle-{suffix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(work);
        return (work, new AuditLog(Path.Combine(work, "audit.jsonl")));
    }

    private static IReadOnlyList<JsonElement> ReadEvents(string work, string evt)
    {
        var path = Path.Combine(work, "audit.jsonl");
        if (!File.Exists(path)) return Array.Empty<JsonElement>();
        var list = new List<JsonElement>();
        foreach (var line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.GetProperty("event").GetString() == evt) list.Add(doc.RootElement.Clone());
        }
        return list;
    }

    [Fact]
    public void TryResolve_returns_hit_when_bundle_dir_exists_with_content()
    {
        var (work, audit) = NewAudit("hit");
        try
        {
            var bundleRoot = Path.Combine(work, "bundle");
            var cveDir = Path.Combine(bundleRoot, "metasploit-git", "CVE-2024-1");
            Directory.CreateDirectory(cveDir);
            File.WriteAllText(Path.Combine(cveDir, "exploit.rb"), "# fake metasploit module");
            File.WriteAllText(Path.Combine(cveDir, "README.md"), "doc");

            var bundle = new PocOfflineBundle(bundleRoot);
            var hit = bundle.TryResolve("metasploit-git", "CVE-2024-1", audit);

            Assert.NotNull(hit);
            Assert.Equal(cveDir, hit!.BundleDir);
            Assert.Equal(2, hit.RelativePaths.Count);
            Assert.True(hit.ByteSize > 0);
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    [Fact]
    public void TryResolve_returns_null_when_cve_dir_missing()
    {
        var (work, audit) = NewAudit("miss");
        try
        {
            var bundleRoot = Path.Combine(work, "bundle");
            Directory.CreateDirectory(Path.Combine(bundleRoot, "metasploit-git"));

            var bundle = new PocOfflineBundle(bundleRoot);
            var hit = bundle.TryResolve("metasploit-git", "CVE-2099-9999", audit);

            Assert.Null(hit);
            audit.Dispose();
            Assert.Empty(ReadEvents(work, "poc.fetch.offline_hit"));
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    [Fact]
    public void TryResolve_returns_null_when_cve_dir_exists_but_empty()
    {
        var (work, audit) = NewAudit("empty");
        try
        {
            var bundleRoot = Path.Combine(work, "bundle");
            Directory.CreateDirectory(Path.Combine(bundleRoot, "nuclei-git", "CVE-2024-2"));

            var bundle = new PocOfflineBundle(bundleRoot);
            Assert.Null(bundle.TryResolve("nuclei-git", "CVE-2024-2", audit));
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    [Fact]
    public void TryResolve_emits_poc_fetch_offline_hit_event()
    {
        var (work, audit) = NewAudit("audit");
        try
        {
            var bundleRoot = Path.Combine(work, "bundle");
            var cveDir = Path.Combine(bundleRoot, "poc-in-github", "CVE-2024-3");
            Directory.CreateDirectory(cveDir);
            File.WriteAllText(Path.Combine(cveDir, "poc.py"), "print('staged poc')");

            var bundle = new PocOfflineBundle(bundleRoot);
            var hit = bundle.TryResolve("poc-in-github", "CVE-2024-3", audit);
            Assert.NotNull(hit);
            audit.Dispose();

            var e = Assert.Single(ReadEvents(work, "poc.fetch.offline_hit"));
            Assert.Equal("poc-in-github", e.GetProperty("source").GetString());
            Assert.Equal("CVE-2024-3", e.GetProperty("cve_id").GetString());
            Assert.Equal(bundleRoot, e.GetProperty("bundle_root").GetString());
            Assert.Equal(1, e.GetProperty("file_count").GetInt32());
            Assert.True(e.GetProperty("byte_size").GetInt64() > 0);
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    [Fact]
    public void TryFindContent_normalises_unsafe_cve_chars_via_safe_id()
    {
        var (work, audit) = NewAudit("safeid");
        try
        {
            var bundleRoot = Path.Combine(work, "bundle");
            // SafeId('CVE-2024-5') is unchanged; verify lookup works.
            var cveDir = Path.Combine(bundleRoot, "metasploit-git", "CVE-2024-5");
            Directory.CreateDirectory(cveDir);
            File.WriteAllText(Path.Combine(cveDir, "m.rb"), "x");

            var bundle = new PocOfflineBundle(bundleRoot);
            Assert.NotNull(bundle.TryFindContent("metasploit-git", "CVE-2024-5"));
            // A different CVE shape with no staged dir misses.
            Assert.Null(bundle.TryFindContent("metasploit-git", "CVE-2099-9999"));
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    [Fact]
    public void TryResolve_preserves_nested_relative_paths()
    {
        var (work, audit) = NewAudit("nested");
        try
        {
            var bundleRoot = Path.Combine(work, "bundle");
            var cveDir = Path.Combine(bundleRoot, "nuclei-git", "CVE-2024-6");
            Directory.CreateDirectory(Path.Combine(cveDir, "http", "cves", "2024"));
            File.WriteAllText(Path.Combine(cveDir, "http", "cves", "2024", "cve-2024-6.yaml"), "id: cve-2024-6");

            var bundle = new PocOfflineBundle(bundleRoot);
            var hit = bundle.TryResolve("nuclei-git", "CVE-2024-6", audit);
            Assert.NotNull(hit);
            Assert.Contains("http/cves/2024/cve-2024-6.yaml", hit!.RelativePaths);
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    [Fact]
    public void Constructor_rejects_blank_bundle_root()
    {
        Assert.Throws<ArgumentException>(() => new PocOfflineBundle(""));
        Assert.Throws<ArgumentException>(() => new PocOfflineBundle("   "));
    }

    [Fact]
    public void TryResolve_returns_null_when_only_other_source_dir_staged()
    {
        var (work, audit) = NewAudit("othersrc");
        try
        {
            var bundleRoot = Path.Combine(work, "bundle");
            // Stage metasploit-git but ask for nuclei-git → miss.
            var cveDir = Path.Combine(bundleRoot, "metasploit-git", "CVE-2024-1");
            Directory.CreateDirectory(cveDir);
            File.WriteAllText(Path.Combine(cveDir, "m.rb"), "x");

            var bundle = new PocOfflineBundle(bundleRoot);
            Assert.Null(bundle.TryResolve("nuclei-git", "CVE-2024-1", audit));
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }
}
