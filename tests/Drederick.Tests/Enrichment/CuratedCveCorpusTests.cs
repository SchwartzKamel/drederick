using System.Text.Json;
using Drederick.Audit;
using Drederick.Enrichment;
using Drederick.Recon;
using Drederick.Reporting;
using Drederick.Scope;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Enrichment;

/// <summary>
/// htb-cms-cve-pack: tests for the curated CVE corpus + its integration
/// with <see cref="CveAnnotator"/>. Closes GAP-052: a Pterodactyl Panel
/// 1.11.10 CMS fingerprint must yield ≥3 real CVE rows (not zero, not
/// the 36 false positives previously emitted by NVD CPE-string spray).
/// </summary>
public class CuratedCveCorpusTests : IDisposable
{
    private readonly string _workDir;

    public CuratedCveCorpusTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-curated-cve-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private string NewOutDir()
    {
        var d = Path.Combine(_workDir, "out-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    [Fact]
    public void EmbeddedCorpus_Loads_PterodactylSeedPresent()
    {
        var corpus = CuratedCveCorpus.LoadEmbedded();
        Assert.True(corpus.Count >= 4,
            $"expected ≥4 embedded entries (Pterodactyl seed); got {corpus.Count}");

        var matches = corpus.Match(vendor: "pterodactyl", product: "panel", version: "1.11.10");
        Assert.True(matches.Count >= 3,
            $"expected ≥3 Pterodactyl 1.11.10 matches; got {matches.Count}");

        Assert.Contains(matches, m => m.CveId == "CVE-2024-43791");
        Assert.Contains(matches, m => m.CveId == "CVE-2025-49132");
    }

    [Fact]
    public void Match_VersionAboveRange_NoHits()
    {
        var corpus = CuratedCveCorpus.LoadEmbedded();
        // 9.9.9 is well above the curated <=1.11.10 range — must not match.
        var matches = corpus.Match(vendor: "pterodactyl", product: "panel", version: "9.9.9");
        Assert.Empty(matches);
    }

    [Fact]
    public void Match_ProductMismatch_NoHits()
    {
        var corpus = CuratedCveCorpus.LoadEmbedded();
        var matches = corpus.Match(vendor: "pterodactyl", product: "wings", version: "1.0.0");
        Assert.Empty(matches);
    }

    [Fact]
    public void MatchCpe_RoundTrip_DriversMatching()
    {
        var corpus = CuratedCveCorpus.LoadEmbedded();
        var hits = corpus.MatchCpe("cpe:2.3:a:pterodactyl:panel:1.11.10:*:*:*:*:*:*:*");
        Assert.True(hits.Count >= 3);
    }

    [Fact]
    public void LoadFromDirectory_BadFile_RecordsErrorButLoadsRest()
    {
        var dir = Path.Combine(_workDir, "corpus");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "good.json"),
            """
            {
              "entries": [
                {
                  "cpe_pattern": "cpe:2.3:a:acme:widget:*",
                  "version_range": "<=2.0.0",
                  "cve_id": "CVE-2099-0001",
                  "severity": "high",
                  "summary": "demo"
                }
              ]
            }
            """);
        File.WriteAllText(Path.Combine(dir, "bad.json"), "{ this is not json");

        var corpus = CuratedCveCorpus.LoadFromDirectory(dir, out var errors);

        Assert.Equal(1, corpus.Count);
        Assert.NotEmpty(errors);
        Assert.Contains(errors, e => e.Contains("bad.json"));
        Assert.Contains(corpus.Match("acme", "widget", "1.0.0"), m => m.CveId == "CVE-2099-0001");
    }

    [Fact]
    public void VersionRange_BoundedAndOpen_BothWork()
    {
        var entries = new List<CuratedCveEntry>
        {
            new()
            {
                CpePattern = "cpe:2.3:a:acme:widget:*",
                VersionRange = ">=1.0.0,<2.0.0",
                CveId = "CVE-2099-0010",
            },
        };
        var corpus = new CuratedCveCorpus(entries);

        Assert.NotEmpty(corpus.Match("acme", "widget", "1.5.0"));
        Assert.Empty(corpus.Match("acme", "widget", "0.9.9"));
        Assert.Empty(corpus.Match("acme", "widget", "2.0.0"));
        // Wildcard version_range "*" matches anything (including null version).
        var wild = new CuratedCveCorpus(new List<CuratedCveEntry>
        {
            new() { CpePattern = "cpe:2.3:a:acme:widget:*", VersionRange = "*", CveId = "CVE-2099-0011" },
        });
        Assert.NotEmpty(wild.Match("acme", "widget", null));
    }

    [Fact]
    public void ParseCpe_HandlesShortAndMalformed()
    {
        var (v, p, ver) = CuratedCveCorpus.ParseCpe("cpe:2.3:a:pterodactyl:panel:1.11.10");
        Assert.Equal("pterodactyl", v);
        Assert.Equal("panel", p);
        Assert.Equal("1.11.10", ver);

        var (_, _, _) = CuratedCveCorpus.ParseCpe("");
        var (vEmpty, pEmpty, _) = CuratedCveCorpus.ParseCpe("not-a-cpe");
        Assert.Equal("", vEmpty);
        Assert.Equal("", pEmpty);
    }

    /// <summary>
    /// GAP-052 acceptance: feed a Pterodactyl Panel 1.11.10 CMS
    /// fingerprint into the full CveAnnotator pipeline and assert
    /// that ≥3 CVE rows land with <c>enrichment_source = "curated"</c>.
    /// </summary>
    [Fact]
    public async Task Annotate_PterodactylCmsFingerprint_YieldsCuratedCves()
    {
        var outDir = NewOutDir();
        var host = new HostFinding
        {
            Target = "10.129.31.77",
            CmsFingerprint = new List<CmsFinding>
            {
                new()
                {
                    Target = "10.129.31.77",
                    BaseUrl = "http://10.129.31.77:80",
                    Matches = new[]
                    {
                        new CmsMatch(
                            Name: "PterodactylPanel",
                            Version: "1.11.10",
                            Confidence: 3,
                            SignalsMatched: new[] { "cookie:pterodactyl_session", "html:<title>Pterodactyl</title>", "path:/assets/manifest.json=200" },
                            Cpe: "cpe:2.3:a:pterodactyl:panel:1.11.10:*:*:*:*:*:*:*"),
                    },
                },
            },
            Nmap = new NmapResult
            {
                OpenPorts = new List<NmapPort>
                {
                    new() { Port = 80, Protocol = "tcp", Service = "http" },
                },
            },
        };
        var findings = new List<HostFinding> { host };
        new SqliteReport(outDir).WriteReport(findings);

        // Use a NvdCache that can't load — confirms curated runs even
        // when NVD is offline (the GAP-052 scenario).
        var emptyCacheDir = Path.Combine(_workDir, "empty-nvd-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(emptyCacheDir);
        var nvdCache = new NvdCache(emptyCacheDir, new ThrowingFetcher(), TimeSpan.FromDays(365));
        var annotator = new CveAnnotator(nvdCache);

        Assert.True(annotator.CuratedEntryCount >= 4);

        var result = await annotator.AnnotateAsync(findings, outDir);

        Assert.True(result.CveCount >= 3,
            $"expected ≥3 curated CVE matches for Pterodactyl 1.11.10; got {result.CveCount}");
        Assert.True(result.FindingCount >= 3);

        var payloads = LoadCveFindingPayloads(outDir);
        Assert.Contains(payloads, p => p.Contains("CVE-2024-43791"));
        Assert.Contains(payloads, p => p.Contains("CVE-2025-49132"));
        Assert.Contains(payloads, p => p.Contains("\"enrichment_source\":\"curated\""));
    }

    [Fact]
    public async Task Annotate_OutOfScope_AnnotatorIgnoresUnknownHost()
    {
        // Negative path: HostFinding with no matching DB row → no findings.
        // Confirms the annotator does not bypass the host-id lookup just
        // because the CMS fingerprint has a CPE.
        var outDir = NewOutDir();
        // Note: never writing the host to SqliteReport, so LookupHostId returns null.
        var host = new HostFinding
        {
            Target = "10.0.0.99",
            CmsFingerprint = new List<CmsFinding>
            {
                new()
                {
                    Target = "10.0.0.99",
                    BaseUrl = "http://10.0.0.99/",
                    Matches = new[]
                    {
                        new CmsMatch("PterodactylPanel", "1.11.10", 3, Array.Empty<string>(),
                            "cpe:2.3:a:pterodactyl:panel:1.11.10:*:*:*:*:*:*:*"),
                    },
                },
            },
        };
        // Ensure DB exists with schema but no host row.
        new SqliteReport(outDir).WriteReport(Array.Empty<HostFinding>());

        var emptyCacheDir = Path.Combine(_workDir, "empty-nvd-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(emptyCacheDir);
        var nvdCache = new NvdCache(emptyCacheDir, new ThrowingFetcher(), TimeSpan.FromDays(365));
        var annotator = new CveAnnotator(nvdCache);

        var result = await annotator.AnnotateAsync(new[] { host }, outDir);

        Assert.Equal(0, result.FindingCount);
    }

    [Fact]
    public void CmsFingerprintTool_ScopeIsRequired_BeforeAnyNetwork()
    {
        // Sanity guardrail for the curated-corpus path: CMS fingerprint
        // is the upstream signal; if it ever stopped enforcing scope,
        // curated CVEs would still resolve against arbitrary IPs. This
        // test keeps the CMS tool wired to the @invariant-id:scope-in-every-tool
        // guarantee.
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = new AuditLog(Path.Combine(_workDir, "audit-" + Guid.NewGuid().ToString("N") + ".jsonl"));
        var tool = new CmsFingerprintTool(scope, audit);

        Assert.ThrowsAsync<ScopeException>(() => tool.FingerprintAsync("8.8.8.8", 80));
    }

    private static List<string> LoadCveFindingPayloads(string outDir)
    {
        var dbPath = Path.Combine(outDir, "findings.db");
        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT data_json FROM findings WHERE kind = 'cve';";
        using var rdr = cmd.ExecuteReader();
        var rows = new List<string>();
        while (rdr.Read()) rows.Add(rdr.GetString(0));
        return rows;
    }

    private sealed class ThrowingFetcher : IHttpFetcher
    {
        public Task<byte[]?> FetchAsync(string url, CancellationToken ct)
            => throw new InvalidOperationException("offline");
    }
}
