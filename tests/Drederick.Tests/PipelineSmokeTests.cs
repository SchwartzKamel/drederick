using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Drederick.Agent;
using Drederick.Audit;
using Drederick.Enrichment;
using Drederick.Memory;
using Drederick.Recon;
using Drederick.Reporting;
using Drederick.Scope;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

/// <summary>
/// End-to-end smoke coverage of the full in-process pipeline. Avoids running
/// nmap or touching the network by seeding deterministic fixture data at the
/// seams:
///   * HostFinding list is seeded directly (the AdaptiveRunner/ReconToolbox
///     seam — nmap/NmapTool is bypassed, NmapResult is constructed inline).
///   * IHttpFetcher is never called; CveAnnotator's NvdCache is pre-populated
///     by copying the tests/fixtures/nvd-mini.json.gz fixture into a fresh
///     cache dir.
///   * IPocSource is replaced by a fake that returns canned refs and writes a
///     canned byte blob into out/poc_cache, registering its SHA-256 via
///     SqliteReport.UpsertPocSource (matching the production PoC cache
///     contract).
///
/// AdaptiveRunner is exercised once with an empty target list to emit its
/// runner.start/runner.finish audit events. Downstream stages (JsonReport →
/// MarkdownReport → ManualCommandsCheatsheet → SqliteReport → CveAnnotator →
/// PocAggregator → KnowledgeBase.Merge) are then driven with the seeded
/// findings, mirroring the Program.cs sequence including audit-event
/// bookkeeping.
/// </summary>
public class PipelineSmokeTests : IDisposable
{
    private readonly string _workDir;

    public PipelineSmokeTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-pipeline-smoke-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private static string FindFixturePath(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "fixtures", name);
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException($"fixture not found: {name}");
    }

    private sealed class StubFetcher : IHttpFetcher
    {
        public int Calls;
        public Task<byte[]?> FetchAsync(string url, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult<byte[]?>(null);
        }
    }

    /// <summary>
    /// Fake PoC source that returns one canned ref per CVE. When FetchPoc is
    /// true, writes canned bytes under ctx.CacheRoot and records the
    /// SHA-256/path via ctx.Report.UpsertPocSource — exactly as the real
    /// Exploit-DB mirror source would.
    /// </summary>
    private sealed class FakePocSource : IPocSource
    {
        public string Name { get; }
        private readonly string _externalId;
        private readonly string _url;
        private readonly byte[] _bytes;

        public FakePocSource(string name, string externalId, string url, byte[] bytes)
        {
            Name = name;
            _externalId = externalId;
            _url = url;
            _bytes = bytes;
        }

        public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
        {
            string? localPath = null;
            if (ctx.FetchPoc)
            {
                var dir = Path.Combine(ctx.CacheRoot, Name, _externalId);
                Directory.CreateDirectory(dir);
                localPath = Path.Combine(dir, $"{_externalId}.bin");
                File.WriteAllBytes(localPath, _bytes);
                var sha = Convert.ToHexString(SHA256.HashData(_bytes)).ToLowerInvariant();
                ctx.Report.UpsertPocSource(Name, _externalId, sha, localPath, sourceUrl: _url);
            }
            IReadOnlyList<PocRef> refs = new[]
            {
                new PocRef(Name, Url: _url, ExternalId: _externalId, LocalPath: localPath),
            };
            return Task.FromResult(refs);
        }
    }

    [Fact]
    public async Task Full_pipeline_smoke_writes_reports_db_memory_and_audit()
    {
        var outDir = Path.Combine(_workDir, "out");
        Directory.CreateDirectory(outDir);
        var auditPath = Path.Combine(outDir, "audit.jsonl");
        var memoryPath = Path.Combine(outDir, "memory", "knowledge.json");
        const string target = "127.0.0.42";

        // Scope covering the loopback target.
        var scope = ScopeLoader.Parse($"{target}/32", source: "<smoke>", allowBroad: false, labMode: true);
        Assert.True(scope.Contains(target));

        // 1) AdaptiveRunner with an empty target list — exercises runner.start
        //    + runner.finish without needing nmap. The real toolbox is
        //    constructed but never invoked because targets is empty.
        var kb = KnowledgeBase.Load(memoryPath);
        using (var audit = new AuditLog(auditPath))
        {
            audit.Record("session.start", new Dictionary<string, object?>
            {
                ["scope_source"] = scope.Source,
                ["target_count"] = 0,
                ["runner"] = "adaptive",
                ["lab_mode"] = true,
            });

            var toolbox = new ReconToolbox(
                new IReconTool[]
                {
                    new NmapTool(scope, audit, nmapPath: "/drederick-smoke-test-nonexistent-nmap", labMode: true),
                    new HttpProbeTool(scope, audit),
                    new TlsProbeTool(scope, audit),
                    new DnsProbeTool(scope, audit),
                },
                audit);

            var runner = new AdaptiveRunner(audit, hostConcurrency: 1, serviceConcurrency: 1);
            await runner.RunAsync(Array.Empty<string>(), toolbox, kb, CancellationToken.None);

            // 2) Seed fixture HostFinding objects (bypassing the NmapTool
            //    subprocess seam). vsftpd 2.3.4 will match CVE-2011-2523 from
            //    tests/fixtures/nvd-mini.json.gz via CpeMatcher.
            var now = DateTimeOffset.UtcNow.ToString("o");
            var finding = new HostFinding
            {
                Target = target,
                Started = now,
                Finished = now,
                Nmap = new NmapResult
                {
                    ReturnCode = 0,
                    OpenPorts = new()
                    {
                        new NmapPort
                        {
                            Port = 21, Protocol = "tcp", Service = "ftp",
                            Product = "vsftpd", Version = "2.3.4",
                        },
                        new NmapPort
                        {
                            Port = 22, Protocol = "tcp", Service = "ssh",
                            Product = "openssh", Version = "7.4",
                        },
                    },
                },
                Http = new()
                {
                    new HttpResult { Url = $"http://{target}:80/", Status = 200, Title = "smoke" },
                },
                Dns = new DnsResult { Target = target, Reverse = "smoke.local" },
            };
            var allFindings = new List<HostFinding> { finding };

            // 3) Reporting stages (match Program.cs ordering).
            JsonReport.Write(Path.Combine(outDir, "report.json"), allFindings, scope.Source);
            MarkdownReport.Write(Path.Combine(outDir, "report.md"), allFindings, scope.Source);
            ManualCommandsCheatsheet.Write(outDir, allFindings, emitCheatsheet: true);
            new SqliteReport(outDir).WriteReport(allFindings);

            // 4) CVE annotation — use a pre-populated NvdCache pointing at the
            //    fixture, so the stub HTTP fetcher is never called.
            var cacheDir = Path.Combine(_workDir, "nvd-cache");
            Directory.CreateDirectory(cacheDir);
            var nvdFile = Path.Combine(cacheDir, "nvdcve-2.0-2011.json.gz");
            File.Copy(FindFixturePath("nvd-mini.json.gz"), nvdFile);
            // File.Copy preserves the source mtime; refresh the cache file's
            // last-write-time to "now" so NvdCache treats it as fresh and
            // skips the network refresh path.
            File.SetLastWriteTimeUtc(nvdFile, DateTime.UtcNow);
            var fetcher = new StubFetcher();
            var nvdCache = new NvdCache(cacheDir: cacheDir, fetcher: fetcher);
            var annotator = new CveAnnotator(nvdCache);
            var annotation = await annotator.AnnotateAsync(allFindings, outDir, CancellationToken.None);
            Assert.True(annotation.CacheLoaded);
            Assert.True(annotation.CveCount >= 1);
            Assert.True(annotation.FindingCount >= 1);
            Assert.Equal(0, fetcher.Calls); // fresh cache: no network
            audit.Record("cve.annotate", new Dictionary<string, object?>
            {
                ["cves"] = annotation.CveCount,
                ["findings"] = annotation.FindingCount,
                ["cache_loaded"] = annotation.CacheLoaded,
            });

            // 5) PoC aggregation — fake sources return canned refs; one of
            //    them also writes a canned blob and registers its SHA-256.
            var canned = Encoding.UTF8.GetBytes("# Fake PoC payload for pipeline smoke\n");
            var expectedSha = Convert.ToHexString(SHA256.HashData(canned)).ToLowerInvariant();
            var pocSources = new IPocSource[]
            {
                new FakePocSource("exploit-db", externalId: "EDB-777", url: "https://example/edb/777", bytes: canned),
                new FakePocSource("ghsa", externalId: "GHSA-xxxx", url: "https://example/ghsa/xxxx", bytes: canned),
            };
            var pocAgg = new PocAggregator(pocSources);
            var pocResult = await pocAgg.AggregateAsync(allFindings, outDir, fetchPoc: true, CancellationToken.None);
            Assert.Equal(annotation.CveCount, pocResult.CveCount);
            Assert.True(pocResult.RefCount >= 2);
            Assert.True(pocResult.CachedCount >= 2);
            audit.Record("poc.aggregate", new Dictionary<string, object?>
            {
                ["cves"] = pocResult.CveCount,
                ["refs"] = pocResult.RefCount,
                ["cached"] = pocResult.CachedCount,
                ["fetch_poc"] = true,
            });

            // 6) Knowledge base merge/save.
            kb.Merge(allFindings);
            kb.Save(memoryPath);

            audit.Record("session.end", new Dictionary<string, object?>
            {
                ["host_count"] = allFindings.Count,
                ["tool_calls"] = toolbox.ToolCallsTotal,
            });

            // Store for post-block assertions.
            _expectedCveCount = annotation.CveCount;
            _expectedPocShaMap["exploit-db"] = ("EDB-777", expectedSha);
            _expectedPocShaMap["ghsa"] = ("GHSA-xxxx", expectedSha);
        }

        // --- Assertions on produced artefacts --------------------------------

        // report.json parses and contains the host.
        var reportJsonPath = Path.Combine(outDir, "report.json");
        Assert.True(File.Exists(reportJsonPath));
        using (var doc = JsonDocument.Parse(File.ReadAllBytes(reportJsonPath)))
        {
            var hostsEl = doc.RootElement.GetProperty("hosts");
            Assert.Equal(JsonValueKind.Array, hostsEl.ValueKind);
            var hostArr = hostsEl.EnumerateArray().ToList();
            Assert.Single(hostArr);
            Assert.Equal(target, hostArr[0].GetProperty("target").GetString());
        }

        // report.md exists and contains at least one scanner section.
        var reportMdPath = Path.Combine(outDir, "report.md");
        Assert.True(File.Exists(reportMdPath));
        var md = File.ReadAllText(reportMdPath);
        Assert.Contains(target, md);
        Assert.True(
            md.Contains("nmap", StringComparison.OrdinalIgnoreCase) ||
            md.Contains("Open ports", StringComparison.OrdinalIgnoreCase) ||
            md.Contains("HTTP", StringComparison.OrdinalIgnoreCase),
            "report.md should contain at least one scanner section");

        // manual_commands.txt exists per-host and is non-empty.
        var cheatsheetPath = Path.Combine(outDir, target, "manual_commands.txt");
        Assert.True(File.Exists(cheatsheetPath), $"expected {cheatsheetPath}");
        Assert.True(new FileInfo(cheatsheetPath).Length > 0);

        // findings.db contract.
        var dbPath = Path.Combine(outDir, "findings.db");
        Assert.True(File.Exists(dbPath));
        using (var conn = new SqliteConnection($"Data Source={dbPath}"))
        {
            conn.Open();

            Assert.Equal(1L, ScalarLong(conn, "SELECT COUNT(*) FROM hosts WHERE address=$a;",
                ("$a", (object)target)));
            var hostId = ScalarLong(conn, "SELECT id FROM hosts WHERE address=$a;", ("$a", target));

            Assert.Equal(2L, ScalarLong(conn, "SELECT COUNT(*) FROM services WHERE host_id=$h;",
                ("$h", (object)hostId)));
            Assert.Equal(1L, ScalarLong(conn,
                "SELECT COUNT(*) FROM services WHERE host_id=$h AND port=21 AND service='ftp';",
                ("$h", (object)hostId)));
            Assert.Equal(1L, ScalarLong(conn,
                "SELECT COUNT(*) FROM services WHERE host_id=$h AND port=22 AND service='ssh';",
                ("$h", (object)hostId)));

            Assert.True(ScalarLong(conn,
                "SELECT COUNT(*) FROM findings WHERE host_id=$h AND kind='nmap';",
                ("$h", (object)hostId)) >= 2);
            Assert.True(ScalarLong(conn,
                "SELECT COUNT(*) FROM findings WHERE host_id=$h AND kind='cve';",
                ("$h", (object)hostId)) >= 1);

            Assert.True(ScalarLong(conn, "SELECT COUNT(*) FROM cves;") >= 1);
            Assert.Equal(1L, ScalarLong(conn, "SELECT COUNT(*) FROM cves WHERE cve_id=$c;",
                ("$c", (object)"CVE-2011-2523")));

            Assert.True(ScalarLong(conn,
                "SELECT COUNT(*) FROM poc_refs WHERE cve_id='CVE-2011-2523';") >= 2);

            foreach (var kv in _expectedPocShaMap)
            {
                var src = kv.Key;
                var (ext, sha) = kv.Value;
                var observed = ScalarString(conn,
                    "SELECT sha256 FROM poc_sources WHERE source=$s AND external_id=$e;",
                    ("$s", src), ("$e", ext));
                Assert.Equal(sha, observed);
            }
        }

        // audit.jsonl contains the pipeline-stage events the code emits.
        Assert.True(File.Exists(auditPath));
        var auditLines = File.ReadAllLines(auditPath);
        var auditKinds = auditLines
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .Select(l =>
            {
                using var d = JsonDocument.Parse(l);
                return d.RootElement.TryGetProperty("event", out var ev) ? ev.GetString() : null;
            })
            .Where(k => k is not null)
            .Select(k => k!)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var kind in new[]
        {
            "session.start", "runner.start", "runner.finish",
            "cve.annotate", "poc.aggregate", "session.end",
        })
        {
            Assert.Contains(kind, auditKinds);
        }

        // Knowledge base updated with the host.
        Assert.True(File.Exists(memoryPath));
        using (var mdoc = JsonDocument.Parse(File.ReadAllBytes(memoryPath)))
        {
            var hosts = mdoc.RootElement.GetProperty("hosts");
            Assert.Equal(JsonValueKind.Object, hosts.ValueKind);
            Assert.True(hosts.TryGetProperty(target, out var hostObj));
            Assert.Equal(target, hostObj.GetProperty("target").GetString());
            var openPorts = hostObj.GetProperty("nmap").GetProperty("open_ports");
            Assert.Equal(2, openPorts.GetArrayLength());
        }

        Assert.True(_expectedCveCount >= 1);
    }

    // Carried across the using-block boundary so the post-audit assertions
    // can inspect the deterministic fixture expectations.
    private int _expectedCveCount;
    private readonly Dictionary<string, (string externalId, string sha)> _expectedPocShaMap = new();

    private static long ScalarLong(SqliteConnection conn, string sql, params (string name, object value)[] args)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    private static string ScalarString(SqliteConnection conn, string sql, params (string name, object value)[] args)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v);
        var r = cmd.ExecuteScalar();
        return r is null or DBNull ? "" : Convert.ToString(r)!;
    }
}
