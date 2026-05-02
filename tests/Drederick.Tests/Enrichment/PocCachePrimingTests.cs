using System.Security.Cryptography;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Enrichment;
using Drederick.Exploit;
using Drederick.Recon;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Enrichment;

/// <summary>
/// GAP-031b — verifies the PoC cache priming pipeline:
///   recon → CveAnnotator → PocAggregator (msf + nuclei sources cache to
///   poc_cache/) → ExploitationPlanner emits band-490 msfrc / band-500 nuclei
///   instead of band-250 cve-lead.
/// Covers the missing link the JobTwo R5 fight exposed: cache was empty.
/// </summary>
public class PocCachePrimingTests : IDisposable
{
    private readonly string _workDir;

    public PocCachePrimingTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-pocprime-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private string AuditPath() => Path.Combine(_workDir, "audit.jsonl");

    private PocQueryContext Ctx(bool fetchPoc, AuditLog? audit = null)
        => new(Path.Combine(_workDir, "poc_cache"), fetchPoc, new SqliteReport(_workDir), audit);

    // -------- MetasploitSource: filesystem probe primes cache -----------

    [Fact]
    public async Task Metasploit_Filesystem_Probe_Caches_Module_With_Cve_Reference()
    {
        // Build a fake msf modules tree.
        var modulesRoot = Path.Combine(_workDir, "msf-tree", "modules");
        var moduleDir = Path.Combine(modulesRoot, "exploits", "windows", "http");
        Directory.CreateDirectory(moduleDir);
        var modulePath = Path.Combine(moduleDir, "veeam_backup_response.rb");
        File.WriteAllText(modulePath, "## Veeam stub\n# References include CVE-2024-29849\n");

        var runner = new RecordingProcessRunner();
        // grep over the modules root must succeed and return our file.
        runner.OnRun((f, a) => f == "grep" && a.Contains("CVE-2024-29849"), 0, stdout: modulePath + "\n");
        // msfconsole CLI absent — return Win32 not-found (the dual-path
        // contract: FS probe alone is enough).
        runner.OnRunThrow((f, _) => f == "msfconsole", new System.ComponentModel.Win32Exception(2, "not found"));

        using var audit = new AuditLog(AuditPath());
        var src = new MetasploitSource(runner, modulesDirProbe: () => modulesRoot);
        var refs = await src.QueryAsync("CVE-2024-29849", Ctx(fetchPoc: true, audit), CancellationToken.None);

        var poc = Assert.Single(refs);
        Assert.Equal("metasploit", poc.Source);
        Assert.Equal("exploit/windows/http/veeam_backup_response", poc.ExternalId);
        Assert.NotNull(poc.LocalPath);
        Assert.True(File.Exists(poc.LocalPath));

        // Cached file lives under out/poc_cache/metasploit/<safe-id>/
        var expectedDir = Path.Combine(_workDir, "poc_cache", "metasploit",
            "exploit_windows_http_veeam_backup_response");
        Assert.True(Directory.Exists(expectedDir));

        // SHA-256 on cached bytes matches source bytes.
        var cachedSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(poc.LocalPath!))).ToLowerInvariant();
        var sourceSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(modulePath))).ToLowerInvariant();
        Assert.Equal(sourceSha, cachedSha);

        // poc_sources row exists with matching sha256.
        using var conn = new SqliteConnection($"Data Source={Path.Combine(_workDir, "findings.db")}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sha256 FROM poc_sources WHERE source='metasploit' AND external_id=$id;";
        cmd.Parameters.AddWithValue("$id", "exploit/windows/http/veeam_backup_response");
        Assert.Equal(sourceSha, (string)cmd.ExecuteScalar()!);

        // poc.fetch event emitted.
        audit.Dispose();
        var auditLines = File.ReadAllLines(AuditPath());
        Assert.Contains(auditLines, l => l.Contains("\"event\":\"poc.fetch\"")
                                       && l.Contains("\"source\":\"metasploit\"")
                                       && l.Contains(sourceSha));
    }

    [Fact]
    public async Task Metasploit_FetchPoc_False_Does_Not_Touch_Cache()
    {
        var modulesRoot = Path.Combine(_workDir, "msf-tree", "modules");
        var moduleDir = Path.Combine(modulesRoot, "exploits", "linux", "ftp");
        Directory.CreateDirectory(moduleDir);
        var modulePath = Path.Combine(moduleDir, "vsftpd_234_backdoor.rb");
        File.WriteAllText(modulePath, "# CVE-2011-2523\n");

        var runner = new RecordingProcessRunner();
        runner.OnRunThrow((f, _) => f == "msfconsole", new System.ComponentModel.Win32Exception(2, "not found"));
        // grep should NOT be invoked when FetchPoc is false.

        var src = new MetasploitSource(runner, modulesDirProbe: () => modulesRoot);
        var refs = await src.QueryAsync("CVE-2011-2523", Ctx(fetchPoc: false), CancellationToken.None);

        Assert.Empty(refs);
        Assert.DoesNotContain(runner.Calls, c => c.FileOrCmd == "grep");
        Assert.False(Directory.Exists(Path.Combine(_workDir, "poc_cache", "metasploit")));
    }

    [Fact]
    public async Task Metasploit_Rejects_Non_Cve_Shape()
    {
        var runner = new RecordingProcessRunner();
        var src = new MetasploitSource(runner);
        var refs = await src.QueryAsync("../../etc/passwd", Ctx(fetchPoc: true), CancellationToken.None);
        Assert.Empty(refs);
        // No subprocess invoked at all — argv is rejected before exec.
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public void Metasploit_ToModuleId_Maps_Path_To_Canonical_Form()
    {
        var root = Path.Combine("/tmp", "msf", "modules");
        var path = Path.Combine(root, "exploits", "windows", "http", "foo.rb");
        Assert.Equal("exploit/windows/http/foo", MetasploitSource.ToModuleId(root, path));

        var aux = Path.Combine(root, "auxiliary", "scanner", "ftp", "ftp_version.rb");
        Assert.Equal("auxiliary/scanner/ftp/ftp_version", MetasploitSource.ToModuleId(root, aux));
    }

    // -------- NucleiSource: caching path -------------------------------

    [Fact]
    public async Task Nuclei_FetchPoc_True_Copies_Template_Into_PocCache_And_Audits()
    {
        var templates = Path.Combine(_workDir, "nuclei-templates");
        var src = Path.Combine(templates, "cves", "2024", "CVE-2024-29849-veeam.yaml");
        Directory.CreateDirectory(Path.GetDirectoryName(src)!);
        File.WriteAllText(src, "id: CVE-2024-29849\n");

        var runner = new RecordingProcessRunner();
        runner.OnRun((f, a) => f == "grep" && a.Contains("CVE-2024-29849"), 0, stdout: src + "\n");

        using var audit = new AuditLog(AuditPath());
        var nuc = new NucleiSource(runner, templatesDirProbe: () => templates);
        var refs = await nuc.QueryAsync("CVE-2024-29849", Ctx(fetchPoc: true, audit), CancellationToken.None);

        var r = Assert.Single(refs);
        Assert.NotNull(r.LocalPath);
        // LocalPath now points to the cached copy under out/poc_cache/nuclei/...
        Assert.StartsWith(Path.Combine(_workDir, "poc_cache", "nuclei"), r.LocalPath!);
        Assert.True(File.Exists(r.LocalPath));

        audit.Dispose();
        var auditLines = File.ReadAllLines(AuditPath());
        Assert.Contains(auditLines, l => l.Contains("\"event\":\"poc.fetch\"")
                                       && l.Contains("\"source\":\"nuclei\""));
    }

    [Fact]
    public async Task Nuclei_FetchPoc_False_Records_Original_Path_And_Does_Not_Cache()
    {
        // Preserves backward-compatible behaviour for --no-fetch-poc.
        var templates = Path.Combine(_workDir, "nuclei-templates");
        var src = Path.Combine(templates, "cves", "2024", "CVE-2024-29849.yaml");
        Directory.CreateDirectory(Path.GetDirectoryName(src)!);
        File.WriteAllText(src, "id: CVE-2024-29849\n");

        var runner = new RecordingProcessRunner();
        runner.OnRun((f, a) => f == "grep", 0, stdout: src + "\n");

        var nuc = new NucleiSource(runner, templatesDirProbe: () => templates);
        var refs = await nuc.QueryAsync("CVE-2024-29849", Ctx(fetchPoc: false), CancellationToken.None);

        var r = Assert.Single(refs);
        Assert.Equal(src, r.LocalPath);
        Assert.False(Directory.Exists(Path.Combine(_workDir, "poc_cache", "nuclei")));
    }

    [Fact]
    public async Task Nuclei_Rejects_Non_Cve_Shape()
    {
        var runner = new RecordingProcessRunner();
        var nuc = new NucleiSource(runner, templatesDirProbe: () => _workDir);
        var refs = await nuc.QueryAsync("$(rm -rf /)", Ctx(fetchPoc: true), CancellationToken.None);
        Assert.Empty(refs);
        Assert.Empty(runner.Calls);
    }

    // -------- GAP-031b integration: planner reads primed cache --------

    [Fact]
    public void Planner_Emits_Msfrc_When_Cache_Has_Module_And_Falls_Back_To_CveLead_When_Empty()
    {
        var outDir = _workDir;
        using var audit = new AuditLog(AuditPath());

        // Seed poc_refs with a metasploit hit for the CVE.
        var report = new SqliteReport(outDir);
        report.UpsertCve("CVE-2024-29849");
        var moduleId = "exploit/windows/http/veeam_backup_response";
        report.UpsertPocRef(
            cveId: "CVE-2024-29849",
            source: MetasploitSource.SourceName,
            url: null,
            externalId: moduleId,
            localPath: Path.Combine(outDir, "poc_cache", "metasploit",
                "exploit_windows_http_veeam_backup_response", "veeam_backup_response.rb"),
            fetchedAt: DateTimeOffset.UtcNow.ToString("o"));

        var creds = new CredentialStore(audit);
        var host = new HostFinding
        {
            Target = "10.129.238.35",
            Nmap = new NmapResult
            {
                OpenPorts =
                {
                    new NmapPort
                    {
                        Port = 9419,
                        Service = "http",
                        Scripts =
                        {
                            new NmapScript { Id = "vulners", Output = "CVE-2024-29849 9.8" },
                        },
                    },
                },
            },
        };

        // With cache populated → band-490 msfrc.
        var planner = new ExploitationPlanner(audit, outDir);
        var plan = planner.Plan(new[] { host }, creds, new RunPermissions());

        var msfrc = Assert.Single(plan, a => a.Tool == "msfrc" && a.CveId == "CVE-2024-29849");
        Assert.Equal(490, msfrc.Priority);
        Assert.Equal(moduleId, msfrc.Module);
        Assert.Equal(9419, msfrc.Port);
        // The cve-lead lead is suppressed for this CVE — the artifact covers it.
        Assert.DoesNotContain(plan, a => a.Tool == "cve-lead" && a.CveId == "CVE-2024-29849");

        // Now wipe the poc_refs row → planner falls back to band-250 cve-lead.
        using (var conn = new SqliteConnection($"Data Source={Path.Combine(outDir, "findings.db")}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM poc_refs;";
            cmd.ExecuteNonQuery();
        }
        SqliteConnection.ClearAllPools();

        var plan2 = planner.Plan(new[] { host }, creds, new RunPermissions());
        var lead = Assert.Single(plan2, a => a.Tool == "cve-lead" && a.CveId == "CVE-2024-29849");
        Assert.Equal(250, lead.Priority);
        Assert.DoesNotContain(plan2, a => a.Tool == "msfrc" && a.CveId == "CVE-2024-29849");
    }

    // -------- PocAggregator wiring: end-to-end through SQLite ----------

    [Fact]
    public async Task PocAggregator_With_Audit_And_Stub_Source_Writes_Cache_And_Audit()
    {
        // Mocked CVE-matched finding lives in the cves table.
        var report = new SqliteReport(_workDir);
        report.UpsertCve("CVE-2011-2523");

        // Stub source returns one ref with a cached file.
        var cacheRoot = Path.Combine(_workDir, "poc_cache");
        var stubDir = Path.Combine(cacheRoot, "stub", "1");
        Directory.CreateDirectory(stubDir);
        var local = Path.Combine(stubDir, "x.rb");
        File.WriteAllText(local, "# verbatim\n");

        var stub = new StubSource("stub", new[]
        {
            new PocRef("stub", Url: "https://example/stub/1", ExternalId: "1", LocalPath: local),
        });

        using var audit = new AuditLog(AuditPath());
        var agg = new PocAggregator(new IPocSource[] { stub }, audit);
        var result = await agg.AggregateAsync(null, _workDir, fetchPoc: true);

        Assert.Equal(1, result.RefCount);
        Assert.Equal(1, result.CachedCount);

        // poc_refs row exists pointing at our local file.
        using var conn = new SqliteConnection($"Data Source={Path.Combine(_workDir, "findings.db")}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT local_path FROM poc_refs WHERE source='stub';";
        Assert.Equal(local, (string)cmd.ExecuteScalar()!);

        // The aggregator's audit field is non-null and was forwarded to ctx
        // for sources to record poc.fetch on caching. (Stub doesn't audit;
        // that's the source's responsibility — covered above.)
        Assert.True(File.Exists(AuditPath()));
    }

    private sealed class StubSource : IPocSource
    {
        private readonly IReadOnlyList<PocRef> _refs;
        public StubSource(string name, IEnumerable<PocRef> refs)
        {
            Name = name;
            _refs = refs.ToArray();
        }
        public string Name { get; }
        public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
            => Task.FromResult(_refs);
    }
}
