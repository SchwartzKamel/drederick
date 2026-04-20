using Drederick.Recon;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

public class SqliteReportTests : IDisposable
{
    private readonly string _dir;

    public SqliteReportTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "drederick-sqlite-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static HostFinding SampleFinding(string target = "10.0.0.1") => new()
    {
        Target = target,
        Started = DateTimeOffset.UtcNow.ToString("o"),
        Finished = DateTimeOffset.UtcNow.ToString("o"),
        Nmap = new NmapResult
        {
            ReturnCode = 0,
            OpenPorts = new()
            {
                new NmapPort
                {
                    Port = 80,
                    Protocol = "tcp",
                    Service = "http",
                    Product = "nginx",
                    Version = "1.24",
                    Scripts = new() { new NmapScript { Id = "http-title", Output = "Welcome" } },
                },
                new NmapPort { Port = 443, Protocol = "tcp", Service = "https" },
            },
        },
        Http = new() { new HttpResult { Url = "http://10.0.0.1/", Status = 200, Title = "Welcome" } },
        Tls = new() { new TlsResult { Port = 443, TlsVersion = "1.3", Subject = "CN=x" } },
        Dns = new DnsResult { Target = target, Forward = "x.example" },
    };

    private static HashSet<string> GetColumns(SqliteConnection conn, string table)
    {
        var cols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info({table});";
        using var r = cmd.ExecuteReader();
        while (r.Read()) cols.Add(r.GetString(1));
        return cols;
    }

    private static long Count(SqliteConnection conn, string table)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT COUNT(*) FROM {table};";
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    [Fact]
    public void WriteReport_CreatesSchema_OnEmptyDb()
    {
        var report = new SqliteReport(_dir);
        report.WriteReport(Array.Empty<HostFinding>());

        Assert.True(File.Exists(Path.Combine(_dir, "findings.db")));

        using var conn = new SqliteConnection($"Data Source={report.DatabasePath}");
        conn.Open();
        var expected = new[] { "hosts", "services", "findings", "cves", "poc_refs", "poc_sources", "tooling" };
        foreach (var t in expected)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name=$n;";
            cmd.Parameters.AddWithValue("$n", t);
            Assert.Equal(t, cmd.ExecuteScalar());
        }
    }

    [Fact]
    public void AllSevenTables_HaveExpectedColumns()
    {
        var report = new SqliteReport(_dir);
        report.WriteReport(Array.Empty<HostFinding>());

        using var conn = new SqliteConnection($"Data Source={report.DatabasePath}");
        conn.Open();

        Assert.Superset(new HashSet<string> { "id", "address", "hostname", "first_seen", "last_seen" },
            GetColumns(conn, "hosts"));
        Assert.Superset(new HashSet<string> { "id", "host_id", "port", "proto", "service", "product", "version" },
            GetColumns(conn, "services"));
        Assert.Superset(new HashSet<string> { "id", "host_id", "service_id", "kind", "data_json", "created_at" },
            GetColumns(conn, "findings"));
        Assert.Superset(new HashSet<string> { "id", "cve_id", "cvss", "summary", "published" },
            GetColumns(conn, "cves"));
        Assert.Superset(new HashSet<string> { "id", "cve_id", "source", "url", "external_id", "local_path", "fetched_at" },
            GetColumns(conn, "poc_refs"));
        Assert.Superset(new HashSet<string> { "id", "source", "external_id", "sha256", "path", "fetched_at", "source_url" },
            GetColumns(conn, "poc_sources"));
        Assert.Superset(new HashSet<string> { "id", "name", "version", "source", "path", "detected_at" },
            GetColumns(conn, "tooling"));
    }

    [Fact]
    public void WriteReport_IsIdempotent()
    {
        var report = new SqliteReport(_dir);
        var findings = new[] { SampleFinding() };

        report.WriteReport(findings);
        report.WriteReport(findings);

        using var conn = new SqliteConnection($"Data Source={report.DatabasePath}");
        conn.Open();
        Assert.Equal(1, Count(conn, "hosts"));
        Assert.Equal(2, Count(conn, "services")); // 80 + 443
        // nmap(2) + nmap-script(1) + http(1) + tls(1) + dns(1) = 6, deduped on 2nd write
        Assert.Equal(6, Count(conn, "findings"));
    }

    [Fact]
    public void ReopeningExistingDb_DoesNotFail()
    {
        var r1 = new SqliteReport(_dir);
        r1.WriteReport(new[] { SampleFinding() });

        var r2 = new SqliteReport(_dir);
        r2.WriteReport(new[] { SampleFinding("10.0.0.2") });

        using var conn = new SqliteConnection($"Data Source={r2.DatabasePath}");
        conn.Open();
        Assert.Equal(2, Count(conn, "hosts"));
    }

    [Fact]
    public void UpsertHelpers_AreIdempotent()
    {
        var report = new SqliteReport(_dir);
        report.UpsertCve("CVE-2024-0001", 9.8, "bad", "2024-01-01");
        report.UpsertCve("CVE-2024-0001", 9.8, "bad", "2024-01-01");
        report.UpsertPocRef("CVE-2024-0001", "exploit-db", url: "https://x/1", externalId: "1");
        report.UpsertPocRef("CVE-2024-0001", "exploit-db", url: "https://x/1", externalId: "1");
        report.UpsertPocSource("exploit-db", "1", "abc", "/p/1.py");
        report.UpsertPocSource("exploit-db", "1", "abc", "/p/1.py");
        report.UpsertTooling("nmap", "7.95", "apt", "/usr/bin/nmap");
        report.UpsertTooling("nmap", "7.95", "apt", "/usr/bin/nmap");

        using var conn = new SqliteConnection($"Data Source={report.DatabasePath}");
        conn.Open();
        Assert.Equal(1, Count(conn, "cves"));
        Assert.Equal(1, Count(conn, "poc_refs"));
        Assert.Equal(1, Count(conn, "poc_sources"));
        Assert.Equal(1, Count(conn, "tooling"));
    }
}
