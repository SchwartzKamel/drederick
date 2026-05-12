using Drederick.Enrichment.FingerprintStack;
using Drederick.Recon;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Reporting;

/// <summary>
/// GAP-040 (pterodactyl-R1 follow-up) — services-table persistence
/// regression coverage for the *non-nmap* signal path.
///
/// Symptom: pterodactyl-R1 audit shows
/// <c>cve.annotate cves=36 findings=36</c> (annotation worked) but
/// <c>SELECT COUNT(*) FROM services WHERE host=…</c> returns 0. Root cause:
/// <see cref="SqliteReport.WriteReport"/> only upserted services from
/// <c>host.Nmap.OpenPorts</c> and <c>host.NativeScan.OpenPorts</c>. When
/// recon-derived service info came purely from HTTP / fingerprint / CMS
/// signals, <c>services</c> stayed empty even though the findings did land.
/// </summary>
public class ServicesPersistenceTests : IDisposable
{
    private readonly string _dir;

    public ServicesPersistenceTests()
    {
        _dir = Path.Combine(AppContext.BaseDirectory,
            "services-persistence-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private SqliteConnection OpenDb()
    {
        var conn = new SqliteConnection($"Data Source={Path.Combine(_dir, "findings.db")}");
        conn.Open();
        return conn;
    }

    [Fact]
    public void Http_only_host_produces_services_row()
    {
        // Direct unit test for the bug: a host whose only recon signal is
        // an HTTP probe must still get a services row at the HTTP port.
        var host = new HostFinding
        {
            Target = "10.10.11.99",
            Http =
            {
                new HttpResult
                {
                    Url = "http://10.10.11.99:8080/",
                    Server = "Apache/2.4.49 (Ubuntu)",
                    Status = 200,
                },
            },
        };

        new SqliteReport(_dir).WriteReport(new[] { host });

        using var conn = OpenDb();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT s.port, s.proto, s.service, s.product, s.version
FROM services s JOIN hosts h ON h.id = s.host_id
WHERE h.address = $a;";
        cmd.Parameters.AddWithValue("$a", host.Target);
        using var r = cmd.ExecuteReader();
        Assert.True(r.Read(), "HTTP-only host must produce a services row (regression for GAP-040 pterodactyl-R1).");
        Assert.Equal(8080, r.GetInt32(0));
        Assert.Equal("tcp", r.GetString(1));
        Assert.Equal("http", r.GetString(2));
        Assert.Equal("Apache", r.GetString(3));
        Assert.Equal("2.4.49", r.GetString(4));
        Assert.False(r.Read(), "exactly one services row expected for the HTTP probe");
    }

    [Fact]
    public void Fingerprint_only_host_produces_services_row()
    {
        var host = new HostFinding
        {
            Target = "10.10.11.100",
            Fingerprint =
            {
                new FingerprintReport
                {
                    Port = 22,
                    Candidates =
                    {
                        new FingerprintCandidate
                        {
                            Vendor = "openbsd",
                            Product = "OpenSSH",
                            Version = "8.2p1",
                            Confidence = 0.91,
                            Cpe = "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*",
                        },
                    },
                },
            },
        };

        new SqliteReport(_dir).WriteReport(new[] { host });

        using var conn = OpenDb();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT COUNT(*) FROM services s JOIN hosts h ON h.id = s.host_id
WHERE h.address = $a AND s.port = 22 AND s.product = 'OpenSSH' AND s.version = '8.2p1';";
        cmd.Parameters.AddWithValue("$a", host.Target);
        Assert.Equal(1, Convert.ToInt32(cmd.ExecuteScalar()));
    }

    [Fact]
    public void Cms_only_host_produces_services_row_at_baseurl_port()
    {
        var host = new HostFinding
        {
            Target = "10.10.11.101",
            CmsFingerprint =
            {
                new CmsFinding
                {
                    Target = "10.10.11.101",
                    BaseUrl = "https://10.10.11.101/",
                    Matches = new[]
                    {
                        new CmsMatch("WordPress", "5.7.2", 90,
                            new[] { "generator-meta" }, "cpe:2.3:a:wordpress:wordpress:5.7.2:*:*:*:*:*:*:*"),
                    },
                },
            },
        };

        new SqliteReport(_dir).WriteReport(new[] { host });

        using var conn = OpenDb();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT s.port, s.product, s.version
FROM services s JOIN hosts h ON h.id = s.host_id
WHERE h.address = $a;";
        cmd.Parameters.AddWithValue("$a", host.Target);
        using var r = cmd.ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal(443, r.GetInt32(0));
        Assert.Equal("WordPress", r.GetString(1));
        Assert.Equal("5.7.2", r.GetString(2));
    }

    [Fact]
    public void Idempotent_rerun_does_not_duplicate_http_services()
    {
        var host = new HostFinding
        {
            Target = "10.10.11.102",
            Http =
            {
                new HttpResult { Url = "http://10.10.11.102/", Server = "nginx/1.18.0" },
                new HttpResult { Url = "https://10.10.11.102/", Server = "nginx/1.18.0" },
            },
        };

        var report = new SqliteReport(_dir);
        report.WriteReport(new[] { host });
        report.WriteReport(new[] { host });
        report.WriteReport(new[] { host });

        using var conn = OpenDb();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT COUNT(*) FROM services s JOIN hosts h ON h.id = s.host_id WHERE h.address = $a;";
        cmd.Parameters.AddWithValue("$a", host.Target);
        Assert.Equal(2, Convert.ToInt32(cmd.ExecuteScalar()));
    }

    [Fact]
    public void Harvester_parses_server_header_and_assigns_https_default_port()
    {
        var host = new HostFinding
        {
            Target = "10.10.11.103",
            Http =
            {
                new HttpResult { Url = "https://10.10.11.103/", Server = "Apache/2.4.49 (Ubuntu)" },
            },
        };

        var tuples = ServicesPersistenceFix.HarvestNonNmapServiceTuples(host).ToList();
        Assert.Single(tuples);
        Assert.Equal(443, tuples[0].Port);
        Assert.Equal("tcp", tuples[0].Protocol);
        Assert.Equal("https", tuples[0].Service);
        Assert.Equal("Apache", tuples[0].Product);
        Assert.Equal("2.4.49", tuples[0].Version);
    }
}
