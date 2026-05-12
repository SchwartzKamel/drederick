using Drederick.Recon;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Integration;

/// <summary>
/// GAP-040 — end-to-end regression for the nmap → findings.db services
/// pipeline. Stubs a parsed <see cref="NmapResult"/> shape (mirroring what
/// <c>NmapTool.ParseXml</c> emits — open port plus service/product/version
/// attributes) for two hosts × three ports each, runs it through
/// <see cref="SqliteReport.WriteReport"/>, then asserts every (host, port)
/// landed in the <c>services</c> table.
/// </summary>
public class NmapToServicesDbTests : IDisposable
{
    private readonly string _dir;

    public NmapToServicesDbTests()
    {
        _dir = Path.Combine(AppContext.BaseDirectory,
            "nmap-services-db-" + Guid.NewGuid().ToString("N"));
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

    private static HostFinding MakeHost(string target, params (int Port, string Proto, string Service, string Product, string Version)[] ports)
    {
        var nmap = new NmapResult { ReturnCode = 0 };
        foreach (var p in ports)
        {
            nmap.OpenPorts.Add(new NmapPort
            {
                Port = p.Port,
                Protocol = p.Proto,
                Service = p.Service,
                Product = p.Product,
                Version = p.Version,
            });
        }
        return new HostFinding { Target = target, Nmap = nmap };
    }

    [Fact]
    public void Two_hosts_three_services_each_yields_six_rows()
    {
        var hosts = new[]
        {
            MakeHost("10.10.11.10",
                (22, "tcp", "ssh", "OpenSSH", "8.2p1"),
                (80, "tcp", "http", "Apache httpd", "2.4.49"),
                (443, "tcp", "https", "Apache httpd", "2.4.49")),
            MakeHost("10.10.11.11",
                (21, "tcp", "ftp", "vsftpd", "3.0.3"),
                (139, "tcp", "netbios-ssn", "Samba smbd", "4.6.2"),
                (445, "tcp", "microsoft-ds", "Samba smbd", "4.6.2")),
        };

        new SqliteReport(_dir).WriteReport(hosts);

        using var conn = OpenDb();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT COUNT(*) FROM services;";
            Assert.Equal(6, Convert.ToInt32(cmd.ExecuteScalar()));
        }

        // Spot-check exact rows.
        var rows = new List<(string Host, int Port, string Proto, string? Product, string? Version)>();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
SELECT h.address, s.port, s.proto, s.product, s.version
FROM services s JOIN hosts h ON h.id = s.host_id
ORDER BY h.address, s.port;";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                rows.Add((
                    r.GetString(0),
                    r.GetInt32(1),
                    r.GetString(2),
                    r.IsDBNull(3) ? null : r.GetString(3),
                    r.IsDBNull(4) ? null : r.GetString(4)));
            }
        }

        Assert.Equal(6, rows.Count);
        Assert.Equal(("10.10.11.10", 22, "tcp", "OpenSSH", "8.2p1"), rows[0]);
        Assert.Equal(("10.10.11.10", 80, "tcp", "Apache httpd", "2.4.49"), rows[1]);
        Assert.Equal(("10.10.11.10", 443, "tcp", "Apache httpd", "2.4.49"), rows[2]);
        Assert.Equal(("10.10.11.11", 21, "tcp", "vsftpd", "3.0.3"), rows[3]);
        Assert.Equal(("10.10.11.11", 139, "tcp", "Samba smbd", "4.6.2"), rows[4]);
        Assert.Equal(("10.10.11.11", 445, "tcp", "Samba smbd", "4.6.2"), rows[5]);
    }

    [Fact]
    public void Rerunning_same_pipeline_produces_no_duplicates()
    {
        var hosts = new[]
        {
            MakeHost("10.10.11.20",
                (22, "tcp", "ssh", "OpenSSH", "8.4p1"),
                (80, "tcp", "http", "nginx", "1.18.0"),
                (3306, "tcp", "mysql", "MariaDB", "10.3.31")),
            MakeHost("10.10.11.21",
                (53, "udp", "domain", "BIND", "9.16.1"),
                (88, "tcp", "kerberos-sec", "Microsoft Windows Kerberos", null!),
                (389, "tcp", "ldap", "Microsoft AD LDAP", null!)),
        };

        var report = new SqliteReport(_dir);
        report.WriteReport(hosts);
        report.WriteReport(hosts);
        report.WriteReport(hosts);

        using var conn = OpenDb();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM services;";
        Assert.Equal(6, Convert.ToInt32(cmd.ExecuteScalar()));
    }

    [Fact]
    public void Mixed_nmap_and_http_signals_produce_distinct_rows()
    {
        // pterodactyl-R1 shape: nmap finds 22 + 80, HTTP probe additionally
        // discovers an admin panel on 8443. All three must show up.
        var host = MakeHost("10.10.11.30",
            (22, "tcp", "ssh", "OpenSSH", "9.0p1"),
            (80, "tcp", "http", "nginx", "1.20.1"));
        host.Http.Add(new HttpResult
        {
            Url = "https://10.10.11.30:8443/admin",
            Server = "Werkzeug/2.0.1",
            Status = 401,
        });

        new SqliteReport(_dir).WriteReport(new[] { host });

        using var conn = OpenDb();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT s.port FROM services s JOIN hosts h ON h.id = s.host_id
WHERE h.address = $a ORDER BY s.port;";
        cmd.Parameters.AddWithValue("$a", host.Target);
        var ports = new List<int>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) ports.Add(r.GetInt32(0));
        Assert.Equal(new[] { 22, 80, 8443 }, ports);
    }
}
