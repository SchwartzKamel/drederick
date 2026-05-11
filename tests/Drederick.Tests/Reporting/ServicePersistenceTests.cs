using Drederick.Recon;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Reporting;

/// <summary>
/// GAP-040 — services-table persistence regression coverage.
///
/// Symptom: PingPong R1 ran 9 nmap scans across ~70 minutes and persisted
/// zero rows to <c>services</c>. Audit confirmed the scans completed; the
/// findings.db was empty. Root cause: <see cref="SqliteReport.WriteReport"/>
/// only persisted <c>host.Nmap.OpenPorts</c> and silently dropped
/// <c>host.NativeScan.OpenPorts</c>, so when the nmap binary was absent /
/// produced empty parse output, the native fallback's discovered services
/// never reached the table.
/// </summary>
public class ServicePersistenceTests : IDisposable
{
    private readonly string _dir;

    public ServicePersistenceTests()
    {
        _dir = Path.Combine(AppContext.BaseDirectory,
            "service-persistence-tests-" + Guid.NewGuid().ToString("N"));
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

    private static int CountServices(SqliteConnection conn, long? hostId = null)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = hostId is null
            ? "SELECT COUNT(*) FROM services;"
            : "SELECT COUNT(*) FROM services WHERE host_id = $h;";
        if (hostId is not null) cmd.Parameters.AddWithValue("$h", hostId.Value);
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    private static long HostId(SqliteConnection conn, string address)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id FROM hosts WHERE address = $a;";
        cmd.Parameters.AddWithValue("$a", address);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    [Fact]
    public void NmapWithThreeServices_PersistsThreeRowsWithCorrectColumns()
    {
        var finding = new HostFinding
        {
            Target = "10.10.10.10",
            Started = DateTimeOffset.UtcNow.ToString("o"),
            Finished = DateTimeOffset.UtcNow.ToString("o"),
            Nmap = new NmapResult
            {
                ReturnCode = 0,
                OpenPorts = new()
                {
                    new NmapPort { Port = 22, Protocol = "tcp", Service = "ssh", Product = "OpenSSH", Version = "9.6" },
                    new NmapPort { Port = 80, Protocol = "tcp", Service = "http", Product = "nginx", Version = "1.24" },
                    new NmapPort { Port = 443, Protocol = "tcp", Service = "https", Product = "nginx", Version = "1.24" },
                },
            },
        };

        new SqliteReport(_dir).WriteReport(new[] { finding });

        using var conn = OpenDb();
        var hostId = HostId(conn, "10.10.10.10");
        Assert.Equal(3, CountServices(conn, hostId));

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT port, proto, service FROM services WHERE host_id = $h ORDER BY port;";
        cmd.Parameters.AddWithValue("$h", hostId);
        using var r = cmd.ExecuteReader();
        Assert.True(r.Read()); Assert.Equal(22, r.GetInt32(0)); Assert.Equal("tcp", r.GetString(1)); Assert.Equal("ssh", r.GetString(2));
        Assert.True(r.Read()); Assert.Equal(80, r.GetInt32(0)); Assert.Equal("tcp", r.GetString(1)); Assert.Equal("http", r.GetString(2));
        Assert.True(r.Read()); Assert.Equal(443, r.GetInt32(0)); Assert.Equal("tcp", r.GetString(1)); Assert.Equal("https", r.GetString(2));
        Assert.False(r.Read());
    }

    /// <summary>
    /// GAP-040 root-cause regression: when <c>NmapResult</c> parses to an
    /// empty <c>OpenPorts</c> list (the PingPong R6 symptom — scan returned
    /// 0, parser produced no ports) but <c>NativeScan</c> did discover open
    /// ports, those services MUST land in the <c>services</c> table.
    /// </summary>
    [Fact]
    public void NativeScanServices_PersistedEvenWhenNmapEmpty()
    {
        var finding = new HostFinding
        {
            Target = "10.129.30.247",
            Started = DateTimeOffset.UtcNow.ToString("o"),
            Finished = DateTimeOffset.UtcNow.ToString("o"),
            // PingPong R6 shape: nmap exited 0 but parser yielded zero ports.
            Nmap = new NmapResult { ReturnCode = 0, OpenPorts = new() },
            NativeScan = new NativeScanResult
            {
                Source = "nativescan",
                OpenPorts = new()
                {
                    new NmapPort { Port = 53, Protocol = "tcp", Service = "domain" },
                    new NmapPort { Port = 88, Protocol = "tcp", Service = "kerberos" },
                    new NmapPort { Port = 389, Protocol = "tcp", Service = "ldap" },
                    new NmapPort { Port = 445, Protocol = "tcp", Service = "microsoft-ds" },
                },
            },
        };

        new SqliteReport(_dir).WriteReport(new[] { finding });

        using var conn = OpenDb();
        var hostId = HostId(conn, "10.129.30.247");
        Assert.Equal(4, CountServices(conn, hostId));

        // The nmap-style finding rows are also persisted under the
        // `native_scan` kind so triage queries can distinguish source.
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM findings WHERE host_id = $h AND kind = 'native_scan';";
        cmd.Parameters.AddWithValue("$h", hostId);
        Assert.Equal(4, Convert.ToInt32(cmd.ExecuteScalar()));
    }

    [Fact]
    public void NmapAndNativeScan_OverlappingPorts_DedupedByUniqueConstraint()
    {
        // services has UNIQUE(host_id, port, proto). When both Nmap and
        // NativeScan report the same (port, proto) we should land on a
        // single row (with the upsert merging non-null fields).
        var finding = new HostFinding
        {
            Target = "10.0.0.5",
            Started = DateTimeOffset.UtcNow.ToString("o"),
            Nmap = new NmapResult
            {
                ReturnCode = 0,
                OpenPorts = new()
                {
                    new NmapPort { Port = 22, Protocol = "tcp", Service = "ssh", Product = "OpenSSH" },
                },
            },
            NativeScan = new NativeScanResult
            {
                OpenPorts = new()
                {
                    new NmapPort { Port = 22, Protocol = "tcp", Service = "ssh" },
                    new NmapPort { Port = 8080, Protocol = "tcp", Service = "http-proxy" },
                },
            },
        };

        new SqliteReport(_dir).WriteReport(new[] { finding });

        using var conn = OpenDb();
        var hostId = HostId(conn, "10.0.0.5");
        Assert.Equal(2, CountServices(conn, hostId));
    }

    [Fact]
    public void NmapServiceCount_MatchesParsedOpenPortsCount()
    {
        // Regression for the original PingPong R1 symptom phrased the way
        // it would have caught it: N parsed ports → N rows in `services`.
        var ports = new List<NmapPort>();
        for (int p = 1000; p < 1009; p++)
        {
            ports.Add(new NmapPort { Port = p, Protocol = "tcp", Service = "svc" + p });
        }
        var finding = new HostFinding
        {
            Target = "10.0.0.99",
            Started = DateTimeOffset.UtcNow.ToString("o"),
            Nmap = new NmapResult { ReturnCode = 0, OpenPorts = ports },
        };

        new SqliteReport(_dir).WriteReport(new[] { finding });

        using var conn = OpenDb();
        var hostId = HostId(conn, "10.0.0.99");
        Assert.Equal(ports.Count, CountServices(conn, hostId));
    }
}
