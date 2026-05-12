using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Reporting;

/// <summary>
/// Empire SQLite schema coverage (Empire Wave A).
///
/// Verifies that the four Empire tables (servers, listeners, agents,
/// modules_executed) create idempotently on an empty DB, enforce their
/// UNIQUE constraints, and round-trip through the parameterized helper
/// inserts. Foreign-key wiring back to <c>hosts(id)</c> is also exercised
/// end-to-end (PRAGMA foreign_keys = ON, so a bad FK rejects).
/// </summary>
public sealed class EmpireSchemaExtensionTests : IDisposable
{
    private readonly string _dir;
    private readonly string _dbPath;

    public EmpireSchemaExtensionTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "drederick-empire-schema-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _dbPath = Path.Combine(_dir, "findings.db");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best-effort */ }
    }

    private SqliteConnection OpenWithHostsAndFkOn()
    {
        // Trigger full SqliteReport schema init (creates hosts + everything
        // else, and applies EmpireSchemaExtension via the anchored hook).
        var report = new SqliteReport(_dir);
        report.WriteReport(Array.Empty<Drederick.Recon.HostFinding>());

        var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = "PRAGMA foreign_keys = ON;";
            pragma.ExecuteNonQuery();
        }
        return conn;
    }

    private static bool TableExists(SqliteConnection conn, string name)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name=$n;";
        cmd.Parameters.AddWithValue("$n", name);
        return cmd.ExecuteScalar() is string;
    }

    [Fact]
    public void Apply_CreatesAllFourEmpireTables_OnEmptyDb()
    {
        using var conn = OpenWithHostsAndFkOn();

        Assert.True(TableExists(conn, "empire_servers"));
        Assert.True(TableExists(conn, "empire_listeners"));
        Assert.True(TableExists(conn, "empire_agents"));
        Assert.True(TableExists(conn, "empire_modules_executed"));
    }

    [Fact]
    public void Apply_IsIdempotent_WhenInvokedTwice()
    {
        using var conn = OpenWithHostsAndFkOn();
        // First Apply already ran via SqliteReport. Run it a second time
        // directly — must not throw.
        EmpireSchemaExtension.Apply(conn);
        EmpireSchemaExtension.Apply(conn);

        Assert.True(TableExists(conn, "empire_servers"));
        Assert.True(TableExists(conn, "empire_modules_executed"));
    }

    [Fact]
    public void InsertServer_Roundtrips_AndAssignsId()
    {
        using var conn = OpenWithHostsAndFkOn();
        var now = DateTimeOffset.UtcNow.ToString("o");

        var id = EmpireSchemaExtension.InsertServer(conn, "127.0.0.1", 1337,
            pid: 4242, startedAt: now, stoppedAt: null, status: "running");

        Assert.True(id > 0);

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT host, port, pid, started_at, status FROM empire_servers WHERE id=$i;";
        cmd.Parameters.AddWithValue("$i", id);
        using var r = cmd.ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal("127.0.0.1", r.GetString(0));
        Assert.Equal(1337, r.GetInt32(1));
        Assert.Equal(4242, r.GetInt32(2));
        Assert.Equal(now, r.GetString(3));
        Assert.Equal("running", r.GetString(4));
    }

    [Fact]
    public void InsertServer_UniqueConstraint_RejectsDuplicate()
    {
        using var conn = OpenWithHostsAndFkOn();
        var now = DateTimeOffset.UtcNow.ToString("o");

        EmpireSchemaExtension.InsertServer(conn, "127.0.0.1", 1337, null, now, null, "running");
        Assert.Throws<SqliteException>(() =>
            EmpireSchemaExtension.InsertServer(conn, "127.0.0.1", 1337, null, now, null, "running"));
    }

    [Fact]
    public void InsertListener_Roundtrips_AndUniqueByServerAndExternalId()
    {
        using var conn = OpenWithHostsAndFkOn();
        var now = DateTimeOffset.UtcNow.ToString("o");
        var serverId = EmpireSchemaExtension.InsertServer(conn, "127.0.0.1", 1337, null, now, null, "running");

        var listenerId = EmpireSchemaExtension.InsertListener(conn, serverId,
            externalId: "abc-123", name: "http", type: "http",
            listenHost: "0.0.0.0", listenPort: 8080, createdAt: now);
        Assert.True(listenerId > 0);

        Assert.Throws<SqliteException>(() =>
            EmpireSchemaExtension.InsertListener(conn, serverId, "abc-123",
                "http2", "http", "0.0.0.0", 8081, now));
    }

    [Fact]
    public void InsertListener_FkRequiresValidServerId()
    {
        using var conn = OpenWithHostsAndFkOn();
        var now = DateTimeOffset.UtcNow.ToString("o");

        Assert.Throws<SqliteException>(() =>
            EmpireSchemaExtension.InsertListener(conn, serverId: 99999,
                externalId: "x", name: "n", type: "http",
                listenHost: "0.0.0.0", listenPort: 8080, createdAt: now));
    }

    [Fact]
    public void InsertAgent_JoinsCleanlyToHosts_AndListener()
    {
        using var conn = OpenWithHostsAndFkOn();
        var now = DateTimeOffset.UtcNow.ToString("o");

        // Seed a real host row via the existing hosts table so we can FK to it.
        long hostId;
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"INSERT INTO hosts(address, hostname, first_seen, last_seen)
                                VALUES($a, NULL, $n, $n) RETURNING id;";
            cmd.Parameters.AddWithValue("$a", "10.0.0.5");
            cmd.Parameters.AddWithValue("$n", now);
            hostId = Convert.ToInt64(cmd.ExecuteScalar());
        }

        var serverId = EmpireSchemaExtension.InsertServer(conn, "127.0.0.1", 1337, null, now, null, "running");
        var listenerId = EmpireSchemaExtension.InsertListener(conn, serverId,
            "L1", "http", "http", "0.0.0.0", 8080, now);

        var agentId = EmpireSchemaExtension.InsertAgent(conn, serverId,
            externalId: "AG1", hostId: hostId, listenerId: listenerId,
            userName: "SYSTEM", processName: "powershell.exe", pid: 1234,
            os: "Windows", language: "powershell",
            checkinAt: now, lastSeenAt: now, status: "active");
        Assert.True(agentId > 0);

        // Round-trip join: empire_agents → hosts.
        using var join = conn.CreateCommand();
        join.CommandText = @"
SELECT h.address, a.external_id, a.user_name, l.name
FROM empire_agents a
JOIN hosts h ON h.id = a.host_id
JOIN empire_listeners l ON l.id = a.listener_id
WHERE a.id = $i;";
        join.Parameters.AddWithValue("$i", agentId);
        using var r = join.ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal("10.0.0.5", r.GetString(0));
        Assert.Equal("AG1", r.GetString(1));
        Assert.Equal("SYSTEM", r.GetString(2));
        Assert.Equal("http", r.GetString(3));
    }

    [Fact]
    public void InsertAgent_UniqueByServerAndExternalId()
    {
        using var conn = OpenWithHostsAndFkOn();
        var now = DateTimeOffset.UtcNow.ToString("o");
        var serverId = EmpireSchemaExtension.InsertServer(conn, "127.0.0.1", 1337, null, now, null, "running");

        EmpireSchemaExtension.InsertAgent(conn, serverId, "AG1", null, null,
            null, null, null, null, null, now, null, "active");
        Assert.Throws<SqliteException>(() =>
            EmpireSchemaExtension.InsertAgent(conn, serverId, "AG1", null, null,
                null, null, null, null, null, now, null, "active"));
    }

    [Fact]
    public void InsertModuleExecution_Roundtrips_AndJoinsToAgent()
    {
        using var conn = OpenWithHostsAndFkOn();
        var now = DateTimeOffset.UtcNow.ToString("o");
        var serverId = EmpireSchemaExtension.InsertServer(conn, "127.0.0.1", 1337, null, now, null, "running");
        var agentId = EmpireSchemaExtension.InsertAgent(conn, serverId, "AG1", null, null,
            null, null, null, null, null, now, null, "active");

        var modId = EmpireSchemaExtension.InsertModuleExecution(conn, agentId,
            moduleName: "powershell/credentials/mimikatz/logonpasswords",
            argvDigest: "deadbeef",
            executedAt: now,
            exitStatus: "success",
            outputDigest: "cafebabe");
        Assert.True(modId > 0);

        // Second insertion with same (agent, module) is allowed (no UNIQUE).
        var modId2 = EmpireSchemaExtension.InsertModuleExecution(conn, agentId,
            "powershell/credentials/mimikatz/logonpasswords", "deadbeef", now, "success", "cafebabe");
        Assert.True(modId2 > 0);
        Assert.NotEqual(modId, modId2);

        using var join = conn.CreateCommand();
        join.CommandText = @"
SELECT m.module_name, m.argv_digest, m.exit_status, a.external_id
FROM empire_modules_executed m
JOIN empire_agents a ON a.id = m.agent_id
WHERE m.id = $i;";
        join.Parameters.AddWithValue("$i", modId);
        using var r = join.ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal("powershell/credentials/mimikatz/logonpasswords", r.GetString(0));
        Assert.Equal("deadbeef", r.GetString(1));
        Assert.Equal("success", r.GetString(2));
        Assert.Equal("AG1", r.GetString(3));
    }

    [Fact]
    public void InsertModuleExecution_FkRequiresValidAgentId()
    {
        using var conn = OpenWithHostsAndFkOn();
        var now = DateTimeOffset.UtcNow.ToString("o");

        Assert.Throws<SqliteException>(() =>
            EmpireSchemaExtension.InsertModuleExecution(conn, agentId: 99999,
                "mod", "digest", now, null, null));
    }
}
