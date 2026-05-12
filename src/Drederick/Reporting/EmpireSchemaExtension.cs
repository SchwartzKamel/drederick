using Microsoft.Data.Sqlite;

namespace Drederick.Reporting;

/// <summary>
/// Empire C2 schema extension for <c>findings.db</c>.
///
/// Adds four tables — <c>empire_servers</c>, <c>empire_listeners</c>,
/// <c>empire_agents</c>, <c>empire_modules_executed</c> — keyed so that
/// agents can be joined back to <c>hosts(id)</c> and (loosely) to
/// <c>sessions</c> via target address. Schema is idempotent
/// (<c>CREATE TABLE IF NOT EXISTS</c>); helper inserts are parameterized
/// — never interpolate into SQL.
///
/// Foreign keys assume <c>PRAGMA foreign_keys = ON</c> is enabled by
/// <see cref="SqliteReport"/> (which it is — verified at schema init).
/// </summary>
public static class EmpireSchemaExtension
{
    /// <summary>Apply the Empire schema to <paramref name="conn"/>. Idempotent.</summary>
    public static void Apply(SqliteConnection conn)
    {
        ArgumentNullException.ThrowIfNull(conn);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS empire_servers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  pid INTEGER,
  started_at TEXT NOT NULL,
  stopped_at TEXT,
  status TEXT NOT NULL,
  UNIQUE(host, port, started_at)
);
CREATE TABLE IF NOT EXISTS empire_listeners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id INTEGER NOT NULL,
  external_id TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  listen_host TEXT NOT NULL,
  listen_port INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (server_id) REFERENCES empire_servers(id),
  UNIQUE(server_id, external_id)
);
CREATE TABLE IF NOT EXISTS empire_agents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id INTEGER NOT NULL,
  external_id TEXT NOT NULL,
  host_id INTEGER,
  listener_id INTEGER,
  user_name TEXT,
  process_name TEXT,
  pid INTEGER,
  os TEXT,
  language TEXT,
  checkin_at TEXT NOT NULL,
  last_seen_at TEXT,
  status TEXT NOT NULL,
  FOREIGN KEY (server_id) REFERENCES empire_servers(id),
  FOREIGN KEY (listener_id) REFERENCES empire_listeners(id),
  FOREIGN KEY (host_id) REFERENCES hosts(id),
  UNIQUE(server_id, external_id)
);
CREATE TABLE IF NOT EXISTS empire_modules_executed (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL,
  module_name TEXT NOT NULL,
  argv_digest TEXT NOT NULL,
  executed_at TEXT NOT NULL,
  exit_status TEXT,
  output_digest TEXT,
  FOREIGN KEY (agent_id) REFERENCES empire_agents(id)
);
CREATE INDEX IF NOT EXISTS idx_empire_agents_host_id ON empire_agents(host_id);
CREATE INDEX IF NOT EXISTS idx_empire_agents_server_id ON empire_agents(server_id);
CREATE INDEX IF NOT EXISTS idx_empire_listeners_server_id ON empire_listeners(server_id);
CREATE INDEX IF NOT EXISTS idx_empire_modules_agent_id ON empire_modules_executed(agent_id);
";
        cmd.ExecuteNonQuery();
    }

    /// <summary>Insert an <c>empire_servers</c> row. Returns the new row id.</summary>
    public static long InsertServer(SqliteConnection conn, string host, int port,
        int? pid, string startedAt, string? stoppedAt, string status,
        SqliteTransaction? tx = null)
    {
        ArgumentNullException.ThrowIfNull(conn);
        if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("host required", nameof(host));
        if (string.IsNullOrWhiteSpace(startedAt)) throw new ArgumentException("startedAt required", nameof(startedAt));
        if (string.IsNullOrWhiteSpace(status)) throw new ArgumentException("status required", nameof(status));
        using var cmd = conn.CreateCommand();
        if (tx is not null) cmd.Transaction = tx;
        cmd.CommandText = @"
INSERT INTO empire_servers(host, port, pid, started_at, stopped_at, status)
VALUES($host, $port, $pid, $started, $stopped, $status)
RETURNING id;";
        cmd.Parameters.AddWithValue("$host", host);
        cmd.Parameters.AddWithValue("$port", port);
        cmd.Parameters.AddWithValue("$pid", (object?)pid ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$started", startedAt);
        cmd.Parameters.AddWithValue("$stopped", (object?)stoppedAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$status", status);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    /// <summary>Insert an <c>empire_listeners</c> row. Returns the new row id.</summary>
    public static long InsertListener(SqliteConnection conn, long serverId, string externalId,
        string name, string type, string listenHost, int listenPort, string createdAt,
        SqliteTransaction? tx = null)
    {
        ArgumentNullException.ThrowIfNull(conn);
        if (string.IsNullOrWhiteSpace(externalId)) throw new ArgumentException("externalId required", nameof(externalId));
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("name required", nameof(name));
        if (string.IsNullOrWhiteSpace(type)) throw new ArgumentException("type required", nameof(type));
        if (string.IsNullOrWhiteSpace(listenHost)) throw new ArgumentException("listenHost required", nameof(listenHost));
        if (string.IsNullOrWhiteSpace(createdAt)) throw new ArgumentException("createdAt required", nameof(createdAt));
        using var cmd = conn.CreateCommand();
        if (tx is not null) cmd.Transaction = tx;
        cmd.CommandText = @"
INSERT INTO empire_listeners(server_id, external_id, name, type, listen_host, listen_port, created_at)
VALUES($srv, $ext, $name, $type, $host, $port, $created)
RETURNING id;";
        cmd.Parameters.AddWithValue("$srv", serverId);
        cmd.Parameters.AddWithValue("$ext", externalId);
        cmd.Parameters.AddWithValue("$name", name);
        cmd.Parameters.AddWithValue("$type", type);
        cmd.Parameters.AddWithValue("$host", listenHost);
        cmd.Parameters.AddWithValue("$port", listenPort);
        cmd.Parameters.AddWithValue("$created", createdAt);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    /// <summary>Insert an <c>empire_agents</c> row. Returns the new row id.</summary>
    public static long InsertAgent(SqliteConnection conn, long serverId, string externalId,
        long? hostId, long? listenerId, string? userName, string? processName, int? pid,
        string? os, string? language, string checkinAt, string? lastSeenAt, string status,
        SqliteTransaction? tx = null)
    {
        ArgumentNullException.ThrowIfNull(conn);
        if (string.IsNullOrWhiteSpace(externalId)) throw new ArgumentException("externalId required", nameof(externalId));
        if (string.IsNullOrWhiteSpace(checkinAt)) throw new ArgumentException("checkinAt required", nameof(checkinAt));
        if (string.IsNullOrWhiteSpace(status)) throw new ArgumentException("status required", nameof(status));
        using var cmd = conn.CreateCommand();
        if (tx is not null) cmd.Transaction = tx;
        cmd.CommandText = @"
INSERT INTO empire_agents(server_id, external_id, host_id, listener_id, user_name,
                          process_name, pid, os, language, checkin_at, last_seen_at, status)
VALUES($srv, $ext, $host, $lst, $user, $proc, $pid, $os, $lang, $checkin, $lastseen, $status)
RETURNING id;";
        cmd.Parameters.AddWithValue("$srv", serverId);
        cmd.Parameters.AddWithValue("$ext", externalId);
        cmd.Parameters.AddWithValue("$host", (object?)hostId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$lst", (object?)listenerId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$user", (object?)userName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$proc", (object?)processName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$pid", (object?)pid ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$os", (object?)os ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$lang", (object?)language ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$checkin", checkinAt);
        cmd.Parameters.AddWithValue("$lastseen", (object?)lastSeenAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$status", status);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    /// <summary>Insert an <c>empire_modules_executed</c> row. Returns the new row id.</summary>
    public static long InsertModuleExecution(SqliteConnection conn, long agentId,
        string moduleName, string argvDigest, string executedAt, string? exitStatus,
        string? outputDigest, SqliteTransaction? tx = null)
    {
        ArgumentNullException.ThrowIfNull(conn);
        if (string.IsNullOrWhiteSpace(moduleName)) throw new ArgumentException("moduleName required", nameof(moduleName));
        if (string.IsNullOrWhiteSpace(argvDigest)) throw new ArgumentException("argvDigest required", nameof(argvDigest));
        if (string.IsNullOrWhiteSpace(executedAt)) throw new ArgumentException("executedAt required", nameof(executedAt));
        using var cmd = conn.CreateCommand();
        if (tx is not null) cmd.Transaction = tx;
        cmd.CommandText = @"
INSERT INTO empire_modules_executed(agent_id, module_name, argv_digest, executed_at, exit_status, output_digest)
VALUES($agent, $mod, $digest, $ts, $exit, $out)
RETURNING id;";
        cmd.Parameters.AddWithValue("$agent", agentId);
        cmd.Parameters.AddWithValue("$mod", moduleName);
        cmd.Parameters.AddWithValue("$digest", argvDigest);
        cmd.Parameters.AddWithValue("$ts", executedAt);
        cmd.Parameters.AddWithValue("$exit", (object?)exitStatus ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$out", (object?)outputDigest ?? DBNull.Value);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }
}
