using Drederick.Exploit;

namespace Drederick.Reporting;

/// <summary>
/// Abstraction for writing <see cref="LootRecord"/>s so that tools can
/// emit loot without taking a hard dependency on <see cref="SqliteReport"/>.
///
/// The real implementation calls <see cref="SqliteReport.UpsertLoot"/>.
/// Tests substitute a recording stub.
///
/// Invariant: implementations must never store plaintext secret material.
/// Only <c>value_sha256</c> (a SHA-256 of the captured value) is acceptable
/// in persistent storage. File contents must be written to <c>out/</c> and
/// referenced by path — not stored in the record itself.
/// </summary>
public interface ILootSink
{
    void WriteRecord(LootRecord record);
}

/// <summary>
/// Production implementation — writes to <see cref="SqliteReport"/>.
/// </summary>
public sealed class SqliteLootSink : ILootSink
{
    private readonly SqliteReport _db;

    public SqliteLootSink(SqliteReport db)
    {
        ArgumentNullException.ThrowIfNull(db);
        _db = db;
    }

    public void WriteRecord(LootRecord record) => _db.UpsertLoot(record);
}

/// <summary>
/// No-op sink used when SQLite reporting is not configured.
/// </summary>
public sealed class NullLootSink : ILootSink
{
    public static readonly NullLootSink Instance = new();
    public void WriteRecord(LootRecord record) { }
}
