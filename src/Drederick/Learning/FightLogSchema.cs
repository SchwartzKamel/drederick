using System;
using System.Collections.Generic;

namespace Drederick.Learning;

/// <summary>
/// Top-level shape of <c>~/HTB/fight-log.yaml</c> (schema v1). The fight
/// corpus is the operator-curated catalogue of every drederick engagement;
/// see <c>docs/LEARNING_LOOP.md</c> for the discovery contract and
/// <c>.github/copilot-instructions.md</c> §"Fight history and learning
/// loop" for the full process.
/// </summary>
public sealed record FightLogV1(
    int SchemaVersion,
    IReadOnlyList<FightEntry> Fights);

/// <summary>One engagement against a target box (HTB or otherwise).</summary>
public sealed record FightEntry(
    string Id,
    string Box,
    DateTime Date,
    string TargetIp,
    string Difficulty,
    string Outcome,
    string? RematchOf,
    IReadOnlyList<string> GapsAddressed,
    string? Delta,
    IReadOnlyList<ServiceFound> ServicesFound,
    IReadOnlyList<string> VulnsIdentified,
    IReadOnlyList<ExploitAttempt> ExploitsAttempted);

/// <summary>A service discovered during recon for a fight.</summary>
public sealed record ServiceFound(
    int Port,
    string Service,
    string? Version);

/// <summary>An exploit (or credential / payload) attempt during a fight.</summary>
public sealed record ExploitAttempt(
    string Tool,
    string Target,
    string? Outcome,
    string? Notes);

/// <summary>
/// Thrown when <c>~/HTB/fight-log.yaml</c> declares a <c>schema_version</c>
/// other than 1. The corpus loader is read-only and will not auto-migrate;
/// the operator must update the file (or pin an older drederick) before the
/// learning loop can read it.
/// </summary>
public sealed class FightCorpusSchemaException : Exception
{
    public int FoundVersion { get; }
    public int ExpectedVersion { get; }
    public string CorpusPath { get; }

    public FightCorpusSchemaException(string corpusPath, int foundVersion, int expectedVersion)
        : base($"Fight corpus {corpusPath} declares schema_version={foundVersion}; "
               + $"this drederick build only understands schema_version={expectedVersion}. "
               + "Migrate the corpus to v" + expectedVersion + " or pin an older drederick. "
               + "See docs/LEARNING_LOOP.md.")
    {
        CorpusPath = corpusPath;
        FoundVersion = foundVersion;
        ExpectedVersion = expectedVersion;
    }
}
