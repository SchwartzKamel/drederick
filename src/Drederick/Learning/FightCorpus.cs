using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Drederick.Learning;

/// <summary>
/// Read-only loader for the operator-curated fight corpus
/// (<c>~/HTB/fight-log.yaml</c>). See <c>docs/LEARNING_LOOP.md</c>
/// §"Discovery". The loader never writes to the corpus — that's the
/// <c>fight-corpus-writer</c> tier-5 deliverable, not this one.
/// </summary>
/// <remarks>
/// Discovery precedence (highest to lowest):
///   1. Explicit <c>--fight-corpus &lt;path&gt;</c> CLI flag.
///   2. <c>DREDERICK_FIGHT_CORPUS</c> env var.
///   3. <c>~/HTB/fight-log.yaml</c> if it exists.
///   4. None — graceful no-op, returns an empty <see cref="FightLogV1"/>.
/// </remarks>
public sealed class FightCorpus
{
    public const int CurrentSchemaVersion = 1;
    public const string EnvVar = "DREDERICK_FIGHT_CORPUS";
    public const string DefaultRelativePath = "HTB/fight-log.yaml";

    private static readonly FightLogV1 EmptyLog = new(CurrentSchemaVersion, Array.Empty<FightEntry>());

    private readonly string? _resolvedPath;
    private readonly AuditLog? _audit;
    private FightLogV1? _cached;

    public FightCorpus(string? cliPath, AuditLog? audit = null, IDictionary<string, string?>? envOverride = null, string? homeOverride = null)
    {
        _audit = audit;
        _resolvedPath = ResolvePath(cliPath, envOverride, homeOverride);
    }

    /// <summary>
    /// Path the loader will read, or <c>null</c> if no corpus was discovered.
    /// </summary>
    public string? ResolvedPath => _resolvedPath;

    /// <summary>True when a corpus file was discovered on disk.</summary>
    public bool HasCorpus => _resolvedPath is not null && File.Exists(_resolvedPath);

    /// <summary>
    /// Resolve corpus path using the documented precedence. Returns null when
    /// no source is available — callers must treat that as a graceful no-op
    /// (return <see cref="EmptyLog"/>).
    /// </summary>
    private static string? ResolvePath(string? cliPath, IDictionary<string, string?>? envOverride, string? homeOverride)
    {
        if (!string.IsNullOrWhiteSpace(cliPath))
        {
            return Path.GetFullPath(cliPath);
        }

        string? envValue = envOverride is not null
            ? (envOverride.TryGetValue(EnvVar, out var v) ? v : null)
            : Environment.GetEnvironmentVariable(EnvVar);
        if (!string.IsNullOrWhiteSpace(envValue))
        {
            return Path.GetFullPath(envValue);
        }

        var home = homeOverride ?? Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home))
        {
            return null;
        }
        var defaultPath = Path.Combine(home, DefaultRelativePath);
        return File.Exists(defaultPath) ? defaultPath : null;
    }

    /// <summary>
    /// Load and parse the corpus. Returns an empty <see cref="FightLogV1"/>
    /// when no source is available. Throws <see cref="FightCorpusSchemaException"/>
    /// when the file declares a non-v1 schema.
    /// </summary>
    public Task<FightLogV1> LoadAsync(CancellationToken ct = default)
    {
        if (_cached is not null)
        {
            return Task.FromResult(_cached);
        }

        if (_resolvedPath is null || !File.Exists(_resolvedPath))
        {
            Console.Error.WriteLine(
                "INFO: fight-corpus: no ~/HTB/fight-log.yaml found (and no --fight-corpus / "
                + "DREDERICK_FIGHT_CORPUS override). Learning loop will run with an empty corpus.");
            _cached = EmptyLog;
            return Task.FromResult(_cached);
        }

        ct.ThrowIfCancellationRequested();
        var text = File.ReadAllText(_resolvedPath);
        _cached = Parse(text, _resolvedPath);
        return Task.FromResult(_cached);
    }

    /// <summary>
    /// Parse YAML text into a <see cref="FightLogV1"/>. Exposed as a static
    /// helper so tests can drive synthetic fixtures without a filesystem.
    /// </summary>
    public static FightLogV1 Parse(string yamlText, string sourcePathForErrors = "<inline>")
    {
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        FightLogDto? dto;
        try
        {
            dto = deserializer.Deserialize<FightLogDto>(yamlText);
        }
        catch (YamlException ex)
        {
            throw new InvalidDataException(
                $"fight-corpus: failed to parse {sourcePathForErrors}: {ex.Message}", ex);
        }

        dto ??= new FightLogDto();

        // Schema v1 is the implicit default when the field is absent. Any
        // explicit schema_version other than 1 is a hard stop.
        var declared = dto.SchemaVersion ?? CurrentSchemaVersion;
        if (declared != CurrentSchemaVersion)
        {
            throw new FightCorpusSchemaException(sourcePathForErrors, declared, CurrentSchemaVersion);
        }

        var fights = (dto.Fights ?? new List<FightEntryDto>())
            .Select(f => f.ToEntry())
            .ToList();
        return new FightLogV1(CurrentSchemaVersion, fights);
    }

    // -------- query helpers -------------------------------------------------

    /// <summary>All fights against a given box (case-insensitive).</summary>
    public IEnumerable<FightEntry> ByBox(string box)
    {
        if (_cached is null)
        {
            return Enumerable.Empty<FightEntry>();
        }
        return _cached.Fights.Where(f =>
            string.Equals(f.Box, box, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// All fights whose <c>rematch_of</c> field equals <paramref name="ofId"/>.
    /// </summary>
    public IEnumerable<FightEntry> Rematches(string ofId)
    {
        if (_cached is null)
        {
            return Enumerable.Empty<FightEntry>();
        }
        return _cached.Fights.Where(f =>
            string.Equals(f.RematchOf, ofId, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Fights whose <c>gaps_addressed</c> list contains <paramref name="gapId"/>
    /// (case-insensitive — gap IDs are conventionally GAP-NNN).
    /// </summary>
    public IEnumerable<FightEntry> AddressingGap(string gapId)
    {
        if (_cached is null)
        {
            return Enumerable.Empty<FightEntry>();
        }
        return _cached.Fights.Where(f =>
            f.GapsAddressed.Any(g => string.Equals(
                ExtractGapId(g), gapId, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Fights whose date is within <paramref name="window"/> of now (UTC).
    /// </summary>
    public IEnumerable<FightEntry> Recent(TimeSpan window)
    {
        if (_cached is null)
        {
            return Enumerable.Empty<FightEntry>();
        }
        var cutoff = DateTime.UtcNow - window;
        return _cached.Fights.Where(f => f.Date >= cutoff);
    }

    private static string ExtractGapId(string raw)
    {
        // gaps_addressed list items often look like "GAP-001  # comment".
        var s = raw?.Trim() ?? string.Empty;
        var hash = s.IndexOf('#');
        if (hash >= 0)
        {
            s = s[..hash].Trim();
        }
        return s;
    }

    // -------- DTOs ----------------------------------------------------------

    private sealed class FightLogDto
    {
        public int? SchemaVersion { get; set; }
        public List<FightEntryDto>? Fights { get; set; }
    }

    private sealed class FightEntryDto
    {
        public string? Id { get; set; }
        public string? Box { get; set; }
        public string? Date { get; set; }
        public string? TargetIp { get; set; }
        public string? Difficulty { get; set; }
        public string? Outcome { get; set; }
        public string? RematchOf { get; set; }
        public List<string>? GapsAddressed { get; set; }
        public string? Delta { get; set; }
        public List<ServiceDto>? ServicesFound { get; set; }
        public List<string>? VulnsIdentified { get; set; }
        public List<ExploitDto>? ExploitsAttempted { get; set; }

        public FightEntry ToEntry()
        {
            return new FightEntry(
                Id ?? string.Empty,
                Box ?? string.Empty,
                ParseDate(Date),
                TargetIp ?? string.Empty,
                Difficulty ?? string.Empty,
                Outcome ?? string.Empty,
                RematchOf,
                GapsAddressed ?? new List<string>(),
                Delta,
                (ServicesFound ?? new List<ServiceDto>()).Select(s => s.ToService()).ToList(),
                VulnsIdentified ?? new List<string>(),
                (ExploitsAttempted ?? new List<ExploitDto>()).Select(e => e.ToAttempt()).ToList());
        }

        private static DateTime ParseDate(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                return default;
            }
            if (DateTime.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var dt))
            {
                return DateTime.SpecifyKind(dt, DateTimeKind.Utc);
            }
            return default;
        }
    }

    private sealed class ServiceDto
    {
        public int Port { get; set; }
        public string? Service { get; set; }
        public string? Version { get; set; }

        public ServiceFound ToService() => new(Port, Service ?? string.Empty, Version);
    }

    private sealed class ExploitDto
    {
        public string? Tool { get; set; }
        public string? Target { get; set; }
        // Real corpus uses "result"; we expose it as "Outcome" in the schema.
        public string? Result { get; set; }
        public string? Outcome { get; set; }
        public string? Notes { get; set; }

        public ExploitAttempt ToAttempt() => new(
            Tool ?? string.Empty,
            Target ?? string.Empty,
            Outcome ?? Result,
            Notes);
    }
}
