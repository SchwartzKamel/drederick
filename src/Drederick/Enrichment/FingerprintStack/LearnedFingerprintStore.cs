using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Drederick.Enrichment.FingerprintStack;

/// <summary>
/// A fingerprint signature learned from a completed fight. Each entry pins a
/// specific observable signal (HTTP <c>Server</c> header, TLS subject DN, SSH
/// banner, SMB OS string, SNMP sysDescr, …) to a best-guess
/// (vendor, product, version) tuple plus the port on which it was observed.
/// Re-observation increments <see cref="Hits"/> and merges the contributing
/// fight ids so cross-run convergence is visible to operators and the LLM
/// planner.
/// </summary>
public sealed record LearnedFingerprint(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("signal_kind")] string SignalKind,
    [property: JsonPropertyName("signal_value")] string SignalValue,
    [property: JsonPropertyName("vendor")] string Vendor,
    [property: JsonPropertyName("product")] string Product,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("port")] int Port,
    [property: JsonPropertyName("hits")] int Hits,
    [property: JsonPropertyName("first_seen")] string FirstSeen,
    [property: JsonPropertyName("last_seen")] string LastSeen,
    [property: JsonPropertyName("evidence_fights")] IReadOnlyList<string> EvidenceFights);

/// <summary>
/// On-disk envelope for the learned-fingerprint corpus. Persisted to
/// <c>memory/learned-fingerprints.json</c> under the per-run output root and
/// loaded on the next run so the FingerprintStack auto-extends from past
/// fights.
/// </summary>
internal sealed class LearnedFingerprintFile
{
    [JsonPropertyName("version")] public int Version { get; set; } = 1;
    [JsonPropertyName("updated")] public string Updated { get; set; } = DateTimeOffset.UtcNow.ToString("o");
    [JsonPropertyName("entries")] public List<LearnedFingerprint> Entries { get; set; } = new();
}

/// <summary>
/// Thread-safe persistent store for <see cref="LearnedFingerprint"/> entries.
/// Backed by a flat JSON file under the run's <c>memory/</c> directory; load
/// is lossy-tolerant (corrupt file → empty store) and save is idempotent.
/// </summary>
public sealed class LearnedFingerprintStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _path;
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, LearnedFingerprint> _entries = new(StringComparer.Ordinal);

    public LearnedFingerprintStore(string outRoot)
    {
        ArgumentException.ThrowIfNullOrEmpty(outRoot);
        _path = System.IO.Path.Combine(outRoot, "memory", "learned-fingerprints.json");
    }

    public string Path => _path;

    public int Count => _entries.Count;

    /// <summary>Stable id for a (kind, value) pair — SHA-256 hex truncated to 32 chars.</summary>
    public static string ComputeId(string signalKind, string signalValue)
    {
        ArgumentException.ThrowIfNullOrEmpty(signalKind);
        ArgumentNullException.ThrowIfNull(signalValue);
        var bytes = Encoding.UTF8.GetBytes(signalKind + "\u0000" + signalValue);
        var hash = SHA256.HashData(bytes);
        var sb = new StringBuilder(32);
        for (var i = 0; i < 16; i++) sb.Append(hash[i].ToString("x2"));
        return sb.ToString();
    }

    /// <summary>Loads the store from disk. Missing or corrupt → empty store.</summary>
    public async Task LoadAsync(CancellationToken ct = default)
    {
        if (!File.Exists(_path))
        {
            _entries.Clear();
            return;
        }
        try
        {
            await using var stream = File.OpenRead(_path);
            var file = await JsonSerializer.DeserializeAsync<LearnedFingerprintFile>(stream, JsonOpts, ct).ConfigureAwait(false);
            _entries.Clear();
            if (file?.Entries == null) return;
            foreach (var e in file.Entries)
            {
                if (string.IsNullOrEmpty(e.Id)) continue;
                _entries[e.Id] = e;
            }
        }
        catch (JsonException)
        {
            _entries.Clear();
        }
    }

    /// <summary>Saves the store to disk. Idempotent — calling twice produces the same content (modulo the <c>updated</c> timestamp).</summary>
    public async Task SaveAsync(CancellationToken ct = default)
    {
        var dir = System.IO.Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        LearnedFingerprintFile snapshot;
        lock (_gate)
        {
            snapshot = new LearnedFingerprintFile
            {
                Version = 1,
                Updated = DateTimeOffset.UtcNow.ToString("o"),
                Entries = _entries.Values
                    .OrderBy(e => e.SignalKind, StringComparer.Ordinal)
                    .ThenBy(e => e.SignalValue, StringComparer.Ordinal)
                    .ToList(),
            };
        }

        await using var stream = File.Create(_path);
        await JsonSerializer.SerializeAsync(stream, snapshot, JsonOpts, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Insert-or-merge an entry by <c>Id</c>. On collision: <c>Hits</c> is
    /// incremented by the incoming hits (default 1), <c>EvidenceFights</c>
    /// is union-merged (deduped, order-preserving), <c>FirstSeen</c> is
    /// preserved from the existing entry, <c>LastSeen</c> is overwritten,
    /// and vendor/product/version/port from the incoming entry win when
    /// non-empty (so a more confident later observation can refine an
    /// earlier guess).
    /// </summary>
    public LearnedFingerprint Upsert(LearnedFingerprint fp)
    {
        ArgumentNullException.ThrowIfNull(fp);
        return _entries.AddOrUpdate(
            fp.Id,
            _ => fp,
            (_, existing) =>
            {
                var fights = new List<string>(existing.EvidenceFights);
                var seen = new HashSet<string>(fights, StringComparer.Ordinal);
                foreach (var f in fp.EvidenceFights)
                {
                    if (seen.Add(f)) fights.Add(f);
                }
                return existing with
                {
                    Vendor = string.IsNullOrEmpty(fp.Vendor) ? existing.Vendor : fp.Vendor,
                    Product = string.IsNullOrEmpty(fp.Product) ? existing.Product : fp.Product,
                    Version = string.IsNullOrEmpty(fp.Version) ? existing.Version : fp.Version,
                    Port = fp.Port != 0 ? fp.Port : existing.Port,
                    Hits = existing.Hits + Math.Max(1, fp.Hits),
                    LastSeen = string.IsNullOrEmpty(fp.LastSeen) ? existing.LastSeen : fp.LastSeen,
                    EvidenceFights = fights,
                };
            });
    }

    public bool TryGetByValue(string signalKind, string signalValue, out LearnedFingerprint fp)
    {
        var id = ComputeId(signalKind, signalValue);
        return _entries.TryGetValue(id, out fp!);
    }

    public IReadOnlyList<LearnedFingerprint> All()
    {
        return _entries.Values
            .OrderBy(e => e.SignalKind, StringComparer.Ordinal)
            .ThenBy(e => e.SignalValue, StringComparer.Ordinal)
            .ToList();
    }
}
