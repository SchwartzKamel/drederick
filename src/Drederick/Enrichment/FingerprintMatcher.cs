using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Drederick.Recon.Windows;

namespace Drederick.Enrichment;

/// <summary>
/// Confidence band for a fingerprint-driven CVE candidate. The
/// <c>windows-vulns --analyze</c> CLI prints High and Medium by
/// default and gates Low behind <c>--verbose</c>.
/// </summary>
public enum FingerprintMatchConfidence
{
    Low = 0,
    Medium = 1,
    High = 2,
}

/// <summary>One CVE candidate emitted by
/// <see cref="FingerprintMatcher.MatchWindowsBuild"/>. Pure data row
/// — no IO, no scope dep.</summary>
public sealed record CveCandidate(
    string Cve,
    string Title,
    string Severity,
    string? MissingKb,
    string? FeatureGate,
    FingerprintMatchConfidence Confidence,
    string Source,
    string Reason,
    IReadOnlyList<string> References);

/// <summary>
/// Slice-C matcher: joins a <see cref="WindowsBuildFingerprint"/> against
/// the bundled <c>data/windows-build-fingerprints.json</c> corpus to
/// suppress already-patched CVEs and surface the unpatched ones with a
/// confidence score. Pure data — no scope calls, no IO beyond the
/// embedded resource load at construction time.
/// </summary>
public sealed class FingerprintMatcher
{
    private readonly IReadOnlyList<WindowsBuildFingerprintEntry> _entries;

    public FingerprintMatcher(IEnumerable<WindowsBuildFingerprintEntry> entries)
    {
        _entries = entries?.ToList() ?? new List<WindowsBuildFingerprintEntry>();
    }

    /// <summary>Number of curated entries — exposed for tests.</summary>
    public int Count => _entries.Count;

    /// <summary>Read-only view of every loaded entry.</summary>
    public IReadOnlyList<WindowsBuildFingerprintEntry> All => _entries;

    /// <summary>
    /// Match the supplied fingerprint against the corpus. Output is sorted
    /// High → Medium → Low, severity-weighted. Patched entries are
    /// suppressed entirely.
    /// </summary>
    public IReadOnlyList<CveCandidate> MatchWindowsBuild(WindowsBuildFingerprint fp)
    {
        ArgumentNullException.ThrowIfNull(fp);

        var hits = new List<CveCandidate>();
        var installed = new HashSet<string>(fp.InstalledKbs, StringComparer.OrdinalIgnoreCase);
        var enabledFeatures = new HashSet<string>(fp.EnabledFeatures, StringComparer.OrdinalIgnoreCase);
        var productTags = new HashSet<string>(fp.ProductTags(), StringComparer.OrdinalIgnoreCase);

        foreach (var entry in _entries)
        {
            // --- product filter -----------------------------------------
            // Empty product tags on the fingerprint == unknown ⇒ keep the
            // entry (prefer false positives over false negatives).
            if (productTags.Count > 0 && entry.Products is { Count: > 0 })
            {
                var overlap = entry.Products.Any(p => productTags.Contains(p));
                if (!overlap) continue;
            }

            // --- feature gate -------------------------------------------
            // A feature_gate of "domain-controller" means the entry only
            // applies if AD is detected. Unknown is a soft pass.
            if (!string.IsNullOrWhiteSpace(entry.FeatureGate) && enabledFeatures.Count > 0)
            {
                if (!enabledFeatures.Contains(entry.FeatureGate!)) continue;
            }

            // --- KB suppression -----------------------------------------
            // If the operator has the patch KB or any superseding KB
            // installed, this CVE is patched ⇒ drop entirely.
            if (KbSatisfies(entry, installed))
            {
                continue;
            }

            // --- UBR / build threshold ---------------------------------
            // If `min_build_revision` is "17763.4651", we suppress only
            // when the host's CurrentBuild matches 17763 *and* UBR >= 4651.
            var ubrCmp = CompareUbr(entry.MinBuildRevision, fp);
            if (ubrCmp == UbrComparison.AboveThreshold) continue;

            // --- candidate emission ------------------------------------
            FingerprintMatchConfidence confidence;
            string reason;

            if (installed.Count > 0 && ubrCmp == UbrComparison.BelowThreshold)
            {
                confidence = FingerprintMatchConfidence.High;
                reason = $"KB {entry.Kb} absent AND build {fp.CurrentBuild}.{fp.Ubr ?? "?"} below {entry.MinBuildRevision}";
            }
            else if (installed.Count > 0 && ubrCmp == UbrComparison.Unknown)
            {
                confidence = FingerprintMatchConfidence.High;
                reason = $"KB {entry.Kb} absent in installed hotfix list ({installed.Count} KBs known)";
            }
            else if (ubrCmp == UbrComparison.BelowThreshold)
            {
                confidence = FingerprintMatchConfidence.Medium;
                reason = $"build {fp.CurrentBuild}.{fp.Ubr ?? "?"} below {entry.MinBuildRevision} (KB list unavailable)";
            }
            else
            {
                confidence = FingerprintMatchConfidence.Low;
                reason = "banner / product family match only — no KB or build telemetry";
            }

            foreach (var cve in entry.Fixes ?? new())
            {
                hits.Add(new CveCandidate(
                    Cve: cve,
                    Title: entry.Title ?? cve,
                    Severity: entry.Severity ?? "yellow",
                    MissingKb: entry.Kb,
                    FeatureGate: entry.FeatureGate,
                    Confidence: confidence,
                    Source: "windows-build-fingerprints",
                    Reason: reason,
                    References: entry.References ?? new List<string>()));
            }
        }

        return hits
            .OrderByDescending(c => (int)c.Confidence)
            .ThenByDescending(c => SeverityRank(c.Severity))
            .ThenBy(c => c.Cve, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private enum UbrComparison { AboveThreshold, BelowThreshold, Unknown }

    private static UbrComparison CompareUbr(string? minBuildRevision, WindowsBuildFingerprint fp)
    {
        if (string.IsNullOrWhiteSpace(minBuildRevision)) return UbrComparison.Unknown;
        var parts = minBuildRevision!.Split('.', 2);
        if (parts.Length != 2) return UbrComparison.Unknown;
        if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var minBuild)) return UbrComparison.Unknown;
        if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var minUbr)) return UbrComparison.Unknown;

        var build = fp.CurrentBuildInt;
        if (build is null) return UbrComparison.Unknown;

        // Different build branch ⇒ threshold not directly comparable.
        // Treat as below-threshold so we don't false-suppress.
        if (build.Value != minBuild) return UbrComparison.BelowThreshold;

        var ubr = fp.UbrInt;
        if (ubr is null) return UbrComparison.Unknown;
        return ubr.Value >= minUbr ? UbrComparison.AboveThreshold : UbrComparison.BelowThreshold;
    }

    private static bool KbSatisfies(WindowsBuildFingerprintEntry entry, HashSet<string> installed)
    {
        if (installed.Count == 0) return false;
        if (!string.IsNullOrWhiteSpace(entry.Kb) && installed.Contains(entry.Kb!)) return true;
        foreach (var sup in entry.Supersedes ?? new())
        {
            if (!string.IsNullOrWhiteSpace(sup) && installed.Contains(sup)) return true;
        }
        return false;
    }

    private static int SeverityRank(string severity) => severity?.ToLowerInvariant() switch
    {
        "red" => 3,
        "yellow" => 2,
        "green" => 1,
        _ => 0,
    };

    // ---------- loaders ----------

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>Load from the embedded
    /// <c>data/windows-build-fingerprints.json</c> resource shipped with
    /// <c>drederick.dll</c>. Used by the runners and CLI.</summary>
    public static FingerprintMatcher LoadEmbedded()
    {
        var asm = typeof(FingerprintMatcher).Assembly;
        foreach (var name in asm.GetManifestResourceNames())
        {
            if (!name.EndsWith("windows-build-fingerprints.json", StringComparison.OrdinalIgnoreCase)) continue;
            using var s = asm.GetManifestResourceStream(name);
            if (s is null) continue;
            using var r = new StreamReader(s);
            var doc = JsonSerializer.Deserialize<WindowsBuildFingerprintDocument>(r.ReadToEnd(), JsonOpts);
            if (doc?.Entries is { Count: > 0 })
                return new FingerprintMatcher(doc.Entries);
        }
        return new FingerprintMatcher(Array.Empty<WindowsBuildFingerprintEntry>());
    }

    /// <summary>Load from an on-disk JSON file — used by tests against a
    /// fixture.</summary>
    public static FingerprintMatcher LoadFromFile(string path)
    {
        var json = File.ReadAllText(path);
        var doc = JsonSerializer.Deserialize<WindowsBuildFingerprintDocument>(json, JsonOpts)
            ?? throw new InvalidDataException($"empty or invalid windows-build-fingerprints document: {path}");
        return new FingerprintMatcher(doc.Entries ?? new List<WindowsBuildFingerprintEntry>());
    }
}

/// <summary>JSON envelope for <c>data/windows-build-fingerprints.json</c>.</summary>
public sealed class WindowsBuildFingerprintDocument
{
    [JsonPropertyName("entries")]
    public List<WindowsBuildFingerprintEntry> Entries { get; set; } = new();
}

/// <summary>One row of the curated Windows KB → CVE corpus.</summary>
public sealed class WindowsBuildFingerprintEntry
{
    [JsonPropertyName("kb")] public string? Kb { get; set; }
    [JsonPropertyName("supersedes")] public List<string>? Supersedes { get; set; }
    [JsonPropertyName("fixes")] public List<string>? Fixes { get; set; }
    [JsonPropertyName("products")] public List<string>? Products { get; set; }
    [JsonPropertyName("min_build_revision")] public string? MinBuildRevision { get; set; }
    [JsonPropertyName("feature_gate")] public string? FeatureGate { get; set; }
    [JsonPropertyName("severity")] public string? Severity { get; set; }
    [JsonPropertyName("title")] public string? Title { get; set; }
    [JsonPropertyName("references")] public List<string>? References { get; set; }
}
