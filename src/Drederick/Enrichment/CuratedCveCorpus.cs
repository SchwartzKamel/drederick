using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Drederick.Enrichment;

/// <summary>
/// htb-cms-cve-pack (closes GAP-052, partial GAP-034): operator-curated
/// CVE corpus that bypasses NVD CPE-string ambiguity for top OSS panels
/// (Pterodactyl, Cockpit, Wings, Ghost, Flarum, Shopware, Laravel SPA).
///
/// The NVD feed is sparsely populated for niche OSS — Pterodactyl Panel
/// has no useful CPE coverage as of this writing, so a fingerprint hit
/// of <c>cpe:2.3:a:pterodactyl:panel:1.11.10</c> would yield zero CVE
/// rows even though four upstream advisories apply. This corpus is the
/// fix: hand-curated <c>(cpe_pattern, cve_id, ref_urls, severity,
/// summary)</c> tuples, loaded from JSON files under
/// <c>data/curated-cves/</c>, matched by vendor/product/version with a
/// liberal range syntax (<c>&lt;=1.11.10</c>, <c>&gt;=1.0.0,&lt;2.0.0</c>,
/// <c>=1.11.10</c>, <c>*</c>).
///
/// Matching policy mirrors <see cref="CpeMatcher"/>: prefer false
/// positives over false negatives. Curated entries are merged into
/// <see cref="CveAnnotator"/> output BEFORE NVD matching, with
/// <c>enrichment_source = "curated"</c> recorded in the finding payload
/// so the operator can tell them apart.
/// </summary>
public sealed class CuratedCveCorpus
{
    private readonly IReadOnlyList<CuratedCveEntry> _entries;

    public CuratedCveCorpus(IReadOnlyList<CuratedCveEntry> entries)
    {
        _entries = entries ?? throw new ArgumentNullException(nameof(entries));
    }

    /// <summary>Total curated entry count — exposed for tests and audit.</summary>
    public int Count => _entries.Count;

    /// <summary>
    /// Match a single (vendor?, product, version?) tuple against the
    /// curated corpus. Vendor is optional; product is required; version
    /// nulls match wildcard patterns (<c>*</c>) only.
    /// </summary>
    public IReadOnlyList<CuratedCveMatch> Match(string? vendor, string product, string? version)
    {
        if (string.IsNullOrWhiteSpace(product)) return Array.Empty<CuratedCveMatch>();
        var nProduct = CpeMatcher.Normalize(product);
        var nVendor = CpeMatcher.Normalize(vendor);

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var results = new List<CuratedCveMatch>();
        foreach (var entry in _entries)
        {
            if (!ProductMatches(entry, nVendor, nProduct)) continue;
            if (!VersionMatches(entry, version)) continue;
            if (!seen.Add(entry.CveId)) continue;
            results.Add(new CuratedCveMatch(
                entry.CveId, entry.GhsaId, entry.Cvss, entry.Severity, entry.Summary, entry.RefUrls));
        }
        return results;
    }

    /// <summary>
    /// Match using a CPE 2.3 string (e.g.
    /// <c>cpe:2.3:a:pterodactyl:panel:1.11.10:*:*:*:*:*:*:*</c>).
    /// Convenience wrapper used by <see cref="CveAnnotator"/> to drive
    /// curated matching directly off CMS fingerprint results.
    /// </summary>
    public IReadOnlyList<CuratedCveMatch> MatchCpe(string cpe)
    {
        if (string.IsNullOrWhiteSpace(cpe)) return Array.Empty<CuratedCveMatch>();
        var (vendor, product, version) = ParseCpe(cpe);
        if (string.IsNullOrEmpty(product)) return Array.Empty<CuratedCveMatch>();
        return Match(vendor, product, version);
    }

    private static bool ProductMatches(CuratedCveEntry entry, string nVendor, string nProduct)
    {
        var (eVendor, eProduct, _) = ParseCpe(entry.CpePattern);
        var nEv = CpeMatcher.Normalize(eVendor);
        var nEp = CpeMatcher.Normalize(eProduct);

        if (nEp.Length == 0 || nEp == "*") return true;
        if (nEp != nProduct &&
            !nEp.StartsWith(nProduct, StringComparison.Ordinal) &&
            !nProduct.StartsWith(nEp, StringComparison.Ordinal))
        {
            return false;
        }
        if (nEv.Length > 0 && nEv != "*" && nVendor.Length > 0 && nEv != nVendor)
        {
            return false;
        }
        return true;
    }

    private static bool VersionMatches(CuratedCveEntry entry, string? queryVersion)
    {
        var range = entry.VersionRange;
        var (_, _, cpeVersion) = ParseCpe(entry.CpePattern);

        // No range → fall back to the CPE pattern's own version field.
        if (string.IsNullOrWhiteSpace(range))
        {
            if (string.IsNullOrEmpty(cpeVersion) || cpeVersion == "*" || cpeVersion == "-")
            {
                return true;
            }
            if (string.IsNullOrEmpty(queryVersion)) return false;
            return CpeMatcher.CompareVersions(queryVersion!, cpeVersion!) == 0;
        }

        if (range.Trim() == "*") return true;
        if (string.IsNullOrEmpty(queryVersion))
        {
            // No concrete version: a range is "specific", refuse to spray.
            return false;
        }

        // Comma-separated AND list of constraints: "<=1.11.10", ">=1.0.0,<2.0.0".
        foreach (var raw in range.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var c = raw.Trim();
            if (c.Length == 0) continue;
            string op;
            string boundary;
            if (c.StartsWith("<=", StringComparison.Ordinal)) { op = "<="; boundary = c[2..].Trim(); }
            else if (c.StartsWith(">=", StringComparison.Ordinal)) { op = ">="; boundary = c[2..].Trim(); }
            else if (c.StartsWith('<')) { op = "<"; boundary = c[1..].Trim(); }
            else if (c.StartsWith('>')) { op = ">"; boundary = c[1..].Trim(); }
            else if (c.StartsWith('=')) { op = "="; boundary = c[1..].Trim(); }
            else { op = "="; boundary = c; }

            int cmp = CpeMatcher.CompareVersions(queryVersion!, boundary);
            bool ok = op switch
            {
                "=" => cmp == 0,
                "<" => cmp < 0,
                "<=" => cmp <= 0,
                ">" => cmp > 0,
                ">=" => cmp >= 0,
                _ => false,
            };
            if (!ok) return false;
        }
        return true;
    }

    /// <summary>
    /// Best-effort CPE 2.3 parse: returns (vendor, product, version)
    /// with empty strings for missing slots. Tolerates short or
    /// malformed patterns so loader-time validation is permissive.
    /// </summary>
    internal static (string Vendor, string Product, string Version) ParseCpe(string cpe)
    {
        if (string.IsNullOrWhiteSpace(cpe)) return ("", "", "");
        var parts = cpe.Split(':');
        // cpe:2.3:a:vendor:product:version:...
        string vendor = parts.Length > 3 ? parts[3] : "";
        string product = parts.Length > 4 ? parts[4] : "";
        string version = parts.Length > 5 ? parts[5] : "";
        if (vendor == "*") vendor = "";
        return (vendor, product, version);
    }

    // --- loader -----------------------------------------------------------

    /// <summary>
    /// Load every curated corpus file under the given directory. Files
    /// must be JSON shaped per <see cref="CuratedCveDocument"/>. Bad
    /// files are skipped with their path recorded in <paramref name="errors"/>
    /// — one bad file does not poison the whole corpus.
    /// </summary>
    public static CuratedCveCorpus LoadFromDirectory(string dir, out IReadOnlyList<string> errors)
    {
        var errs = new List<string>();
        var entries = new List<CuratedCveEntry>();
        if (!Directory.Exists(dir))
        {
            errors = errs;
            return new CuratedCveCorpus(entries);
        }
        foreach (var path in Directory.EnumerateFiles(dir, "*.json", SearchOption.TopDirectoryOnly))
        {
            try
            {
                var json = File.ReadAllText(path);
                var doc = JsonSerializer.Deserialize<CuratedCveDocument>(json, JsonOpts);
                if (doc?.Entries is { Count: > 0 })
                {
                    entries.AddRange(doc.Entries.Where(e => !string.IsNullOrWhiteSpace(e.CveId)));
                }
            }
            catch (Exception ex)
            {
                errs.Add($"{path}: {ex.Message}");
            }
        }
        errors = errs;
        return new CuratedCveCorpus(entries);
    }

    /// <summary>
    /// Load embedded curated corpus files (resources whose name ends
    /// with <c>curated-cves.&lt;name&gt;.json</c>). Used by
    /// <see cref="CveAnnotator"/> when no on-disk override is provided.
    /// </summary>
    public static CuratedCveCorpus LoadEmbedded()
    {
        var asm = typeof(CuratedCveCorpus).Assembly;
        var entries = new List<CuratedCveEntry>();
        foreach (var name in asm.GetManifestResourceNames())
        {
            if (!name.Contains(".curated-cves.", StringComparison.OrdinalIgnoreCase)) continue;
            if (!name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                using var s = asm.GetManifestResourceStream(name);
                if (s is null) continue;
                using var r = new StreamReader(s);
                var doc = JsonSerializer.Deserialize<CuratedCveDocument>(r.ReadToEnd(), JsonOpts);
                if (doc?.Entries is { Count: > 0 })
                {
                    entries.AddRange(doc.Entries.Where(e => !string.IsNullOrWhiteSpace(e.CveId)));
                }
            }
            catch
            {
                // bad embedded file — skip silently; the on-disk loader
                // surfaces parse errors to operators via `errors`.
            }
        }
        return new CuratedCveCorpus(entries);
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };
}

/// <summary>One hand-curated CVE entry from <c>data/curated-cves/*.json</c>.</summary>
public sealed class CuratedCveEntry
{
    [JsonPropertyName("cpe_pattern")] public string CpePattern { get; set; } = "";
    [JsonPropertyName("version_range")] public string? VersionRange { get; set; }
    [JsonPropertyName("cve_id")] public string CveId { get; set; } = "";
    [JsonPropertyName("ghsa_id")] public string? GhsaId { get; set; }
    [JsonPropertyName("severity")] public string? Severity { get; set; }
    [JsonPropertyName("cvss")] public double? Cvss { get; set; }
    [JsonPropertyName("summary")] public string? Summary { get; set; }
    [JsonPropertyName("ref_urls")] public List<string> RefUrls { get; set; } = new();
}

internal sealed class CuratedCveDocument
{
    [JsonPropertyName("vendor")] public string? Vendor { get; set; }
    [JsonPropertyName("product")] public string? Product { get; set; }
    [JsonPropertyName("entries")] public List<CuratedCveEntry> Entries { get; set; } = new();
}

/// <summary>Match result returned by <see cref="CuratedCveCorpus"/>.</summary>
public sealed record CuratedCveMatch(
    string CveId,
    string? GhsaId,
    double? Cvss,
    string? Severity,
    string? Summary,
    IReadOnlyList<string> RefUrls);
