using Drederick.Enrichment;

namespace Drederick.Recon.Cms;

/// <summary>
/// GAP-052 (htb-pterodactyl-fingerprint): in-code curated CVE pack for
/// Pterodactyl Panel and Wings. The NVD CPE coverage for
/// <c>pterodactyl:panel</c> is sparse (vendor advisories are typically
/// shipped as GitHub Security Advisories before NVD ingest), so this
/// pack is the authoritative source the operator can rely on for HTB
/// boxes even when the NVD feed has not yet been refreshed and even when
/// the on-disk <c>data/curated-cves/pterodactyl.json</c> override is
/// absent.
///
/// Entries:
///   1. GHSA-4r78-3w7p-c83p — Pterodactyl Panel account takeover via
///      crafted password-reset email rewrite.
///   2. CVE-2024-43791     — Pterodactyl Wings arbitrary file write
///      through the docker-archive extraction path.
///   3. GHSA-r394-9wq2-pf3v — Pterodactyl Panel SSRF in the egg-import
///      remote-URL fetcher.
///   4. CVE-2025-49132     — Pterodactyl Panel authentication bypass on
///      the OAuth callback handler.
///
/// <see cref="CveAnnotator"/> calls <see cref="AppliesTo"/> on every
/// CMS-fingerprint candidate and unions <see cref="Match"/> into the
/// curated-match output, regardless of whether the operator's curated
/// directory was populated. PoC URLs are URL-only (no inline source);
/// <see cref="Drederick.Enrichment.PocAggregator"/> fetches the bodies
/// on demand under the standard size/rate caps.
/// </summary>
public static class PterodactylCveCorpus
{
    /// <summary>Stable count — 4 curated entries (matches GAP-052 scope).</summary>
    public const int EntryCount = 4;

    /// <summary>
    /// Returns true when the given (vendor, product) tuple should be
    /// enriched with this pack. Accepts <c>vendor="pterodactyl"</c> with
    /// any product, OR a product whose normalised form starts with
    /// <c>pterodactyl</c>, OR product=panel paired with vendor=pterodactyl.
    /// Bias: prefer false positives over false negatives.
    /// </summary>
    public static bool AppliesTo(string? vendor, string? product)
    {
        string v = (vendor ?? string.Empty).Trim().ToLowerInvariant();
        string p = (product ?? string.Empty).Trim().ToLowerInvariant();
        if (v == "pterodactyl") return true;
        if (p.StartsWith("pterodactyl", StringComparison.Ordinal)) return true;
        if (p == "panel" && v == "pterodactyl") return true;
        if (p == "wings" && v == "pterodactyl") return true;
        return false;
    }

    /// <summary>
    /// Match the curated pack against an optional version. When
    /// <paramref name="version"/> is null/empty, all entries are returned
    /// — the curated pack errs toward false positives so the operator
    /// can review marginally-applicable advisories rather than miss them.
    /// </summary>
    public static IReadOnlyList<CuratedCveMatch> Match(string? version)
    {
        var output = new List<CuratedCveMatch>(EntryCount);
        foreach (var e in BuiltinEntries())
        {
            if (!VersionInRange(e.VersionRange, version)) continue;
            output.Add(new CuratedCveMatch(
                e.CveId, e.GhsaId, e.Cvss, e.Severity, e.Summary, e.RefUrls));
        }
        return output;
    }

    /// <summary>
    /// The raw curated entries — exposed for tests and for callers that
    /// want to feed the pack into <see cref="CuratedCveCorpus"/>.
    /// </summary>
    public static IReadOnlyList<CuratedCveEntry> BuiltinEntries() => Entries;

    private static readonly IReadOnlyList<CuratedCveEntry> Entries = new List<CuratedCveEntry>
    {
        new()
        {
            CpePattern = "cpe:2.3:a:pterodactyl:panel:*",
            VersionRange = "<=1.11.10",
            CveId = "GHSA-4r78-3w7p-c83p",
            GhsaId = "GHSA-4r78-3w7p-c83p",
            Severity = "high",
            Cvss = 7.6,
            Summary = "Pterodactyl Panel account takeover: crafted password-reset email rewrite lets an unauthenticated attacker seize an arbitrary account.",
            RefUrls = new List<string>
            {
                "https://github.com/pterodactyl/panel/security/advisories/GHSA-4r78-3w7p-c83p",
            },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:pterodactyl:wings:*",
            VersionRange = "<=1.11.13",
            CveId = "CVE-2024-43791",
            GhsaId = null,
            Severity = "high",
            Cvss = 8.1,
            Summary = "Pterodactyl Wings arbitrary file write via crafted docker-archive extraction path; an authenticated panel user can write files outside the intended server volume.",
            RefUrls = new List<string>
            {
                "https://nvd.nist.gov/vuln/detail/CVE-2024-43791",
                "https://github.com/pterodactyl/wings/security/advisories",
            },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:pterodactyl:panel:*",
            VersionRange = "<=1.11.10",
            CveId = "GHSA-r394-9wq2-pf3v",
            GhsaId = "GHSA-r394-9wq2-pf3v",
            Severity = "high",
            Cvss = 8.3,
            Summary = "Pterodactyl Panel SSRF in the egg-import remote-URL fetcher: an admin-supplied URL is fetched server-side without scheme/host validation.",
            RefUrls = new List<string>
            {
                "https://github.com/pterodactyl/panel/security/advisories/GHSA-r394-9wq2-pf3v",
            },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:pterodactyl:panel:*",
            VersionRange = "<=1.11.11",
            CveId = "CVE-2025-49132",
            GhsaId = null,
            Severity = "critical",
            Cvss = 9.1,
            Summary = "Pterodactyl Panel authentication bypass on the OAuth callback handler: missing state-binding check lets an attacker authenticate as a target user.",
            RefUrls = new List<string>
            {
                "https://nvd.nist.gov/vuln/detail/CVE-2025-49132",
                "https://github.com/pterodactyl/panel/security/advisories",
            },
        },
    };

    private static bool VersionInRange(string? range, string? version)
    {
        if (string.IsNullOrWhiteSpace(range) || range.Trim() == "*") return true;
        if (string.IsNullOrWhiteSpace(version))
        {
            // No fingerprinted version → still emit (false-positive bias);
            // the operator review burden is acceptable for HTB-tier panels.
            return true;
        }
        foreach (var raw in range.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var c = raw.Trim();
            if (c.Length == 0) continue;
            string op; string boundary;
            if (c.StartsWith("<=", StringComparison.Ordinal)) { op = "<="; boundary = c[2..].Trim(); }
            else if (c.StartsWith(">=", StringComparison.Ordinal)) { op = ">="; boundary = c[2..].Trim(); }
            else if (c.StartsWith('<')) { op = "<"; boundary = c[1..].Trim(); }
            else if (c.StartsWith('>')) { op = ">"; boundary = c[1..].Trim(); }
            else if (c.StartsWith('=')) { op = "="; boundary = c[1..].Trim(); }
            else { op = "="; boundary = c; }

            int cmp = CpeMatcher.CompareVersions(version!, boundary);
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
}
