using Drederick.Enrichment;

namespace Drederick.Recon.Cms;

/// <summary>
/// GAP-034 (htb-cms-fingerprint-pack): in-code curated CVE pack for the
/// five HTB-tier CMS products covered by this fingerprint pack —
/// WordPress, Joomla!, Drupal, Magento (Adobe Commerce) and SuiteCRM.
/// Acts as a NVD-independent backstop: even when the offline NVD feed
/// has not been refreshed and even when the on-disk curated/ directory
/// is missing, every CMS fingerprint candidate flows through the
/// <see cref="AppliesTo"/> / <see cref="Match"/> pair and is annotated
/// with the headliner advisories operators expect to see on lab boxes
/// (Drupalgeddon I/II/III, CosmicSting, Joomla CVE-2023-23752, etc.).
/// Matching is biased toward false positives — when the fingerprinted
/// version is null/empty, every entry is emitted.
/// </summary>
public static class CmsCveCorpus
{
    /// <summary>
    /// Returns true when this pack should be consulted for the given
    /// (vendor, product) tuple. Accepts loose tuples (vendor-only or
    /// product-only) so signals recovered with partial metadata are
    /// still enriched.
    /// </summary>
    public static bool AppliesTo(string? vendor, string? product)
    {
        string v = (vendor ?? string.Empty).Trim().ToLowerInvariant();
        string p = (product ?? string.Empty).Trim().ToLowerInvariant();
        if (v == "wordpress" || p == "wordpress") return true;
        if (v == "joomla" || p == "joomla" || p == "joomla!") return true;
        if (v == "drupal" || p == "drupal") return true;
        if (v == "magento" || p == "magento" || v == "adobe" && p == "commerce") return true;
        if (v == "salesagility" || p == "suitecrm") return true;
        return false;
    }

    /// <summary>
    /// Match the curated pack against an optional fingerprinted version.
    /// When <paramref name="version"/> is null/empty, every entry for
    /// the resolved product is emitted (false-positive bias). Caller
    /// is responsible for deduplicating against NVD-driven matches.
    /// </summary>
    public static IReadOnlyList<CuratedCveMatch> Match(string? vendor, string? product, string? version)
    {
        var entries = SelectEntries(vendor, product);
        if (entries.Count == 0) return Array.Empty<CuratedCveMatch>();
        var output = new List<CuratedCveMatch>(entries.Count);
        foreach (var e in entries)
        {
            if (!VersionInRange(e.VersionRange, version)) continue;
            output.Add(new CuratedCveMatch(
                e.CveId, e.GhsaId, e.Cvss, e.Severity, e.Summary, e.RefUrls));
        }
        return output;
    }

    /// <summary>All curated entries across the five products — for tests.</summary>
    public static IReadOnlyList<CuratedCveEntry> AllEntries()
    {
        var all = new List<CuratedCveEntry>(
            WordPressEntries.Count + JoomlaEntries.Count + DrupalEntries.Count +
            MagentoEntries.Count + SuiteCrmEntries.Count);
        all.AddRange(WordPressEntries);
        all.AddRange(JoomlaEntries);
        all.AddRange(DrupalEntries);
        all.AddRange(MagentoEntries);
        all.AddRange(SuiteCrmEntries);
        return all;
    }

    private static IReadOnlyList<CuratedCveEntry> SelectEntries(string? vendor, string? product)
    {
        string v = (vendor ?? string.Empty).Trim().ToLowerInvariant();
        string p = (product ?? string.Empty).Trim().ToLowerInvariant();
        if (v == "wordpress" || p == "wordpress") return WordPressEntries;
        if (v == "joomla" || p == "joomla" || p == "joomla!") return JoomlaEntries;
        if (v == "drupal" || p == "drupal") return DrupalEntries;
        if (v == "magento" || p == "magento" || (v == "adobe" && p == "commerce")) return MagentoEntries;
        if (v == "salesagility" || p == "suitecrm") return SuiteCrmEntries;
        return Array.Empty<CuratedCveEntry>();
    }

    private static readonly IReadOnlyList<CuratedCveEntry> WordPressEntries = new List<CuratedCveEntry>
    {
        new()
        {
            CpePattern = "cpe:2.3:a:wordpress:wordpress:*",
            VersionRange = "<=4.7.1",
            CveId = "CVE-2017-1001000",
            Severity = "high", Cvss = 7.5,
            Summary = "WordPress REST API content-injection: unauthenticated attackers can modify the content of any post or page (4.7.0/4.7.1).",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2017-1001000" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:wordpress:wordpress:*",
            VersionRange = "<=4.9.6",
            CveId = "CVE-2019-8942",
            Severity = "high", Cvss = 8.8,
            Summary = "WordPress image-upload to remote code execution via crafted Post Meta entry (chained with image upload).",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2019-8942" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:wordpress:wordpress:*",
            VersionRange = "<=5.0.0",
            CveId = "CVE-2019-8943",
            Severity = "high", Cvss = 7.5,
            Summary = "WordPress path-traversal in image-crop functionality, enabling RCE chain alongside CVE-2019-8942.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2019-8943" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:wordpress:wordpress:*",
            VersionRange = "<=5.7.1",
            CveId = "CVE-2021-29447",
            Severity = "medium", Cvss = 6.5,
            Summary = "WordPress XXE in media library via wp-xmlrpc/PHP libxml processing of crafted WAV uploads.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2021-29447" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:wordpress:wordpress:*",
            VersionRange = "<=5.8.2",
            CveId = "CVE-2022-21661",
            Severity = "high", Cvss = 8.0,
            Summary = "WordPress SQL injection via WP_Query taxonomy parameter — auth required, but a low-privilege user can read arbitrary tables.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2022-21661" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:wordpress:wordpress:*",
            VersionRange = "<=6.2.0",
            CveId = "CVE-2023-2745",
            Severity = "medium", Cvss = 5.4,
            Summary = "WordPress directory-traversal in wp_lang allowing arbitrary language file load (info-disclosure / pre-auth marker).",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2023-2745" },
        },
    };

    private static readonly IReadOnlyList<CuratedCveEntry> JoomlaEntries = new List<CuratedCveEntry>
    {
        new()
        {
            CpePattern = "cpe:2.3:a:joomla:joomla\\!:*",
            VersionRange = "<=3.4.5",
            CveId = "CVE-2015-8562",
            Severity = "critical", Cvss = 9.8,
            Summary = "Joomla! unauthenticated remote code execution via crafted User-Agent / X-Forwarded-For session payload.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2015-8562" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:joomla:joomla\\!:*",
            VersionRange = "<=3.7.0",
            CveId = "CVE-2017-8917",
            Severity = "critical", Cvss = 9.8,
            Summary = "Joomla! SQL injection in com_fields (3.7.0): pre-auth attacker can extract session tokens for the admin user.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2017-8917" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:joomla:joomla\\!:*",
            VersionRange = ">=4.0.0,<=4.2.7",
            CveId = "CVE-2023-23752",
            Severity = "high", Cvss = 7.5,
            Summary = "Joomla! improper access control on the /api/index.php/v1/config/application* endpoint — unauthenticated read of MySQL credentials.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2023-23752" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:joomla:joomla\\!:*",
            VersionRange = "<=3.10.6",
            CveId = "CVE-2022-23797",
            Severity = "medium", Cvss = 5.3,
            Summary = "Joomla! information disclosure on the install endpoint — config values reachable when /installation/ is not removed post-setup.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2022-23797" },
        },
    };

    private static readonly IReadOnlyList<CuratedCveEntry> DrupalEntries = new List<CuratedCveEntry>
    {
        new()
        {
            CpePattern = "cpe:2.3:a:drupal:drupal:*",
            VersionRange = "<=8.5.0",
            CveId = "CVE-2018-7600",
            Severity = "critical", Cvss = 9.8,
            Summary = "Drupalgeddon2 — unauthenticated remote code execution via form-render array injection (Drupal 7.x/8.x).",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2018-7600" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:drupal:drupal:*",
            VersionRange = "<=8.5.1",
            CveId = "CVE-2018-7602",
            Severity = "critical", Cvss = 9.8,
            Summary = "Drupalgeddon3 — authenticated remote code execution via second-stage form-render injection, follow-on to CVE-2018-7600.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2018-7602" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:drupal:drupal:*",
            VersionRange = "<=8.6.10",
            CveId = "CVE-2019-6340",
            Severity = "critical", Cvss = 9.8,
            Summary = "Drupal REST module unserialize() RCE — unauthenticated when /node REST endpoints are exposed (rest module enabled).",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2019-6340" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:drupal:drupal:*",
            VersionRange = "<=8.8.1",
            CveId = "CVE-2020-13671",
            Severity = "high", Cvss = 8.8,
            Summary = "Drupal file-upload sanitisation bypass — double-extension attachments execute as PHP under default file handler config.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2020-13671" },
        },
    };

    private static readonly IReadOnlyList<CuratedCveEntry> MagentoEntries = new List<CuratedCveEntry>
    {
        new()
        {
            CpePattern = "cpe:2.3:a:magento:magento:*",
            VersionRange = "<=2.2.6",
            CveId = "CVE-2019-8144",
            Severity = "critical", Cvss = 9.8,
            Summary = "Magento Page Builder template injection — pre-auth RCE via crafted preview template parameter.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2019-8144" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:magento:magento:*",
            VersionRange = "<=2.3.7",
            CveId = "CVE-2022-24086",
            Severity = "critical", Cvss = 9.8,
            Summary = "Magento / Adobe Commerce input-validation flaw during checkout — pre-auth remote code execution.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2022-24086" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:magento:magento:*",
            VersionRange = "<=2.4.6",
            CveId = "CVE-2024-34102",
            Severity = "critical", Cvss = 9.8,
            Summary = "Adobe Commerce / Magento CosmicSting — XXE leading to remote code execution via REST endpoint.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2024-34102" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:magento:magento:*",
            VersionRange = "<=2.4.5",
            CveId = "CVE-2022-35698",
            Severity = "high", Cvss = 8.6,
            Summary = "Adobe Commerce / Magento DoS via mass-assignment in the customer-address endpoint; chains with CosmicSting on lab targets.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2022-35698" },
        },
    };

    private static readonly IReadOnlyList<CuratedCveEntry> SuiteCrmEntries = new List<CuratedCveEntry>
    {
        new()
        {
            CpePattern = "cpe:2.3:a:salesagility:suitecrm:*",
            VersionRange = "<=7.14.2",
            CveId = "CVE-2023-6886",
            Severity = "critical", Cvss = 9.8,
            Summary = "SuiteCRM authenticated remote code execution via crafted module file upload — chains with default install credentials.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2023-6886" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:salesagility:suitecrm:*",
            VersionRange = "<=7.14.3",
            CveId = "CVE-2024-36412",
            Severity = "critical", Cvss = 9.8,
            Summary = "SuiteCRM unauthenticated SQL injection in /api/v8 — extracts admin password hash for offline crack.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2024-36412" },
        },
        new()
        {
            CpePattern = "cpe:2.3:a:salesagility:suitecrm:*",
            VersionRange = "<=7.12.5",
            CveId = "CVE-2022-23940",
            Severity = "high", Cvss = 8.8,
            Summary = "SuiteCRM PHP object-injection via crafted MergeRecord workflow — authenticated RCE.",
            RefUrls = new List<string> { "https://nvd.nist.gov/vuln/detail/CVE-2022-23940" },
        },
    };

    private static bool VersionInRange(string? range, string? version)
    {
        if (string.IsNullOrWhiteSpace(range) || range.Trim() == "*") return true;
        if (string.IsNullOrWhiteSpace(version))
        {
            // No fingerprinted version → emit (false-positive bias).
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
