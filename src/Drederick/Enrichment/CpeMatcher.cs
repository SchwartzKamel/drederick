namespace Drederick.Enrichment;

/// <summary>
/// Single match result from <see cref="CpeMatcher"/>.
/// </summary>
public sealed record CveMatch(string CveId, double? Cvss, string? Summary, string? Published);

/// <summary>
/// Matches a (vendor?, product, version?) tuple against parsed NVD entries.
/// Matching is deliberately simple and permissive:
///   * vendor / product compared case-insensitively after light normalization
///     (underscores / hyphens / spaces collapsed)
///   * if vendor is unknown we fall back to product-only matching
///   * version is matched either exactly against the CPE's own version, or
///     against the versionStartIncluding / versionEndExcluding style range
/// </summary>
public sealed class CpeMatcher
{
    private readonly IReadOnlyList<NvdEntry> _entries;

    public CpeMatcher(IReadOnlyList<NvdEntry> entries)
    {
        _entries = entries ?? throw new ArgumentNullException(nameof(entries));
    }

    public IReadOnlyList<CveMatch> Match(string? vendor, string product, string? version)
    {
        if (string.IsNullOrWhiteSpace(product)) return Array.Empty<CveMatch>();
        var nProduct = Normalize(product);
        var nVendor = Normalize(vendor);

        var results = new List<CveMatch>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in _entries)
        {
            foreach (var cpe in entry.CpeMatches)
            {
                if (!cpe.Vulnerable) continue;
                var cpeProduct = Normalize(cpe.Product);
                if (cpeProduct.Length == 0 || cpeProduct == "*") continue;
                if (!ProductsMatch(cpeProduct, nProduct)) continue;

                if (!string.IsNullOrEmpty(nVendor))
                {
                    var cpeVendor = Normalize(cpe.Vendor);
                    if (cpeVendor.Length > 0 && cpeVendor != "*" && cpeVendor != nVendor)
                    {
                        continue;
                    }
                }

                if (!VersionMatches(cpe, version)) continue;

                if (seen.Add(entry.CveId))
                {
                    results.Add(new CveMatch(entry.CveId, entry.Cvss, entry.Summary, entry.Published));
                }
                break; // one CPE hit per entry is enough
            }
        }
        return results;
    }

    private static bool ProductsMatch(string cpeProduct, string queryProduct)
    {
        if (cpeProduct == queryProduct) return true;
        // be slightly forgiving so "openssh_server" matches "openssh"
        if (cpeProduct.StartsWith(queryProduct, StringComparison.Ordinal) ||
            queryProduct.StartsWith(cpeProduct, StringComparison.Ordinal))
        {
            return true;
        }
        return false;
    }

    private static bool VersionMatches(NvdCpeMatch cpe, string? queryVersion)
    {
        var hasRange = cpe.VersionStartIncluding is not null
            || cpe.VersionStartExcluding is not null
            || cpe.VersionEndIncluding is not null
            || cpe.VersionEndExcluding is not null;

        // No concrete version from the scanner — only return the CVE if the
        // CPE itself is unrestricted ("*") so we don't spray every version.
        if (string.IsNullOrWhiteSpace(queryVersion))
        {
            return !hasRange && (string.IsNullOrEmpty(cpe.Version) || cpe.Version == "*" || cpe.Version == "-");
        }

        if (hasRange)
        {
            return InRange(queryVersion!, cpe);
        }

        // Exact version comparison — normalize both sides.
        if (string.IsNullOrEmpty(cpe.Version) || cpe.Version == "*")
        {
            return true; // "any version"
        }
        if (cpe.Version == "-") return false;
        return VersionsEqual(cpe.Version!, queryVersion!);
    }

    private static bool InRange(string version, NvdCpeMatch cpe)
    {
        int Cmp(string? boundary) => boundary is null ? 0 : CompareVersions(version, boundary);

        if (cpe.VersionStartIncluding is not null && Cmp(cpe.VersionStartIncluding) < 0) return false;
        if (cpe.VersionStartExcluding is not null && Cmp(cpe.VersionStartExcluding) <= 0) return false;
        if (cpe.VersionEndIncluding is not null && Cmp(cpe.VersionEndIncluding) > 0) return false;
        if (cpe.VersionEndExcluding is not null && Cmp(cpe.VersionEndExcluding) >= 0) return false;
        return true;
    }

    private static bool VersionsEqual(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;
        return CompareVersions(a, b) == 0;
    }

    /// <summary>
    /// Dotted-integer-with-trailing-tag comparison. "8.4p1" is split into
    /// numeric segments "8", "4" and then a tag "p1". Mostly sufficient for
    /// the CPE-style version strings seen in NVD.
    /// </summary>
    internal static int CompareVersions(string a, string b)
    {
        var sa = Tokenize(a);
        var sb = Tokenize(b);
        int n = Math.Max(sa.Count, sb.Count);
        for (int i = 0; i < n; i++)
        {
            var ta = i < sa.Count ? sa[i] : "0";
            var tb = i < sb.Count ? sb[i] : "0";
            if (int.TryParse(ta, out var ia) && int.TryParse(tb, out var ib))
            {
                if (ia != ib) return ia.CompareTo(ib);
            }
            else
            {
                var c = string.Compare(ta, tb, StringComparison.OrdinalIgnoreCase);
                if (c != 0) return c;
            }
        }
        return 0;
    }

    private static List<string> Tokenize(string v)
    {
        // Split on '.', and split numeric / alpha runs within each segment.
        var segments = v.Split('.');
        var tokens = new List<string>();
        foreach (var seg in segments)
        {
            if (string.IsNullOrEmpty(seg)) continue;
            int i = 0;
            while (i < seg.Length)
            {
                int j = i;
                bool digit = char.IsDigit(seg[j]);
                while (j < seg.Length && char.IsDigit(seg[j]) == digit) j++;
                tokens.Add(seg[i..j]);
                i = j;
            }
        }
        return tokens;
    }

    internal static string Normalize(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return string.Empty;
        return s.Trim()
            .ToLowerInvariant()
            .Replace(' ', '_')
            .Replace('-', '_');
    }
}
