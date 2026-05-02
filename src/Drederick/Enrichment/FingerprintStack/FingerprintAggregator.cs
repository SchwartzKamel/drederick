using Drederick.Enrichment.FingerprintStack.Signals;

namespace Drederick.Enrichment.FingerprintStack;

/// <summary>
/// Merges per-signal hits into ranked <see cref="FingerprintCandidate"/>s
/// using a noisy-OR aggregation:
/// <c>combined = 1 - prod(1 - weight_i)</c>, capped at <see cref="MaxConfidence"/>.
/// Hits collapse on a normalized (vendor|product|version) lowercase key,
/// then candidates below <see cref="MinReportConfidence"/> are dropped.
/// </summary>
public sealed class FingerprintAggregator
{
    public const double MaxConfidence = 0.99;
    public const double MinReportConfidence = 0.30;

    public IReadOnlyList<FingerprintCandidate> Aggregate(IEnumerable<FingerprintSignalHit> hits)
    {
        var grouped = new Dictionary<string, List<FingerprintSignalHit>>(StringComparer.Ordinal);
        foreach (var h in hits)
        {
            var key = NormalizeKey(h.Vendor, h.Product, h.Version);
            if (!grouped.TryGetValue(key, out var list))
                grouped[key] = list = new List<FingerprintSignalHit>();
            list.Add(h);
        }

        var candidates = new List<FingerprintCandidate>(grouped.Count);
        foreach (var (_, list) in grouped)
        {
            double notProd = 1.0;
            foreach (var h in list)
            {
                var w = Math.Clamp(h.Weight, 0.0, 1.0);
                notProd *= (1.0 - w);
            }
            var combined = Math.Min(MaxConfidence, 1.0 - notProd);
            if (combined < MinReportConfidence) continue;

            var first = list[0];
            var c = new FingerprintCandidate
            {
                Vendor = (first.Vendor ?? "").ToLowerInvariant(),
                Product = (first.Product ?? "").ToLowerInvariant(),
                Version = first.Version,
                Confidence = Math.Round(combined, 4),
                Cpe = BuildCpe(first.Vendor, first.Product, first.Version),
            };
            foreach (var h in list)
            {
                c.Signals.Add(new FingerprintSignalContribution
                {
                    Signal = h.Signal,
                    Weight = h.Weight,
                    Evidence = h.Evidence,
                });
            }
            candidates.Add(c);
        }

        candidates.Sort((a, b) => b.Confidence.CompareTo(a.Confidence));
        return candidates;
    }

    private static string NormalizeKey(string? vendor, string? product, string? version)
        => $"{(vendor ?? "").Trim().ToLowerInvariant()}|" +
           $"{(product ?? "").Trim().ToLowerInvariant()}|" +
           $"{(version ?? "").Trim().ToLowerInvariant()}";

    /// <summary>
    /// Build a CPE 2.3 URI:
    /// <c>cpe:2.3:a:&lt;vendor&gt;:&lt;product&gt;:&lt;version&gt;:*:*:*:*:*:*:*</c>.
    /// Components are sanitized (lowercased, spaces → underscore, control
    /// chars stripped) and unknowns become <c>*</c>.
    /// </summary>
    public static string BuildCpe(string? vendor, string? product, string? version)
    {
        var v = Sanitize(vendor);
        var p = Sanitize(product);
        var ver = Sanitize(version);
        if (v.Length == 0) v = "*";
        if (p.Length == 0) p = "*";
        if (ver.Length == 0) ver = "*";
        return $"cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*";
    }

    private static string Sanitize(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "";
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var ch in s.Trim().ToLowerInvariant())
        {
            if (char.IsLetterOrDigit(ch) || ch == '.' || ch == '-' || ch == '_')
                sb.Append(ch);
            else if (char.IsWhiteSpace(ch))
                sb.Append('_');
            // drop everything else
        }
        return sb.ToString();
    }
}
