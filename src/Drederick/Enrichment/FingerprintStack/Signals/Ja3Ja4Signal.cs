namespace Drederick.Enrichment.FingerprintStack.Signals;

/// <summary>
/// Placeholder JA3 / JA4 fingerprint corpus. Real corpora can be slotted
/// in by extending <c>_ja3</c> / <c>_ja4</c>; weights are intentionally
/// modest (0.4) since JA3 collisions across products are common.
/// </summary>
public sealed class Ja3Ja4Signal : IFingerprintSignal
{
    public string Name => "ja3-ja4";

    private const double Weight = 0.4;

    // Synthetic placeholders; replace with curated corpus when available.
    private static readonly Dictionary<string, (string Vendor, string Product)> _ja3
        = new(StringComparer.OrdinalIgnoreCase);

    private static readonly Dictionary<string, (string Vendor, string Product)> _ja4
        = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<FingerprintSignalHit> Extract(FingerprintInput input)
    {
        var hits = new List<FingerprintSignalHit>();
        if (!string.IsNullOrWhiteSpace(input.Ja3) && _ja3.TryGetValue(input.Ja3!, out var ja3hit))
        {
            hits.Add(new FingerprintSignalHit(
                Name, ja3hit.Vendor, ja3hit.Product, null, Weight, $"ja3={input.Ja3}"));
        }
        if (!string.IsNullOrWhiteSpace(input.Ja4) && _ja4.TryGetValue(input.Ja4!, out var ja4hit))
        {
            hits.Add(new FingerprintSignalHit(
                Name, ja4hit.Vendor, ja4hit.Product, null, Weight, $"ja4={input.Ja4}"));
        }
        return hits;
    }
}
