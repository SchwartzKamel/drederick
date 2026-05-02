namespace Drederick.Enrichment.FingerprintStack.Signals;

/// <summary>
/// Looks up <see cref="FingerprintInput.FaviconSha256"/> against the
/// embedded favicon corpus. Hits score 0.7 — distinctive favicons are
/// strong tells but software with shared static defaults (Bootstrap
/// starter, blank ICO) collide.
/// </summary>
public sealed class FaviconSha256Signal : IFingerprintSignal
{
    public string Name => "favicon-sha256";

    private const double Weight = 0.7;

    private readonly FaviconCorpus _corpus;

    public FaviconSha256Signal(FaviconCorpus corpus)
    {
        _corpus = corpus;
    }

    public IReadOnlyList<FingerprintSignalHit> Extract(FingerprintInput input)
    {
        if (string.IsNullOrWhiteSpace(input.FaviconSha256))
            return Array.Empty<FingerprintSignalHit>();
        if (!_corpus.TryLookup(input.FaviconSha256!, out var entry))
            return Array.Empty<FingerprintSignalHit>();
        return new[]
        {
            new FingerprintSignalHit(
                Name, entry.Vendor, entry.Product, entry.Version, Weight,
                $"favicon sha256={input.FaviconSha256}"),
        };
    }
}
