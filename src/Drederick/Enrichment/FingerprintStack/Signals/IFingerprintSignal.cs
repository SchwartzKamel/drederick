namespace Drederick.Enrichment.FingerprintStack.Signals;

/// <summary>
/// One pluggable fingerprint signal. Pure function from
/// <see cref="FingerprintInput"/> to a list of weighted candidate hits.
/// Implementations must be deterministic and side-effect-free; all I/O is
/// performed up-front by <see cref="FingerprintStackTool"/>.
/// </summary>
public interface IFingerprintSignal
{
    /// <summary>Stable kebab-case identifier (e.g. "banner", "tls-cert").</summary>
    string Name { get; }

    IReadOnlyList<FingerprintSignalHit> Extract(FingerprintInput input);
}

/// <summary>
/// One (vendor, product, version) candidate emitted by a single signal,
/// with a weight in [0, 1]. Weights are interpreted as the per-signal
/// probability that the candidate is correct; the aggregator combines
/// them using a noisy-OR.
/// </summary>
public sealed record FingerprintSignalHit(
    string Signal,
    string Vendor,
    string Product,
    string? Version,
    double Weight,
    string? Evidence = null
);
