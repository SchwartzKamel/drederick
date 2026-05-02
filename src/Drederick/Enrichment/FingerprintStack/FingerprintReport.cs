using System.Text.Json.Serialization;

namespace Drederick.Enrichment.FingerprintStack;

/// <summary>
/// Per-port fingerprint result attached to <c>HostFinding.Fingerprint</c>.
/// Holds the ranked candidate list together with the source port and any
/// pipeline error.
/// </summary>
public sealed class FingerprintReport
{
    [JsonPropertyName("port")] public int? Port { get; set; }
    [JsonPropertyName("candidates")] public List<FingerprintCandidate> Candidates { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

/// <summary>
/// Single (vendor, product, version) fingerprint candidate with merged
/// confidence, contributing signals, and a CPE 2.3 string suitable for
/// CVE matching.
/// </summary>
public sealed class FingerprintCandidate
{
    [JsonPropertyName("vendor")] public string Vendor { get; set; } = "";
    [JsonPropertyName("product")] public string Product { get; set; } = "";
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("confidence")] public double Confidence { get; set; }
    [JsonPropertyName("cpe")] public string Cpe { get; set; } = "";
    [JsonPropertyName("signals")] public List<FingerprintSignalContribution> Signals { get; set; } = new();
}

/// <summary>
/// Per-signal contribution to a merged candidate. Captures the originating
/// signal name, the raw weight it emitted, and the evidence string so the
/// operator (and the LLM planner) can audit *why* a candidate ranked.
/// </summary>
public sealed class FingerprintSignalContribution
{
    [JsonPropertyName("signal")] public string Signal { get; set; } = "";
    [JsonPropertyName("weight")] public double Weight { get; set; }
    [JsonPropertyName("evidence")] public string? Evidence { get; set; }
}
