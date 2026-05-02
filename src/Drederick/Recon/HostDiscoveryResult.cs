using System.Text.Json.Serialization;

namespace Drederick.Recon;

/// <summary>
/// Result of a fast TCP-knock host-discovery sweep against a single target.
/// Populated by <see cref="HostDiscoveryTool"/>; kept in its own file so the
/// canonical <see cref="HostFinding"/> shape is not modified by recon-zone
/// agents working in parallel.
/// </summary>
public sealed class HostDiscoveryResult
{
    [JsonPropertyName("target")]
    public string Target { get; set; } = "";

    [JsonPropertyName("alive")]
    public bool Alive { get; set; }

    [JsonPropertyName("responding_ports")]
    public List<int> RespondingPorts { get; set; } = new();

    [JsonPropertyName("probe_duration_ms")]
    public long ProbeDurationMs { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}
