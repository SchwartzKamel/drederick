using System.Text.Json.Serialization;

namespace Drederick.Recon.Binary;

/// <summary>
/// Represents a single security finding, dependency issue, or metadata anomaly
/// discovered during binary analysis.
/// </summary>
public sealed class BinaryFinding
{
    /// <summary>
    /// Severity level of the finding.
    /// </summary>
    [JsonPropertyName("severity")]
    public FindingSeverity Severity { get; set; } = FindingSeverity.Info;

    /// <summary>
    /// Category of the finding for organizational and filtering purposes.
    /// </summary>
    [JsonPropertyName("category")]
    public FindingCategory Category { get; set; } = FindingCategory.Metadata;

    /// <summary>
    /// Short, human-readable title describing the finding.
    /// </summary>
    [JsonPropertyName("title")]
    public string Title { get; set; } = "";

    /// <summary>
    /// Detailed description explaining what was found and why it matters.
    /// </summary>
    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    /// <summary>
    /// Optional remediation steps or mitigation advice for the finding.
    /// </summary>
    [JsonPropertyName("remediation")]
    public string? Remediation { get; set; }
}

/// <summary>
/// Severity levels for binary analysis findings.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FindingSeverity
{
    Info,
    Warning,
    Critical
}

/// <summary>
/// Categories for organizing and filtering binary analysis findings.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FindingCategory
{
    Metadata,
    Security,
    Dependency,
    Suspicious
}
