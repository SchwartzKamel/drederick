namespace Drederick.Doctor;

/// <summary>
/// Detection snapshot for a single operator-workstation tool.
/// </summary>
public sealed record ToolInfo(
    string Name,
    bool Found,
    string? Version,
    string? Path,
    DateTimeOffset DetectedAt);
