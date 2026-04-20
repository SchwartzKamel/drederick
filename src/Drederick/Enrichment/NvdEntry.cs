namespace Drederick.Enrichment;

/// <summary>
/// Flattened representation of a single CVE record from the NVD JSON 2.0 feed,
/// with just the fields CpeMatcher / CveAnnotator actually consume.
/// </summary>
public sealed class NvdEntry
{
    public string CveId { get; init; } = "";
    public string? Summary { get; init; }
    public string? Published { get; init; }
    public double? Cvss { get; init; }
    public List<NvdCpeMatch> CpeMatches { get; init; } = new();
}

public sealed class NvdCpeMatch
{
    public string Criteria { get; init; } = "";
    public string? Vendor { get; init; }
    public string? Product { get; init; }
    public string? Version { get; init; } // "*" means any, "-" means NA
    public string? VersionStartIncluding { get; init; }
    public string? VersionStartExcluding { get; init; }
    public string? VersionEndIncluding { get; init; }
    public string? VersionEndExcluding { get; init; }
    public bool Vulnerable { get; init; } = true;
}
