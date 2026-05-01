using System.Text.Json.Serialization;

namespace Drederick.Memory;

/// <summary>
/// Bloodhound / SharpHound ingestion findings. Populated by
/// <see cref="SharpHoundIngest"/>. We keep this intentionally narrow —
/// only the high-signal fields a planner cares about (kerberoastable,
/// asreproastable, unconstrained delegation, high-value membership,
/// computer DNSHostName for KB-host joins). The full ACE / session /
/// LocalAdmin graph is left in the original on-disk SharpHound zip
/// for the operator to query directly with bloodhound-cli or the
/// BloodHound UI.
/// </summary>
public sealed class BloodhoundFindings
{
    [JsonPropertyName("source_zip")] public string? SourceZip { get; set; }
    [JsonPropertyName("ingested_at")] public string? IngestedAt { get; set; }
    [JsonPropertyName("domain_count")] public int DomainCount { get; set; }
    [JsonPropertyName("computers")] public List<BloodhoundComputer> Computers { get; set; } = new();
    [JsonPropertyName("users")] public List<BloodhoundUser> Users { get; set; } = new();
    [JsonPropertyName("groups")] public List<BloodhoundGroup> Groups { get; set; } = new();
    [JsonPropertyName("high_value_groups")] public List<string> HighValueGroups { get; set; } = new();
}

public sealed class BloodhoundComputer
{
    [JsonPropertyName("object_id")] public string ObjectId { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("dns_host_name")] public string? DnsHostName { get; set; }
    [JsonPropertyName("domain")] public string? Domain { get; set; }
    [JsonPropertyName("operating_system")] public string? OperatingSystem { get; set; }
    [JsonPropertyName("enabled")] public bool? Enabled { get; set; }
    [JsonPropertyName("high_value")] public bool HighValue { get; set; }
    [JsonPropertyName("unconstrained_delegation")] public bool UnconstrainedDelegation { get; set; }
    [JsonPropertyName("has_laps")] public bool? HasLaps { get; set; }
    [JsonPropertyName("owned")] public bool Owned { get; set; }
}

public sealed class BloodhoundUser
{
    [JsonPropertyName("object_id")] public string ObjectId { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("domain")] public string? Domain { get; set; }
    [JsonPropertyName("enabled")] public bool? Enabled { get; set; }
    [JsonPropertyName("high_value")] public bool HighValue { get; set; }
    [JsonPropertyName("sensitive")] public bool Sensitive { get; set; }
    [JsonPropertyName("admin_count")] public bool AdminCount { get; set; }
    [JsonPropertyName("dont_req_preauth")] public bool DontReqPreauth { get; set; }
    [JsonPropertyName("has_spn")] public bool HasSpn { get; set; }
    [JsonPropertyName("unconstrained_delegation")] public bool UnconstrainedDelegation { get; set; }
    [JsonPropertyName("password_not_required")] public bool PasswordNotRequired { get; set; }
    [JsonPropertyName("owned")] public bool Owned { get; set; }
}

public sealed class BloodhoundGroup
{
    [JsonPropertyName("object_id")] public string ObjectId { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("domain")] public string? Domain { get; set; }
    [JsonPropertyName("high_value")] public bool HighValue { get; set; }
    [JsonPropertyName("member_count")] public int MemberCount { get; set; }
}

/// <summary>
/// Counts and high-value summary returned by a single ingest call.
/// Designed for printing to the operator and for one-line audit events.
/// </summary>
public sealed class BloodhoundIngestResult
{
    public string? SourceZip { get; init; }
    public int FilesIngested { get; init; }
    public int Computers { get; init; }
    public int Users { get; init; }
    public int Groups { get; init; }
    public int Domains { get; init; }
    public int KerberoastableUsers { get; init; }
    public int AsRepRoastableUsers { get; init; }
    public int UnconstrainedDelegationComputers { get; init; }
    public int UnconstrainedDelegationUsers { get; init; }
    public int HighValueGroups { get; init; }
    public List<string> Errors { get; init; } = new();
}
