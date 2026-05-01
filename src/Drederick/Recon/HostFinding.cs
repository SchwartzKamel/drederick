using System.Text.Json.Serialization;

namespace Drederick.Recon;

public sealed class HostFinding
{
    [JsonPropertyName("target")] public string Target { get; set; } = "";
    [JsonPropertyName("started")] public string Started { get; set; } = "";
    [JsonPropertyName("finished")] public string? Finished { get; set; }
    [JsonPropertyName("nmap")] public NmapResult? Nmap { get; set; }
    [JsonPropertyName("http")] public List<HttpResult> Http { get; set; } = new();
    [JsonPropertyName("tls")] public List<TlsResult> Tls { get; set; } = new();
    [JsonPropertyName("dns")] public DnsResult? Dns { get; set; }
    [JsonPropertyName("ftp")] public List<FtpResult> Ftp { get; set; } = new();
    [JsonPropertyName("ssh")] public List<SshResult> Ssh { get; set; } = new();
    [JsonPropertyName("snmp")] public List<SnmpResult> Snmp { get; set; } = new();
    [JsonPropertyName("smb")] public List<SmbResult> Smb { get; set; } = new();
    [JsonPropertyName("ldap")] public List<LdapResult> Ldap { get; set; } = new();
    [JsonPropertyName("rpc")] public List<RpcResult> Rpc { get; set; } = new();
    [JsonPropertyName("kerberos")] public List<KerberosResult> Kerberos { get; set; } = new();
    [JsonPropertyName("dns_zone_transfer")] public List<DnsZoneTransferResult> DnsZoneTransfer { get; set; } = new();
    [JsonPropertyName("http_content_discovery")] public List<HttpContentDiscoveryResult> HttpContentDiscovery { get; set; } = new();
    [JsonPropertyName("tls_cipher_enum")] public List<TlsCipherEnumResult> TlsCipherEnum { get; set; } = new();
    [JsonPropertyName("empire_module_results")] public List<EmpireModuleResultRecord>? EmpireModuleResults { get; set; }
    [JsonPropertyName("errors")] public List<string> Errors { get; set; } = new();
}

public sealed class NmapResult
{
    [JsonPropertyName("returncode")] public int ReturnCode { get; set; }
    [JsonPropertyName("stderr")] public string? Stderr { get; set; }
    [JsonPropertyName("open_ports")] public List<NmapPort> OpenPorts { get; set; } = new();
}

public sealed class NmapPort
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("protocol")] public string Protocol { get; set; } = "tcp";
    [JsonPropertyName("service")] public string? Service { get; set; }
    [JsonPropertyName("product")] public string? Product { get; set; }
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("extra")] public string? Extra { get; set; }
    [JsonPropertyName("scripts")] public List<NmapScript> Scripts { get; set; } = new();
}

public sealed class NmapScript
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("output")] public string Output { get; set; } = "";
}

public sealed class HttpResult
{
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("status")] public int? Status { get; set; }
    [JsonPropertyName("final_url")] public string? FinalUrl { get; set; }
    [JsonPropertyName("server")] public string? Server { get; set; }
    [JsonPropertyName("title")] public string? Title { get; set; }
    [JsonPropertyName("content_type")] public string? ContentType { get; set; }
    [JsonPropertyName("missing_security_headers")] public List<string> MissingSecurityHeaders { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class TlsResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("tls_version")] public string? TlsVersion { get; set; }
    [JsonPropertyName("subject")] public string? Subject { get; set; }
    [JsonPropertyName("issuer")] public string? Issuer { get; set; }
    [JsonPropertyName("subject_alt_names")] public List<string> SubjectAltNames { get; set; } = new();
    [JsonPropertyName("not_before")] public string? NotBefore { get; set; }
    [JsonPropertyName("not_after")] public string? NotAfter { get; set; }
    [JsonPropertyName("days_until_expiry")] public int? DaysUntilExpiry { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class DnsResult
{
    [JsonPropertyName("target")] public string Target { get; set; } = "";
    [JsonPropertyName("forward")] public string? Forward { get; set; }
    [JsonPropertyName("reverse")] public string? Reverse { get; set; }
    [JsonPropertyName("forward_error")] public string? ForwardError { get; set; }
    [JsonPropertyName("reverse_error")] public string? ReverseError { get; set; }
}

public sealed class FtpResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("banner")] public string? Banner { get; set; }
    [JsonPropertyName("anonymous_allowed")] public bool AnonymousAllowed { get; set; }
    [JsonPropertyName("root_listing")] public List<string> RootListing { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class SshResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("banner")] public string? Banner { get; set; }
    [JsonPropertyName("kex_algorithms")] public List<string> KexAlgorithms { get; set; } = new();
    [JsonPropertyName("host_key_algorithms")] public List<string> HostKeyAlgorithms { get; set; } = new();
    [JsonPropertyName("encryption_algorithms")] public List<string> EncryptionAlgorithms { get; set; } = new();
    [JsonPropertyName("mac_algorithms")] public List<string> MacAlgorithms { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class SnmpResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("community")] public string Community { get; set; } = "";
    [JsonPropertyName("reachable")] public bool Reachable { get; set; }
    [JsonPropertyName("system_oids")] public Dictionary<string, string> SystemOids { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class SmbResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("os")] public string? Os { get; set; }
    [JsonPropertyName("computer_name")] public string? ComputerName { get; set; }
    [JsonPropertyName("domain")] public string? Domain { get; set; }
    [JsonPropertyName("protocols")] public List<string> Protocols { get; set; } = new();
    [JsonPropertyName("signing_required")] public bool? SigningRequired { get; set; }
    [JsonPropertyName("shares")] public List<string> Shares { get; set; } = new();
    [JsonPropertyName("users")] public List<string> Users { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class LdapResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("anonymous_bind")] public bool AnonymousBind { get; set; }
    [JsonPropertyName("naming_contexts")] public List<string> NamingContexts { get; set; } = new();
    [JsonPropertyName("supported_controls")] public List<string> SupportedControls { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class RpcResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("programs")] public List<RpcProgram> Programs { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class RpcProgram
{
    [JsonPropertyName("program")] public int Program { get; set; }
    [JsonPropertyName("version")] public int Version { get; set; }
    [JsonPropertyName("protocol")] public string Protocol { get; set; } = "";
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
}

public sealed class KerberosResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("realm")] public string? Realm { get; set; }
    [JsonPropertyName("spns")] public List<string> Spns { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

/// <summary>
/// Result of a delegation enumeration sweep against a Domain Controller.
/// All four AD delegation primitives are surfaced as separate buckets so
/// downstream planners can pick the right follow-up:
/// <list type="bullet">
///   <item>Unconstrained → S4U2Self isn't possible, but a forced auth
///   (e.g. PetitPotam) of a privileged account against the host yields
///   a TGT for that account.</item>
///   <item>Constrained / Constrained-with-protocol-transition → S4U2Self
///   + S4U2Proxy chain to impersonate any user to the listed services.</item>
///   <item>RBCD (resource-based constrained delegation) → if we control
///   any account in <c>msDS-AllowedToActOnBehalfOfOtherIdentity</c>, we
///   can S4U-impersonate to the resource. Frequently abusable on
///   computer accounts an attacker just added (e.g. via
///   ms-DS-MachineAccountQuota).</item>
/// </list>
/// </summary>
public sealed class DelegationEnumResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("realm")] public string? Realm { get; set; }
    [JsonPropertyName("base_dn")] public string? BaseDn { get; set; }
    [JsonPropertyName("authenticated")] public bool Authenticated { get; set; }
    [JsonPropertyName("unconstrained")] public List<DelegationPrincipal> Unconstrained { get; set; } = new();
    [JsonPropertyName("constrained")] public List<DelegationPrincipal> Constrained { get; set; } = new();
    [JsonPropertyName("constrained_with_protocol_transition")]
    public List<DelegationPrincipal> ConstrainedWithProtocolTransition { get; set; } = new();
    [JsonPropertyName("rbcd")] public List<DelegationPrincipal> Rbcd { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class DelegationPrincipal
{
    [JsonPropertyName("sam_account_name")] public string SamAccountName { get; set; } = "";
    [JsonPropertyName("dn")] public string DistinguishedName { get; set; } = "";
    [JsonPropertyName("user_account_control")] public int UserAccountControl { get; set; }
    /// <summary>True when the principal name ends in <c>$</c> — i.e. a
    /// computer or trust account.</summary>
    [JsonPropertyName("is_computer")] public bool IsComputer { get; set; }
    /// <summary>For Constrained / Constrained-with-protocol-transition,
    /// the value of <c>msDS-AllowedToDelegateTo</c> (list of SPNs).</summary>
    [JsonPropertyName("allowed_to_delegate_to")] public List<string> AllowedToDelegateTo { get; set; } = new();
    /// <summary>For RBCD, the principal SIDs parsed out of the
    /// <c>msDS-AllowedToActOnBehalfOfOtherIdentity</c> security descriptor.</summary>
    [JsonPropertyName("allowed_to_act_principal_sids")] public List<string> AllowedToActPrincipalSids { get; set; } = new();
    /// <summary>Human-readable hint linking the primitive to its abuse path.</summary>
    [JsonPropertyName("hint")] public string Hint { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = "yellow";
}

public sealed class DnsZoneTransferResult
{
    [JsonPropertyName("domain")] public string Domain { get; set; } = "";
    [JsonPropertyName("nameserver")] public string? NameServer { get; set; }
    [JsonPropertyName("success")] public bool Success { get; set; }
    [JsonPropertyName("records")] public List<string> Records { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class HttpContentDiscoveryResult
{
    [JsonPropertyName("base_url")] public string BaseUrl { get; set; } = "";
    [JsonPropertyName("entries")] public List<HttpContentDiscoveryEntry> Entries { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class HttpContentDiscoveryEntry
{
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("status")] public int Status { get; set; }
    [JsonPropertyName("size")] public long Size { get; set; }
}

public sealed class TlsCipherEnumResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("versions")] public Dictionary<string, TlsCipherVersion> Versions { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class TlsCipherVersion
{
    [JsonPropertyName("ciphers")] public List<string> Ciphers { get; set; } = new();
    [JsonPropertyName("grade")] public string? Grade { get; set; }
}

public sealed class EmpireModuleResultRecord
{
    [JsonPropertyName("module_name")] public string ModuleName { get; set; } = "";
    [JsonPropertyName("output")] public string? Output { get; set; }
    [JsonPropertyName("executed_at")] public string? ExecutedAt { get; set; }
    [JsonPropertyName("success")] public bool Success { get; set; }
}
