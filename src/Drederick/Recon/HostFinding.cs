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
    [JsonPropertyName("native_dns")] public List<NativeDnsResult> NativeDns { get; set; } = new();
    [JsonPropertyName("http_content_discovery")] public List<HttpContentDiscoveryResult> HttpContentDiscovery { get; set; } = new();
    [JsonPropertyName("tls_cipher_enum")] public List<TlsCipherEnumResult> TlsCipherEnum { get; set; } = new();
    [JsonPropertyName("empire_module_results")] public List<EmpireModuleResultRecord>? EmpireModuleResults { get; set; }
    [JsonPropertyName("native_scan")] public NativeScanResult? NativeScan { get; set; }
    [JsonPropertyName("fingerprint")] public List<Drederick.Enrichment.FingerprintStack.FingerprintReport> Fingerprint { get; set; } = new();
    [JsonPropertyName("nse_findings")] public List<NseFinding> NseFindings { get; set; } = new();
    [JsonPropertyName("http_title")] public List<HttpTitleResult> HttpTitle { get; set; } = new();
    [JsonPropertyName("http_headers")] public List<HttpHeadersResult> HttpHeaders { get; set; } = new();
    [JsonPropertyName("http_robots")] public List<HttpRobotsResult> HttpRobots { get; set; } = new();
    [JsonPropertyName("http_methods")] public List<HttpMethodsResult> HttpMethods { get; set; } = new();
    [JsonPropertyName("ssl_cert")] public List<SslCertResult> SslCert { get; set; } = new();
    [JsonPropertyName("ssh_hostkey")] public List<SshHostkeyResult> SshHostkey { get; set; } = new();
    [JsonPropertyName("ftp_anon")] public List<FtpAnonResult> FtpAnon { get; set; } = new();
    [JsonPropertyName("ldap_rootdse")] public List<LdapRootDseResult> LdapRootDse { get; set; } = new();
    [JsonPropertyName("errors")] public List<string> Errors { get; set; } = new();
    // --- s3 --- (GAP-037)
    [JsonPropertyName("s3")] public List<S3Finding> S3 { get; set; } = new();
    // --- cms fingerprint --- (GAP-036)
    [JsonPropertyName("cms_fingerprint")] public List<CmsFinding> CmsFingerprint { get; set; } = new();
    // --- ad --- (GAP-042)
    [JsonPropertyName("smb_null_session")] public List<SmbNullSessionFinding> SmbNullSession { get; set; } = new();
}

/// <summary>
/// Pattern 1 graceful enrichment record: per-script output produced by
/// <see cref="NseProxy"/> when an <c>nmap</c> binary is available on PATH.
/// Drederick's native scanners always run; this is purely additive depth.
/// </summary>
public sealed class NseFinding
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("script")] public string Script { get; set; } = "";
    [JsonPropertyName("output")] public string Output { get; set; } = "";
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

    // GAP-034: structured taxonomy for http.error events. One of
    // {connection_refused, connection_timeout, dns_failure,
    //  tls_handshake, redirect_loop, http_5xx, scope_reject, transport}.
    // Null on success. `ExceptionType` is the .NET exception type name
    // for forensics (audit trail also carries it).
    [JsonPropertyName("reason")] public string? Reason { get; set; }
    [JsonPropertyName("exception_type")] public string? ExceptionType { get; set; }

    // GAP-032: vhost-aware http_probe. When a probe to an IP returns
    // 3xx → Location with a hostname authority, mark the finding so the
    // planner / LLM retries with the hostname as the target. The hostname
    // is informational (`Host:` header + SNI); the resolved IP is what
    // _scope.Require authorizes.
    [JsonPropertyName("vhost_required")] public bool VhostRequired { get; set; }
    [JsonPropertyName("vhost_hostname")] public string? VhostHostname { get; set; }
    [JsonPropertyName("hostname")] public string? Hostname { get; set; }
    [JsonPropertyName("resolved_ip")] public string? ResolvedIp { get; set; }
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

public sealed class NativeDnsResult
{
    [JsonPropertyName("target")] public string Target { get; set; } = "";
    [JsonPropertyName("query_type")] public string QueryType { get; set; } = "";
    [JsonPropertyName("records")] public Dictionary<string, List<string>> Records { get; set; } = new();
    [JsonPropertyName("axfr_attempted")] public bool AxfrAttempted { get; set; }
    [JsonPropertyName("axfr_success")] public bool AxfrSuccess { get; set; }
    [JsonPropertyName("axfr_records")] public List<string> AxfrRecords { get; set; } = new();
    [JsonPropertyName("axfr_error")] public string? AxfrError { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class NativeScanResult
{
    [JsonPropertyName("source")] public string Source { get; set; } = "nativescan";
    [JsonPropertyName("started")] public string? Started { get; set; }
    [JsonPropertyName("finished")] public string? Finished { get; set; }
    [JsonPropertyName("open_ports")] public List<NmapPort> OpenPorts { get; set; } = new();
}

public sealed class HttpTitleResult
{
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("status")] public int? Status { get; set; }
    [JsonPropertyName("title")] public string? Title { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class HttpHeadersResult
{
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("status")] public int? Status { get; set; }
    [JsonPropertyName("method")] public string Method { get; set; } = "HEAD";
    [JsonPropertyName("headers")] public Dictionary<string, List<string>> Headers { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class HttpRobotsResult
{
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("status")] public int? Status { get; set; }
    [JsonPropertyName("disallowed")] public List<string> Disallowed { get; set; } = new();
    [JsonPropertyName("allowed")] public List<string> Allowed { get; set; } = new();
    [JsonPropertyName("sitemaps")] public List<string> Sitemaps { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class HttpMethodsResult
{
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("status")] public int? Status { get; set; }
    [JsonPropertyName("allow")] public List<string> Allow { get; set; } = new();
    [JsonPropertyName("public")] public List<string> Public { get; set; } = new();
    [JsonPropertyName("risky_methods")] public List<string> RiskyMethods { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class SslCertResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("subject")] public string? Subject { get; set; }
    [JsonPropertyName("issuer")] public string? Issuer { get; set; }
    [JsonPropertyName("subject_alt_names")] public List<string> SubjectAltNames { get; set; } = new();
    [JsonPropertyName("not_before")] public string? NotBefore { get; set; }
    [JsonPropertyName("not_after")] public string? NotAfter { get; set; }
    [JsonPropertyName("days_until_expiry")] public int? DaysUntilExpiry { get; set; }
    [JsonPropertyName("serial_number")] public string? SerialNumber { get; set; }
    [JsonPropertyName("signature_algorithm")] public string? SignatureAlgorithm { get; set; }
    [JsonPropertyName("public_key_algorithm")] public string? PublicKeyAlgorithm { get; set; }
    [JsonPropertyName("public_key_bits")] public int? PublicKeyBits { get; set; }
    [JsonPropertyName("sha256_fingerprint")] public string? Sha256Fingerprint { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class SshHostkeyResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("banner")] public string? Banner { get; set; }
    [JsonPropertyName("host_key_algorithms")] public List<string> HostKeyAlgorithms { get; set; } = new();
    [JsonPropertyName("kex_algorithms")] public List<string> KexAlgorithms { get; set; } = new();
    [JsonPropertyName("encryption_algorithms")] public List<string> EncryptionAlgorithms { get; set; } = new();
    [JsonPropertyName("mac_algorithms")] public List<string> MacAlgorithms { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class FtpAnonResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("banner")] public string? Banner { get; set; }
    [JsonPropertyName("anonymous_allowed")] public bool AnonymousAllowed { get; set; }
    [JsonPropertyName("login_response")] public string? LoginResponse { get; set; }
    [JsonPropertyName("root_listing")] public List<string> RootListing { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class LdapRootDseResult
{
    [JsonPropertyName("port")] public int Port { get; set; }
    [JsonPropertyName("anonymous_bind")] public bool AnonymousBind { get; set; }
    [JsonPropertyName("naming_contexts")] public List<string> NamingContexts { get; set; } = new();
    [JsonPropertyName("supported_controls")] public List<string> SupportedControls { get; set; } = new();
    [JsonPropertyName("supported_ldap_versions")] public List<string> SupportedLdapVersions { get; set; } = new();
    [JsonPropertyName("supported_sasl_mechanisms")] public List<string> SupportedSaslMechanisms { get; set; } = new();
    [JsonPropertyName("error")] public string? Error { get; set; }
}

// --- s3 --- (GAP-037: MinIO / S3-compatible service finding)
public sealed record S3Finding
{
    [JsonPropertyName("target")] public required string Target { get; init; }
    [JsonPropertyName("port")] public int Port { get; init; }
    [JsonPropertyName("is_s3")] public bool IsS3 { get; init; }
    [JsonPropertyName("is_minio")] public bool IsMinio { get; init; }
    [JsonPropertyName("anonymous_list_allowed")] public bool AnonymousListAllowed { get; init; }
    [JsonPropertyName("anonymous_buckets")] public IReadOnlyList<string> AnonymousBuckets { get; init; } = [];
    [JsonPropertyName("authenticated_buckets")] public IReadOnlyList<S3BucketEntry> AuthenticatedBuckets { get; init; } = [];
    [JsonPropertyName("server")] public string? Server { get; init; }
    [JsonPropertyName("minio_version")] public string? MinioVersion { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
}

public sealed record S3BucketEntry
{
    [JsonPropertyName("name")] public required string Name { get; init; }
    [JsonPropertyName("object_count")] public int ObjectCount { get; init; }
    [JsonPropertyName("objects")] public IReadOnlyList<S3ObjectEntry> Objects { get; init; } = [];
}

public sealed record S3ObjectEntry
{
    [JsonPropertyName("key")] public required string Key { get; init; }
    [JsonPropertyName("size")] public long Size { get; init; }
    [JsonPropertyName("last_modified")] public string? LastModified { get; init; }
}

// --- GAP-036 CMS fingerprint result records ---
public sealed record CmsFinding
{
    [JsonPropertyName("target")] public required string Target { get; init; }
    [JsonPropertyName("base_url")] public required string BaseUrl { get; init; }
    [JsonPropertyName("matches")] public IReadOnlyList<CmsMatch> Matches { get; init; } = [];
    [JsonPropertyName("error")] public string? Error { get; init; }
}

public sealed record CmsMatch(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("confidence")] int Confidence,
    [property: JsonPropertyName("signals_matched")] IReadOnlyList<string> SignalsMatched);

// --- GAP-042 SMB null-session + anonymous LDAP enumeration result records ---

/// <summary>
/// GAP-042: SMB null-session + anonymous LDAP enumeration result. Populated
/// by <see cref="Drederick.Recon.Ad.SmbNullSessionTool"/>. Captures SMB2
/// negotiate metadata, share list, RID-cycled / SAMR-enumerated users, and
/// AD naming-context details obtained via anonymous LDAP bind. All steps are
/// credential-free (anonymous IPC$ tree connect; LDAP bind with empty DN +
/// empty password). Authoritative result for the &quot;is this an AD-shaped
/// box and what can we see without creds?&quot; question.
/// </summary>
public sealed record SmbNullSessionFinding
{
    [JsonPropertyName("target")] public required string Target { get; init; }
    [JsonPropertyName("null_session_open")] public bool NullSessionOpen { get; init; }
    [JsonPropertyName("smb2_dialect")] public string? Smb2Dialect { get; init; }
    [JsonPropertyName("signing_required")] public bool SigningRequired { get; init; }
    [JsonPropertyName("server_guid")] public string? ServerGuid { get; init; }
    [JsonPropertyName("domain_name")] public string? DomainName { get; init; }
    [JsonPropertyName("domain_sid")] public string? DomainSid { get; init; }
    [JsonPropertyName("dns_domain")] public string? DnsDomain { get; init; }
    [JsonPropertyName("default_naming_context")] public string? DefaultNamingContext { get; init; }
    [JsonPropertyName("root_naming_context")] public string? RootDomainNamingContext { get; init; }
    [JsonPropertyName("ldap_anon_bind_ok")] public bool LdapAnonBindOk { get; init; }
    [JsonPropertyName("shares")] public IReadOnlyList<SmbShare> Shares { get; init; } = [];
    [JsonPropertyName("users")] public IReadOnlyList<DomainUser> Users { get; init; } = [];
    [JsonPropertyName("supported_sasl_mechanisms")] public IReadOnlyList<string> SupportedSaslMechanisms { get; init; } = [];
    [JsonPropertyName("error")] public string? Error { get; init; }
}

public sealed record SmbShare(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("comment")] string? Comment,
    [property: JsonPropertyName("readable_anonymously")] bool ReadableAnonymously);

public sealed record DomainUser(
    [property: JsonPropertyName("sam_account_name")] string SamAccountName,
    [property: JsonPropertyName("rid")] int? Rid,
    [property: JsonPropertyName("user_account_control")] string? UserAccountControl,
    [property: JsonPropertyName("member_of")] IReadOnlyList<string> MemberOf);
