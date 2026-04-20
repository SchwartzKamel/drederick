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
