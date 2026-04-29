using System.Text.Json.Serialization;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// HTTP parameter fuzzing: detect which query / POST body parameters a service
/// reflects in its response. Each discovered parameter is a potential injection
/// surface for XSS, SQLi, or command injection follow-on testing.
/// </summary>
public sealed class WebParamFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("discovered_parameters")] public IReadOnlyList<string> DiscoveredParameters { get; init; } = Array.Empty<string>();
    [JsonPropertyName("requests_sent")] public int RequestsSent { get; init; }
    [JsonPropertyName("reflected_count")] public int ReflectedCount { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>
/// Virtual host discovery: detect which Host header values a reverse proxy
/// accepts and routes differently. Each hit is a potential hidden vhost that
/// may host admin panels, staging environments, or bypass authentication.
/// </summary>
public sealed class VhostFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("hits")] public IReadOnlyList<VhostHit> Hits { get; init; } = Array.Empty<VhostHit>();
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>A single vhost discovery match.</summary>
public sealed record VhostHit(
    [property: JsonPropertyName("vhost")] string Vhost,
    [property: JsonPropertyName("status")] int Status,
    [property: JsonPropertyName("size")] long Size,
    [property: JsonPropertyName("redirect_to")] string? RedirectTo);

/// <summary>
/// Subdomain brute force: discover which subdomains resolve for a given domain.
/// Each discovered subdomain expands the attack surface and may host forgotten
/// or unpatched services.
/// </summary>
public sealed class SubdomainFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("subdomains")] public IReadOnlyList<string> Subdomains { get; init; } = Array.Empty<string>();
    [JsonPropertyName("words_tried")] public int WordsTried { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>
/// REST / kiterunner API endpoint discovery: detect which HTTP methods and
/// paths a service accepts. Each hit is a potential API surface that may leak
/// data, accept unauthenticated writes, or expose admin functions.
/// </summary>
public sealed class ApiEndpointFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("hits")] public IReadOnlyList<ApiHit> Hits { get; init; } = Array.Empty<ApiHit>();
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>A single API endpoint discovery match.</summary>
public sealed record ApiHit(
    [property: JsonPropertyName("method")] string Method,
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("status")] int Status,
    [property: JsonPropertyName("size")] long Size);

/// <summary>
/// GraphQL introspection and schema fuzzing: detect whether introspection is
/// enabled, extract the schema, and identify high-risk mutations (account
/// creation, password reset, admin ops). Also detects COP (Confused Officer
/// Problem) — aliased queries that bypass rate limits or leak data.
/// </summary>
public sealed class GraphqlFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("introspection_enabled")] public bool IntrospectionEnabled { get; init; }
    [JsonPropertyName("schema_digest")] public string? SchemaDigest { get; init; }
    [JsonPropertyName("mutations")] public IReadOnlyList<string> Mutations { get; init; } = Array.Empty<string>();
    [JsonPropertyName("queries")] public IReadOnlyList<string> Queries { get; init; } = Array.Empty<string>();
    [JsonPropertyName("cop_findings")] public IReadOnlyList<string> CopFindings { get; init; } = Array.Empty<string>();
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>
/// JWT token fuzzing: detect algorithm confusion (alg=none, RS256-to-HS256
/// key confusion), weak HMAC secrets (wordlist-driven brute force), KID header
/// injection (path traversal, SQLi, CRLF), and JKU/X5U URL injection. Each
/// vulnerability is a potential authentication bypass.
/// </summary>
public sealed class JwtFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("vulnerabilities")] public IReadOnlyList<JwtVulnerability> Vulnerabilities { get; init; } = Array.Empty<JwtVulnerability>();
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>JWT vulnerability classes detected by JWT fuzzers.</summary>
public enum JwtVulnerability
{
    /// <summary>Server accepts tokens with alg=none (no signature required).</summary>
    AlgNone,

    /// <summary>Weak HMAC secret brute-forced from a common wordlist.</summary>
    WeakHmacSecret,

    /// <summary>KID (Key ID) header allows path traversal to load arbitrary keys.</summary>
    KidPathTraversal,

    /// <summary>KID header is vulnerable to SQL injection.</summary>
    KidSqlInjection,

    /// <summary>Server accepts RS256 tokens signed with HS256 using the public key as the HMAC secret.</summary>
    RsaToHsKeyConfusion,

    /// <summary>JKU (JWK Set URL) header accepts attacker-controlled URLs.</summary>
    JkuInjection,

    /// <summary>X5U (X.509 URL) header accepts attacker-controlled URLs.</summary>
    X5uInjection,
}

/// <summary>
/// HTTP header fuzzing: detect request smuggling (Content-Length vs
/// Transfer-Encoding conflicts), Host header injection, CRLF injection, and
/// cache poisoning via header manipulation. Each finding is a potential bypass
/// or state-corruption vector.
/// </summary>
public sealed class HeaderFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("findings")] public IReadOnlyList<HeaderFinding> Findings { get; init; } = Array.Empty<HeaderFinding>();
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>A single header fuzzing finding.</summary>
public sealed record HeaderFinding(
    [property: JsonPropertyName("issue")] HeaderIssue Issue,
    [property: JsonPropertyName("header")] string Header,
    [property: JsonPropertyName("evidence")] string Evidence);

/// <summary>Header-injection issue classes detected by header fuzzers.</summary>
public enum HeaderIssue
{
    /// <summary>CL.TE or TE.CL request smuggling detected.</summary>
    RequestSmuggling,

    /// <summary>Host header injection: server reflects arbitrary Host values in Location, links, or emails.</summary>
    HostHeaderInjection,

    /// <summary>CRLF injection: server reflects verbatim newlines from header values.</summary>
    CrlfInjection,

    /// <summary>Cache poisoning: server caches responses keyed on attacker-controlled headers.</summary>
    CachePoisoning,
}

/// <summary>
/// Binary protocol fuzzing (boofuzz-driven): mutate protocol messages to
/// trigger crashes, hangs, or memory-safety bugs. Each crash or hang is a
/// potential DoS or RCE surface. DESTRUCTIVE category — default-off even in
/// lab mode.
/// </summary>
public sealed class ProtocolFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("protocol")] public string Protocol { get; init; } = "";
    [JsonPropertyName("iterations")] public int Iterations { get; init; }
    [JsonPropertyName("crashes")] public int Crashes { get; init; }
    [JsonPropertyName("hangs")] public int Hangs { get; init; }
    [JsonPropertyName("anomaly_markers")] public IReadOnlyList<string> AnomalyMarkers { get; init; } = Array.Empty<string>();
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>
/// File-format mutation fuzzing (radamsa / LLM-driven): generate malformed
/// inputs (PDFs, images, office docs, archives) to test parser robustness.
/// Each anomaly is a potential crash or RCE surface. DESTRUCTIVE category —
/// default-off even in lab mode.
/// </summary>
public sealed class FileFormatFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("seed_file")] public string SeedFile { get; init; } = "";
    [JsonPropertyName("mutations_generated")] public int MutationsGenerated { get; init; }
    [JsonPropertyName("anomalies")] public int Anomalies { get; init; }
    [JsonPropertyName("sample_crash_input_digests")] public IReadOnlyList<string> SampleCrashInputDigests { get; init; } = Array.Empty<string>();
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>
/// LLM-assisted payload mutation: iteratively refine payloads based on response
/// deltas to maximize code coverage or trigger anomalous behavior. Each mutation
/// step is recorded so the operator can replay successful chains. Requires
/// <c>OPENAI_API_KEY</c> or equivalent LLM backend; falls back gracefully when
/// unavailable.
/// </summary>
public sealed class LlmPayloadFuzzResult
{
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("tool_name")] public string ToolName { get; init; } = "";
    [JsonPropertyName("started_at")] public DateTimeOffset StartedAt { get; init; }
    [JsonPropertyName("duration")] public TimeSpan Duration { get; init; }
    [JsonPropertyName("rounds")] public int Rounds { get; init; }
    [JsonPropertyName("mutations")] public IReadOnlyList<MutationStep> Mutations { get; init; } = new List<MutationStep>();
    [JsonPropertyName("llm_available")] public bool LlmAvailable { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>A single LLM-driven mutation step.</summary>
public sealed record MutationStep(
    [property: JsonPropertyName("round")] int Round,
    [property: JsonPropertyName("payload_digest")] string PayloadDigest,
    [property: JsonPropertyName("response_status")] int ResponseStatus,
    [property: JsonPropertyName("response_size")] long ResponseSize,
    [property: JsonPropertyName("notes")] string? Notes);
