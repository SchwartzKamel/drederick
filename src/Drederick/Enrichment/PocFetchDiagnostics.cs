using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Enrichment;

/// <summary>
/// GAP-053 — diagnostic wrapper around a single git PoC-source clone
/// attempt. Records <c>poc.fetch.error.diagnosed</c> with stable fields
/// when the wrapped operation reports failure, so production triage no
/// longer requires re-running the source with verbose logging:
/// <list type="bullet">
///   <item><c>git_present</c> + the <c>git --version</c> string captured
///   from <see cref="IGitClient.GitVersion"/>.</item>
///   <item><c>dns_ok</c> + resolved address list for the target host
///   (via <see cref="IDnsResolver"/>).</item>
///   <item><c>https_reachable</c> + HTTP status code or exception type
///   from a HEAD probe (via <see cref="IHttpReachabilityProbe"/>).</item>
///   <item>Full stderr from the clone, UTF-8 truncated at 4&#160;KB and
///   accompanied by the SHA-256 of the verbatim full stderr.</item>
/// </list>
/// Auth tokens are stripped from <c>target_url</c> and from stderr
/// before emission — see <see cref="RedactSecrets"/>.
/// Composes with the existing <see cref="GitPocDiagnostics"/>: callers
/// may call both (this wrapper adds the network-layer triage surface;
/// the older helper records <c>poc.fetch.diagnostics</c> +
/// <c>poc.fetch.error</c> with the clone-stage detail).
/// </summary>
public sealed class PocFetchDiagnostics
{
    /// <summary>Hard cap on stderr bytes embedded in the audit event.</summary>
    public const int StderrTruncateBytes = 4096;

    private readonly IGitClient _git;
    private readonly IDnsResolver _dns;
    private readonly IHttpReachabilityProbe _http;

    public PocFetchDiagnostics(
        IGitClient git,
        IDnsResolver? dns = null,
        IHttpReachabilityProbe? http = null)
    {
        _git = git ?? throw new ArgumentNullException(nameof(git));
        _dns = dns ?? new SystemDnsResolver();
        _http = http ?? new DefaultHttpReachabilityProbe();
    }

    /// <summary>
    /// Run <paramref name="gitOperation"/>; on failure (returning a
    /// <see cref="GitCloneResult"/> with <c>Success=false</c>), emit
    /// <c>poc.fetch.error.diagnosed</c>. Returns the original result
    /// verbatim so the caller can keep its existing control flow.
    /// </summary>
    public async Task<GitCloneResult> WrapAsync(
        AuditLog? audit,
        string sourceName,
        string cveId,
        string targetUrl,
        Func<CancellationToken, Task<GitCloneResult>> gitOperation,
        CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetUrl);
        ArgumentNullException.ThrowIfNull(gitOperation);

        var result = await gitOperation(ct).ConfigureAwait(false);
        if (result.Success) return result;

        var gitVersion = _git.GitVersion ?? string.Empty;
        var gitPresent = !gitVersion.StartsWith("git not available", StringComparison.OrdinalIgnoreCase);

        var redactedUrl = RedactUrlCredentials(targetUrl);
        var host = ExtractHost(targetUrl);

        DnsProbeResult dnsResult;
        try { dnsResult = await _dns.ResolveAsync(host, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { dnsResult = new DnsProbeResult(false, Array.Empty<string>(), ex.GetType().Name); }

        HttpProbeResult httpResult;
        try { httpResult = await _http.HeadAsync(redactedUrl, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { httpResult = new HttpProbeResult(false, null, ex.GetType().Name); }

        var rawStderr = result.Stderr ?? string.Empty;
        var sanitisedStderr = RedactSecrets(rawStderr);
        var stderrFullBytes = Utf8ByteSize(sanitisedStderr);
        var stderrTrunc = TruncateUtf8(sanitisedStderr, StderrTruncateBytes);
        var stderrSha = Sha256Hex(sanitisedStderr);

        audit?.Record("poc.fetch.error.diagnosed", new Dictionary<string, object?>
        {
            ["source"] = sourceName,
            ["cve_id"] = cveId,
            ["target_url"] = redactedUrl,
            ["target_host"] = host,
            ["git_present"] = gitPresent,
            ["git_version"] = gitVersion,
            ["dns_ok"] = dnsResult.Ok,
            ["dns_addresses"] = dnsResult.Addresses,
            ["dns_error"] = dnsResult.ErrorKind,
            ["https_reachable"] = httpResult.Reachable,
            ["https_status"] = httpResult.StatusCode,
            ["https_error"] = httpResult.ErrorKind,
            ["exit_code"] = result.ExitCode,
            ["stage"] = result.Stage,
            ["stderr"] = stderrTrunc,
            ["stderr_full_byte_size"] = stderrFullBytes,
            ["stderr_truncated"] = stderrFullBytes > StderrTruncateBytes,
            ["stderr_sha256"] = stderrSha,
        });

        return result;
    }

    // --- helpers ---------------------------------------------------------

    internal static string ExtractHost(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var u)) return u.Host;
        return string.Empty;
    }

    /// <summary>Strip <c>user[:pass]@</c> userinfo from a URL. Never throws.</summary>
    internal static string RedactUrlCredentials(string url)
    {
        if (string.IsNullOrEmpty(url)) return url;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return url;
        if (string.IsNullOrEmpty(u.UserInfo)) return url;
        var b = new UriBuilder(u) { UserName = string.Empty, Password = string.Empty };
        return b.Uri.ToString();
    }

    private static readonly Regex UrlInlineCredsRegex = new(
        @"(?<scheme>https?://)(?<creds>[^@/\s:]+(?::[^@/\s]*)?)@",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex BearerHeaderRegex = new(
        @"(?i)(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._\-+/=]{6,})",
        RegexOptions.Compiled);

    private static readonly Regex GitHubTokenRegex = new(
        @"\b(gh[pousr]_[A-Za-z0-9]{20,})\b",
        RegexOptions.Compiled);

    /// <summary>
    /// Best-effort redaction of common credential shapes in subprocess
    /// output: inline <c>https://user:token@host</c> URLs, <c>Authorization:
    /// Bearer …</c> headers, GitHub PATs (<c>ghp_…</c>, <c>gho_…</c>, etc.).
    /// Idempotent; intended to keep tokens out of <c>audit.jsonl</c>.
    /// </summary>
    internal static string RedactSecrets(string s)
    {
        if (string.IsNullOrEmpty(s)) return s ?? string.Empty;
        var r1 = UrlInlineCredsRegex.Replace(s, m => m.Groups["scheme"].Value + "REDACTED@");
        var r2 = BearerHeaderRegex.Replace(r1, m => m.Groups[1].Value + "REDACTED");
        var r3 = GitHubTokenRegex.Replace(r2, "REDACTED");
        return r3;
    }

    internal static string TruncateUtf8(string s, int maxBytes)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        var bytes = Encoding.UTF8.GetBytes(s);
        if (bytes.Length <= maxBytes) return s;
        var cut = maxBytes;
        while (cut > 0 && (bytes[cut] & 0xC0) == 0x80) cut--;
        return Encoding.UTF8.GetString(bytes, 0, cut);
    }

    internal static int Utf8ByteSize(string s)
        => string.IsNullOrEmpty(s) ? 0 : Encoding.UTF8.GetByteCount(s);

    internal static string Sha256Hex(string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s ?? string.Empty);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}

/// <summary>
/// DNS probe abstraction. Tests substitute a stub to assert the
/// classification path. Default impl uses <see cref="Dns.GetHostAddressesAsync(string, CancellationToken)"/>.
/// </summary>
public interface IDnsResolver
{
    Task<DnsProbeResult> ResolveAsync(string host, CancellationToken ct);
}

public sealed record DnsProbeResult(bool Ok, IReadOnlyList<string> Addresses, string? ErrorKind);

internal sealed class SystemDnsResolver : IDnsResolver
{
    public async Task<DnsProbeResult> ResolveAsync(string host, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(host))
            return new DnsProbeResult(false, Array.Empty<string>(), "empty-host");
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            if (addrs is null || addrs.Length == 0)
                return new DnsProbeResult(false, Array.Empty<string>(), "no-addresses");
            return new DnsProbeResult(true, addrs.Select(a => a.ToString()).ToArray(), null);
        }
        catch (OperationCanceledException) { throw; }
        catch (SocketException ex) { return new DnsProbeResult(false, Array.Empty<string>(), ex.SocketErrorCode.ToString()); }
        catch (Exception ex) { return new DnsProbeResult(false, Array.Empty<string>(), ex.GetType().Name); }
    }
}

/// <summary>
/// HTTPS reachability probe (HEAD request). Tests substitute a stub.
/// Returns <c>Reachable=true</c> on any HTTP response (even 4xx/5xx);
/// only network-layer failures (timeouts, refused, TLS errors) count
/// as unreachable.
/// </summary>
public interface IHttpReachabilityProbe
{
    Task<HttpProbeResult> HeadAsync(string url, CancellationToken ct);
}

public sealed record HttpProbeResult(bool Reachable, int? StatusCode, string? ErrorKind);

internal sealed class DefaultHttpReachabilityProbe : IHttpReachabilityProbe
{
    private static readonly HttpClient SharedClient = new(new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromSeconds(10),
    };

    public async Task<HttpProbeResult> HeadAsync(string url, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(url)) return new HttpProbeResult(false, null, "empty-url");
        if (!Uri.TryCreate(url, UriKind.Absolute, out _)) return new HttpProbeResult(false, null, "invalid-url");
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Head, url);
            using var resp = await SharedClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            return new HttpProbeResult(true, (int)resp.StatusCode, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new HttpProbeResult(false, null, "Timeout");
        }
        catch (OperationCanceledException) { throw; }
        catch (HttpRequestException ex) { return new HttpProbeResult(false, null, ex.GetType().Name); }
        catch (Exception ex) { return new HttpProbeResult(false, null, ex.GetType().Name); }
    }
}
