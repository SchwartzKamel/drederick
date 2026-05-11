using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// HTTP fingerprinting probe. GETs "/" and reports status, title, server
/// header, and which common security headers are missing. Does not follow
/// redirects off the target host and does not submit credentials.
/// <para>
/// GAP-032: targets may be either a literal IP or a hostname. Hostnames
/// are resolved via DNS; the resolved IP is what <see cref="Scope.Scope.Require"/>
/// authorizes — the hostname alone is informational (used for the
/// <c>Host:</c> header and SNI). On a 3xx → Location to a different
/// hostname, the result records <c>VhostRequired</c>/<c>VhostHostname</c>
/// so the planner / LLM retries with the hostname as the target.
/// </para>
/// </summary>
public sealed partial class HttpProbeTool : IReconTool
{
    public string Name => "http";

    public string Description =>
        "Fetch an HTTP(S) response from a single port and return status, title, server, " +
        "and which common security headers are missing. Accepts hostname targets " +
        "(resolved IP must pass scope). Non-exploitative.";

    private static readonly string[] SecurityHeaders =
    [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ];

    [GeneratedRegex("<title[^>]*>(.*?)</title>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex TitleRegex();

    private const int MaxTitleBufferBytes = 65536;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _dnsResolver;
    private readonly Func<IPAddress, HttpMessageHandler>? _handlerFactory;

    public HttpProbeTool(Scope.Scope scope, AuditLog audit)
        : this(scope, audit, null, null)
    {
    }

    internal HttpProbeTool(
        Scope.Scope scope,
        AuditLog audit,
        Func<string, CancellationToken, Task<IPAddress[]>>? dnsResolver,
        Func<IPAddress, HttpMessageHandler>? handlerFactory)
    {
        _scope = scope;
        _audit = audit;
        _dnsResolver = dnsResolver ?? ((host, ct) => Dns.GetHostAddressesAsync(host, ct));
        _handlerFactory = handlerFactory;
    }

    /// <summary>
    /// Resolved-target record: which IP we will dial, the optional
    /// hostname for <c>Host:</c>/SNI, and every IP the hostname mapped
    /// to (for the audit trail). Only the <see cref="ResolvedIp"/> is
    /// authorized — DNS rebinding is mitigated by validating the IP and
    /// always dialing it via <c>SocketsHttpHandler.ConnectCallback</c>.
    /// </summary>
    internal sealed record ResolvedTarget(
        IPAddress ResolvedIp,
        string? Hostname,
        IReadOnlyList<IPAddress> AllResolved);

    /// <summary>
    /// Resolve <paramref name="target"/> to an authorized IP. If
    /// <paramref name="target"/> parses as an IP, returns it directly
    /// after <c>_scope.Require</c>. Otherwise resolves via DNS and picks
    /// the first IP that passes scope; throws <see cref="ScopeException"/>
    /// when none resolved IPs are in scope.
    /// </summary>
    internal async Task<ResolvedTarget> ResolveAsync(string target, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(target);
        // Strip brackets that callers may pass for bare-IPv6 targets.
        var stripped = target.StartsWith('[') && target.EndsWith(']')
            ? target.Substring(1, target.Length - 2)
            : target;

        if (IPAddress.TryParse(stripped, out var ipDirect))
        {
            // IP target — scope authorizes directly. Backward-compatible path.
            _scope.Require(stripped);
            return new ResolvedTarget(ipDirect, null, new[] { ipDirect });
        }

        // Hostname target. Resolve, then authorize the resolved IP.
        IPAddress[] addrs;
        try
        {
            addrs = await _dnsResolver(target, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new ScopeException(
                $"Failed to resolve hostname '{target}' for http_probe: {ex.Message}");
        }
        if (addrs.Length == 0)
        {
            throw new ScopeException(
                $"Hostname '{target}' did not resolve to any address.");
        }

        foreach (var addr in addrs)
        {
            if (_scope.Contains(addr.ToString()))
            {
                _scope.Require(addr.ToString());
                return new ResolvedTarget(addr, target, addrs);
            }
        }

        var joined = string.Join(", ", addrs.Select(a => a.ToString()));
        throw new ScopeException(
            $"hostname '{target}' resolves to {{{joined}}}, none in scope.");
    }

    public async Task<HttpResult> ProbeAsync(
        string target,
        int port,
        bool useTls,
        CancellationToken ct = default)
    {
        // Scope enforcement: target may be an IP or a hostname. Hostnames
        // are resolved first, then the resolved IP is authorized via
        // _scope.Require. The hostname is never an authorization signal.
        // (@invariant-id:scope-in-every-tool — interpretation: the FIRST
        // authorization call is _scope.Require on the resolved IP; no
        // request to the target is issued before this.)
        var resolved = await ResolveAsync(target, ct).ConfigureAwait(false);

        var scheme = useTls ? "https" : "http";
        var authority = BuildAuthority(resolved.Hostname ?? resolved.ResolvedIp.ToString());
        var url = $"{scheme}://{authority}:{port}/";

        _audit.Record("http.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["url"] = url,
            ["resolved_ip"] = resolved.ResolvedIp.ToString(),
            ["hostname"] = resolved.Hostname,
            ["all_resolved"] = resolved.AllResolved.Select(a => a.ToString()).ToArray(),
        });

        var handler = _handlerFactory is not null
            ? _handlerFactory(resolved.ResolvedIp)
            : BuildSocketsHandler(resolved.ResolvedIp);

        using var http = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(15),
        };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("drederick/0.1 (+lab-recon)");

        var result = new HttpResult
        {
            Url = url,
            Hostname = resolved.Hostname,
            ResolvedIp = resolved.ResolvedIp.ToString(),
        };
        var sw = Stopwatch.StartNew();
        try
        {
            using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            result.Status = (int)resp.StatusCode;
            result.Server = resp.Headers.Server?.ToString();
            result.ContentType = resp.Content.Headers.ContentType?.ToString();
            // GAP-034: surface 5xx to the planner via reason without
            // forcing it to parse status. The response is not an error
            // from HttpClient's perspective; we just tag it.
            if ((int)resp.StatusCode >= 500 && (int)resp.StatusCode <= 599)
            {
                result.Reason = "http_5xx";
            }

            var allHeaders = resp.Headers
                .Concat(resp.Content.Headers)
                .Select(h => h.Key.ToLowerInvariant())
                .ToHashSet();
            result.MissingSecurityHeaders = SecurityHeaders
                .Where(h => !allHeaders.Contains(h))
                .ToList();

            if (IsRedirect(resp.StatusCode))
            {
                var loc = resp.Headers.Location?.ToString();
                result.FinalUrl = loc;
                DetectVhost(target, resolved, loc, result);
            }

            if ((resp.Content.Headers.ContentType?.MediaType ?? "").Contains("html",
                    StringComparison.OrdinalIgnoreCase))
            {
                var buf = new byte[MaxTitleBufferBytes];
                await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                int total = 0;
                while (total < buf.Length)
                {
                    var n = await stream.ReadAsync(buf.AsMemory(total, buf.Length - total), ct)
                        .ConfigureAwait(false);
                    if (n <= 0) break;
                    total += n;
                }
                var body = System.Text.Encoding.UTF8.GetString(buf, 0, total);
                var m = TitleRegex().Match(body);
                if (m.Success) result.Title = m.Groups[1].Value.Trim();

                // --- phpinfo additions (GAP-054) ---
                if (PhpInfoParser.LooksLikePhpInfo(body))
                {
                    var info = PhpInfoParser.Parse(body, url);
                    result.PhpInfo = info;
                    _audit.Record("phpinfo.parsed", new Dictionary<string, object?>
                    {
                        ["target"] = target,
                        ["url"] = url,
                        ["php_version"] = info.PhpVersion,
                        ["rce_on_write_likely"] = info.RceOnWriteLikely,
                        ["user_ini_injection_likely"] = info.UserIniInjectionLikely,
                        ["fpm_user"] = info.FpmUser,
                        ["fpm_group"] = info.FpmGroup,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            sw.Stop();
            var reason = ClassifyException(ex, ct);
            _audit.Record("http.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["url"] = url,
                ["error"] = ex.Message,
                ["reason"] = reason,
                ["exception_type"] = ex.GetType().Name,
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
            });
            result.Error = ex.Message;
            result.Reason = reason;
            result.ExceptionType = ex.GetType().Name;
        }
        _audit.Record("http.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["url"] = url,
            ["status"] = result.Status,
            ["error"] = result.Error,
            ["vhost_required"] = result.VhostRequired,
            ["vhost_hostname"] = result.VhostHostname,
        });
        return result;
    }

    private static bool IsRedirect(HttpStatusCode code) =>
        code is HttpStatusCode.Redirect or HttpStatusCode.MovedPermanently
            or HttpStatusCode.Found or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;

    /// <summary>
    /// Inspect a 3xx Location and, if it points at a hostname authority
    /// distinct from the target we just probed, flag the finding as
    /// vhost-routed and emit an audit event so the operator and the LLM
    /// planner can retry with the hostname as the target.
    /// </summary>
    internal void DetectVhost(string target, ResolvedTarget resolved, string? location, HttpResult result)
    {
        if (string.IsNullOrEmpty(location)) return;
        if (!Uri.TryCreate(location, UriKind.RelativeOrAbsolute, out var uri)) return;
        if (!uri.IsAbsoluteUri) return;

        var locHost = uri.Host;
        if (string.IsNullOrEmpty(locHost)) return;

        // If Location points back at the same IP/hostname that was used as
        // the *request target*, this is an in-app redirect, not a vhost
        // redirect. Compare against `target` (the caller-supplied argument),
        // NOT `resolved.Hostname` — reverse DNS may resolve the IP to
        // exactly the vhost hostname (e.g. 10.x → facts.htb), which would
        // cause us to miss the redirect when the request was sent to the IP.
        if (string.Equals(locHost, target, StringComparison.OrdinalIgnoreCase))
            return;

        // If Location points at the resolved IP itself, also not a vhost.
        if (string.Equals(locHost, resolved.ResolvedIp.ToString(), StringComparison.OrdinalIgnoreCase))
            return;

        // Only flag when Location authority is a hostname (not another IP).
        // Cross-IP redirects are a different (out-of-scope) concern.
        if (IPAddress.TryParse(locHost, out _)) return;

        result.VhostRequired = true;
        result.VhostHostname = locHost;
        _audit.Record("http.vhost.detected", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["resolved_ip"] = resolved.ResolvedIp.ToString(),
            ["vhost_hostname"] = locHost,
            ["location"] = location,
        });
    }

    /// <summary>
    /// Wraps an IPv6 literal in brackets when used as a URI authority.
    /// Hostnames and IPv4 literals pass through unchanged.
    /// </summary>
    private static string BuildAuthority(string host)
    {
        if (IPAddress.TryParse(host, out var ip)
            && ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return $"[{host}]";
        }
        return host;
    }

    /// <summary>
    /// Build a <see cref="SocketsHttpHandler"/> whose <c>ConnectCallback</c>
    /// always dials the scope-authorized resolved IP. The HTTP layer still
    /// uses the URI authority for <c>Host:</c> and SNI, which is exactly
    /// what vhost-routed apps require — and DNS rebinding is mitigated
    /// because the URI's hostname is never re-resolved by the runtime.
    /// </summary>
    private static SocketsHttpHandler BuildSocketsHandler(IPAddress resolvedIp)
    {
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            },
            ConnectCallback = async (context, ct) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(
                        new IPEndPoint(resolvedIp, context.DnsEndPoint.Port), ct)
                        .ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
    }

    /// <summary>
    /// GAP-034: map a thrown exception from the HTTP send pipeline to a
    /// structured <c>reason</c> string. Triage on R3+R4 tape was
    /// dominated by <c>connection_refused</c> on closed ports the
    /// planner explored; distinguishing it from <c>dns_failure</c>,
    /// <c>tls_handshake</c>, <c>redirect_loop</c>, and <c>scope_reject</c>
    /// is load-bearing once exploitation gets serious.
    /// </summary>
    internal static string ClassifyException(Exception ex, CancellationToken ct)
    {
        for (var cur = ex; cur is not null; cur = cur.InnerException!)
        {
            switch (cur)
            {
                case ScopeException:
                    return "scope_reject";
                case AuthenticationException:
                    return "tls_handshake";
                case SocketException sock:
                    return ClassifySocketError(sock);
                case OperationCanceledException:
                    // TaskCanceledException (HttpClient timeout) and
                    // OperationCanceledException both land here.
                    return ct.IsCancellationRequested ? "transport" : "connection_timeout";
                case HttpRequestException httpEx:
                    var msg = httpEx.Message ?? "";
                    if (msg.Contains("name resolution", StringComparison.OrdinalIgnoreCase)
                        || msg.Contains("host not found", StringComparison.OrdinalIgnoreCase)
                        || msg.Contains("no such host", StringComparison.OrdinalIgnoreCase))
                        return "dns_failure";
                    if (msg.Contains("redirect", StringComparison.OrdinalIgnoreCase))
                        return "redirect_loop";
                    if (httpEx.StatusCode is { } sc && (int)sc >= 500 && (int)sc <= 599)
                        return "http_5xx";
                    break;
                case InvalidOperationException invOp:
                    if ((invOp.Message ?? "").Contains("redirect", StringComparison.OrdinalIgnoreCase))
                        return "redirect_loop";
                    break;
            }
            if (cur.InnerException is null) break;
        }
        return "transport";
    }

    private static string ClassifySocketError(SocketException sock)
    {
        switch (sock.SocketErrorCode)
        {
            case SocketError.ConnectionRefused:
                return "connection_refused";
            case SocketError.TimedOut:
            case SocketError.HostUnreachable:
            case SocketError.NetworkUnreachable:
                return "connection_timeout";
            case SocketError.HostNotFound:
            case SocketError.NoData:
            case SocketError.TryAgain:
                return "dns_failure";
        }
        // Linux ECONNREFUSED=111, Windows WSAECONNREFUSED=10061.
        if (sock.ErrorCode is 111 or 10061) return "connection_refused";
        if (sock.ErrorCode is 11001 or 11002 or 11003 or 11004) return "dns_failure";
        return "transport";
    }
}
