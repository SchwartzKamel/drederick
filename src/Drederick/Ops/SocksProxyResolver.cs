using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;

namespace Drederick.Ops;

/// <summary>
/// GAP-049 (htb-socks-proxy-scanning) — DI-injectable façade that turns a
/// raw <c>--proxy &lt;uri&gt;</c> CLI flag into a validated
/// <see cref="SocksProxyConfig"/> and provides interop helpers for every
/// consumer subsystem:
/// <list type="bullet">
///   <item><description><see cref="BuildHttpClientHandler"/> — for
///   <c>HttpProbeTool</c> / <c>HttpContentDiscoveryTool</c>.</description></item>
///   <item><description><see cref="BuildNmapProxiesArg"/> — for
///   <c>NmapTool.BuildArgs</c>.</description></item>
///   <item><description><see cref="BuildProcessEnv"/> /
///   <see cref="ApplyToCurrentProcessEnv"/> — for spawned subprocesses
///   (msfconsole / hydra / netexec / cached PoCs / etc.) that pick up
///   <c>HTTP_PROXY</c>, <c>HTTPS_PROXY</c>, and <c>ALL_PROXY</c>
///   automatically.</description></item>
/// </list>
///
/// Scope semantics are unchanged: scope enforces the <em>target</em>
/// allow-list. The proxy is a network path. The reverse-safety check
/// (<see cref="Resolve"/>) refuses configurations where the proxy host
/// itself sits inside the scope — that is almost always an operator typo
/// (pointed the proxy at a target instead of the pivot listener) and
/// would route every recon connection through a target host.
///
/// Audit:
/// <list type="bullet">
///   <item><description><c>proxy.config.loaded</c> — emitted once at
///   <see cref="Resolve"/> with the redacted URI. If credentials were
///   supplied, the password is recorded only as a SHA-256 digest.</description></item>
///   <item><description><c>proxy.applied.&lt;tool&gt;</c> — emitted by
///   <see cref="RecordApplied"/> each time a downstream tool dispatches
///   with the proxy active.</description></item>
/// </list>
/// </summary>
public sealed class SocksProxyResolver
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;

    public SocksProxyResolver(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    /// <summary>
    /// Resolve a raw CLI value into a typed <see cref="SocksProxyConfig"/>.
    /// Returns null for null/whitespace input (no proxy). On valid input
    /// records <c>proxy.config.loaded</c> with redacted credentials.
    /// </summary>
    /// <param name="raw">The verbatim <c>--proxy</c> argument value.</param>
    /// <param name="labMode">When false (strict mode), a non-loopback proxy
    /// requires <paramref name="allowExternalProxy"/> = true.</param>
    /// <param name="allowExternalProxy">Operator-provided
    /// <c>--allow-external-proxy</c> opt-in.</param>
    /// <exception cref="ArgumentException">URI is malformed / scheme
    /// unsupported / shell-metachar embedded / strict-mode non-loopback
    /// without opt-in.</exception>
    /// <exception cref="InvalidOperationException">Reverse-safety violation
    /// — the proxy host is itself a scope-resolved target.</exception>
    public SocksProxyConfig? Resolve(string? raw, bool labMode, bool allowExternalProxy)
    {
        var cfg = SocksProxyConfig.TryValidate(raw);
        if (cfg is null) return null;

        if (!labMode && !cfg.IsLoopback && !allowExternalProxy)
        {
            throw new ArgumentException(
                $"--proxy: '{cfg.Host}' is not loopback; pass --allow-external-proxy in strict mode.");
        }

        // Reverse safety: refuse when the proxy endpoint resolves into
        // scope. Operators routinely typo --proxy and point it at a
        // target — that would route every dial through a target host
        // and silently leak operator intent.
        if (IPAddress.TryParse(cfg.Host, out _) && _scope.Contains(cfg.Host))
        {
            throw new InvalidOperationException(
                $"--proxy: proxy host '{cfg.Host}' is itself inside the authorized target scope. " +
                "This is almost certainly a typo — the proxy must be the pivot listener, not a target. " +
                "Refusing to dispatch through it.");
        }

        var fields = new Dictionary<string, object?>
        {
            ["scheme"] = cfg.SchemeString,
            ["host"] = cfg.Host,
            ["port"] = cfg.Port,
            ["loopback"] = cfg.IsLoopback,
            ["redacted_uri"] = cfg.ToRedactedUri(),
            ["username"] = cfg.Username,            // username is operator-supplied identifier; OK to record
            ["password_present"] = !string.IsNullOrEmpty(cfg.Password),
        };
        if (!string.IsNullOrEmpty(cfg.Password))
        {
            fields["password_sha256"] = Sha256Hex(cfg.Password);
        }
        _audit.Record("proxy.config.loaded", fields);

        return cfg;
    }

    /// <summary>
    /// Build an <see cref="HttpClientHandler"/> configured to route all
    /// requests through <paramref name="cfg"/>. When <paramref name="cfg"/>
    /// is null, returns a default handler (no proxy). Caller owns the
    /// handler lifetime.
    /// </summary>
    public HttpClientHandler BuildHttpClientHandler(SocksProxyConfig? cfg)
    {
        var handler = new HttpClientHandler();
        if (cfg is null)
        {
            handler.UseProxy = false;
            return handler;
        }
        var webProxy = new WebProxy(new Uri(cfg.ToRedactedUri()));
        if (!string.IsNullOrEmpty(cfg.Username))
        {
            webProxy.Credentials = new NetworkCredential(cfg.Username, cfg.Password ?? string.Empty);
        }
        handler.Proxy = webProxy;
        handler.UseProxy = true;
        return handler;
    }

    /// <summary>
    /// Produce the <c>--proxies</c> argv value nmap accepts. nmap's
    /// <c>--proxies</c> chain historically supports <c>socks4://</c> and
    /// <c>http://</c> (recent nmap also accepts <c>socks5://</c>); HTTPS
    /// is translated down to HTTP. SOCKS5h is rendered as <c>socks5://</c>
    /// — the "h" (proxy-side DNS) flag has no nmap analogue and the proxy
    /// will still resolve target names client-side.
    /// </summary>
    public static string BuildNmapProxiesArg(SocksProxyConfig cfg)
    {
        ArgumentNullException.ThrowIfNull(cfg);
        var scheme = cfg.Scheme switch
        {
            SocksProxyScheme.Socks5 => "socks5",
            SocksProxyScheme.Socks5h => "socks5",
            SocksProxyScheme.Http => "http",
            SocksProxyScheme.Https => "http",
            _ => throw new InvalidOperationException($"Unsupported scheme {cfg.Scheme}"),
        };
        return $"{scheme}://{cfg.Host}:{cfg.Port}";
    }

    /// <summary>
    /// Build the environment-variable dictionary that proxychains-aware
    /// CLI tools (curl, wget, msfconsole, hydra, netexec, most Go-based
    /// PoCs) pick up: <c>HTTP_PROXY</c>, <c>HTTPS_PROXY</c>,
    /// <c>ALL_PROXY</c>, plus their lowercase variants which some tools
    /// honour exclusively.
    /// </summary>
    public static IReadOnlyDictionary<string, string> BuildProcessEnv(SocksProxyConfig cfg)
    {
        ArgumentNullException.ThrowIfNull(cfg);
        var uri = cfg.ToFullUri();
        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["HTTP_PROXY"] = uri,
            ["HTTPS_PROXY"] = uri,
            ["ALL_PROXY"] = uri,
            ["http_proxy"] = uri,
            ["https_proxy"] = uri,
            ["all_proxy"] = uri,
        };
    }

    /// <summary>
    /// Set <c>HTTP_PROXY</c> / <c>HTTPS_PROXY</c> / <c>ALL_PROXY</c> on
    /// the current process. Child processes spawned via
    /// <see cref="System.Diagnostics.Process.Start(System.Diagnostics.ProcessStartInfo)"/>
    /// inherit these by default. Idempotent; subsequent calls overwrite.
    /// </summary>
    public void ApplyToCurrentProcessEnv(SocksProxyConfig? cfg)
    {
        if (cfg is null) return;
        var env = BuildProcessEnv(cfg);
        foreach (var kv in env)
        {
            Environment.SetEnvironmentVariable(kv.Key, kv.Value);
        }
        _audit.Record("proxy.env.applied", new Dictionary<string, object?>
        {
            ["redacted_uri"] = cfg.ToRedactedUri(),
            ["vars"] = env.Keys.ToArray(),
        });
    }

    /// <summary>
    /// Emit a per-tool dispatch breadcrumb so the audit trail shows which
    /// tools actually routed through the proxy versus dialed direct.
    /// No-op when <paramref name="cfg"/> is null.
    /// </summary>
    public void RecordApplied(string toolName, SocksProxyConfig? cfg)
    {
        if (cfg is null) return;
        if (string.IsNullOrWhiteSpace(toolName)) toolName = "unknown";
        _audit.Record($"proxy.applied.{toolName}", new Dictionary<string, object?>
        {
            ["tool"] = toolName,
            ["redacted_uri"] = cfg.ToRedactedUri(),
            ["scheme"] = cfg.SchemeString,
        });
    }

    internal static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
