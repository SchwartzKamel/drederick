using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Drederick.Ops;

/// <summary>
/// GAP-049 (htb-socks-proxy-scanning) — accepted upstream proxy schemes for
/// pivot-routed recon and exploitation. <c>Socks5h</c> resolves DNS through
/// the proxy (critical for internal hostnames that only the pivot's resolver
/// knows); <c>Socks5</c> resolves client-side. HTTP(S) proxies are accepted
/// for completeness — a few corporate pivots terminate as plain HTTP CONNECT.
/// </summary>
public enum SocksProxyScheme
{
    Socks5,
    /// <summary>SOCKS5 with DNS resolved by the proxy (socks5h://).</summary>
    Socks5h,
    Http,
    Https,
}

/// <summary>
/// GAP-049 — typed, validated configuration for an upstream pivot proxy
/// supplied via <c>--proxy &lt;uri&gt;</c>. Scope authorization remains a
/// property of the <em>target</em>, never the proxy endpoint: the proxy is
/// a network path, not an authorization signal. The reverse-safety check
/// (refusing a config whose proxy host is itself a scope-resolved target)
/// lives in <see cref="SocksProxyResolver.Resolve"/>.
///
/// Plaintext credentials are never serialized or logged in audit events.
/// Callers wanting to surface "credentials supplied" record only the
/// SHA-256 digest of the password — see <see cref="SocksProxyResolver"/>.
/// </summary>
public sealed record SocksProxyConfig(
    SocksProxyScheme Scheme,
    string Host,
    int Port,
    string? Username,
    string? Password)
{
    /// <summary>True when host parses to an IPv4/IPv6 loopback or equals
    /// <c>localhost</c> (case-insensitive). Used by the resolver to
    /// short-circuit the <c>--allow-external-proxy</c> requirement in
    /// strict mode.</summary>
    public bool IsLoopback
    {
        get
        {
            if (string.IsNullOrEmpty(Host)) return false;
            if (string.Equals(Host, "localhost", StringComparison.OrdinalIgnoreCase))
                return true;
            return IPAddress.TryParse(Host, out var ip) && IPAddress.IsLoopback(ip);
        }
    }

    /// <summary>Lower-case scheme string suitable for emitting back into a
    /// URI / env var (e.g. <c>socks5h</c>). <see cref="SocksProxyScheme.Socks5h"/>
    /// is rendered with the trailing <c>h</c>.</summary>
    public string SchemeString => Scheme switch
    {
        SocksProxyScheme.Socks5 => "socks5",
        SocksProxyScheme.Socks5h => "socks5h",
        SocksProxyScheme.Http => "http",
        SocksProxyScheme.Https => "https",
        _ => throw new InvalidOperationException($"Unknown scheme {Scheme}"),
    };

    /// <summary>Render a URI without credentials. Always safe to log.</summary>
    public string ToRedactedUri()
        => $"{SchemeString}://{Host}:{Port}";

    /// <summary>Render a URI including inline <c>user:pass@</c>. NEVER pass
    /// to <see cref="Drederick.Audit.AuditLog"/>; callers that need this
    /// value (e.g. <c>HTTP_PROXY</c> for a child process) must scrub before
    /// recording.</summary>
    internal string ToFullUri()
    {
        if (!string.IsNullOrEmpty(Username))
        {
            var u = Uri.EscapeDataString(Username);
            var p = string.IsNullOrEmpty(Password) ? string.Empty : ":" + Uri.EscapeDataString(Password);
            return $"{SchemeString}://{u}{p}@{Host}:{Port}";
        }
        return ToRedactedUri();
    }

    // Hostnames per RFC 1123 (letters, digits, hyphens, dots); IPv6 in
    // [bracketed] form is normalized away during Parse. Bracket the
    // anti-injection guard tightly — shell metachars, backticks, $(,
    // newlines, and bare URI fragments are all unconditional rejects.
    private static readonly Regex HostShape = new(
        @"^(?:[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$",
        RegexOptions.Compiled);

    private static readonly char[] ForbiddenInUri =
    {
        ' ', '\t', '\n', '\r', '`', '$', '|', ';', '&', '<', '>', '\\', '"', '\'', '*', '?',
    };

    /// <summary>
    /// Parse a raw <c>--proxy</c> value. Accepts:
    /// <c>socks5://host:port</c>, <c>socks5h://host:port</c>,
    /// <c>http://host:port</c>, <c>https://host:port</c>, with optional
    /// <c>user[:password]@</c> userinfo. Throws <see cref="ArgumentException"/>
    /// for any malformed / unsupported / suspicious input.
    /// </summary>
    public static SocksProxyConfig Parse(string raw)
    {
        if (raw is null) throw new ArgumentNullException(nameof(raw));
        if (string.IsNullOrWhiteSpace(raw))
            throw new ArgumentException("--proxy requires a non-empty URI.", nameof(raw));

        // Reject obvious shell-metachar / injection patterns up front. Uri.TryCreate
        // will accept e.g. "socks5://`whoami`:1080" because backticks are
        // technically allowed in some userinfo positions, and we never want
        // those argv fragments anywhere near a spawned subprocess.
        foreach (var ch in ForbiddenInUri)
        {
            if (raw.IndexOf(ch) >= 0)
                throw new ArgumentException(
                    $"--proxy: refusing URI containing forbidden character '{(ch == '\t' ? "\\t" : ch == '\n' ? "\\n" : ch.ToString())}' in '{raw}'.",
                    nameof(raw));
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
            throw new ArgumentException($"--proxy: '{raw}' is not a valid absolute URI.", nameof(raw));

        var scheme = uri.Scheme.ToLowerInvariant() switch
        {
            "socks5" => SocksProxyScheme.Socks5,
            "socks5h" => SocksProxyScheme.Socks5h,
            "http" => SocksProxyScheme.Http,
            "https" => SocksProxyScheme.Https,
            _ => throw new ArgumentException(
                $"--proxy: unsupported scheme '{uri.Scheme}'. Use socks5://, socks5h://, http://, or https://.",
                nameof(raw)),
        };

        if (string.IsNullOrEmpty(uri.Host))
            throw new ArgumentException($"--proxy: '{raw}' is missing a host.", nameof(raw));
        if (uri.Port <= 0 || uri.Port > 65535)
            throw new ArgumentException($"--proxy: '{raw}' is missing a valid port.", nameof(raw));

        // Catch the "operator typoed and the host field IS a scheme" case
        // (e.g. --proxy=http://). Uri.Host on "http://" is "" which we caught,
        // but socks5://http:// becomes host=http path=//.
        if (uri.Host.Equals("http", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.Equals("https", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.Equals("socks5", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.Equals("socks5h", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"--proxy: host '{uri.Host}' looks like a URI scheme — check your --proxy value.",
                nameof(raw));

        // Refuse wildcard / multicast / IPv6-wildcard hosts. The proxy
        // endpoint itself cannot be the wildcard — that would make every
        // outbound connection ambiguous.
        var hostNorm = uri.Host;
        if (hostNorm == "0.0.0.0" || hostNorm == "::" || hostNorm == "*")
            throw new ArgumentException($"--proxy: wildcard proxy host '{hostNorm}' is refused.", nameof(raw));
        if (IPAddress.TryParse(hostNorm, out var hostIp))
        {
            if (IPAddress.Any.Equals(hostIp) || IPAddress.IPv6Any.Equals(hostIp))
                throw new ArgumentException($"--proxy: wildcard proxy host '{hostNorm}' is refused.", nameof(raw));
            var b = hostIp.GetAddressBytes();
            if (hostIp.AddressFamily == AddressFamily.InterNetwork && b[0] >= 224 && b[0] <= 239)
                throw new ArgumentException($"--proxy: multicast proxy host '{hostNorm}' is refused.", nameof(raw));
        }
        else
        {
            // Not an IP — must look like a hostname. Uri.Host strips the brackets
            // around bare IPv6 already; anything getting here is text.
            if (!HostShape.IsMatch(hostNorm))
                throw new ArgumentException(
                    $"--proxy: host '{hostNorm}' is not a valid hostname or IP address.",
                    nameof(raw));
        }

        string? user = null, pass = null;
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            var sep = uri.UserInfo.IndexOf(':');
            if (sep < 0)
            {
                user = Uri.UnescapeDataString(uri.UserInfo);
            }
            else
            {
                user = Uri.UnescapeDataString(uri.UserInfo[..sep]);
                pass = Uri.UnescapeDataString(uri.UserInfo[(sep + 1)..]);
            }
            if (string.IsNullOrEmpty(user))
                throw new ArgumentException($"--proxy: empty username in userinfo.", nameof(raw));
        }

        return new SocksProxyConfig(scheme, hostNorm, uri.Port, user, pass);
    }

    /// <summary>Static validate-only — used by CLI parse-time fast-fail.
    /// Returns null for null/empty input; throws on malformed input.</summary>
    public static SocksProxyConfig? TryValidate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        return Parse(raw);
    }
}
