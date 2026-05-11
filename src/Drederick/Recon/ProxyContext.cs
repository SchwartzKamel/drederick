using System.Net;
using System.Net.Sockets;
using Drederick.Audit;

namespace Drederick.Recon;

/// <summary>
/// Type of upstream proxy used to reach scope-resolved targets that live
/// behind a pivot (chisel/ligolo SOCKS, ssh -D, an HTTP proxy, etc.).
/// </summary>
public enum ProxyType
{
    Socks5,
    /// <summary>SOCKS5 with DNS resolved by the proxy (socks5h://).</summary>
    Socks5Hostname,
    Http,
}

/// <summary>
/// Plumbed-through proxy descriptor. Constructed once from
/// <c>--proxy &lt;uri&gt;</c> in <see cref="Drederick.Cli.CommandLineOptions"/>
/// and handed to every recon scanner that touches the network. The proxy
/// itself is a privileged hop — it is validated separately from scope:
/// scope-resolution always runs against the *target*, never the proxy
/// endpoint. The proxy URI itself is rejected if it points at a wildcard
/// or multicast address; non-loopback proxies require
/// <c>--allow-external-proxy</c> in strict mode.
/// </summary>
public sealed record ProxyContext(Uri Endpoint, ProxyType Type, bool AllowExternal)
{
    public string Host => Endpoint.Host;
    public int Port => Endpoint.Port;

    public bool IsLoopback
    {
        get
        {
            if (IPAddress.TryParse(Endpoint.Host, out var ip)) return IPAddress.IsLoopback(ip);
            return Endpoint.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Parse a <c>--proxy</c> URI value. Accepts <c>socks5://</c>,
    /// <c>socks5h://</c>, and <c>http://</c>. Throws
    /// <see cref="ArgumentException"/> on any malformed input,
    /// wildcard / multicast / loopback-network ranges that would let
    /// the proxy endpoint itself become the wildcard, or strict-mode
    /// rules without <paramref name="allowExternal"/>.
    /// </summary>
    public static ProxyContext Parse(string raw, bool labMode, bool allowExternal)
    {
        if (string.IsNullOrWhiteSpace(raw))
            throw new ArgumentException("--proxy requires a non-empty URI.");
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
            throw new ArgumentException($"--proxy: '{raw}' is not a valid absolute URI.");
        ProxyType type = uri.Scheme.ToLowerInvariant() switch
        {
            "socks5" => ProxyType.Socks5,
            "socks5h" => ProxyType.Socks5Hostname,
            "http" => ProxyType.Http,
            _ => throw new ArgumentException(
                $"--proxy: unsupported scheme '{uri.Scheme}'. Use socks5://, socks5h://, or http://."),
        };
        if (string.IsNullOrEmpty(uri.Host))
            throw new ArgumentException($"--proxy: '{raw}' is missing a host.");
        if (uri.Port <= 0 || uri.Port > 65535)
            throw new ArgumentException($"--proxy: '{raw}' is missing a valid port.");
        if (uri.Host == "0.0.0.0" || uri.Host == "::" || uri.Host == "*")
            throw new ArgumentException($"--proxy: wildcard proxy host '{uri.Host}' is refused.");
        if (IPAddress.TryParse(uri.Host, out var ip))
        {
            if (IPAddress.Any.Equals(ip) || IPAddress.IPv6Any.Equals(ip))
                throw new ArgumentException($"--proxy: wildcard proxy host '{uri.Host}' is refused.");
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork && b[0] >= 224 && b[0] <= 239)
                throw new ArgumentException($"--proxy: multicast proxy host '{uri.Host}' is refused.");
        }
        var ctx = new ProxyContext(uri, type, allowExternal);
        if (!labMode && !ctx.IsLoopback && !allowExternal)
            throw new ArgumentException(
                $"--proxy: '{uri.Host}' is not loopback; pass --allow-external-proxy in strict mode.");
        return ctx;
    }

    /// <summary>
    /// Produce the <c>--proxies</c> argv value nmap accepts. nmap historically
    /// only supports SOCKS4 / HTTP proxies via <c>--proxies</c>; SOCKS5 is
    /// translated to its closest stand-in (SOCKS4) and a warning audit event
    /// is recorded by the caller.
    /// </summary>
    public string ToNmapProxiesArg()
    {
        return Type switch
        {
            ProxyType.Http => $"http://{Host}:{Port}",
            _ => $"socks4://{Host}:{Port}",
        };
    }
}
