using System.Net;

namespace Drederick.Ops;

/// <summary>
/// Known Hack The Box network ranges and <c>.htb</c> hostname helpers.
///
/// The CIDR list below matches the public HTB lab/VPN footprint at the time
/// of writing:
///   * <c>10.10.10.0/24</c>, <c>10.10.11.0/24</c>  — classic "Machines".
///   * <c>10.10.14.0/23</c>                         — tun ingress range.
///   * <c>10.129.0.0/16</c>                         — Release Arena / Pro Labs.
///
/// This is intentionally a small static allow-list: we would rather fail to
/// warn on a new HTB prefix than spuriously nag on a self-hosted 10.x lab.
/// </summary>
public static class HtbRanges
{
    public static readonly IReadOnlyList<IPNetwork> KnownCidrs = new IPNetwork[]
    {
        IPNetwork.Parse("10.10.10.0/24"),
        IPNetwork.Parse("10.10.11.0/24"),
        IPNetwork.Parse("10.10.14.0/23"),
        IPNetwork.Parse("10.129.0.0/16"),
    };

    /// <summary>True if <paramref name="addr"/> falls inside any known HTB CIDR.</summary>
    public static bool IsHtbTarget(IPAddress addr)
    {
        ArgumentNullException.ThrowIfNull(addr);
        foreach (var net in KnownCidrs)
        {
            if (net.Contains(addr)) return true;
        }
        return false;
    }

    /// <summary>
    /// True if <paramref name="host"/> looks like an HTB hostname — i.e. its
    /// final DNS label (case-insensitive) is <c>htb</c>. Returns false for
    /// IP literals or empty strings.
    /// </summary>
    public static bool IsHtbHostname(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        if (IPAddress.TryParse(host, out _)) return false;
        var trimmed = host.TrimEnd('.');
        var dot = trimmed.LastIndexOf('.');
        if (dot < 0) return false;
        var tld = trimmed.AsSpan(dot + 1);
        return tld.Equals("htb", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Best-effort hostname resolution preferring <c>/etc/hosts</c>. For
    /// <c>.htb</c> hostnames we deliberately consult the hosts file first
    /// (HTB boxes typically ship an <c>/etc/hosts</c> entry and DNS would
    /// otherwise NXDOMAIN). For every other hostname we fall back to a
    /// normal DNS lookup. Returns <c>null</c> if resolution fails.
    /// </summary>
    public static IPAddress? TryResolve(string host, string? hostsFilePath = null)
    {
        if (string.IsNullOrWhiteSpace(host)) return null;
        if (IPAddress.TryParse(host, out var literal)) return literal;

        var fromHosts = LookupHostsFile(host, hostsFilePath ?? DefaultHostsFilePath());
        if (fromHosts is not null) return fromHosts;

        // Non-.htb hostnames may legitimately resolve via DNS.
        if (!IsHtbHostname(host))
        {
            try
            {
                var entries = Dns.GetHostAddresses(host);
                foreach (var addr in entries)
                {
                    if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) return addr;
                }
            }
            catch (System.Net.Sockets.SocketException) { }
            catch (ArgumentException) { }
        }
        return null;
    }

    internal static IPAddress? LookupHostsFile(string host, string hostsFilePath)
    {
        if (string.IsNullOrEmpty(hostsFilePath) || !File.Exists(hostsFilePath)) return null;
        string[] lines;
        try { lines = File.ReadAllLines(hostsFilePath); }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }

        foreach (var raw in lines)
        {
            var line = raw;
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            if (string.IsNullOrWhiteSpace(line)) continue;
            var tokens = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (tokens.Length < 2) continue;
            if (!IPAddress.TryParse(tokens[0], out var ip)) continue;
            for (int i = 1; i < tokens.Length; i++)
            {
                if (string.Equals(tokens[i], host, StringComparison.OrdinalIgnoreCase))
                    return ip;
            }
        }
        return null;
    }

    private static string DefaultHostsFilePath()
    {
        if (OperatingSystem.IsWindows())
        {
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            return Path.Combine(sys, "drivers", "etc", "hosts");
        }
        return "/etc/hosts";
    }
}
