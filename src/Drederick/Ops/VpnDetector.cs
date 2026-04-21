using System.Net;
using System.Net.NetworkInformation;
using Drederick.Audit;
using Drederick.Reporting;

namespace Drederick.Ops;

/// <summary>
/// Snapshot of a single network interface, as consumed by <see cref="VpnDetector"/>.
/// Decoupled from <see cref="System.Net.NetworkInformation.NetworkInterface"/>
/// so tests can feed in deterministic fixtures.
/// </summary>
public sealed record VpnInterfaceInfo(
    string Name,
    OperationalStatus Status,
    IReadOnlyList<IPAddress> IPv4Addresses);

/// <summary>Provides the set of network interfaces visible to the current process.</summary>
public interface INetworkInterfaceProvider
{
    IEnumerable<VpnInterfaceInfo> GetInterfaces();
}

/// <summary>Default provider wrapping <see cref="NetworkInterface.GetAllNetworkInterfaces"/>.</summary>
public sealed class SystemNetworkInterfaceProvider : INetworkInterfaceProvider
{
    public IEnumerable<VpnInterfaceInfo> GetInterfaces()
    {
        NetworkInterface[] ifaces;
        try { ifaces = NetworkInterface.GetAllNetworkInterfaces(); }
        catch (NetworkInformationException) { yield break; }

        foreach (var nic in ifaces)
        {
            var v4 = new List<IPAddress>();
            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    v4.Add(ua.Address);
            }
            yield return new VpnInterfaceInfo(nic.Name, nic.OperationalStatus, v4);
        }
    }
}

/// <summary>Result of a <see cref="VpnDetector.DetectVpn"/> call.</summary>
public sealed record VpnStatus(bool IsActive, string? InterfaceName, IPAddress? LocalIp)
{
    public static VpnStatus Inactive { get; } = new(false, null, null);
}

/// <summary>
/// Detects whether an OpenVPN / WireGuard style <c>tun*</c> or <c>tap*</c>
/// interface is up with a routable IPv4 address. Used by the HTB ergonomics
/// preflight to refuse to scan HTB CIDRs without an active tunnel.
/// </summary>
public sealed class VpnDetector
{
    private readonly INetworkInterfaceProvider _provider;

    public VpnDetector() : this(new SystemNetworkInterfaceProvider()) { }
    public VpnDetector(INetworkInterfaceProvider provider)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Returns the first operationally-up <c>tun*</c>/<c>tap*</c> interface
    /// that has a non-link-local IPv4 address, or <see cref="VpnStatus.Inactive"/>.
    /// </summary>
    public VpnStatus DetectVpn()
    {
        foreach (var iface in _provider.GetInterfaces())
        {
            if (iface.Status != OperationalStatus.Up) continue;
            if (!IsVpnName(iface.Name)) continue;
            foreach (var addr in iface.IPv4Addresses)
            {
                if (IsRoutableIpv4(addr))
                    return new VpnStatus(true, iface.Name, addr);
            }
        }
        return VpnStatus.Inactive;
    }

    private static bool IsVpnName(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        return name.StartsWith("tun", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("tap", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRoutableIpv4(IPAddress addr)
    {
        if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        var bytes = addr.GetAddressBytes();
        // 169.254.0.0/16 link-local — skip.
        if (bytes[0] == 169 && bytes[1] == 254) return false;
        // 0.0.0.0 and 127.x — skip.
        if (bytes[0] == 0 || bytes[0] == 127) return false;
        return true;
    }
}

/// <summary>Outcome of <see cref="VpnPreflight.Run"/>.</summary>
public enum VpnPreflightOutcome
{
    /// <summary>Preflight was skipped (e.g. <c>--skip-vpn-check</c>).</summary>
    Skipped,
    /// <summary>No target resolved into a known HTB CIDR; no-op.</summary>
    NotHtbTarget,
    /// <summary>HTB target detected and a VPN tunnel was up.</summary>
    VpnActive,
    /// <summary>HTB target + no VPN; operator was warned but the run continues.</summary>
    WarnNoVpn,
    /// <summary>HTB target + no VPN + <c>--require-vpn</c>; caller must abort.</summary>
    AbortNoVpn,
}

/// <summary>
/// Orchestrates the VPN / HTB-CIDR preflight: resolves targets, decides
/// whether they look like HTB traffic, queries <see cref="VpnDetector"/>,
/// and records the outcome into audit + findings.db <c>tooling</c> table.
///
/// Exposed as an explicit class (rather than inline in Program.cs) so the
/// integration tests can drive the same code-path without spawning a
/// subprocess.
/// </summary>
public static class VpnPreflight
{
    public sealed record Options(
        IReadOnlyList<string> Targets,
        bool RequireVpn,
        bool SkipVpnCheck,
        string? HostsFilePath = null);

    public static VpnPreflightOutcome Run(
        Options options,
        AuditLog audit,
        SqliteReport? sqliteReport,
        TextWriter stderr,
        VpnDetector? detector = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(stderr);

        if (options.SkipVpnCheck)
        {
            audit.Record("vpn.preflight.skipped", new Dictionary<string, object?>
            {
                ["reason"] = "skip-vpn-check",
                ["target_count"] = options.Targets.Count,
            });
            return VpnPreflightOutcome.Skipped;
        }

        var htbTargets = new List<string>();
        foreach (var t in options.Targets)
        {
            if (LooksHtb(t, options.HostsFilePath)) htbTargets.Add(t);
        }

        if (htbTargets.Count == 0) return VpnPreflightOutcome.NotHtbTarget;

        var status = (detector ?? new VpnDetector()).DetectVpn();
        var now = DateTimeOffset.UtcNow.ToString("o");

        if (status.IsActive)
        {
            audit.Record("vpn.preflight.ok", new Dictionary<string, object?>
            {
                ["interface"] = status.InterfaceName,
                ["local_ip"] = status.LocalIp?.ToString(),
                ["htb_targets"] = htbTargets,
            });
            TryUpsertTooling(sqliteReport, name: "vpn", version: status.InterfaceName,
                source: "present", path: status.LocalIp?.ToString(), detectedAt: now);
            return VpnPreflightOutcome.VpnActive;
        }

        var msg = $"[vpn-preflight] WARNING: HTB CIDR target(s) detected ({string.Join(", ", htbTargets)}) "
                + "but no tun*/tap* VPN interface is up. Traffic will egress over your primary interface.";
        stderr.WriteLine("==============================================================");
        stderr.WriteLine(msg);
        stderr.WriteLine("==============================================================");

        audit.Record("vpn.preflight.warn", new Dictionary<string, object?>
        {
            ["htb_targets"] = htbTargets,
            ["reason"] = "no-tun-interface",
            ["require_vpn"] = options.RequireVpn,
        });
        TryUpsertTooling(sqliteReport, name: "vpn", version: null, source: "absent",
            path: "HTB CIDR target detected but no tun* interface up", detectedAt: now);

        return options.RequireVpn ? VpnPreflightOutcome.AbortNoVpn : VpnPreflightOutcome.WarnNoVpn;
    }

    private static bool LooksHtb(string target, string? hostsFilePath)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;
        if (IPAddress.TryParse(target, out var literal))
            return HtbRanges.IsHtbTarget(literal);
        if (HtbRanges.IsHtbHostname(target)) return true;
        var resolved = HtbRanges.TryResolve(target, hostsFilePath);
        return resolved is not null && HtbRanges.IsHtbTarget(resolved);
    }

    private static void TryUpsertTooling(SqliteReport? sqliteReport,
        string name, string? version, string? source, string? path, string detectedAt)
    {
        if (sqliteReport is null) return;
        try { sqliteReport.UpsertTooling(name, version, source, path, detectedAt); }
        catch { /* preflight must never break a scan */ }
    }
}
