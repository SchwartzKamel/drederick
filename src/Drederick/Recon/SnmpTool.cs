using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Scope;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;

namespace Drederick.Recon;

/// <summary>
/// Native SNMPv2c probe using SharpSNMP — no external <c>snmpwalk</c> binary
/// required. Walks the system MIB (<c>1.3.6.1.2.1.1</c>), running-process
/// table (<c>1.3.6.1.2.1.25.4.2</c>), and installed-software table
/// (<c>1.3.6.1.2.1.25.6.3</c>). Tries a list of common read-community strings
/// and stops on the first one that returns data. Never performs writes
/// (<c>snmpset</c>) and never attempts communities beyond the fixed list below.
/// </summary>
public sealed class SnmpTool : IReconTool
{
    public string Name => "snmp";

    public string Description =>
        "Native SNMP v1/v2c enumeration: system info, process list, installed software walk " +
        "without external snmpwalk dependency. Tries common read communities and walks the " +
        "system MIB, hrSWRun, and hrSWInstalled subtrees. Read-only.";

    // Extended discovery community list. This is not a brute force —
    // these are the universally common defaults found in lab environments.
    internal static readonly string[] DefaultCommunities =
        ["public", "private", "community", "manager", "snmp", "secret", "cisco"];

    // OID subtrees to walk (in order: system info first, then process/software).
    private static readonly string SystemSubtree = "1.3.6.1.2.1.1";
    private static readonly string HrSwRunSubtree = "1.3.6.1.2.1.25.4.2";
    private static readonly string HrSwInstalledSubtree = "1.3.6.1.2.1.25.6.3";

    // Output caps prevent a chatty agent from filling memory.
    internal const int MaxOids = 500;
    internal const int MaxBytes = 64 * 1024;

    // Per-walk timeout in milliseconds. 2 s keeps things fast; on a healthy
    // LAN the first UDP response is sub-100 ms.
    private const int TimeoutMs = 2000;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly ISnmpWalker _walker;

    public SnmpTool(Scope.Scope scope, AuditLog audit)
        : this(scope, audit, new DefaultSnmpWalker()) { }

    internal SnmpTool(Scope.Scope scope, AuditLog audit, ISnmpWalker walker)
    {
        _scope = scope;
        _audit = audit;
        _walker = walker;
    }

    public async Task<SnmpResult> ProbeAsync(
        string target,
        int port = 161,
        CancellationToken ct = default)
    {
        _scope.Require(target);

        _audit.Record("snmp.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["community_count"] = DefaultCommunities.Length,
        });

        var result = new SnmpResult { Port = port };
        string? lastError = null;

        // Resolve hostname to IP — SharpSNMP needs an IPEndPoint.
        IPAddress? ip = null;
        if (!IPAddress.TryParse(target, out ip))
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(target, ct).ConfigureAwait(false);
                ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                    ?? addresses.FirstOrDefault();
            }
            catch (Exception ex)
            {
                lastError = $"DNS resolution failed: {ex.Message}";
            }
        }

        if (ip is not null)
        {
            var endpoint = new IPEndPoint(ip, port);

            foreach (var community in DefaultCommunities)
            {
                ct.ThrowIfCancellationRequested();

                var variables = new List<(string Oid, string Value)>();
                try
                {
                    // Walk system subtree — if this succeeds the community is valid.
                    await Task.Run(
                        () => _walker.Walk(community, endpoint, SystemSubtree, TimeoutMs, variables),
                        ct).ConfigureAwait(false);

                    if (variables.Count == 0)
                    {
                        lastError = "No OIDs returned for this community";
                        continue;
                    }

                    // Best-effort walks for process/software tables; ignore failures so
                    // a partial system MIB is still reported.
                    foreach (var subtree in new[] { HrSwRunSubtree, HrSwInstalledSubtree })
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            await Task.Run(
                                () => _walker.Walk(community, endpoint, subtree, TimeoutMs, variables),
                                ct).ConfigureAwait(false);
                        }
                        catch { /* best-effort */ }
                    }

                    result.Community = community;
                    result.Reachable = true;
                    lastError = null;

                    // Populate with caps to prevent runaway output.
                    int totalBytes = 0;
                    foreach (var (oid, value) in variables)
                    {
                        if (result.SystemOids.Count >= MaxOids) break;
                        if (totalBytes + oid.Length + value.Length > MaxBytes) break;
                        totalBytes += oid.Length + value.Length;
                        result.SystemOids[oid] = value;
                    }
                    break;
                }
                catch (SnmpTimeoutException)
                {
                    // Timeout can mean: port closed, host unreachable, or community rejected
                    // by a silent-drop policy. Try remaining communities before giving up.
                    lastError = "SNMP timeout (no response — port may be closed or community rejected)";
                }
                catch (Exception ex)
                {
                    lastError = ex.Message;
                }
            }
        }

        if (!result.Reachable)
            result.Error = lastError is { Length: > 500 } e ? e[^500..] : (lastError ?? "snmp probe failed");

        _audit.Record("snmp.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["reachable"] = result.Reachable,
            // SHA-256 of the working community, never the plaintext value.
            ["community_digest"] = result.Reachable ? Sha256Hex(result.Community) : null,
            ["oid_count"] = result.SystemOids.Count,
        });

        return result;
    }

    private static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

/// <summary>
/// Abstraction over a single SNMP GET-NEXT walk operation.
/// Injected into <see cref="SnmpTool"/> so unit tests can drive the tool
/// without network access.
/// </summary>
internal interface ISnmpWalker
{
    /// <summary>
    /// Walks <paramref name="subtreeOid"/> using SNMPv2c and appends
    /// <c>(oid, value)</c> pairs to <paramref name="output"/>.
    /// </summary>
    /// <exception cref="SnmpTimeoutException">
    /// Thrown when the agent does not respond within <paramref name="timeoutMs"/> ms.
    /// </exception>
    void Walk(
        string community,
        IPEndPoint endpoint,
        string subtreeOid,
        int timeoutMs,
        List<(string Oid, string Value)> output);
}

/// <summary>Signals a UDP timeout from the SNMP agent (port closed, host unreachable, or silent-drop).</summary>
internal sealed class SnmpTimeoutException : Exception
{
    public SnmpTimeoutException(string message) : base(message) { }
    public SnmpTimeoutException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Production walker backed by SharpSNMP's <see cref="Messenger.Walk"/>.</summary>
internal sealed class DefaultSnmpWalker : ISnmpWalker
{
    public void Walk(
        string community,
        IPEndPoint endpoint,
        string subtreeOid,
        int timeoutMs,
        List<(string Oid, string Value)> output)
    {
        var variables = new List<Variable>();
        try
        {
            Messenger.Walk(
                VersionCode.V2,
                endpoint,
                new OctetString(community),
                new ObjectIdentifier(subtreeOid),
                variables,
                timeoutMs,
                WalkMode.WithinSubtree);
        }
        catch (Lextm.SharpSnmpLib.Messaging.TimeoutException ex)
        {
            throw new SnmpTimeoutException(ex.Message, ex);
        }
        catch (SocketException ex)
        {
            // ICMP port-unreachable surfaces as SocketException on Linux
            throw new SnmpTimeoutException($"Socket error: {ex.Message}", ex);
        }

        foreach (var v in variables)
            output.Add((v.Id.ToString(), v.Data.ToString() ?? string.Empty));
    }
}
