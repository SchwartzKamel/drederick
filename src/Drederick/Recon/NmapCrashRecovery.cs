using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon;

// --- htb-crash-resilient-nmap ---
/// <summary>
/// GAP-053: when <c>nmap</c> crashes, sigfaults, or emits truncated XML,
/// salvage whatever work was done. Strategy is two-tier:
///
///   1. <see cref="RecoverPartialXml"/> — pull every complete
///      <c>&lt;host&gt;…&lt;/host&gt;</c> block out of the raw stdout,
///      wrap each in a synthetic root and parse with <see cref="XDocument"/>.
///      Tail garbage (a half-written host element, a chopped XML close
///      tag, a SIGSEGV banner from <c>nmap</c> itself) is discarded.
///   2. <see cref="TcpConnectFallbackAsync"/> — if zero complete hosts were
///      recovered AND the subprocess did real work (≥10s elapsed OR ≥1
///      byte of stdout), open raw TCP connects against the requested
///      port list. Pure connect — no banner grab, no fingerprint, no
///      half-open SYN. Concurrency capped at <see cref="MaxConnectConcurrency"/>;
///      per-port timeout <see cref="ConnectTimeoutMs"/> ms.
///
/// Both tiers re-validate the target through <see cref="Scope.Scope.Require"/>
/// — the caller has already done so, but defense in depth here protects
/// any future caller that wires the helper directly.
/// </summary>
public static class NmapCrashRecovery
{
    public const int MaxConnectConcurrency = 64;
    public const int ConnectTimeoutMs = 1500;

    /// <summary>
    /// Lower bound on subprocess "did real work" before TCP-connect fallback is
    /// allowed. Either threshold satisfies — wallclock or non-empty stdout.
    /// </summary>
    public static readonly TimeSpan MinElapsedForFallback = TimeSpan.FromSeconds(10);

    // Reject obvious argv-injection / scope-bypass shapes in any host string
    // that crosses the fallback boundary. nmap itself accepts CIDR ranges
    // and hostnames; the fallback path is single-IP-only, so we tighten.
    private static readonly Regex SafeHostShape = new(
        @"^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+|[a-zA-Z0-9][-a-zA-Z0-9.]{0,253})$",
        RegexOptions.Compiled);

    private static readonly Regex HostBlock = new(
        @"<host\b[^>]*>.*?</host>",
        RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary>
    /// Extract every complete <c>&lt;host&gt;</c> block in <paramref name="xml"/>
    /// and return their parsed open-port entries. Tail garbage (partial last
    /// host, half-closed root element, NUL bytes) is discarded silently.
    /// Returns an empty list if no complete host element is found.
    /// </summary>
    public static List<NmapPort> RecoverPartialXml(string xml)
    {
        var ports = new List<NmapPort>();
        if (string.IsNullOrWhiteSpace(xml)) return ports;

        foreach (Match m in HostBlock.Matches(xml))
        {
            XElement host;
            try
            {
                host = XElement.Parse(m.Value);
            }
            catch (System.Xml.XmlException)
            {
                continue;
            }
            foreach (var p in host.Elements("ports").Elements("port"))
            {
                var state = p.Element("state")?.Attribute("state")?.Value;
                if (state != "open") continue;
                var svc = p.Element("service");
                var port = new NmapPort
                {
                    Port = int.TryParse(p.Attribute("portid")?.Value, out var n) ? n : 0,
                    Protocol = p.Attribute("protocol")?.Value ?? "tcp",
                    Service = svc?.Attribute("name")?.Value,
                    Product = svc?.Attribute("product")?.Value,
                    Version = svc?.Attribute("version")?.Value,
                    Extra = svc?.Attribute("extrainfo")?.Value,
                };
                foreach (var s in p.Elements("script"))
                {
                    port.Scripts.Add(new NmapScript
                    {
                        Id = s.Attribute("id")?.Value ?? "",
                        Output = s.Attribute("output")?.Value ?? "",
                    });
                }
                ports.Add(port);
            }
        }
        return ports;
    }

    /// <summary>
    /// Heuristic: did the subprocess do enough work that a TCP-connect
    /// fallback is justified? Either it ran for at least
    /// <see cref="MinElapsedForFallback"/> or produced any stdout bytes.
    /// Exit code is consulted by the caller, not here.
    /// </summary>
    public static bool ShouldAttemptConnectFallback(TimeSpan elapsed, long stdoutBytes)
        => elapsed >= MinElapsedForFallback || stdoutBytes > 0;

    /// <summary>
    /// Expand an nmap-style port spec ("80,443,8000-8005") into discrete
    /// integers. Returns an empty list when <paramref name="portSpec"/> is
    /// null/empty or contains "-" (all ports — too wide for a fallback
    /// connect sweep; caller should substitute top-N instead).
    /// </summary>
    public static List<int> ExpandPortSpec(string? portSpec)
    {
        var result = new List<int>();
        if (string.IsNullOrWhiteSpace(portSpec) || portSpec == "-") return result;
        foreach (var token in portSpec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = token.IndexOf('-');
            if (dash < 0)
            {
                if (int.TryParse(token, out var p) && p is > 0 and <= 65535) result.Add(p);
                continue;
            }
            if (int.TryParse(token[..dash], out var lo) &&
                int.TryParse(token[(dash + 1)..], out var hi) &&
                lo > 0 && hi > 0 && hi <= 65535 && lo <= hi && hi - lo <= 4096)
            {
                for (var p = lo; p <= hi; p++) result.Add(p);
            }
        }
        return result;
    }

    /// <summary>
    /// nmap's top-100 TCP ports (from the <c>nmap-services</c> frequency
    /// table). Used when nmap was invoked with no explicit <c>-p</c> and
    /// we need a default fallback target set.
    /// </summary>
    public static readonly IReadOnlyList<int> TopPorts100 = new[]
    {
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
        4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
        32768, 49152, 49153, 49154, 49155, 49156, 49157,
    };

    /// <summary>
    /// Race a bounded set of TCP connect probes against
    /// <paramref name="target"/> and return the open ports. Pure
    /// <see cref="TcpClient.ConnectAsync(string, int)"/>; no read,
    /// no write, no banner grab. Validates the target through
    /// <paramref name="scope"/> before any socket touches the wire.
    /// </summary>
    public static async Task<List<int>> TcpConnectFallbackAsync(
        Scope.Scope scope,
        string target,
        IReadOnlyList<int> ports,
        int maxConcurrency = MaxConnectConcurrency,
        int connectTimeoutMs = ConnectTimeoutMs,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(target))
            throw new ArgumentException("target empty.", nameof(target));
        if (!SafeHostShape.IsMatch(target))
            throw new ArgumentException($"Unsafe host shape '{target}'.", nameof(target));
        scope.Require(target);

        var open = new System.Collections.Concurrent.ConcurrentBag<int>();
        using var sem = new SemaphoreSlim(Math.Max(1, Math.Min(maxConcurrency, MaxConnectConcurrency)));
        var tasks = new List<Task>(ports.Count);

        foreach (var port in ports.Distinct())
        {
            if (port is <= 0 or > 65535) continue;
            await sem.WaitAsync(ct).ConfigureAwait(false);
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    using var client = new TcpClient();
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeout.CancelAfter(connectTimeoutMs);
                    try
                    {
                        await client.ConnectAsync(target, port, timeout.Token).ConfigureAwait(false);
                        if (client.Connected) open.Add(port);
                    }
                    catch
                    {
                        // closed / filtered / timeout — drop silently.
                    }
                }
                finally
                {
                    sem.Release();
                }
            }, ct));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        var list = open.ToList();
        list.Sort();
        return list;
    }

    /// <summary>
    /// Compute SHA-256 of <paramref name="text"/> as a lowercase hex
    /// digest. Used for audit fingerprints (e.g. truncated stderr tail
    /// hash) so we never serialise raw subprocess output to the log.
    /// </summary>
    public static string Sha256Hex(string text)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(text ?? ""));
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    /// <summary>
    /// Take the last <paramref name="max"/> bytes of <paramref name="s"/>.
    /// Used to truncate stderr before hashing — the audit log records the
    /// SHA-256 of the tail, never the tail itself.
    /// </summary>
    public static string Tail(string s, int max)
        => string.IsNullOrEmpty(s) || s.Length <= max ? (s ?? "") : s[^max..];

    /// <summary>
    /// Record a <c>nmap.crash</c> audit event. Stderr is hashed (last
    /// 4 KB) but never logged verbatim.
    /// </summary>
    public static void RecordCrash(
        AuditLog audit,
        string target,
        int exitCode,
        string stderr,
        int recoveredHostCount)
    {
        audit.Record("nmap.crash", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["exit_code"] = exitCode,
            ["stderr_tail_sha256"] = Sha256Hex(Tail(stderr, 4096)),
            ["recovered_host_count"] = recoveredHostCount,
        });
    }

    /// <summary>
    /// Record a <c>nmap.fallback_connect</c> audit event after a
    /// TCP-connect sweep substitutes for crashed nmap output.
    /// </summary>
    public static void RecordFallback(
        AuditLog audit,
        string target,
        int portCount,
        int foundOpenCount)
    {
        audit.Record("nmap.fallback_connect", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port_count"] = portCount,
            ["found_open_count"] = foundOpenCount,
        });
    }
}
// --- end htb-crash-resilient-nmap ---
