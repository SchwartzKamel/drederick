using System.Collections.Concurrent;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;

namespace Drederick.Recon;

/// <summary>
/// Fully-async native TCP port scanner with service banner grabbing.
/// Replaces nmap for basic port discovery when nmap is unavailable.
/// Scope-enforced: <see cref="Scope.Scope.Require"/> is the first
/// statement in every public method.
/// </summary>
public sealed class NativeScannerTool : IReconTool
{
    public string Name => "nativescan";

    public string Description =>
        "Fast native TCP port scanner with banner grabbing. " +
        "Use when nmap is unavailable or for initial quick sweep. " +
        "The target MUST be inside the authorized scope.";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly ProxyContext? _proxy;

    // Top common ports mirroring nmap's -F / --top-ports 1000 list (key subset).
    private static readonly int[] DefaultPorts =
    [
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445,
        465, 514, 587, 631, 993, 995, 1080, 1433, 1521, 2049, 2121,
        3000, 3306, 3389, 3632, 4848, 5000, 5432, 5900, 5984,
        6379, 6443, 7001, 7080, 7443,
        8000, 8080, 8081, 8082, 8443, 8888,
        9000, 9090, 9200, 9300, 10000, 11211,
        27017, 27018, 50000, 50070, 61616,
    ];

    private const int BannerReadTimeoutMs = 1000;
    private const int BannerMaxBytes = 2048;
    private const int BannerTruncateAt = 200;

    public NativeScannerTool(Scope.Scope scope, AuditLog audit, ProxyContext? proxy = null)
    {
        _scope = scope;
        _audit = audit;
        _proxy = proxy;
    }

    /// <summary>
    /// Scan <paramref name="target"/> by attempting a TCP connect on each port,
    /// then grabbing the first 2 KB of banner data for open ports.
    /// Returns a <see cref="HostFinding"/> with <see cref="HostFinding.NativeScan"/>
    /// populated. Never throws on per-port failures.
    /// </summary>
    public async Task<HostFinding> ScanAsync(
        string target,
        int[]? ports = null,
        int concurrency = 500,
        int timeoutMs = 2000,
        CancellationToken ct = default)
    {
        _scope.Require(target);

        var portList = ports ?? DefaultPorts;
        var portsDigest = ComputePortsDigest(portList);

        _audit.Record("nativescan.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port_count"] = portList.Length,
            ["ports_digest"] = portsDigest,
        });

        var started = DateTimeOffset.UtcNow.ToString("o");
        var openPorts = new ConcurrentBag<NmapPort>();
        using var sem = new SemaphoreSlim(Math.Max(1, concurrency), Math.Max(1, concurrency));

        try
        {
            var tasks = portList.Select(port =>
                ScanPortAsync(target, port, timeoutMs, sem, openPorts, _proxy, _audit, ct));
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _audit.Record("nativescan.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["error"] = ex.Message,
            });
        }

        var finished = DateTimeOffset.UtcNow.ToString("o");
        var scanResult = new NativeScanResult
        {
            Source = "nativescan",
            Started = started,
            Finished = finished,
            OpenPorts = [.. openPorts.OrderBy(p => p.Port)],
        };

        _audit.Record("nativescan.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["open_count"] = scanResult.OpenPorts.Count,
        });

        return new HostFinding
        {
            Target = target,
            Started = started,
            Finished = finished,
            NativeScan = scanResult,
        };
    }

    private static async Task ScanPortAsync(
        string target,
        int port,
        int timeoutMs,
        SemaphoreSlim sem,
        ConcurrentBag<NmapPort> results,
        ProxyContext? proxy,
        AuditLog audit,
        CancellationToken ct)
    {
        await sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var tcp = new TcpClient();
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(timeoutMs);

            Socket? proxiedSocket = null;
            try
            {
                if (proxy is not null)
                {
                    audit.Record("proxy.connect.start", new Dictionary<string, object?>
                    {
                        ["target"] = target,
                        ["port"] = port,
                        ["proxy_endpoint"] = $"{proxy.Host}:{proxy.Port}",
                        ["proxy_type"] = proxy.Type.ToString(),
                    });
                    var resolveAtProxy = proxy.Type == ProxyType.Socks5Hostname;
                    proxiedSocket = await Drederick.Recon.Scanning.Socks5Connector.ConnectAsync(
                        proxy, target, port, timeoutMs, resolveAtProxy, connectCts.Token)
                        .ConfigureAwait(false);
                    audit.Record("proxy.connect.success", new Dictionary<string, object?>
                    {
                        ["target"] = target,
                        ["port"] = port,
                    });
                }
                else
                {
                    await tcp.ConnectAsync(target, port, connectCts.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                if (proxy is not null)
                    audit.Record("proxy.connect.fail", new Dictionary<string, object?>
                    { ["target"] = target, ["port"] = port, ["error"] = "timeout" });
                proxiedSocket?.Dispose();
                return;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                if (proxy is not null)
                    audit.Record("proxy.connect.fail", new Dictionary<string, object?>
                    { ["target"] = target, ["port"] = port, ["error"] = ex.Message });
                proxiedSocket?.Dispose();
                return;
            }

            // Port is open — identify service via port-specific logic or banner
            string? banner = null;
            string? service = port switch
            {
                445 => "smb",
                3389 => "rdp",
                _ => null,
            };

            // SOCKS5-tunnelled banners are intentionally skipped for now (the
            // open-port record is what the planner consumes; banner-grab over
            // a SOCKS Socket would need a parallel TLS/raw read path).
            if (proxiedSocket is null && service is null)
            {
                try
                {
                    if (port is 443 or 8443)
                    {
                        banner = await GrabTlsBannerAsync(tcp, target, ct).ConfigureAwait(false);
                        service = "https";
                    }
                    else
                    {
                        banner = await GrabRawBannerAsync(tcp, port, ct).ConfigureAwait(false);
                        service = DetectServiceFromBanner(port, banner);
                    }
                }
                catch
                {
                    // Banner grab failure does not suppress the open-port record.
                }
            }

            results.Add(new NmapPort
            {
                Port = port,
                Protocol = "tcp",
                Service = service,
                Extra = banner is not null ? Truncate(banner, BannerTruncateAt) : null,
            });
            proxiedSocket?.Dispose();
        }
        finally
        {
            sem.Release();
        }
    }

    private static async Task<string?> GrabRawBannerAsync(
        TcpClient tcp,
        int port,
        CancellationToken ct)
    {
        using var bannerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bannerCts.CancelAfter(BannerReadTimeoutMs);

        try
        {
            var stream = tcp.GetStream();

            // Redis does not emit a banner on connect — probe it.
            if (port == 6379)
            {
                await stream.WriteAsync(
                    Encoding.ASCII.GetBytes("PING\r\n"),
                    bannerCts.Token).ConfigureAwait(false);
            }

            var buf = new byte[BannerMaxBytes];
            var n = await stream.ReadAsync(buf.AsMemory(0, BannerMaxBytes), bannerCts.Token)
                .ConfigureAwait(false);
            return n > 0 ? Encoding.ASCII.GetString(buf, 0, n) : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<string?> GrabTlsBannerAsync(
        TcpClient tcp,
        string host,
        CancellationToken ct)
    {
        using var bannerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bannerCts.CancelAfter(BannerReadTimeoutMs);

        try
        {
            var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                },
                bannerCts.Token).ConfigureAwait(false);

            var buf = new byte[BannerMaxBytes];
            var n = await ssl.ReadAsync(buf.AsMemory(0, BannerMaxBytes), bannerCts.Token)
                .ConfigureAwait(false);
            return n > 0 ? Encoding.ASCII.GetString(buf, 0, n) : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? DetectServiceFromBanner(int port, string? banner)
    {
        if (banner is not null)
        {
            if (banner.StartsWith("SSH-", StringComparison.Ordinal))
                return "ssh";
            if (banner.StartsWith("+PONG", StringComparison.Ordinal))
                return "redis";
            if (banner.StartsWith("HTTP/", StringComparison.Ordinal) ||
                banner.StartsWith("HTTP ", StringComparison.Ordinal))
                return "http";
            if (banner.StartsWith("<html", StringComparison.OrdinalIgnoreCase) ||
                banner.StartsWith("<?xml", StringComparison.Ordinal))
                return "http";
            if (banner.StartsWith("220 ", StringComparison.Ordinal))
                return banner.Contains("ftp", StringComparison.OrdinalIgnoreCase) ? "ftp" : "smtp";
        }

        return port switch
        {
            3306 => "mysql",
            5432 => "postgresql",
            6379 => "redis",
            _ => null,
        };
    }

    private static string ComputePortsDigest(int[] ports)
    {
        var text = string.Join(",", ports.OrderBy(p => p));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max];
}
