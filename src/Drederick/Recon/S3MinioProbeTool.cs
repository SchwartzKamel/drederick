using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// GAP-037: MinIO / S3-compatible service prober. Detects S3 protocol via
/// MinIO health endpoints, Server header, anonymous bucket listing, and
/// AccessDenied error fingerprints. When AWS credentials are available
/// in the <see cref="CredentialStore"/> (realm = "s3"), performs an
/// authenticated bucket + object listing through an injected
/// <see cref="IS3BucketLister"/>.
///
/// Hostname targets are resolved via DNS and the resolved IP is what
/// passes <see cref="Scope.Scope.Require"/> (gap-032 pattern). Object
/// listing is metadata-only — download is a separate tool.
/// </summary>
public sealed partial class S3MinioProbeTool : IReconTool
{
    public string Name => "s3";

    public string Description =>
        "Probe a target for S3/MinIO service. Detects via /minio/health/live, " +
        "Server header, anonymous bucket listing, and AccessDenied XML. " +
        "Lists buckets + object metadata when credentials are available. " +
        "Read-only metadata only — does not download object payloads.";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly CredentialStore? _credentials;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _dnsResolver;
    private readonly Func<IPAddress, HttpMessageHandler>? _handlerFactory;
    private readonly IS3BucketLister? _bucketLister;
    private readonly TimeSpan _timeout;

    [GeneratedRegex(@"MinIO/?(?<v>[A-Za-z0-9._\-]+)?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MinioServerRegex();

    public S3MinioProbeTool(Scope.Scope scope, AuditLog audit, CredentialStore? credentials = null)
        : this(scope, audit, credentials, null, null, null, TimeSpan.FromSeconds(8))
    {
    }

    internal S3MinioProbeTool(
        Scope.Scope scope,
        AuditLog audit,
        CredentialStore? credentials,
        Func<string, CancellationToken, Task<IPAddress[]>>? dnsResolver,
        Func<IPAddress, HttpMessageHandler>? handlerFactory,
        IS3BucketLister? bucketLister,
        TimeSpan timeout)
    {
        _scope = scope;
        _audit = audit;
        _credentials = credentials;
        _dnsResolver = dnsResolver ?? ((host, ct) => Dns.GetHostAddressesAsync(host, ct));
        _handlerFactory = handlerFactory;
        _bucketLister = bucketLister;
        _timeout = timeout;
    }

    internal sealed record ResolvedTarget(IPAddress ResolvedIp, string? Hostname);

    internal async Task<ResolvedTarget> ResolveAsync(string target, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(target);
        var stripped = target.StartsWith('[') && target.EndsWith(']')
            ? target.Substring(1, target.Length - 2)
            : target;

        if (IPAddress.TryParse(stripped, out var ipDirect))
        {
            _scope.Require(stripped);
            return new ResolvedTarget(ipDirect, null);
        }

        IPAddress[] addrs;
        try
        {
            addrs = await _dnsResolver(target, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new ScopeException(
                $"Failed to resolve hostname '{target}' for s3_probe: {ex.Message}");
        }
        if (addrs.Length == 0)
        {
            throw new ScopeException($"Hostname '{target}' did not resolve to any address.");
        }
        foreach (var addr in addrs)
        {
            if (_scope.Contains(addr.ToString()))
            {
                _scope.Require(addr.ToString());
                return new ResolvedTarget(addr, target);
            }
        }
        var joined = string.Join(", ", addrs.Select(a => a.ToString()));
        throw new ScopeException($"hostname '{target}' resolves to {{{joined}}}, none in scope.");
    }

    public async Task<S3Finding> ProbeAsync(
        string target,
        int port = 9000,
        CancellationToken ct = default)
    {
        // First statement: scope authorization on resolved IP.
        var resolved = await ResolveAsync(target, ct).ConfigureAwait(false);

        var endpointUrl = BuildEndpoint(resolved, port);
        _audit.Record("s3.probe.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["resolved_ip"] = resolved.ResolvedIp.ToString(),
            ["port"] = port,
            ["endpoint"] = endpointUrl,
        });

        bool isS3 = false;
        bool isMinio = false;
        bool anonAllowed = false;
        var anonBuckets = new List<string>();
        string? server = null;
        string? minioVersion = null;
        string? error = null;
        IReadOnlyList<S3BucketEntry> authBuckets = [];

        var handler = _handlerFactory is not null
            ? _handlerFactory(resolved.ResolvedIp)
            : BuildSocketsHandler(resolved.ResolvedIp);
        using var http = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = _timeout,
        };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("drederick/0.1 (+lab-recon)");

        try
        {
            using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            probeCts.CancelAfter(_timeout);
            var pct = probeCts.Token;

            // 1. MinIO health endpoint (highest signal).
            try
            {
                using var resp = await http.GetAsync($"{endpointUrl}minio/health/live",
                    HttpCompletionOption.ResponseHeadersRead, pct).ConfigureAwait(false);
                CaptureServer(resp, ref server, ref minioVersion);
                if ((int)resp.StatusCode == 200)
                {
                    isMinio = true;
                    isS3 = true;
                }
            }
            catch (Exception ex) when (!IsCancellation(ex, ct))
            {
                _audit.Record("s3.probe.health_error", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["error"] = ex.Message,
                });
            }

            // 2. Root listing — anonymous bucket list / Server header / error fingerprint.
            try
            {
                using var resp = await http.GetAsync(endpointUrl,
                    HttpCompletionOption.ResponseContentRead, pct).ConfigureAwait(false);
                CaptureServer(resp, ref server, ref minioVersion);

                var body = await resp.Content.ReadAsStringAsync(pct).ConfigureAwait(false);
                var status = (int)resp.StatusCode;

                if (status == 200 && body.Contains("<ListAllMyBucketsResult", StringComparison.OrdinalIgnoreCase))
                {
                    isS3 = true;
                    anonAllowed = true;
                    anonBuckets.AddRange(ParseListAllMyBuckets(body));
                }
                else if (body.Contains("<Code>AccessDenied</Code>", StringComparison.OrdinalIgnoreCase)
                         && body.Contains("<HostId>", StringComparison.OrdinalIgnoreCase))
                {
                    isS3 = true;
                }
                else if (body.Contains("<Code>NoSuchBucket</Code>", StringComparison.OrdinalIgnoreCase)
                         && body.Contains("MinIO", StringComparison.OrdinalIgnoreCase))
                {
                    isMinio = true;
                    isS3 = true;
                }
            }
            catch (Exception ex) when (!IsCancellation(ex, ct))
            {
                _audit.Record("s3.probe.root_error", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["error"] = ex.Message,
                });
            }

            // 3. ListObjectsV2-style probe (some S3 emulators only respond to list-type=2).
            if (!isS3)
            {
                try
                {
                    using var resp = await http.GetAsync($"{endpointUrl}?delimiter=/&list-type=2",
                        HttpCompletionOption.ResponseContentRead, pct).ConfigureAwait(false);
                    CaptureServer(resp, ref server, ref minioVersion);
                    var body = await resp.Content.ReadAsStringAsync(pct).ConfigureAwait(false);
                    if ((int)resp.StatusCode == 200
                        && body.Contains("<ListBucketResult", StringComparison.OrdinalIgnoreCase))
                    {
                        isS3 = true;
                        anonAllowed = true;
                    }
                }
                catch (Exception ex) when (!IsCancellation(ex, ct))
                {
                    _audit.Record("s3.probe.list_error", new Dictionary<string, object?>
                    {
                        ["target"] = target,
                        ["error"] = ex.Message,
                    });
                }
            }

            // 4. Authenticated bucket listing if creds available.
            if (isS3 && _bucketLister is not null && _credentials is not null)
            {
                var cred = TryFindS3Credential();
                if (cred is not null)
                {
                    try
                    {
                        authBuckets = await _bucketLister.ListAsync(
                            new S3Endpoint(endpointUrl, target, resolved.ResolvedIp.ToString(), port),
                            cred.Value,
                            pct).ConfigureAwait(false);
                        foreach (var b in authBuckets)
                        {
                            _audit.Record("s3.bucket.listed", new Dictionary<string, object?>
                            {
                                ["target"] = target,
                                ["bucket"] = b.Name,
                                ["object_count"] = b.ObjectCount,
                                ["access_key_sha256"] = CredentialStore.Sha256Hex(cred.Value.AccessKey),
                            });
                            foreach (var obj in b.Objects)
                            {
                                _audit.Record("s3.object.found", new Dictionary<string, object?>
                                {
                                    ["target"] = target,
                                    ["bucket"] = b.Name,
                                    ["key"] = obj.Key,
                                    ["size"] = obj.Size,
                                });
                            }
                        }
                    }
                    catch (Exception ex) when (!IsCancellation(ex, ct))
                    {
                        _audit.Record("s3.list.error", new Dictionary<string, object?>
                        {
                            ["target"] = target,
                            ["access_key_sha256"] = CredentialStore.Sha256Hex(cred.Value.AccessKey),
                            ["error"] = ex.Message,
                        });
                        error ??= ex.Message;
                    }
                }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            error = "timeout";
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }

        var finding = new S3Finding
        {
            Target = target,
            Port = port,
            IsS3 = isS3,
            IsMinio = isMinio,
            AnonymousListAllowed = anonAllowed,
            AnonymousBuckets = anonBuckets,
            AuthenticatedBuckets = authBuckets,
            Server = server,
            MinioVersion = minioVersion,
            Error = error,
        };

        _audit.Record("s3.probe.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["is_s3"] = isS3,
            ["is_minio"] = isMinio,
            ["anonymous_list_allowed"] = anonAllowed,
            ["anonymous_bucket_count"] = anonBuckets.Count,
            ["authenticated_bucket_count"] = authBuckets.Count,
            ["error"] = error,
        });
        return finding;
    }

    private static bool IsCancellation(Exception ex, CancellationToken ct) =>
        ex is OperationCanceledException && ct.IsCancellationRequested;

    private static string BuildEndpoint(ResolvedTarget resolved, int port)
    {
        var host = resolved.Hostname ?? resolved.ResolvedIp.ToString();
        if (resolved.ResolvedIp.AddressFamily == AddressFamily.InterNetworkV6 && resolved.Hostname is null)
            host = $"[{host}]";
        return $"http://{host}:{port}/";
    }

    private static void CaptureServer(HttpResponseMessage resp, ref string? server, ref string? version)
    {
        var hdr = resp.Headers.Server?.ToString();
        if (string.IsNullOrEmpty(hdr)) return;
        server ??= hdr;
        if (version is null)
        {
            var m = MinioServerRegex().Match(hdr);
            if (m.Success && m.Groups["v"].Success && !string.IsNullOrEmpty(m.Groups["v"].Value))
            {
                version = m.Groups["v"].Value;
            }
        }
    }

    internal static IEnumerable<string> ParseListAllMyBuckets(string xml)
    {
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch { yield break; }
        foreach (var b in doc.Descendants().Where(e => e.Name.LocalName == "Bucket"))
        {
            var name = b.Elements().FirstOrDefault(e => e.Name.LocalName == "Name")?.Value;
            if (!string.IsNullOrEmpty(name)) yield return name;
        }
    }

    private S3Credential? TryFindS3Credential()
    {
        if (_credentials is null) return null;
        foreach (var refc in _credentials.List())
        {
            if (string.Equals(refc.Realm, "s3", StringComparison.OrdinalIgnoreCase))
            {
                var secret = _credentials.TryGetSecret(refc);
                if (secret is not null)
                {
                    return new S3Credential(refc.User, secret);
                }
            }
        }
        return null;
    }

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
                        new IPEndPoint(resolvedIp, context.DnsEndPoint.Port), ct).ConfigureAwait(false);
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
}

/// <summary>Minimal S3 endpoint description handed to <see cref="IS3BucketLister"/>.</summary>
public sealed record S3Endpoint(string ServiceUrl, string Target, string ResolvedIp, int Port);

/// <summary>AWS access-key + secret pair held only in-memory while listing.</summary>
public readonly record struct S3Credential(string AccessKey, string SecretKey);

/// <summary>
/// Authenticated bucket lister. The default production implementation uses
/// AWSSDK.S3 with <c>ForcePathStyle=true</c>; tests use an in-memory stub.
/// Listing is metadata-only — implementations MUST NOT download object
/// payloads.
/// </summary>
public interface IS3BucketLister
{
    Task<IReadOnlyList<S3BucketEntry>> ListAsync(
        S3Endpoint endpoint,
        S3Credential credential,
        CancellationToken ct);
}
