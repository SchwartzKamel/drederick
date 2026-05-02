using System.Net.Http;
using System.Security.Cryptography;
using Drederick.Audit;
using Drederick.Enrichment.FingerprintStack.Signals;
using Drederick.Recon;
using Drederick.Scope;

namespace Drederick.Enrichment.FingerprintStack;

/// <summary>
/// Multi-signal host fingerprinter (Pattern 4 in
/// <c>docs/PLUGIN_STRATEGY.md</c>). Reads existing recon signals on a
/// <see cref="HostFinding"/> (banner, TLS subject/issuer, HTTP headers),
/// optionally fetches <c>/favicon.ico</c> over a scope-checked HTTP
/// probe, runs each <see cref="IFingerprintSignal"/>, and feeds the
/// merged hits through <see cref="FingerprintAggregator"/>.
/// </summary>
public sealed class FingerprintStackTool : IReconTool
{
    public string Name => "fingerprint-stack";
    public string Description =>
        "Multi-signal host fingerprinter: banner + TLS cert + HTTP headers + favicon SHA-256 + JA3/JA4 → ranked CPE candidates.";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly FaviconCorpus _favicons;
    private readonly Func<string, int, bool, HttpMessageHandler>? _handlerFactory;
    private readonly FingerprintAggregator _aggregator = new();
    private readonly IReadOnlyList<IFingerprintSignal> _signals;

    public FingerprintStackTool(Scope.Scope scope, AuditLog audit)
        : this(scope, audit, FaviconCorpus.LoadEmbedded(), handlerFactory: null) { }

    public FingerprintStackTool(
        Scope.Scope scope,
        AuditLog audit,
        FaviconCorpus favicons,
        Func<string, int, bool, HttpMessageHandler>? handlerFactory)
    {
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _favicons = favicons ?? throw new ArgumentNullException(nameof(favicons));
        _handlerFactory = handlerFactory;
        _signals = new IFingerprintSignal[]
        {
            new BannerSignal(),
            new HttpHeaderSignal(),
            new TlsCertSignal(),
            new FaviconSha256Signal(_favicons),
            new Ja3Ja4Signal(),
        };
    }

    /// <summary>
    /// Run the fingerprint pipeline against an in-scope target using the
    /// signals already recorded on <paramref name="finding"/>. Returns one
    /// <see cref="FingerprintReport"/> per port that had at least one
    /// candidate clearing <see cref="FingerprintAggregator.MinReportConfidence"/>.
    /// </summary>
    public async Task<IReadOnlyList<FingerprintReport>> FingerprintHostAsync(
        string target, HostFinding finding, CancellationToken ct = default)
    {
        _scope.Require(target);
        if (finding is null) throw new ArgumentNullException(nameof(finding));

        _audit.Record("fingerprint-stack.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["signal_count"] = _signals.Count,
            ["favicon_corpus_size"] = _favicons.Count,
        });

        var reports = new List<FingerprintReport>();
        try
        {
            var inputs = await BuildPortInputsAsync(target, finding, ct).ConfigureAwait(false);
            foreach (var (port, input) in inputs)
            {
                var allHits = new List<FingerprintSignalHit>();
                foreach (var sig in _signals)
                {
                    try
                    {
                        allHits.AddRange(sig.Extract(input));
                    }
                    catch (Exception ex)
                    {
                        _audit.Record("fingerprint-stack.signal.error", new Dictionary<string, object?>
                        {
                            ["target"] = target,
                            ["signal"] = sig.Name,
                            ["error"] = ex.Message,
                        });
                    }
                }
                var candidates = _aggregator.Aggregate(allHits);
                if (candidates.Count == 0) continue;
                reports.Add(new FingerprintReport
                {
                    Port = port,
                    Candidates = candidates.ToList(),
                });
            }

            _audit.Record("fingerprint-stack.finish", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["report_count"] = reports.Count,
            });
        }
        catch (ScopeException) { throw; }
        catch (Exception ex)
        {
            _audit.Record("fingerprint-stack.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["error"] = ex.Message,
            });
            reports.Add(new FingerprintReport { Error = ex.Message });
        }

        return reports;
    }

    private async Task<List<KeyValuePair<int?, FingerprintInput>>> BuildPortInputsAsync(
        string target, HostFinding f, CancellationToken ct)
    {
        var byPort = new Dictionary<int, FingerprintInputBuilder>();

        foreach (var p in f.Nmap?.OpenPorts ?? new List<NmapPort>())
        {
            var b = byPort.GetValueOrDefault(p.Port) ?? (byPort[p.Port] = new FingerprintInputBuilder { Port = p.Port });
            b.NmapProduct = p.Product;
            b.NmapVersion = p.Version;
            b.Banner ??= ComposeBanner(p.Product, p.Version, p.Extra);
        }
        foreach (var t in f.Tls)
        {
            var b = byPort.GetValueOrDefault(t.Port) ?? (byPort[t.Port] = new FingerprintInputBuilder { Port = t.Port });
            b.TlsSubject = t.Subject;
            b.TlsIssuer = t.Issuer;
            b.TlsSubjectAltNames = t.SubjectAltNames;
        }
        foreach (var h in f.Http)
        {
            var port = TryParsePort(h.Url) ?? TryParsePort(h.FinalUrl);
            if (port is null) continue;
            var b = byPort.GetValueOrDefault(port.Value) ?? (byPort[port.Value] = new FingerprintInputBuilder { Port = port.Value });
            b.HttpServer = h.Server;
            b.HttpUrlForFavicon ??= h.FinalUrl ?? h.Url;
        }
        foreach (var s in f.Ssh)
        {
            var b = byPort.GetValueOrDefault(s.Port) ?? (byPort[s.Port] = new FingerprintInputBuilder { Port = s.Port });
            b.Banner ??= s.Banner;
        }
        foreach (var ftp in f.Ftp)
        {
            var b = byPort.GetValueOrDefault(ftp.Port) ?? (byPort[ftp.Port] = new FingerprintInputBuilder { Port = ftp.Port });
            b.Banner ??= ftp.Banner;
        }

        var results = new List<KeyValuePair<int?, FingerprintInput>>(byPort.Count);
        foreach (var (port, b) in byPort)
        {
            string? faviconHash = null;
            if (!string.IsNullOrWhiteSpace(b.HttpUrlForFavicon))
            {
                faviconHash = await TryFetchFaviconSha256Async(target, port, b.HttpUrlForFavicon!, ct)
                    .ConfigureAwait(false);
            }

            results.Add(new KeyValuePair<int?, FingerprintInput>(port, new FingerprintInput
            {
                Target = target,
                Port = port,
                Banner = b.Banner,
                NmapProduct = b.NmapProduct,
                NmapVersion = b.NmapVersion,
                TlsSubject = b.TlsSubject,
                TlsIssuer = b.TlsIssuer,
                TlsSubjectAltNames = b.TlsSubjectAltNames ?? Array.Empty<string>(),
                HttpServer = b.HttpServer,
                FaviconSha256 = faviconHash,
            }));
        }
        return results;
    }

    private async Task<string?> TryFetchFaviconSha256Async(
        string target, int port, string baseUrl, CancellationToken ct)
    {
        try
        {
            _scope.Require(target);
            if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri)) return null;
            var faviconUri = new Uri(baseUri, "/favicon.ico");
            var isHttps = string.Equals(faviconUri.Scheme, "https", StringComparison.OrdinalIgnoreCase);

            HttpMessageHandler handler = _handlerFactory is not null
                ? _handlerFactory(target, port, isHttps)
                : new SocketsHttpHandler
                {
                    ConnectTimeout = TimeSpan.FromSeconds(5),
                    PooledConnectionLifetime = TimeSpan.FromSeconds(15),
                };
            using var http = new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(8),
            };
            using var resp = await http.GetAsync(faviconUri, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;
            var bytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            if (bytes.Length == 0 || bytes.Length > 256 * 1024) return null;
            var hash = SHA256.HashData(bytes);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch (Exception ex)
        {
            _audit.Record("fingerprint-stack.favicon.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["error"] = ex.Message,
            });
            return null;
        }
    }

    private static int? TryParsePort(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return null;
        return u.Port > 0 ? u.Port : null;
    }

    private static string? ComposeBanner(string? product, string? version, string? extra)
    {
        var parts = new List<string>(3);
        if (!string.IsNullOrWhiteSpace(product)) parts.Add(product!);
        if (!string.IsNullOrWhiteSpace(version)) parts.Add(version!);
        if (!string.IsNullOrWhiteSpace(extra)) parts.Add(extra!);
        return parts.Count == 0 ? null : string.Join(' ', parts);
    }

    private sealed class FingerprintInputBuilder
    {
        public int Port { get; set; }
        public string? Banner { get; set; }
        public string? NmapProduct { get; set; }
        public string? NmapVersion { get; set; }
        public string? TlsSubject { get; set; }
        public string? TlsIssuer { get; set; }
        public IReadOnlyList<string>? TlsSubjectAltNames { get; set; }
        public string? HttpServer { get; set; }
        public string? HttpUrlForFavicon { get; set; }
    }
}
