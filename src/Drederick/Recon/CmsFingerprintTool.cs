using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Scope;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Drederick.Recon;

/// <summary>
/// GAP-036: CMS / web-framework fingerprint tool. Identifies the CMS or
/// framework running on a target via cookies, meta-generator tags,
/// response-header patterns, regex matches against the HTML body, and
/// per-CMS path probes. The corpus is bundled as an embedded YAML
/// resource (<c>cms-fingerprints.yaml</c>) and parsed once on first use.
///
/// Hostname targets are resolved via DNS and the resolved IP is what
/// passes <see cref="Scope.Scope.Require"/> (gap-032 pattern). Every
/// path-probe sub-request reuses the same scope-validated IP via the
/// <see cref="SocketsHttpHandler.ConnectCallback"/>, so DNS rebinding
/// inside the run cannot pivot the scanner off the authorized address.
/// </summary>
public sealed class CmsFingerprintTool : IReconTool
{
    public string Name => "cms-fingerprint";

    public string Description =>
        "Identify the CMS / web framework on an HTTP(S) target via cookies, " +
        "meta generator, response headers, HTML patterns, and path probes. " +
        "Returns ranked matches with version where extractable.";

    private const int MaxBodyBytes = 512 * 1024;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);
    private static readonly Lazy<IReadOnlyList<CmsFingerprintEntry>> EmbeddedCorpus =
        new(LoadEmbeddedCorpus, isThreadSafe: true);

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _dnsResolver;
    private readonly Func<IPAddress, HttpMessageHandler>? _handlerFactory;
    private readonly IReadOnlyList<CmsFingerprintEntry> _corpus;
    private readonly TimeSpan _timeout;

    public CmsFingerprintTool(Scope.Scope scope, AuditLog audit)
        : this(scope, audit, null, null, null, TimeSpan.FromSeconds(10))
    {
    }

    internal CmsFingerprintTool(
        Scope.Scope scope,
        AuditLog audit,
        Func<string, CancellationToken, Task<IPAddress[]>>? dnsResolver,
        Func<IPAddress, HttpMessageHandler>? handlerFactory,
        IReadOnlyList<CmsFingerprintEntry>? corpus,
        TimeSpan timeout)
    {
        _scope = scope;
        _audit = audit;
        _dnsResolver = dnsResolver ?? ((host, ct) => Dns.GetHostAddressesAsync(host, ct));
        _handlerFactory = handlerFactory;
        _corpus = corpus ?? EmbeddedCorpus.Value;
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
                $"Failed to resolve hostname '{target}' for cms_fingerprint: {ex.Message}");
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

    public async Task<CmsFinding> FingerprintAsync(
        string target,
        int port = 80,
        bool tls = false,
        string? hostname = null,
        CancellationToken ct = default)
    {
        // First statement: scope authorization on the resolved IP.
        var resolved = await ResolveAsync(target, ct).ConfigureAwait(false);

        var hostHeader = hostname ?? resolved.Hostname ?? resolved.ResolvedIp.ToString();
        var scheme = tls ? "https" : "http";
        var authority = BuildAuthority(hostHeader);
        var baseUrl = $"{scheme}://{authority}:{port}";

        _audit.Record("cms-fingerprint.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["resolved_ip"] = resolved.ResolvedIp.ToString(),
            ["hostname"] = hostname ?? resolved.Hostname,
            ["base_url"] = baseUrl,
            ["port"] = port,
            ["tls"] = tls,
            ["corpus_size"] = _corpus.Count,
        });

        var matches = new List<CmsMatch>();
        string? error = null;

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
            // Root fetch: status, headers, cookies, body (truncated).
            var root = await FetchAsync(http, baseUrl + "/", ct).ConfigureAwait(false);

            // Pre-extract once for all fingerprints.
            var cookies = ParseCookies(root.SetCookies);
            var headersFlat = FlattenHeaders(root.Headers);
            var metaGenerators = ExtractMetaGenerators(root.Body);

            foreach (var fp in _corpus)
            {
                var (confidence, signals) = MatchSignals(fp, cookies, headersFlat, metaGenerators, root.Body);

                int extraConfidence = 0;
                if (confidence >= fp.ConfidenceRequired && fp.Signals.PathProbes.Count > 0)
                {
                    foreach (var probe in fp.Signals.PathProbes)
                    {
                        var probeUrl = baseUrl + probe.Path;
                        try
                        {
                            var pr = await FetchAsync(http, probeUrl, ct).ConfigureAwait(false);
                            if (ProbeMatches(probe, pr))
                            {
                                extraConfidence++;
                                signals.Add($"path:{probe.Path}={pr.Status}{(probe.ExpectBodyContains.Count > 0 ? "+body" : "")}");
                            }
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
                        {
                            _audit.Record("cms-fingerprint.probe_error", new Dictionary<string, object?>
                            {
                                ["target"] = target,
                                ["path"] = probe.Path,
                                ["error"] = ex.Message,
                            });
                        }
                    }
                }

                var totalConfidence = confidence + extraConfidence;
                if (totalConfidence < 1) continue;

                string? version = ExtractVersion(fp, root.Body, metaGenerators, headersFlat);
                string? cpe = ResolveCpe(fp.CpeTemplate, version);

                var match = new CmsMatch(fp.Name, version, totalConfidence, signals, cpe);
                matches.Add(match);
                _audit.Record("cms-fingerprint.match", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["cms"] = fp.Name,
                    ["confidence"] = totalConfidence,
                    ["version"] = version,
                    ["signals"] = signals,
                });
            }

            matches = matches
                .OrderByDescending(m => m.Confidence)
                .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            error = "timeout";
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _audit.Record("cms-fingerprint.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["error"] = ex.Message,
            });
        }

        var finding = new CmsFinding
        {
            Target = target,
            BaseUrl = baseUrl,
            Matches = matches,
            Error = error,
        };

        _audit.Record("cms-fingerprint.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["base_url"] = baseUrl,
            ["matches_count"] = matches.Count,
            ["top_match"] = matches.FirstOrDefault()?.Name,
            ["top_confidence"] = matches.FirstOrDefault()?.Confidence,
            ["error"] = error,
        });

        return finding;
    }

    private static (int confidence, List<string> signals) MatchSignals(
        CmsFingerprintEntry fp,
        IReadOnlyList<string> cookies,
        string headersFlat,
        IReadOnlyList<string> metaGenerators,
        string body)
    {
        int confidence = 0;
        var signals = new List<string>();

        foreach (var cookie in fp.Signals.Cookies)
        {
            var rx = WildcardToRegex(cookie);
            foreach (var c in cookies)
            {
                if (SafeIsMatch(rx, c))
                {
                    confidence++;
                    signals.Add($"cookie:{c}");
                    break;
                }
            }
        }

        foreach (var gen in fp.Signals.MetaGenerator)
        {
            foreach (var mg in metaGenerators)
            {
                if (mg.Contains(gen, StringComparison.OrdinalIgnoreCase))
                {
                    confidence++;
                    signals.Add($"meta-generator:{gen}");
                    break;
                }
            }
        }

        foreach (var hp in fp.Signals.HeaderPatterns)
        {
            if (SafeIsMatch(hp, headersFlat, RegexOptions.IgnoreCase))
            {
                confidence++;
                signals.Add($"header:{hp}");
            }
        }

        foreach (var hp in fp.Signals.HtmlPatterns)
        {
            if (SafeIsMatch(hp, body, RegexOptions.None))
            {
                confidence++;
                signals.Add($"html:{Truncate(hp, 60)}");
            }
        }

        return (confidence, signals);
    }

    private static bool ProbeMatches(CmsPathProbe probe, FetchResult pr)
    {
        if (pr.Status == 0) return false;
        if (probe.ExpectStatus.Count > 0 && !probe.ExpectStatus.Contains(pr.Status)) return false;
        if (probe.ExpectBodyContains.Count > 0)
        {
            foreach (var needle in probe.ExpectBodyContains)
            {
                if (pr.Body.Contains(needle, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
        return true;
    }

    private static string? ExtractVersion(
        CmsFingerprintEntry fp,
        string body,
        IReadOnlyList<string> metaGenerators,
        string headersFlat)
    {
        foreach (var ve in fp.VersionExtract)
        {
            string source = ve.Source switch
            {
                "html" => body,
                "meta_generator" => string.Join("\n", metaGenerators),
                "header" => headersFlat,
                _ => body,
            };
            try
            {
                var m = Regex.Match(source, ve.Regex,
                    RegexOptions.CultureInvariant, RegexTimeout);
                if (m.Success && m.Groups.Count > 1 && !string.IsNullOrEmpty(m.Groups[1].Value))
                {
                    return m.Groups[1].Value.Trim();
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Adversarial body — skip this regex source.
            }
            catch (ArgumentException)
            {
                // Bad regex in corpus — defensive; skip.
            }
        }
        return null;
    }

    internal static string? ResolveCpe(string? template, string? version)
    {
        if (string.IsNullOrWhiteSpace(template)) return null;
        var v = string.IsNullOrWhiteSpace(version) ? "*" : version!.Trim();
        return template.Replace("{version}", v, StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<string> ParseCookies(IEnumerable<string> setCookies)
    {
        var names = new List<string>();
        foreach (var line in setCookies)
        {
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var name = line[..eq].Trim();
            if (name.Length > 0) names.Add(name);
        }
        return names;
    }

    private static string FlattenHeaders(IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var kv in headers)
        {
            foreach (var v in kv.Value)
            {
                sb.Append(kv.Key).Append(": ").Append(v).Append('\n');
            }
        }
        return sb.ToString();
    }

    private static IReadOnlyList<string> ExtractMetaGenerators(string body)
    {
        var found = new List<string>();
        if (string.IsNullOrEmpty(body)) return found;
        try
        {
            var rx = new Regex(
                """<meta[^>]+name\s*=\s*["']?generator["']?[^>]*content\s*=\s*["']([^"']+)["']""",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                RegexTimeout);
            foreach (Match m in rx.Matches(body))
            {
                if (m.Groups.Count > 1) found.Add(m.Groups[1].Value);
            }
        }
        catch (RegexMatchTimeoutException) { /* adversarial body — skip */ }
        return found;
    }

    private static Regex WildcardToRegex(string wildcard)
    {
        // Translate shell-style wildcard ('*' = any chars) to a regex.
        var escaped = Regex.Escape(wildcard).Replace("\\*", ".*");
        return new Regex("^" + escaped + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    }

    private static bool SafeIsMatch(Regex rx, string input)
    {
        try { return rx.IsMatch(input); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static bool SafeIsMatch(string pattern, string input, RegexOptions options)
    {
        try { return Regex.IsMatch(input, pattern, options | RegexOptions.CultureInvariant, RegexTimeout); }
        catch (RegexMatchTimeoutException) { return false; }
        catch (ArgumentException) { return false; }
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n];

    private sealed record FetchResult(
        int Status,
        IReadOnlyList<KeyValuePair<string, IEnumerable<string>>> Headers,
        IReadOnlyList<string> SetCookies,
        string Body);

    private static async Task<FetchResult> FetchAsync(HttpClient http, string url, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        try
        {
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);

            var allHeaders = resp.Headers
                .Concat(resp.Content.Headers)
                .Select(h => new KeyValuePair<string, IEnumerable<string>>(h.Key, h.Value))
                .ToList();

            var cookies = new List<string>();
            if (resp.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                cookies.AddRange(setCookies);
            }

            var body = await ReadBoundedBodyAsync(resp, ct).ConfigureAwait(false);
            return new FetchResult((int)resp.StatusCode, allHeaders, cookies, body);
        }
        catch (HttpRequestException)
        {
            return new FetchResult(0, Array.Empty<KeyValuePair<string, IEnumerable<string>>>(), Array.Empty<string>(), "");
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return new FetchResult(0, Array.Empty<KeyValuePair<string, IEnumerable<string>>>(), Array.Empty<string>(), "");
        }
    }

    private static async Task<string> ReadBoundedBodyAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        try
        {
            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var buf = new byte[MaxBodyBytes];
            int total = 0;
            while (total < buf.Length)
            {
                var n = await stream.ReadAsync(buf.AsMemory(total, buf.Length - total), ct)
                    .ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
            }
            return System.Text.Encoding.UTF8.GetString(buf, 0, total);
        }
        catch
        {
            return "";
        }
    }

    private static string BuildAuthority(string host)
    {
        if (IPAddress.TryParse(host, out var ip)
            && ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return $"[{host}]";
        }
        return host;
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
                        new IPEndPoint(resolvedIp, context.DnsEndPoint.Port), ct)
                        .ConfigureAwait(false);
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

    // --- Embedded corpus loader -----------------------------------------

    internal static IReadOnlyList<CmsFingerprintEntry> LoadEmbeddedCorpus()
    {
        var asm = typeof(CmsFingerprintTool).Assembly;
        var name = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("cms-fingerprints.yaml", StringComparison.OrdinalIgnoreCase));
        IReadOnlyList<CmsFingerprintEntry> parsed;
        if (name is null)
        {
            parsed = Array.Empty<CmsFingerprintEntry>();
        }
        else
        {
            using var stream = asm.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException("Failed to open cms-fingerprints.yaml resource stream.");
            using var reader = new StreamReader(stream);
            parsed = ParseYaml(reader.ReadToEnd());
        }

        // --- htb-pterodactyl-fingerprint ---
        // GAP-052: Programmatic Pterodactyl Panel signature is appended to
        // the corpus chain when the embedded YAML did not provide one
        // (resource stripped, trimmed build, custom corpus, etc.). The
        // YAML entry usually wins on order — this block is a backstop,
        // not a duplicate.
        if (!parsed.Any(e => string.Equals(
                e.Name, Cms.PterodactylSignature.EntryName, StringComparison.OrdinalIgnoreCase)))
        {
            var augmented = new List<CmsFingerprintEntry>(parsed.Count + 1);
            augmented.AddRange(parsed);
            augmented.Add(Cms.PterodactylSignature.BuildEntry());
            parsed = augmented;
        }
        // --- end htb-pterodactyl-fingerprint ---

        // --- htb-cms-fingerprint-pack ---
        // GAP-034: programmatic WordPress / Joomla / Drupal / Magento /
        // SuiteCRM signatures. Each one is appended only when the
        // embedded YAML did not provide an entry of the same name, so
        // the YAML still wins on order for environments that ship a
        // richer corpus.
        var pack = new (string Name, Func<CmsFingerprintEntry> Build)[]
        {
            (Cms.WordPressSignature.EntryName, Cms.WordPressSignature.BuildEntry),
            (Cms.JoomlaSignature.EntryName, Cms.JoomlaSignature.BuildEntry),
            (Cms.DrupalSignature.EntryName, Cms.DrupalSignature.BuildEntry),
            (Cms.MagentoSignature.EntryName, Cms.MagentoSignature.BuildEntry),
            (Cms.SuiteCrmSignature.EntryName, Cms.SuiteCrmSignature.BuildEntry),
        };
        var augmentedPack = new List<CmsFingerprintEntry>(parsed.Count + pack.Length);
        augmentedPack.AddRange(parsed);
        foreach (var (entryName, build) in pack)
        {
            if (!augmentedPack.Any(e => string.Equals(e.Name, entryName, StringComparison.OrdinalIgnoreCase)))
            {
                augmentedPack.Add(build());
            }
        }
        parsed = augmentedPack;
        // --- end htb-cms-fingerprint-pack ---

        return parsed;
    }

    internal static IReadOnlyList<CmsFingerprintEntry> ParseYaml(string yaml)
    {
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
        var doc = deserializer.Deserialize<CmsCorpusDoc>(yaml);
        return doc?.Fingerprints ?? new List<CmsFingerprintEntry>();
    }

    // YAML DTOs (deserialized via YamlDotNet underscored naming).
    internal sealed class CmsCorpusDoc
    {
        public List<CmsFingerprintEntry> Fingerprints { get; set; } = new();
    }
}

internal sealed class CmsFingerprintEntry
{
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public CmsSignals Signals { get; set; } = new();
    public int ConfidenceRequired { get; set; } = 2;
    public List<CmsVersionExtract> VersionExtract { get; set; } = new();
    public string? CpeTemplate { get; set; }
}

internal sealed class CmsSignals
{
    public List<string> Cookies { get; set; } = new();
    public List<string> MetaGenerator { get; set; } = new();
    public List<string> HtmlPatterns { get; set; } = new();
    public List<string> HeaderPatterns { get; set; } = new();
    public List<CmsPathProbe> PathProbes { get; set; } = new();
}

internal sealed class CmsPathProbe
{
    public string Path { get; set; } = "/";
    public List<int> ExpectStatus { get; set; } = new();
    public List<string> ExpectBodyContains { get; set; } = new();
}

internal sealed class CmsVersionExtract
{
    public string Regex { get; set; } = "";
    public string Source { get; set; } = "html";
}
