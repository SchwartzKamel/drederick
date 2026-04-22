using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Jeopardy.Ctfd;

/// <summary>
/// CTFd v3 HTTP client. Scope-gates the platform host (and any external
/// attachment host) at the tool boundary and audits every request. Never
/// logs the API token or plaintext flag submissions — flags are recorded
/// by SHA-256 digest only.
/// </summary>
public interface ICtfdClient
{
    Task<IReadOnlyList<CtfdChallenge>> ListChallengesAsync(CancellationToken ct);
    Task<CtfdChallenge> GetChallengeAsync(int id, CancellationToken ct);
    Task<byte[]> DownloadAttachmentAsync(CtfdAttachment file, CancellationToken ct);
    Task<CtfdSubmissionResult> SubmitFlagAsync(int challengeId, string flag, CancellationToken ct);
    Task<IReadOnlyList<CtfdScoreboardEntry>> GetScoreboardAsync(CancellationToken ct);
}

public sealed class CtfdClient : ICtfdClient, IDisposable
{
    public const long MaxAttachmentBytes = 100L * 1024 * 1024;

    private static readonly Regex TagStripper =
        new("<[^>]+>", RegexOptions.Compiled | RegexOptions.Singleline);
    private static readonly Regex CodeBlockMatcher =
        new("<(pre|code)[^>]*>(?<body>.*?)</\\1>",
            RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

    private readonly Uri _baseUrl;
    private readonly string _token;
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly SemaphoreSlim _rateLimit;
    private readonly ConcurrentDictionary<string, CtfdSubmissionResult> _submissions = new();
    private readonly TimeSpan[] _retryDelays;

    public CtfdClient(
        Uri baseUrl,
        string token,
        Scope.Scope scope,
        AuditLog audit,
        HttpClient? httpClient = null,
        int maxConcurrency = 4,
        TimeSpan[]? retryDelays = null)
    {
        _baseUrl = baseUrl ?? throw new ArgumentNullException(nameof(baseUrl));
        _token = token ?? throw new ArgumentNullException(nameof(token));
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));

        if (!_baseUrl.IsAbsoluteUri)
        {
            throw new ArgumentException("baseUrl must be absolute.", nameof(baseUrl));
        }

        // Hard invariant: the CTFd platform host is a network target. Every
        // tool that touches the network must scope-validate before any
        // outbound I/O.
        _scope.Require(_baseUrl.Host);

        _rateLimit = new SemaphoreSlim(maxConcurrency, maxConcurrency);
        _retryDelays = retryDelays ?? new[]
        {
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(2),
            TimeSpan.FromSeconds(4),
        };

        if (httpClient is null)
        {
            _http = new HttpClient(new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.All,
            });
            _ownsHttp = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttp = false;
        }
    }

    public async Task<IReadOnlyList<CtfdChallenge>> ListChallengesAsync(CancellationToken ct)
    {
        using var resp = await SendAsync(HttpMethod.Get, "/api/v1/challenges", null, "ctfd.list", ct)
            .ConfigureAwait(false);
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(body);
        var data = doc.RootElement.GetProperty("data");
        var list = new List<CtfdChallenge>();
        foreach (var el in data.EnumerateArray())
        {
            list.Add(ParseChallengeSummary(el));
        }
        return list;
    }

    public async Task<CtfdChallenge> GetChallengeAsync(int id, CancellationToken ct)
    {
        using var resp = await SendAsync(
            HttpMethod.Get, $"/api/v1/challenges/{id}", null, "ctfd.get", ct)
            .ConfigureAwait(false);
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(body);
        var data = doc.RootElement.GetProperty("data");
        return ParseChallengeDetail(data);
    }

    public async Task<byte[]> DownloadAttachmentAsync(CtfdAttachment file, CancellationToken ct)
    {
        if (file is null) throw new ArgumentNullException(nameof(file));

        var url = ResolveAttachmentUrl(file.Url);
        // Scope-validate the attachment host — CTFd often hands out S3 / GCS
        // signed URLs, and the download is an outbound request like any other.
        _scope.Require(url.Host);

        var endpointTag = url.PathAndQuery;
        var sw = Stopwatch.StartNew();
        _audit.Record("ctfd.download.start", new Dictionary<string, object?>
        {
            ["url_host"] = url.Host,
            ["path"] = endpointTag,
            ["name"] = file.Name,
        });

        await _rateLimit.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            ApplyAuth(req);
            using var resp = await _http.SendAsync(
                req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                _audit.Record("ctfd.download.finish", new Dictionary<string, object?>
                {
                    ["path"] = endpointTag,
                    ["status"] = (int)resp.StatusCode,
                    ["elapsed_ms"] = sw.ElapsedMilliseconds,
                    ["error"] = "http_status",
                });
                throw new CtfdException($"Attachment download failed: HTTP {(int)resp.StatusCode}");
            }

            var declared = resp.Content.Headers.ContentLength;
            if (declared is > MaxAttachmentBytes)
            {
                _audit.Record("ctfd.download.finish", new Dictionary<string, object?>
                {
                    ["path"] = endpointTag,
                    ["status"] = (int)resp.StatusCode,
                    ["elapsed_ms"] = sw.ElapsedMilliseconds,
                    ["error"] = "oversize_declared",
                    ["declared_bytes"] = declared,
                });
                throw new CtfdException(
                    $"Attachment declared size {declared} exceeds cap {MaxAttachmentBytes}.");
            }

            using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var ms = new MemoryStream();
            var buf = new byte[81920];
            long total = 0;
            while (true)
            {
                var n = await stream.ReadAsync(buf.AsMemory(0, buf.Length), ct).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
                if (total > MaxAttachmentBytes)
                {
                    _audit.Record("ctfd.download.finish", new Dictionary<string, object?>
                    {
                        ["path"] = endpointTag,
                        ["status"] = (int)resp.StatusCode,
                        ["elapsed_ms"] = sw.ElapsedMilliseconds,
                        ["error"] = "oversize_stream",
                        ["bytes_read"] = total,
                    });
                    throw new CtfdException(
                        $"Attachment exceeds cap {MaxAttachmentBytes} bytes while streaming.");
                }
                ms.Write(buf, 0, n);
            }

            _audit.Record("ctfd.download.finish", new Dictionary<string, object?>
            {
                ["path"] = endpointTag,
                ["status"] = (int)resp.StatusCode,
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
                ["bytes"] = total,
            });
            return ms.ToArray();
        }
        finally
        {
            _rateLimit.Release();
        }
    }

    public async Task<CtfdSubmissionResult> SubmitFlagAsync(
        int challengeId, string flag, CancellationToken ct)
    {
        if (flag is null) throw new ArgumentNullException(nameof(flag));
        var flagDigest = Sha256(flag);
        var key = $"{challengeId}:{flagDigest}";

        if (_submissions.TryGetValue(key, out var cached))
        {
            _audit.Record("ctfd.submit.short_circuit", new Dictionary<string, object?>
            {
                ["challenge_id"] = challengeId,
                ["flag_sha256"] = flagDigest,
                ["prior_correct"] = cached.Correct,
            });
            return cached with { AlreadySolved = true, SubmittedAt = DateTimeOffset.UtcNow };
        }

        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["challenge_id"] = challengeId,
            ["submission"] = flag,
        });
        var content = new StringContent(payload, Encoding.UTF8, "application/json");

        // Do not include the plaintext flag in audit; the body is
        // constructed but never logged.
        using var resp = await SendAsync(
            HttpMethod.Post, "/api/v1/challenges/attempt", content,
            "ctfd.submit", ct,
            extraFields: new Dictionary<string, object?>
            {
                ["challenge_id"] = challengeId,
                ["flag_sha256"] = flagDigest,
            }).ConfigureAwait(false);

        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(body);
        var data = doc.RootElement.GetProperty("data");
        string status = data.TryGetProperty("status", out var sEl) ? (sEl.GetString() ?? "") : "";
        string? message = data.TryGetProperty("message", out var mEl) ? mEl.GetString() : null;

        bool correct = status.Equals("correct", StringComparison.OrdinalIgnoreCase);
        bool already = status.Equals("already_solved", StringComparison.OrdinalIgnoreCase);

        var result = new CtfdSubmissionResult(correct, already, message, DateTimeOffset.UtcNow);
        _submissions[key] = result;

        _audit.Record("ctfd.submit.result", new Dictionary<string, object?>
        {
            ["challenge_id"] = challengeId,
            ["flag_sha256"] = flagDigest,
            ["correct"] = correct,
            ["already_solved"] = already,
            ["status"] = status,
        });
        return result;
    }

    public async Task<IReadOnlyList<CtfdScoreboardEntry>> GetScoreboardAsync(CancellationToken ct)
    {
        using var resp = await SendAsync(
            HttpMethod.Get, "/api/v1/scoreboard", null, "ctfd.scoreboard", ct)
            .ConfigureAwait(false);
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(body);
        var data = doc.RootElement.GetProperty("data");
        var list = new List<CtfdScoreboardEntry>();
        foreach (var el in data.EnumerateArray())
        {
            int rank = el.TryGetProperty("pos", out var p) ? p.GetInt32()
                : el.TryGetProperty("rank", out var r) ? r.GetInt32()
                : list.Count + 1;
            int teamId = el.TryGetProperty("account_id", out var a) ? a.GetInt32()
                : el.TryGetProperty("team_id", out var t) ? t.GetInt32()
                : 0;
            string name = el.TryGetProperty("name", out var n) ? (n.GetString() ?? "") : "";
            int score = el.TryGetProperty("score", out var sc) ? sc.GetInt32() : 0;
            list.Add(new CtfdScoreboardEntry(rank, teamId, name, score));
        }
        return list;
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        HttpContent? content,
        string eventPrefix,
        CancellationToken ct,
        IReadOnlyDictionary<string, object?>? extraFields = null)
    {
        var url = new Uri(_baseUrl, path);
        // Defense in depth: the path may not change the host, but re-check.
        _scope.Require(url.Host);

        var startFields = new Dictionary<string, object?> { ["path"] = path };
        if (extraFields is not null)
        {
            foreach (var kv in extraFields) startFields[kv.Key] = kv.Value;
        }
        _audit.Record($"{eventPrefix}.start", startFields);

        var sw = Stopwatch.StartNew();
        Exception? lastError = null;
        for (int attempt = 0; attempt < _retryDelays.Length; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            await _rateLimit.WaitAsync(ct).ConfigureAwait(false);
            HttpResponseMessage? resp = null;
            try
            {
                using var req = new HttpRequestMessage(method, url);
                ApplyAuth(req);
                if (content is not null)
                {
                    // A request body can only be sent once; for POSTs with
                    // retries we buffer the bytes and clone per attempt.
                    var bytes = await content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                    var ctype = content.Headers.ContentType;
                    var newContent = new ByteArrayContent(bytes);
                    if (ctype is not null) newContent.Headers.ContentType = ctype;
                    req.Content = newContent;
                }

                resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
                int code = (int)resp.StatusCode;
                bool transient = code == 429 || (code >= 500 && code <= 599);

                _audit.Record($"{eventPrefix}.attempt", new Dictionary<string, object?>
                {
                    ["path"] = path,
                    ["attempt"] = attempt + 1,
                    ["status"] = code,
                    ["elapsed_ms"] = sw.ElapsedMilliseconds,
                });

                if (!transient)
                {
                    if (!resp.IsSuccessStatusCode)
                    {
                        var finishFields = new Dictionary<string, object?>
                        {
                            ["path"] = path,
                            ["status"] = code,
                            ["elapsed_ms"] = sw.ElapsedMilliseconds,
                            ["error"] = "http_status",
                        };
                        if (extraFields is not null)
                            foreach (var kv in extraFields) finishFields[kv.Key] = kv.Value;
                        _audit.Record($"{eventPrefix}.finish", finishFields);
                        var msg = $"CTFd request {method} {path} failed: HTTP {code}";
                        resp.Dispose();
                        throw new CtfdException(Redact(msg));
                    }

                    var ok = new Dictionary<string, object?>
                    {
                        ["path"] = path,
                        ["status"] = code,
                        ["elapsed_ms"] = sw.ElapsedMilliseconds,
                    };
                    if (extraFields is not null)
                        foreach (var kv in extraFields) ok[kv.Key] = kv.Value;
                    _audit.Record($"{eventPrefix}.finish", ok);
                    return resp;
                }

                // transient — discard and retry
                resp.Dispose();
                resp = null;
                lastError = new CtfdException($"HTTP {code}");
            }
            catch (HttpRequestException ex)
            {
                resp?.Dispose();
                _audit.Record($"{eventPrefix}.attempt", new Dictionary<string, object?>
                {
                    ["path"] = path,
                    ["attempt"] = attempt + 1,
                    ["error"] = Redact(ex.GetType().Name + ": " + ex.Message),
                });
                lastError = ex;
            }
            finally
            {
                _rateLimit.Release();
            }

            if (attempt < _retryDelays.Length - 1)
            {
                var jitter = TimeSpan.FromMilliseconds(Random.Shared.Next(0, 150));
                try { await Task.Delay(_retryDelays[attempt] + jitter, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
            }
        }

        var failFields = new Dictionary<string, object?>
        {
            ["path"] = path,
            ["elapsed_ms"] = sw.ElapsedMilliseconds,
            ["error"] = "retries_exhausted",
        };
        if (extraFields is not null)
            foreach (var kv in extraFields) failFields[kv.Key] = kv.Value;
        _audit.Record($"{eventPrefix}.finish", failFields);

        throw new CtfdException(
            Redact($"CTFd request {method} {path} failed after {_retryDelays.Length} attempts: " +
                   (lastError?.Message ?? "unknown")));
    }

    private void ApplyAuth(HttpRequestMessage req)
    {
        // CTFd uses "Authorization: Token <value>", not Bearer.
        req.Headers.TryAddWithoutValidation("Authorization", $"Token {_token}");
        if (req.Headers.Accept.Count == 0)
        {
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }
    }

    private Uri ResolveAttachmentUrl(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var abs)
            && (abs.Scheme == Uri.UriSchemeHttp || abs.Scheme == Uri.UriSchemeHttps))
        {
            return abs;
        }
        return new Uri(_baseUrl, url);
    }

    private string Redact(string message)
    {
        if (string.IsNullOrEmpty(_token) || string.IsNullOrEmpty(message)) return message;
        return message.Replace(_token, "[REDACTED]");
    }

    private CtfdChallenge ParseChallengeSummary(JsonElement el)
    {
        int id = el.GetProperty("id").GetInt32();
        string name = el.TryGetProperty("name", out var nm) ? (nm.GetString() ?? "") : "";
        string category = el.TryGetProperty("category", out var c) ? (c.GetString() ?? "") : "";
        int value = el.TryGetProperty("value", out var v) ? v.GetInt32() : 0;
        bool solved = el.TryGetProperty("solved_by_me", out var sb) && sb.ValueKind == JsonValueKind.True;
        var tags = ParseTags(el);
        return new CtfdChallenge(
            id, name, category, value,
            Description: string.Empty,
            Files: Array.Empty<CtfdAttachment>(),
            Tags: tags,
            ConnectionInfo: null,
            Solved: solved);
    }

    private CtfdChallenge ParseChallengeDetail(JsonElement el)
    {
        int id = el.GetProperty("id").GetInt32();
        string name = el.TryGetProperty("name", out var nm) ? (nm.GetString() ?? "") : "";
        string category = el.TryGetProperty("category", out var c) ? (c.GetString() ?? "") : "";
        int value = el.TryGetProperty("value", out var v) ? v.GetInt32() : 0;
        string descRaw = el.TryGetProperty("description", out var d) ? (d.GetString() ?? "") : "";
        string desc = HtmlToText(descRaw);
        string? conn = el.TryGetProperty("connection_info", out var cn) && cn.ValueKind == JsonValueKind.String
            ? cn.GetString()
            : null;
        bool solved = el.TryGetProperty("solved_by_me", out var sb) && sb.ValueKind == JsonValueKind.True;

        var files = new List<CtfdAttachment>();
        if (el.TryGetProperty("files", out var fs) && fs.ValueKind == JsonValueKind.Array)
        {
            foreach (var f in fs.EnumerateArray())
            {
                if (f.ValueKind == JsonValueKind.String)
                {
                    var u = f.GetString() ?? "";
                    files.Add(new CtfdAttachment(AttachmentName(u), u, null));
                }
                else if (f.ValueKind == JsonValueKind.Object)
                {
                    string url = f.TryGetProperty("url", out var ue) ? (ue.GetString() ?? "") : "";
                    string fname = f.TryGetProperty("name", out var ne) ? (ne.GetString() ?? "") : AttachmentName(url);
                    long? size = f.TryGetProperty("size", out var se) && se.ValueKind == JsonValueKind.Number
                        ? se.GetInt64() : (long?)null;
                    files.Add(new CtfdAttachment(fname, url, size));
                }
            }
        }

        var tags = ParseTags(el);

        return new CtfdChallenge(id, name, category, value, desc, files, tags, conn, solved);
    }

    private static IReadOnlyList<string> ParseTags(JsonElement el)
    {
        var tags = new List<string>();
        if (!el.TryGetProperty("tags", out var t) || t.ValueKind != JsonValueKind.Array)
            return tags;
        foreach (var item in t.EnumerateArray())
        {
            switch (item.ValueKind)
            {
                case JsonValueKind.String:
                    var s = item.GetString();
                    if (!string.IsNullOrEmpty(s)) tags.Add(s!);
                    break;
                case JsonValueKind.Object:
                    if (item.TryGetProperty("value", out var vv) && vv.ValueKind == JsonValueKind.String)
                    {
                        var sv = vv.GetString();
                        if (!string.IsNullOrEmpty(sv)) tags.Add(sv!);
                    }
                    break;
            }
        }
        return tags;
    }

    private static string AttachmentName(string url)
    {
        if (string.IsNullOrEmpty(url)) return "attachment";
        var q = url.IndexOf('?');
        var path = q >= 0 ? url[..q] : url;
        var slash = path.LastIndexOf('/');
        var name = slash >= 0 ? path[(slash + 1)..] : path;
        return string.IsNullOrEmpty(name) ? "attachment" : name;
    }

    internal static string HtmlToText(string html)
    {
        if (string.IsNullOrEmpty(html)) return string.Empty;
        // Preserve <pre>/<code> block contents verbatim (after decoding
        // entities) by substituting a placeholder and restoring at the end.
        var placeholders = new List<string>();
        string Replace(Match m)
        {
            var inner = m.Groups["body"].Value;
            placeholders.Add(WebUtility.HtmlDecode(inner));
            return $"\u0001CODE{placeholders.Count - 1}\u0001";
        }
        var stripped = CodeBlockMatcher.Replace(html, Replace);
        stripped = TagStripper.Replace(stripped, string.Empty);
        stripped = WebUtility.HtmlDecode(stripped);
        for (int i = 0; i < placeholders.Count; i++)
        {
            stripped = stripped.Replace($"\u0001CODE{i}\u0001", placeholders[i]);
        }
        return stripped.Trim();
    }

    private static string Sha256(string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        var hash = SHA256.HashData(bytes);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    public void Dispose()
    {
        _rateLimit.Dispose();
        if (_ownsHttp) _http.Dispose();
    }
}
