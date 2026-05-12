using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Drederick.Audit;

namespace Drederick.Ops.FlagSubmission;

// --- htb-flag-submission ---

/// <summary>Lightweight summary of a CTFd challenge, as returned by the
/// public challenge listing endpoint. Used by the operator to map a
/// detected flag back to a numeric challenge id when one was not supplied
/// on the command line.</summary>
public sealed record CtfdChallengeSummary(int Id, string Name, string? Category, int? Value);

/// <summary>
/// Operator-side CTFd flag submission client. Like <see cref="HtbFlagClient"/>,
/// the CTFd dashboard is the operator's reporting back-channel — it is
/// intentionally NOT scope-checked. The constructor refuses non-HTTPS base
/// URLs in production; tests construct with <c>allowedScheme: "http"</c>.
/// </summary>
public sealed class CtfdFlagClient : IDisposable
{
    public const string Platform = "ctfd";

    private readonly Uri _baseUrl;
    private readonly string _token;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly AuditLog _audit;
    private readonly TimeSpan _minInterval;
    private readonly TimeSpan[] _retryDelays;
    private readonly object _gate = new();
    private DateTimeOffset _lastSubmission = DateTimeOffset.MinValue;

    public CtfdFlagClient(
        string baseUrl,
        string token,
        AuditLog audit,
        HttpClient? http = null,
        string allowedScheme = "https",
        TimeSpan? minInterval = null,
        TimeSpan[]? retryDelays = null)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) throw new ArgumentException("baseUrl required", nameof(baseUrl));
        if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException("token required", nameof(token));
        _baseUrl = new Uri(baseUrl);
        if (!string.Equals(_baseUrl.Scheme, allowedScheme, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"CtfdFlagClient refuses non-{allowedScheme} endpoint '{_baseUrl}'");
        }
        _token = token;
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _http = http ?? new HttpClient();
        _ownsHttp = http is null;
        _minInterval = minInterval ?? TimeSpan.FromSeconds(2);
        _retryDelays = retryDelays ?? new[]
        {
            TimeSpan.FromMilliseconds(500),
            TimeSpan.FromSeconds(2),
            TimeSpan.FromSeconds(5),
        };
    }

    public async Task<IReadOnlyList<CtfdChallengeSummary>> ListChallengesAsync(CancellationToken ct = default)
    {
        var url = new Uri(_baseUrl, "/api/v1/challenges");
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Token", _token);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        _audit.Record("flag.ctfd.list.start", new Dictionary<string, object?>
        {
            ["platform"] = Platform,
        });

        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var list = new List<CtfdChallengeSummary>();
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in data.EnumerateArray())
                {
                    int id = el.TryGetProperty("id", out var iEl) && iEl.ValueKind == JsonValueKind.Number
                        ? iEl.GetInt32() : 0;
                    string name = el.TryGetProperty("name", out var nEl) ? (nEl.GetString() ?? "") : "";
                    string? category = el.TryGetProperty("category", out var cEl) ? cEl.GetString() : null;
                    int? value = el.TryGetProperty("value", out var vEl) && vEl.ValueKind == JsonValueKind.Number
                        ? vEl.GetInt32() : (int?)null;
                    list.Add(new CtfdChallengeSummary(id, name, category, value));
                }
            }
        }
        catch (JsonException) { /* return empty list */ }

        _audit.Record("flag.ctfd.list.finish", new Dictionary<string, object?>
        {
            ["platform"] = Platform,
            ["count"] = list.Count,
            ["status"] = (int)resp.StatusCode,
        });
        return list;
    }

    public async Task<FlagSubmissionResult> SubmitFlagAsync(
        int challengeId, string flag, CancellationToken ct = default)
    {
        if (flag is null) throw new ArgumentNullException(nameof(flag));

        await ThrottleAsync(ct).ConfigureAwait(false);

        var flagSha = FlagSubmissionResult.Sha256Hex(flag);
        var url = new Uri(_baseUrl, "/api/v1/challenges/attempt");
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["challenge_id"] = challengeId,
            ["submission"] = flag,
        });

        _audit.Record("flag.submit.start", new Dictionary<string, object?>
        {
            ["platform"] = Platform,
            ["kind"] = "challenge",
            ["target_id"] = challengeId,
            ["flag_sha256"] = flagSha,
        });

        var sw = Stopwatch.StartNew();
        HttpResponseMessage? resp = null;
        string body = "";
        int code = 0;
        Exception? lastError = null;

        for (int attempt = 0; attempt < _retryDelays.Length; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent(payload, Encoding.UTF8, "application/json"),
                };
                req.Headers.Authorization = new AuthenticationHeaderValue("Token", _token);
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
                code = (int)resp.StatusCode;
                body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

                if (code == 429 && attempt < _retryDelays.Length - 1)
                {
                    var delay = _retryDelays[attempt];
                    _audit.Record("flag.submit.backoff", new Dictionary<string, object?>
                    {
                        ["platform"] = Platform,
                        ["flag_sha256"] = flagSha,
                        ["status"] = code,
                        ["delay_ms"] = (long)delay.TotalMilliseconds,
                        ["attempt"] = attempt,
                    });
                    resp.Dispose();
                    resp = null;
                    await Task.Delay(delay, ct).ConfigureAwait(false);
                    continue;
                }
                break;
            }
            catch (HttpRequestException ex) when (attempt < _retryDelays.Length - 1)
            {
                lastError = ex;
                await Task.Delay(_retryDelays[attempt], ct).ConfigureAwait(false);
            }
        }

        if (resp is null)
        {
            _audit.Record("flag.submit.error", new Dictionary<string, object?>
            {
                ["platform"] = Platform,
                ["flag_sha256"] = flagSha,
                ["target_id"] = challengeId,
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
            });
            return new FlagSubmissionResult
            {
                Platform = Platform,
                Success = false,
                ResponseCode = 0,
                Message = lastError?.Message ?? "no response",
                FlagSha256 = flagSha,
                SubmittedAt = DateTimeOffset.UtcNow,
                TargetId = challengeId,
                Kind = "challenge",
            };
        }

        bool correct = false;
        string? message = null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("data", out var data))
            {
                if (data.TryGetProperty("status", out var st) && st.ValueKind == JsonValueKind.String)
                {
                    var status = st.GetString() ?? "";
                    correct = status.Equals("correct", StringComparison.OrdinalIgnoreCase)
                        || status.Equals("already_solved", StringComparison.OrdinalIgnoreCase);
                    message = status;
                }
                if (data.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String)
                {
                    message = m.GetString();
                }
            }
        }
        catch (JsonException) { /* non-JSON body */ }

        bool success = resp.IsSuccessStatusCode && correct;
        resp.Dispose();

        var result = new FlagSubmissionResult
        {
            Platform = Platform,
            Success = success,
            ResponseCode = code,
            Message = message,
            FlagSha256 = flagSha,
            SubmittedAt = DateTimeOffset.UtcNow,
            TargetId = challengeId,
            Kind = "challenge",
        };

        _audit.Record("flag.submitted", new Dictionary<string, object?>
        {
            ["platform"] = Platform,
            ["kind"] = "challenge",
            ["target_id"] = challengeId,
            ["flag_sha256"] = flagSha,
            ["success"] = success,
            ["response_code"] = code,
            ["elapsed_ms"] = sw.ElapsedMilliseconds,
        });

        return result;
    }

    private async Task ThrottleAsync(CancellationToken ct)
    {
        TimeSpan wait;
        lock (_gate)
        {
            var elapsed = DateTimeOffset.UtcNow - _lastSubmission;
            wait = _minInterval - elapsed;
            if (wait < TimeSpan.Zero) wait = TimeSpan.Zero;
            _lastSubmission = DateTimeOffset.UtcNow + wait;
        }
        if (wait > TimeSpan.Zero) await Task.Delay(wait, ct).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }
}

// --- end htb-flag-submission ---
