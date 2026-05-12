using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Drederick.Audit;

namespace Drederick.Ops.FlagSubmission;

// --- htb-flag-submission ---

/// <summary>
/// HackTheBox v4 flag submission client. The HTB platform endpoint is the
/// <em>operator's reporting back-channel</em> and is intentionally NOT
/// passed through <c>_scope.Require</c> — scope is the authorization gate
/// for targets we attack, not for the dashboard where we report results.
///
/// Defense in depth still applies: the configured base URL must be HTTPS
/// in production (the constructor accepts an <c>allowedScheme</c> override
/// for tests only). Every submission is audited with platform +
/// <c>flag_sha256</c>; the plaintext flag and the bearer token are never
/// written to the audit log or any persisted artifact.
/// </summary>
public sealed class HtbFlagClient : IDisposable
{
    public const string DefaultBaseUrl = "https://www.hackthebox.com";
    public const string Platform = "htb";

    private readonly Uri _baseUrl;
    private readonly string _token;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly AuditLog _audit;
    private readonly TimeSpan _minInterval;
    private readonly TimeSpan[] _retryDelays;
    private readonly object _gate = new();
    private DateTimeOffset _lastSubmission = DateTimeOffset.MinValue;

    public HtbFlagClient(
        string token,
        AuditLog audit,
        HttpClient? http = null,
        string baseUrl = DefaultBaseUrl,
        string allowedScheme = "https",
        TimeSpan? minInterval = null,
        TimeSpan[]? retryDelays = null)
    {
        if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException("token required", nameof(token));
        if (string.IsNullOrWhiteSpace(baseUrl)) throw new ArgumentException("baseUrl required", nameof(baseUrl));
        _baseUrl = new Uri(baseUrl);
        if (!string.Equals(_baseUrl.Scheme, allowedScheme, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"HtbFlagClient refuses non-{allowedScheme} endpoint '{_baseUrl}'");
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

    public async Task<FlagSubmissionResult> SubmitMachineFlagAsync(
        int machineId, string flag, int difficulty, CancellationToken ct = default)
    {
        if (flag is null) throw new ArgumentNullException(nameof(flag));
        if (difficulty < 1 || difficulty > 100)
            throw new ArgumentOutOfRangeException(nameof(difficulty), "1..100");

        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["flag"] = flag,
            ["id"] = machineId,
            ["difficulty"] = difficulty,
        });
        return await SendSubmissionAsync(
            "/api/v4/machine/own", payload, machineId, "machine", flag, ct)
            .ConfigureAwait(false);
    }

    public async Task<FlagSubmissionResult> SubmitChallengeFlagAsync(
        int challengeId, string flag, CancellationToken ct = default)
    {
        if (flag is null) throw new ArgumentNullException(nameof(flag));

        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["flag"] = flag,
            ["challenge_id"] = challengeId,
        });
        return await SendSubmissionAsync(
            "/api/v4/challenge/own", payload, challengeId, "challenge", flag, ct)
            .ConfigureAwait(false);
    }

    private async Task<FlagSubmissionResult> SendSubmissionAsync(
        string path, string payload, int targetId, string kind, string flag, CancellationToken ct)
    {
        await ThrottleAsync(ct).ConfigureAwait(false);

        var flagSha = FlagSubmissionResult.Sha256Hex(flag);
        var url = new Uri(_baseUrl, path);

        _audit.Record("flag.submit.start", new Dictionary<string, object?>
        {
            ["platform"] = Platform,
            ["kind"] = kind,
            ["target_id"] = targetId,
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
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
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
            var failed = new FlagSubmissionResult
            {
                Platform = Platform,
                Success = false,
                ResponseCode = 0,
                Message = lastError?.Message ?? "no response",
                FlagSha256 = flagSha,
                SubmittedAt = DateTimeOffset.UtcNow,
                TargetId = targetId,
                Kind = kind,
            };
            _audit.Record("flag.submit.error", new Dictionary<string, object?>
            {
                ["platform"] = Platform,
                ["flag_sha256"] = flagSha,
                ["target_id"] = targetId,
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
            });
            return failed;
        }

        bool success = resp.IsSuccessStatusCode;
        string? message = ExtractMessage(body);
        resp.Dispose();

        var result = new FlagSubmissionResult
        {
            Platform = Platform,
            Success = success,
            ResponseCode = code,
            Message = message,
            FlagSha256 = flagSha,
            SubmittedAt = DateTimeOffset.UtcNow,
            TargetId = targetId,
            Kind = kind,
        };

        _audit.Record("flag.submitted", new Dictionary<string, object?>
        {
            ["platform"] = Platform,
            ["kind"] = kind,
            ["target_id"] = targetId,
            ["flag_sha256"] = flagSha,
            ["success"] = success,
            ["response_code"] = code,
            ["elapsed_ms"] = sw.ElapsedMilliseconds,
        });

        return result;
    }

    private static string? ExtractMessage(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String)
                return m.GetString();
            if (doc.RootElement.TryGetProperty("status", out var s) && s.ValueKind == JsonValueKind.String)
                return s.GetString();
        }
        catch (JsonException) { /* non-JSON body falls through */ }
        return body.Length > 256 ? body.Substring(0, 256) : body;
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
