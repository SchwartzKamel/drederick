using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// Minimal interface for LLM-driven payload mutation. Allows testing with
/// fake mutators and adapts the existing <see cref="ICopilotLlmClient"/> to
/// a simpler surface for this specific fuzz tool.
/// </summary>
public interface ILlmMutator
{
    /// <summary>Whether an LLM backend is available and usable.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Ask the LLM to mutate <paramref name="previousPayload"/> based on the
    /// objective and the response observed. Returns a new payload string or
    /// throws on non-retryable LLM failures (auth, quota, etc).
    /// </summary>
    Task<string> MutateAsync(
        string objective,
        string previousPayload,
        int previousStatus,
        string previousResponseSnippet,
        CancellationToken ct);
}

/// <summary>
/// Default LLM mutator that delegates to the existing
/// <see cref="ICopilotLlmClient"/> infrastructure (Copilot SDK, Azure OpenAI,
/// llama.cpp). Uses <c>COPILOT_TOKEN</c> / <c>GH_TOKEN</c> /
/// <c>GITHUB_TOKEN</c> / authenticated <c>gh</c> CLI / Azure env config /
/// llama.cpp endpoint. If none available, <see cref="IsAvailable"/> is
/// <c>false</c>.
/// </summary>
public sealed class DefaultLlmMutator : ILlmMutator
{
    private readonly ICopilotLlmClient? _client;
    private readonly string? _modelId;

    public bool IsAvailable => _client is not null && !string.IsNullOrWhiteSpace(_modelId);

    /// <summary>
    /// Construct from an existing <see cref="ICopilotLlmClient"/> and model
    /// ID. If <paramref name="client"/> is <c>null</c> or
    /// <paramref name="modelId"/> is blank, <see cref="IsAvailable"/> is
    /// <c>false</c> and <see cref="MutateAsync"/> will throw.
    /// </summary>
    public DefaultLlmMutator(ICopilotLlmClient? client, string? modelId)
    {
        _client = client;
        _modelId = modelId;
    }

    /// <summary>
    /// Attempt to build from environment. Returns an instance with
    /// <see cref="IsAvailable"/> = <c>true</c> if any recognized token or
    /// endpoint is set; otherwise <see cref="IsAvailable"/> = <c>false</c>.
    /// Model preference: <c>DREDERICK_MODEL</c> env or <c>gpt-4o-mini</c>.
    /// </summary>
    public static DefaultLlmMutator TryCreateFromEnvironment(AuditLog audit)
    {
        var client = CopilotLlmClient.TryCreateFromEnvironment(audit);
        if (client is null) return new DefaultLlmMutator(null, null);

        var modelId = Environment.GetEnvironmentVariable("DREDERICK_MODEL");
        if (string.IsNullOrWhiteSpace(modelId)) modelId = "gpt-4o-mini";

        return new DefaultLlmMutator(client, modelId);
    }

    public async Task<string> MutateAsync(
        string objective,
        string previousPayload,
        int previousStatus,
        string previousResponseSnippet,
        CancellationToken ct)
    {
        if (_client is null || string.IsNullOrWhiteSpace(_modelId))
        {
            throw new InvalidOperationException(
                "DefaultLlmMutator: no LLM client available. Run `gh auth login --web`, set "
                + "COPILOT_TOKEN / GH_TOKEN / GITHUB_TOKEN, or configure Azure/llama.cpp env vars.");
        }

        var systemPrompt =
            "You are a penetration-testing payload mutator. Your job is to creatively mutate HTTP payloads "
            + "to bypass detection, trigger different behavior, or maximize code coverage. "
            + "Return ONLY the new payload — no preamble, no explanation, no markdown fences. "
            + "The payload must be a single line suitable for direct HTTP transmission.";

        var userPrompt = $@"Objective: {objective}

Previous payload: {previousPayload}
Previous response status: {previousStatus}
Previous response snippet (first 4KB): {previousResponseSnippet}

Based on the observed response, mutate the payload to achieve the objective. Return ONLY the new payload.";

        var messages = new List<CopilotChatMessage>
        {
            new("system", systemPrompt),
            new("user", userPrompt),
        };

        var resp = await _client.ChatAsync(_modelId!, messages, tools: null, ct).ConfigureAwait(false);
        var content = resp.Content?.Trim() ?? string.Empty;

        // Strip markdown fences if the model ignored the instruction.
        if (content.StartsWith("```", StringComparison.Ordinal))
        {
            var lines = content.Split('\n');
            var payloadLines = lines.Skip(1).TakeWhile(l => !l.StartsWith("```", StringComparison.Ordinal)).ToArray();
            content = string.Join("\n", payloadLines).Trim();
        }

        return content;
    }
}

/// <summary>Options for <see cref="LlmPayloadFuzzTool.ProbeAsync"/>.</summary>
public sealed class LlmPayloadFuzzOptions
{
    /// <summary>Max rounds to attempt (clamped to <see cref="HardMaxRounds"/>).</summary>
    public int MaxRounds { get; init; } = 8;

    /// <summary>Hard cap on rounds to prevent runaway loops. Default: 32.</summary>
    public int HardMaxRounds { get; init; } = 32;

    /// <summary>HTTP method. Must be GET / POST / PUT. Default: POST.</summary>
    public string Method { get; init; } = "POST";

    /// <summary>
    /// Content-Type header for the request. Must be one of:
    /// <c>application/x-www-form-urlencoded</c>, <c>application/json</c>,
    /// <c>text/plain</c>, <c>multipart/form-data</c>. Default:
    /// <c>application/x-www-form-urlencoded</c>.
    /// </summary>
    public string ContentType { get; init; } = "application/x-www-form-urlencoded";

    /// <summary>
    /// Parameter name for the payload (GET query / POST body / JSON key).
    /// Must match <c>[A-Za-z0-9_-]+</c>. Default: <c>input</c>.
    /// </summary>
    public string ParameterName { get; init; } = "input";

    /// <summary>
    /// Rate limit: milliseconds to wait between successive HTTP requests.
    /// Default: 500ms.
    /// </summary>
    public int RateLimitMsBetweenRequests { get; init; } = 500;
}

/// <summary>
/// Iterative LLM-driven payload mutation: send payload → capture response →
/// ask LLM to mutate the payload to bypass detection / elicit different
/// behavior → repeat N rounds. The LLM's job is to be a creative mutator; the
/// tool's job is to enforce safety rails (scope, round cap, audit, rate limit,
/// response size limit).
///
/// <para>Requires an <see cref="ILlmMutator"/> backend (default:
/// <see cref="DefaultLlmMutator"/> from environment). Falls back gracefully
/// when no LLM is available — audit records the skip, never throws.</para>
///
/// <para>FuzzCategory: <see cref="FuzzCategory.Mutation"/> (DESTRUCTIVE
/// category — requires <c>--allow-fuzz-mutation</c> AND
/// <c>--allow-destructive</c> opt-in even in lab mode).</para>
/// </summary>
public sealed class LlmPayloadFuzzTool : IFuzzTool
{
    public string Name => "llm-payload-fuzz";

    public string Description =>
        "LLM-assisted payload mutation: iteratively refine payloads based on response " +
        "deltas to maximize code coverage or trigger anomalous behavior. Each mutation " +
        "step is recorded so the operator can replay successful chains. Requires LLM backend; " +
        "falls back gracefully when unavailable.";

    public FuzzCategory Category => FuzzCategory.Mutation;

    private const int MaxPayloadBytes = 64 * 1024; // 64 KB
    private const int MaxResponseSnippetBytes = 4 * 1024; // 4 KB

    private static readonly Regex ParameterNameRegex = new(@"^[A-Za-z0-9_-]+$", RegexOptions.Compiled);
    private static readonly HashSet<string> AllowedMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "GET", "POST", "PUT",
    };
    private static readonly HashSet<string> AllowedContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "application/x-www-form-urlencoded",
        "application/json",
        "text/plain",
        "multipart/form-data",
    };

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly ILlmMutator _llmMutator;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    public LlmPayloadFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        ILlmMutator? llmMutator = null,
        HttpClient? httpClient = null)
    {
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _llmMutator = llmMutator ?? DefaultLlmMutator.TryCreateFromEnvironment(audit);

        if (httpClient is null)
        {
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            _ownsHttp = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttp = false;
        }
    }

    /// <summary>
    /// Iteratively mutate <paramref name="seedPayload"/> via LLM to maximize
    /// the likelihood of achieving <paramref name="objective"/>. Each round
    /// sends the current payload to <paramref name="targetUrl"/>, captures the
    /// response, and asks the LLM to mutate based on observed deltas.
    /// </summary>
    /// <exception cref="ArgumentException">Invalid URL, method, content-type, parameter name, or seed payload.</exception>
    /// <exception cref="ScopeException">URL host is out of scope.</exception>
    public async Task<LlmPayloadFuzzResult> ProbeAsync(
        string targetUrl,
        string objective,
        string seedPayload,
        LlmPayloadFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        options ??= new LlmPayloadFuzzOptions();

        // 1. Validate inputs.
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri)
            || (uri.Scheme != "http" && uri.Scheme != "https"))
        {
            throw new ArgumentException(
                $"targetUrl must be an absolute http/https URL; got: {targetUrl}", nameof(targetUrl));
        }

        if (!AllowedMethods.Contains(options.Method))
        {
            throw new ArgumentException(
                $"Method must be one of GET/POST/PUT; got: {options.Method}", nameof(options));
        }

        if (!AllowedContentTypes.Contains(options.ContentType))
        {
            throw new ArgumentException(
                $"ContentType must be one of application/x-www-form-urlencoded, application/json, "
                + $"text/plain, multipart/form-data; got: {options.ContentType}", nameof(options));
        }

        if (!ParameterNameRegex.IsMatch(options.ParameterName))
        {
            throw new ArgumentException(
                $"ParameterName must match [A-Za-z0-9_-]+; got: {options.ParameterName}", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(seedPayload))
        {
            throw new ArgumentException("seedPayload cannot be empty", nameof(seedPayload));
        }

        if (Encoding.UTF8.GetByteCount(seedPayload) > MaxPayloadBytes)
        {
            throw new ArgumentException(
                $"seedPayload exceeds {MaxPayloadBytes} bytes", nameof(seedPayload));
        }

        // 2. Scope-check (FIRST statement after validation).
        _scope.Require(uri.Host);

        var startedAt = DateTimeOffset.UtcNow;
        var mutations = new List<MutationStep>();

        // 3. Clamp rounds.
        var maxRounds = Math.Clamp(options.MaxRounds, 1, options.HardMaxRounds);

        // 4. Early exit if LLM unavailable.
        if (!_llmMutator.IsAvailable)
        {
            var objDigest = Sha256Hex(objective);
            var seedDigest = Sha256Hex(seedPayload);

            _audit.Record("llm-payload-fuzz.start", new Dictionary<string, object?>
            {
                ["url"] = targetUrl,
                ["objective_digest"] = objDigest,
                ["seed_digest"] = seedDigest,
                ["max_rounds"] = maxRounds,
                ["llm_available"] = false,
            });

            _audit.Record("llm-payload-fuzz.finish", new Dictionary<string, object?>
            {
                ["url"] = targetUrl,
                ["rounds_completed"] = 0,
                ["llm_available"] = false,
                ["duration_ms"] = 0,
            });

            return new LlmPayloadFuzzResult
            {
                Target = targetUrl,
                ToolName = Name,
                StartedAt = startedAt,
                Duration = TimeSpan.Zero,
                Rounds = 0,
                Mutations = mutations,
                LlmAvailable = false,
            };
        }

        // 5. Audit start.
        {
            var objDigest = Sha256Hex(objective);
            var seedDigest = Sha256Hex(seedPayload);
            _audit.Record("llm-payload-fuzz.start", new Dictionary<string, object?>
            {
                ["url"] = targetUrl,
                ["objective_digest"] = objDigest,
                ["seed_digest"] = seedDigest,
                ["max_rounds"] = maxRounds,
                ["llm_available"] = true,
            });
        }

        // 6. Main loop.
        var currentPayload = seedPayload;
        int statusMin = int.MaxValue;
        int statusMax = int.MinValue;
        long totalBytesReceived = 0;

        for (int round = 1; round <= maxRounds; round++)
        {
            if (ct.IsCancellationRequested) break;

            // Send current payload.
            var req = BuildRequest(uri, options.Method, options.ContentType, options.ParameterName, currentPayload);
            HttpResponseMessage? resp = null;
            int status = 0;
            long bodySize = 0;
            string snippet = "";

            try
            {
                resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
                status = (int)resp.StatusCode;
                var bodyBytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                bodySize = bodyBytes.Length;
                totalBytesReceived += bodySize;

                var snippetLength = Math.Min(bodyBytes.Length, MaxResponseSnippetBytes);
                snippet = Encoding.UTF8.GetString(bodyBytes, 0, snippetLength);

                statusMin = Math.Min(statusMin, status);
                statusMax = Math.Max(statusMax, status);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Record the failure and continue or break depending on error type.
                snippet = $"HTTP error: {ex.Message}";
                status = 0;
            }
            finally
            {
                resp?.Dispose();
            }

            // Record mutation step.
            var payloadDigest = Sha256Hex(currentPayload);
            mutations.Add(new MutationStep(
                Round: round,
                PayloadDigest: payloadDigest,
                ResponseStatus: status,
                ResponseSize: bodySize,
                Notes: $"first {snippet.Length} bytes captured"));

            if (ct.IsCancellationRequested) break;

            // Rate-limit.
            if (round < maxRounds && options.RateLimitMsBetweenRequests > 0)
            {
                await Task.Delay(options.RateLimitMsBetweenRequests, ct).ConfigureAwait(false);
            }

            // Ask LLM to mutate for next round.
            if (round < maxRounds)
            {
                string nextPayload;
                try
                {
                    nextPayload = await _llmMutator.MutateAsync(objective, currentPayload, status, snippet, ct)
                        .ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // LLM failure: record and break.
                    mutations.Add(new MutationStep(
                        Round: round + 1,
                        PayloadDigest: "",
                        ResponseStatus: 0,
                        ResponseSize: 0,
                        Notes: $"llm-error: {ex.Message}"));
                    break;
                }

                // Validate LLM-returned payload.
                if (string.IsNullOrWhiteSpace(nextPayload)
                    || Encoding.UTF8.GetByteCount(nextPayload) > MaxPayloadBytes
                    || nextPayload.Contains('\0'))
                {
                    mutations.Add(new MutationStep(
                        Round: round + 1,
                        PayloadDigest: "",
                        ResponseStatus: 0,
                        ResponseSize: 0,
                        Notes: "llm-returned-invalid-payload"));
                    break;
                }

                currentPayload = nextPayload;
            }
        }

        var elapsed = DateTimeOffset.UtcNow - startedAt;

        // 7. Audit finish.
        _audit.Record("llm-payload-fuzz.finish", new Dictionary<string, object?>
        {
            ["url"] = targetUrl,
            ["rounds_completed"] = mutations.Count,
            ["response_status_min"] = statusMin == int.MaxValue ? 0 : statusMin,
            ["response_status_max"] = statusMax == int.MinValue ? 0 : statusMax,
            ["total_bytes_received"] = totalBytesReceived,
            ["duration_ms"] = (long)elapsed.TotalMilliseconds,
        });

        // 8. Return result.
        return new LlmPayloadFuzzResult
        {
            Target = targetUrl,
            ToolName = Name,
            StartedAt = startedAt,
            Duration = elapsed,
            Rounds = mutations.Count,
            Mutations = mutations,
            LlmAvailable = true,
        };
    }

    private static HttpRequestMessage BuildRequest(
        Uri uri,
        string method,
        string contentType,
        string parameterName,
        string payload)
    {
        var req = new HttpRequestMessage(new HttpMethod(method), uri);

        if (method.Equals("GET", StringComparison.OrdinalIgnoreCase))
        {
            var ub = new UriBuilder(uri);
            var query = System.Web.HttpUtility.ParseQueryString(ub.Query);
            query[parameterName] = payload;
            ub.Query = query.ToString();
            req.RequestUri = ub.Uri;
        }
        else if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            var json = $"{{\"{parameterName}\":{System.Text.Json.JsonSerializer.Serialize(payload)}}}";
            req.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }
        else if (contentType.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var form = new Dictionary<string, string> { [parameterName] = payload };
            req.Content = new FormUrlEncodedContent(form);
        }
        else
        {
            // text/plain or fallback
            req.Content = new StringContent(payload, Encoding.UTF8, contentType);
        }

        return req;
    }

    private static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }
}
