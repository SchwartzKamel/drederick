using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Drederick.Audit;
using Microsoft.Extensions.AI;

namespace Drederick.Jeopardy.Llm;

/// <summary>Model descriptor returned by <see cref="ICopilotLlmClient.ListModelsAsync"/>.</summary>
/// <remarks>
/// <c>Family</c> is one of: "openai-gpt", "anthropic-claude", "google-gemini",
/// "xai-grok", "copilot-native".
/// </remarks>
public sealed record CopilotModel(string Id, string Family, long? ContextWindow, bool SupportsTools);

/// <summary>A single chat message. Role is "system" | "user" | "assistant" | "tool".</summary>
public sealed record CopilotChatMessage(string Role, string Content);

/// <summary>Structured tool call extracted from an assistant response.</summary>
public sealed record CopilotToolCall(string Id, string Name, string ArgumentsJson);

/// <summary>Chat completion response with usage + timing metadata.</summary>
public sealed record CopilotChatResponse(
    string ModelId,
    string? Content,
    IReadOnlyList<CopilotToolCall> ToolCalls,
    int PromptTokens,
    int CompletionTokens,
    string? FinishReason,
    TimeSpan Elapsed);

/// <summary>Structured error surface for Copilot HTTP failures.</summary>
public sealed class CopilotLlmException : Exception
{
    public HttpStatusCode? StatusCode { get; }
    public string? ModelId { get; }

    public CopilotLlmException(HttpStatusCode? statusCode, string? modelId, string message, Exception? inner = null)
        : base(message, inner)
    {
        StatusCode = statusCode;
        ModelId = modelId;
    }
}

/// <summary>Thin, thread-safe multi-model client for the GitHub Copilot API.</summary>
public interface ICopilotLlmClient
{
    Task<IReadOnlyList<CopilotModel>> ListModelsAsync(CancellationToken ct);
    Task<CopilotChatResponse> ChatAsync(
        string modelId,
        IReadOnlyList<CopilotChatMessage> messages,
        IReadOnlyList<AITool>? tools,
        CancellationToken ct);
}

/// <summary>
/// OpenAI-wire-compatible client for the GitHub Copilot chat-completions
/// endpoint. Unlocks gpt-5.x, Claude 4.x, Gemini 3.x, Grok Code Fast, and
/// Copilot-native models through a single OAuth token + Copilot-Integration-Id
/// header.
///
/// <para>Thread-safe. Parallel <see cref="ChatAsync"/> calls are safe; the only
/// shared mutable state is the model list cache (<see cref="ConcurrentDictionary{TKey,TValue}"/>).</para>
///
/// <para>Environment:</para>
/// <list type="bullet">
///   <item><c>COPILOT_TOKEN</c>, <c>GH_TOKEN</c>, <c>GITHUB_TOKEN</c> — OAuth token (fall through in that order).</item>
///   <item><c>COPILOT_INTEGRATION_ID</c> — required header, default <c>drederick-cli</c>.</item>
///   <item><c>COPILOT_ENDPOINT</c> — base URL override, default <c>https://api.githubcopilot.com/v1</c>.</item>
/// </list>
///
/// <para>Audit: every chat emits <c>copilot.chat.start</c> and
/// <c>copilot.chat.finish</c>. Prompts and tool arguments are recorded as
/// SHA-256 digests only — plaintext never reaches the audit log.</para>
/// </summary>
public sealed class CopilotLlmClient : ICopilotLlmClient, IDisposable
{
    public static readonly Uri DefaultCopilotEndpoint = new("https://api.githubcopilot.com/v1");
    public static readonly Uri DefaultGithubModelsEndpoint = new("https://models.inference.ai.azure.com/v1");

    private const string DefaultIntegrationId = "drederick-cli";
    private static readonly TimeSpan ModelCacheTtl = TimeSpan.FromHours(1);
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly string _token;
    private readonly string _integrationId;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly Uri _endpoint;
    private readonly bool _ownsHttp;

    // Cache is per-instance; use ConcurrentDictionary with a single key to get
    // lazy init without lock contention on the hot path.
    private readonly ConcurrentDictionary<string, (DateTimeOffset CachedAt, IReadOnlyList<CopilotModel> Models)> _modelCache
        = new();

    public CopilotLlmClient(
        string token,
        string integrationId,
        AuditLog audit,
        HttpClient? http = null,
        Uri? endpoint = null)
    {
        if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException("token required", nameof(token));
        _token = token;
        _integrationId = string.IsNullOrWhiteSpace(integrationId) ? DefaultIntegrationId : integrationId;
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _endpoint = endpoint ?? DefaultCopilotEndpoint;

        if (http is null)
        {
            _http = new HttpClient(new CopilotHeadersHandler(_integrationId, new HttpClientHandler()));
            _ownsHttp = true;
        }
        else
        {
            _http = http;
            _ownsHttp = false;
        }
    }

    /// <summary>
    /// Construct a client from environment variables. Returns <c>null</c> if
    /// no usable token is present. Token preference order:
    /// <c>COPILOT_TOKEN</c> &gt; <c>GH_TOKEN</c> &gt; <c>GITHUB_TOKEN</c>.
    /// If only <c>GITHUB_TOKEN</c> is set and looks like a PAT
    /// (<c>ghp_</c> / <c>github_pat_</c>), the endpoint falls back to the
    /// GitHub Models (Azure AI) inference endpoint.
    /// </summary>
    public static CopilotLlmClient? TryCreateFromEnvironment(AuditLog audit)
    {
        var (token, source) = ResolveToken();
        if (string.IsNullOrWhiteSpace(token)) return null;

        var integrationId = Environment.GetEnvironmentVariable("COPILOT_INTEGRATION_ID");
        if (string.IsNullOrWhiteSpace(integrationId)) integrationId = DefaultIntegrationId;

        Uri endpoint;
        var endpointEnv = Environment.GetEnvironmentVariable("COPILOT_ENDPOINT");
        if (!string.IsNullOrWhiteSpace(endpointEnv) && Uri.TryCreate(endpointEnv, UriKind.Absolute, out var parsed))
        {
            endpoint = parsed;
        }
        else if (source == TokenSource.GithubToken && LooksLikeGithubPat(token!))
        {
            endpoint = DefaultGithubModelsEndpoint;
        }
        else
        {
            endpoint = DefaultCopilotEndpoint;
        }

        return new CopilotLlmClient(token!, integrationId!, audit, http: null, endpoint: endpoint);
    }

    internal enum TokenSource { None, CopilotToken, GhToken, GithubToken }

    internal static (string? Token, TokenSource Source) ResolveToken()
    {
        var c = Environment.GetEnvironmentVariable("COPILOT_TOKEN");
        if (!string.IsNullOrWhiteSpace(c)) return (c, TokenSource.CopilotToken);
        var g = Environment.GetEnvironmentVariable("GH_TOKEN");
        if (!string.IsNullOrWhiteSpace(g)) return (g, TokenSource.GhToken);
        var h = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(h)) return (h, TokenSource.GithubToken);
        return (null, TokenSource.None);
    }

    internal static bool LooksLikeGithubPat(string token)
        => token.StartsWith("ghp_", StringComparison.Ordinal)
        || token.StartsWith("github_pat_", StringComparison.Ordinal);

    /// <inheritdoc />
    public async Task<IReadOnlyList<CopilotModel>> ListModelsAsync(CancellationToken ct)
    {
        if (_modelCache.TryGetValue("all", out var entry)
            && DateTimeOffset.UtcNow - entry.CachedAt < ModelCacheTtl)
        {
            return entry.Models;
        }

        var url = new Uri(Combine(_endpoint, "models"));
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        ApplyAuthHeaders(req);

        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new CopilotLlmException(null, null, Redact(ex.Message), ex);
        }

        using var _ = resp;
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            throw new CopilotLlmException(resp.StatusCode, null, Redact($"list models failed: {(int)resp.StatusCode} {body}"));
        }

        var models = ParseModels(body);
        _modelCache["all"] = (DateTimeOffset.UtcNow, models);
        return models;
    }

    internal static IReadOnlyList<CopilotModel> ParseModels(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var arr = root.TryGetProperty("data", out var dataEl) ? dataEl : root;
        var list = new List<CopilotModel>();
        foreach (var m in arr.EnumerateArray())
        {
            var id = m.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
            if (string.IsNullOrWhiteSpace(id)) continue;

            string family = "copilot-native";
            long? ctx = null;
            bool supportsTools = false;

            if (m.TryGetProperty("capabilities", out var caps))
            {
                if (caps.TryGetProperty("family", out var f) && f.ValueKind == JsonValueKind.String)
                    family = f.GetString() ?? family;
                if (caps.TryGetProperty("limits", out var limits)
                    && limits.TryGetProperty("max_context_window_tokens", out var maxCtx)
                    && maxCtx.ValueKind == JsonValueKind.Number)
                    ctx = maxCtx.GetInt64();
                if (caps.TryGetProperty("supports", out var sup)
                    && sup.TryGetProperty("tool_calls", out var tc)
                    && tc.ValueKind == JsonValueKind.True)
                    supportsTools = true;
            }
            else
            {
                // No capabilities block: infer family from vendor/id heuristics.
                family = InferFamily(id!, m);
            }

            list.Add(new CopilotModel(id!, family, ctx, supportsTools));
        }
        return list;
    }

    private static string InferFamily(string id, JsonElement m)
    {
        if (m.TryGetProperty("vendor", out var vEl) && vEl.ValueKind == JsonValueKind.String)
        {
            return (vEl.GetString() ?? "").ToLowerInvariant() switch
            {
                "openai" => "openai-gpt",
                "anthropic" => "anthropic-claude",
                "google" => "google-gemini",
                "xai" => "xai-grok",
                _ => "copilot-native",
            };
        }
        if (id.StartsWith("gpt-", StringComparison.OrdinalIgnoreCase)) return "openai-gpt";
        if (id.StartsWith("claude-", StringComparison.OrdinalIgnoreCase)) return "anthropic-claude";
        if (id.StartsWith("gemini-", StringComparison.OrdinalIgnoreCase)) return "google-gemini";
        if (id.StartsWith("grok-", StringComparison.OrdinalIgnoreCase)) return "xai-grok";
        return "copilot-native";
    }

    /// <inheritdoc />
    public async Task<CopilotChatResponse> ChatAsync(
        string modelId,
        IReadOnlyList<CopilotChatMessage> messages,
        IReadOnlyList<AITool>? tools,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(modelId)) throw new ArgumentException("modelId required", nameof(modelId));
        if (messages is null || messages.Count == 0) throw new ArgumentException("messages required", nameof(messages));

        var promptDigest = HashPrompt(messages);
        var toolNames = tools is null ? Array.Empty<string>() : tools.Select(t => t.Name).ToArray();

        _audit.Record("copilot.chat.start", new Dictionary<string, object?>
        {
            ["model"] = modelId,
            ["prompt_sha256"] = promptDigest,
            ["message_count"] = messages.Count,
            ["tool_count"] = toolNames.Length,
            ["tool_names"] = toolNames,
            ["endpoint"] = _endpoint.ToString(),
        });

        var body = BuildChatRequestBody(modelId, messages, tools);
        var url = new Uri(Combine(_endpoint, "chat/completions"));

        var sw = Stopwatch.StartNew();
        HttpResponseMessage? resp = null;
        string? respBody = null;
        HttpStatusCode? lastStatus = null;

        const int maxAttempts = 4;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            ApplyAuthHeaders(req);

            try
            {
                resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _audit.Record("copilot.chat.retry", new Dictionary<string, object?>
                {
                    ["model"] = modelId,
                    ["attempt"] = attempt,
                    ["error"] = Redact(ex.Message),
                });
                if (attempt == maxAttempts)
                {
                    throw new CopilotLlmException(null, modelId, Redact(ex.Message), ex);
                }
                await BackoffAsync(attempt, ct).ConfigureAwait(false);
                continue;
            }

            lastStatus = resp.StatusCode;
            respBody = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (resp.IsSuccessStatusCode) break;

            bool retryable = (int)resp.StatusCode == 429 || (int)resp.StatusCode >= 500;
            if (!retryable || attempt == maxAttempts)
            {
                var statusCode = resp.StatusCode;
                var snippet = respBody is null ? string.Empty : respBody[..Math.Min(512, respBody.Length)];
                resp.Dispose();
                throw new CopilotLlmException(statusCode, modelId, Redact($"{(int)statusCode}: {snippet}"));
            }

            _audit.Record("copilot.chat.retry", new Dictionary<string, object?>
            {
                ["model"] = modelId,
                ["attempt"] = attempt,
                ["status"] = (int)resp.StatusCode,
            });
            resp.Dispose();
            resp = null;
            await BackoffAsync(attempt, ct).ConfigureAwait(false);
        }

        sw.Stop();
        if (resp is null || respBody is null)
        {
            throw new CopilotLlmException(lastStatus, modelId, "unreachable: response null after retries");
        }

        CopilotChatResponse parsed;
        try
        {
            parsed = ParseChatResponse(modelId, respBody, sw.Elapsed);
        }
        finally
        {
            resp.Dispose();
        }

        var toolArgDigests = parsed.ToolCalls.Select(tc => Sha256Hex(tc.ArgumentsJson)).ToArray();
        _audit.Record("copilot.chat.finish", new Dictionary<string, object?>
        {
            ["model"] = modelId,
            ["prompt_sha256"] = promptDigest,
            ["prompt_tokens"] = parsed.PromptTokens,
            ["completion_tokens"] = parsed.CompletionTokens,
            ["elapsed_ms"] = (long)parsed.Elapsed.TotalMilliseconds,
            ["finish_reason"] = parsed.FinishReason,
            ["tool_calls_count"] = parsed.ToolCalls.Count,
            ["tool_argument_digests"] = toolArgDigests,
        });

        return parsed;
    }

    /// <summary>Estimate USD cost of a completed chat response using <see cref="CopilotPrices"/>.</summary>
    public static decimal EstimateCostUsd(CopilotChatResponse resp)
        => CopilotPrices.EstimateCostUsd(resp.ModelId, resp.PromptTokens, resp.CompletionTokens);

    // ---- request/response shaping ----

    internal static string BuildChatRequestBody(
        string modelId,
        IReadOnlyList<CopilotChatMessage> messages,
        IReadOnlyList<AITool>? tools)
        => BuildChatRequestBody(modelId, messages, tools, includeModel: true);

    /// <summary>
    /// Build the OpenAI-wire-compatible chat-completions request body. When
    /// <paramref name="includeModel"/> is <c>false</c>, the <c>model</c> key
    /// is omitted — use this for Azure OpenAI, which takes the deployment
    /// from the URL path rather than the body.
    /// </summary>
    internal static string BuildChatRequestBody(
        string modelId,
        IReadOnlyList<CopilotChatMessage> messages,
        IReadOnlyList<AITool>? tools,
        bool includeModel)
    {
        var msgArr = new JsonArray();
        foreach (var m in messages)
        {
            msgArr.Add(new JsonObject
            {
                ["role"] = m.Role,
                ["content"] = m.Content,
            });
        }

        var obj = new JsonObject
        {
            ["messages"] = msgArr,
        };
        if (includeModel) obj["model"] = modelId;

        if (tools is { Count: > 0 })
        {
            var toolArr = new JsonArray();
            foreach (var t in tools)
            {
                var function = new JsonObject { ["name"] = t.Name };
                if (!string.IsNullOrWhiteSpace(t.Description)) function["description"] = t.Description;

                // Best-effort: AIFunction exposes a JSON Schema via JsonSchema property
                // on Microsoft.Extensions.AI.AIFunction. Fall back to empty object schema.
                if (t is AIFunction af)
                {
                    try
                    {
                        var schemaNode = JsonNode.Parse(af.JsonSchema.GetRawText());
                        if (schemaNode is not null) function["parameters"] = schemaNode;
                    }
                    catch
                    {
                        function["parameters"] = new JsonObject { ["type"] = "object" };
                    }
                }
                else
                {
                    function["parameters"] = new JsonObject { ["type"] = "object" };
                }

                toolArr.Add(new JsonObject { ["type"] = "function", ["function"] = function });
            }
            obj["tools"] = toolArr;
        }

        return obj.ToJsonString(Json);
    }

    internal static CopilotChatResponse ParseChatResponse(string modelIdFallback, string json, TimeSpan elapsed)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        string modelId = modelIdFallback;
        if (root.TryGetProperty("model", out var mEl) && mEl.ValueKind == JsonValueKind.String)
            modelId = mEl.GetString() ?? modelIdFallback;

        string? content = null;
        string? finishReason = null;
        var toolCalls = new List<CopilotToolCall>();

        if (root.TryGetProperty("choices", out var choices) && choices.ValueKind == JsonValueKind.Array
            && choices.GetArrayLength() > 0)
        {
            var c0 = choices[0];
            if (c0.TryGetProperty("finish_reason", out var fr) && fr.ValueKind == JsonValueKind.String)
                finishReason = fr.GetString();
            if (c0.TryGetProperty("message", out var msg))
            {
                if (msg.TryGetProperty("content", out var ce) && ce.ValueKind == JsonValueKind.String)
                    content = ce.GetString();
                if (msg.TryGetProperty("tool_calls", out var tcs) && tcs.ValueKind == JsonValueKind.Array)
                {
                    foreach (var tc in tcs.EnumerateArray())
                    {
                        var id = tc.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
                            ? idEl.GetString() ?? "" : "";
                        string name = "";
                        string args = "";
                        if (tc.TryGetProperty("function", out var fn))
                        {
                            if (fn.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String)
                                name = n.GetString() ?? "";
                            if (fn.TryGetProperty("arguments", out var a))
                            {
                                args = a.ValueKind == JsonValueKind.String
                                    ? a.GetString() ?? ""
                                    : a.GetRawText();
                            }
                        }
                        toolCalls.Add(new CopilotToolCall(id, name, args));
                    }
                }
            }
        }

        int prompt = 0, completion = 0;
        if (root.TryGetProperty("usage", out var u))
        {
            if (u.TryGetProperty("prompt_tokens", out var p) && p.ValueKind == JsonValueKind.Number)
                prompt = p.GetInt32();
            if (u.TryGetProperty("completion_tokens", out var cEl) && cEl.ValueKind == JsonValueKind.Number)
                completion = cEl.GetInt32();
        }

        return new CopilotChatResponse(modelId, content, toolCalls, prompt, completion, finishReason, elapsed);
    }

    // ---- helpers ----

    private void ApplyAuthHeaders(HttpRequestMessage req)
    {
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        // Redundant with the DelegatingHandler for the default HttpClient, but
        // sets the header correctly when the caller passes their own HttpClient
        // without the handler (e.g. in tests).
        if (!req.Headers.Contains("Copilot-Integration-Id"))
            req.Headers.Add("Copilot-Integration-Id", _integrationId);
        if (!req.Headers.Contains("Accept"))
            req.Headers.Add("Accept", "application/json");
    }

    private static string Combine(Uri baseUri, string path)
    {
        var b = baseUri.ToString();
        if (!b.EndsWith('/')) b += "/";
        return b + path.TrimStart('/');
    }

    private static async Task BackoffAsync(int attempt, CancellationToken ct)
    {
        // 200ms, 400ms, 800ms...
        var ms = (int)(200 * Math.Pow(2, attempt - 1));
        try { await Task.Delay(ms, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
    }

    internal static string HashPrompt(IReadOnlyList<CopilotChatMessage> messages)
    {
        var sb = new StringBuilder();
        foreach (var m in messages)
        {
            sb.Append(m.Role).Append('\x1f').Append(m.Content).Append('\x1e');
        }
        return Sha256Hex(sb.ToString());
    }

    internal static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Redact Copilot / GitHub-style tokens from free-form strings before they
    /// reach the audit log or an exception message. Patterns covered:
    /// <c>ghu_</c>, <c>gho_</c>, <c>ghp_</c>, <c>ghs_</c>, <c>ghr_</c>,
    /// <c>github_pat_</c>, <c>Bearer &lt;token&gt;</c>.
    /// </summary>
    internal string Redact(string? s)
    {
        if (string.IsNullOrEmpty(s)) return s ?? string.Empty;
        var redacted = s;
        if (!string.IsNullOrEmpty(_token))
            redacted = redacted.Replace(_token, "***REDACTED***", StringComparison.Ordinal);
        redacted = TokenRedactor.Redact(redacted);
        return redacted;
    }

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    // ---- plumbing types ----

    private sealed class CopilotHeadersHandler : DelegatingHandler
    {
        private readonly string _integrationId;
        public CopilotHeadersHandler(string integrationId, HttpMessageHandler inner) : base(inner)
        {
            _integrationId = integrationId;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!request.Headers.Contains("Copilot-Integration-Id"))
                request.Headers.Add("Copilot-Integration-Id", _integrationId);
            return base.SendAsync(request, cancellationToken);
        }
    }
}
