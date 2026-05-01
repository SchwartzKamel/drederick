using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Microsoft.Extensions.AI;

namespace Drederick.Agent;

/// <summary>
/// <see cref="IChatClient"/> implementation backed by the GitHub Copilot
/// chat-completions endpoint. Reuses the same auth / endpoint / token
/// resolution logic as <see cref="CopilotLlmClient"/> but serializes
/// the full <see cref="ChatMessage"/> graph — including structured
/// <see cref="FunctionCallContent"/> and <see cref="FunctionResultContent"/>
/// — so the Microsoft Agent Framework's automatic tool loop works correctly.
///
/// <para>Thread-safe after construction.</para>
/// </summary>
public sealed class CopilotChatClient : IChatClient
{
    private static readonly Uri DefaultCopilotEndpoint = CopilotLlmClient.DefaultCopilotEndpoint;
    private static readonly Uri DefaultGithubModelsEndpoint = CopilotLlmClient.DefaultGithubModelsEndpoint;
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly string _token;
    private readonly string _integrationId;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly Uri _endpoint;
    private readonly bool _ownsHttp;
    private readonly string _modelId;

    // Lazy model list cache (same pattern as CopilotLlmClient).
    private readonly ConcurrentDictionary<string, (DateTimeOffset CachedAt, IReadOnlyList<CopilotModel> Models)> _modelCache
        = new();
    private static readonly TimeSpan ModelCacheTtl = TimeSpan.FromHours(1);

    /// <summary>The model ID this client will use for chat completions.</summary>
    public string ModelId => _modelId;

    public CopilotChatClient(
        string token,
        string integrationId,
        AuditLog audit,
        string modelId,
        HttpClient? http = null,
        Uri? endpoint = null)
    {
        if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException("token required", nameof(token));
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);
        _token = token;
        _integrationId = string.IsNullOrWhiteSpace(integrationId) ? "drederick-cli" : integrationId;
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _modelId = modelId;
        _endpoint = endpoint ?? DefaultCopilotEndpoint;

        if (http is null)
        {
            _http = new HttpClient();
            _ownsHttp = true;
        }
        else
        {
            _http = http;
            _ownsHttp = false;
        }
    }

    /// <summary>
    /// Construct from environment variables or the authenticated GitHub CLI
    /// session. Returns <c>null</c> if no usable token is found. Token
    /// precedence: <c>COPILOT_TOKEN</c> &gt; <c>GH_TOKEN</c> &gt;
    /// <c>GITHUB_TOKEN</c> &gt; <c>gh auth token</c>. If no <c>gh</c> session is
    /// present and an interactive terminal is available, starts
    /// <c>gh auth login --web --skip-ssh-key</c>.
    ///
    /// <para>If <paramref name="modelId"/> is null, auto-selects the first
    /// tool-capable model from the endpoint's <c>/v1/models</c> listing.</para>
    /// </summary>
    public static CopilotChatClient? TryCreateFromEnvironment(
        AuditLog audit,
        string? modelId = null,
        bool allowGitHubCliAuth = true)
    {
        var (token, source) = CopilotAuthTokenResolver.ResolveToken(allowGitHubCliAuth, audit);
        if (string.IsNullOrWhiteSpace(token)) return null;

        var integrationId = Environment.GetEnvironmentVariable("COPILOT_INTEGRATION_ID") ?? "drederick-cli";

        Uri endpoint;
        var endpointEnv = Environment.GetEnvironmentVariable("COPILOT_ENDPOINT");
        if (!string.IsNullOrWhiteSpace(endpointEnv) && Uri.TryCreate(endpointEnv, UriKind.Absolute, out var parsed))
        {
            endpoint = parsed;
        }
        else if (source == CopilotTokenSource.GithubToken && LooksLikeGithubPat(token!))
        {
            endpoint = DefaultGithubModelsEndpoint;
        }
        else
        {
            endpoint = DefaultCopilotEndpoint;
        }

        // If no model specified, try to auto-detect a tool-capable model.
        if (string.IsNullOrWhiteSpace(modelId))
        {
            modelId = AutoSelectModel(token!, integrationId, endpoint);
            if (string.IsNullOrWhiteSpace(modelId))
            {
                // Fall back to a reasonable default
                modelId = "gpt-4o-mini";
            }
        }

        return new CopilotChatClient(token!, integrationId, audit, modelId, http: null, endpoint: endpoint);
    }

    // ---- IChatClient implementation ----

    public async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageList = messages.ToList();
        var toolsFromOptions = options?.Tools;

        var promptDigest = HashMessages(messageList);
        var toolNames = toolsFromOptions is null
            ? Array.Empty<string>()
            : toolsFromOptions.Select(t => t.Name).ToArray();

        _audit.Record("copilot.agent.chat.start", new Dictionary<string, object?>
        {
            ["model"] = _modelId,
            ["prompt_sha256"] = promptDigest,
            ["message_count"] = messageList.Count,
            ["tool_count"] = toolNames.Length,
            ["tool_names"] = toolNames,
            ["endpoint"] = _endpoint.ToString(),
        });

        var body = BuildRequestBody(messageList, toolsFromOptions);
        var url = new Uri(Combine(_endpoint, "chat/completions"));

        var sw = Stopwatch.StartNew();
        HttpResponseMessage? resp = null;
        string? respBody = null;
        HttpStatusCode? lastStatus = null;

        const int maxAttempts = 4;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            ApplyAuthHeaders(req);

            try
            {
                resp = await _http.SendAsync(req, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _audit.Record("copilot.agent.chat.retry", new Dictionary<string, object?>
                {
                    ["model"] = _modelId,
                    ["attempt"] = attempt,
                    ["error"] = Redact(ex.Message),
                });
                if (attempt == maxAttempts)
                    throw new CopilotLlmException(null, _modelId, Redact(ex.Message), ex);
                await BackoffAsync(attempt, cancellationToken).ConfigureAwait(false);
                continue;
            }

            lastStatus = resp.StatusCode;
            respBody = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (resp.IsSuccessStatusCode) break;

            bool retryable = (int)resp.StatusCode == 429 || (int)resp.StatusCode >= 500;
            if (!retryable || attempt == maxAttempts)
            {
                var statusCode = resp.StatusCode;
                var snippet = respBody is null ? string.Empty : respBody[..Math.Min(512, respBody.Length)];
                resp.Dispose();
                throw new CopilotLlmException(statusCode, _modelId, Redact($"{(int)statusCode}: {snippet}"));
            }

            _audit.Record("copilot.agent.chat.retry", new Dictionary<string, object?>
            {
                ["model"] = _modelId,
                ["attempt"] = attempt,
                ["status"] = (int)resp.StatusCode,
            });
            resp.Dispose();
            resp = null;
            await BackoffAsync(attempt, cancellationToken).ConfigureAwait(false);
        }

        sw.Stop();
        if (resp is null || respBody is null)
            throw new CopilotLlmException(lastStatus, _modelId, "unreachable: response null after retries");

        ChatResponse parsed;
        try
        {
            parsed = ParseResponse(respBody, sw.Elapsed);
        }
        finally
        {
            resp.Dispose();
        }

        _audit.Record("copilot.agent.chat.finish", new Dictionary<string, object?>
        {
            ["model"] = _modelId,
            ["prompt_sha256"] = promptDigest,
            ["prompt_tokens"] = parsed.Usage?.InputTokenCount,
            ["completion_tokens"] = parsed.Usage?.OutputTokenCount,
            ["elapsed_ms"] = (long)sw.Elapsed.TotalMilliseconds,
            ["finish_reason"] = parsed.FinishReason?.ToString(),
        });

        return parsed;
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        // The Agent Framework doesn't require streaming; throw not-supported.
        throw new NotSupportedException("Streaming is not supported by CopilotChatClient.");
    }

    public object? GetService(Type serviceType, object? serviceKey = null)
    {
        if (serviceKey is null && serviceType == typeof(IChatClient)) return this;
        return null;
    }

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    // ---- request serialization ----

    internal string BuildRequestBody(
        IReadOnlyList<ChatMessage> messages,
        IList<AITool>? tools)
    {
        var msgArr = new JsonArray();
        foreach (var msg in messages)
        {
            msgArr.Add(SerializeMessage(msg));
        }

        var obj = new JsonObject
        {
            ["model"] = _modelId,
            ["messages"] = msgArr,
        };

        if (tools is { Count: > 0 })
        {
            obj["tools"] = SerializeTools(tools);
        }

        return obj.ToJsonString(Json);
    }

    private static JsonObject SerializeMessage(ChatMessage msg)
    {
        var role = msg.Role.Value;
        var obj = new JsonObject { ["role"] = role };

        // Check for function call content (assistant messages with tool calls)
        var functionCalls = msg.Contents.OfType<FunctionCallContent>().ToList();
        var functionResults = msg.Contents.OfType<FunctionResultContent>().ToList();

        if (functionResults.Count > 0)
        {
            // Tool result message
            var result = functionResults[0];
            obj["role"] = "tool";
            obj["tool_call_id"] = result.CallId;
            obj["content"] = result.Result?.ToString() ?? "";
            return obj;
        }

        if (functionCalls.Count > 0)
        {
            // Assistant message with tool calls
            var textParts = msg.Contents.OfType<TextContent>().ToList();
            if (textParts.Count > 0)
                obj["content"] = string.Join("", textParts.Select(t => t.Text));
            else
                obj["content"] = JsonValue.Create((string?)null);

            var tcArr = new JsonArray();
            foreach (var fc in functionCalls)
            {
                var args = fc.Arguments is not null
                    ? JsonSerializer.Serialize(fc.Arguments, Json)
                    : "{}";
                tcArr.Add(new JsonObject
                {
                    ["id"] = fc.CallId ?? Guid.NewGuid().ToString("N"),
                    ["type"] = "function",
                    ["function"] = new JsonObject
                    {
                        ["name"] = fc.Name,
                        ["arguments"] = args,
                    },
                });
            }
            obj["tool_calls"] = tcArr;
            return obj;
        }

        // Plain text message
        var text = msg.Text;
        if (!string.IsNullOrEmpty(text))
        {
            obj["content"] = text;
        }
        else
        {
            var textContents = msg.Contents.OfType<TextContent>().ToList();
            obj["content"] = textContents.Count > 0
                ? string.Join("", textContents.Select(t => t.Text))
                : "";
        }

        return obj;
    }

    private static JsonArray SerializeTools(IList<AITool> tools)
    {
        var arr = new JsonArray();
        foreach (var t in tools)
        {
            var function = new JsonObject { ["name"] = t.Name };
            if (!string.IsNullOrWhiteSpace(t.Description))
                function["description"] = t.Description;

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

            arr.Add(new JsonObject { ["type"] = "function", ["function"] = function });
        }
        return arr;
    }

    // ---- response parsing ----

    internal ChatResponse ParseResponse(string json, TimeSpan elapsed)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        string modelId = _modelId;
        if (root.TryGetProperty("model", out var mEl) && mEl.ValueKind == JsonValueKind.String)
            modelId = mEl.GetString() ?? _modelId;

        var responseMessage = new ChatMessage(ChatRole.Assistant, (string?)null);
        ChatFinishReason? finishReason = null;

        if (root.TryGetProperty("choices", out var choices) && choices.ValueKind == JsonValueKind.Array
            && choices.GetArrayLength() > 0)
        {
            var c0 = choices[0];
            if (c0.TryGetProperty("finish_reason", out var fr) && fr.ValueKind == JsonValueKind.String)
            {
                var frStr = fr.GetString();
                finishReason = frStr switch
                {
                    "stop" => ChatFinishReason.Stop,
                    "tool_calls" => ChatFinishReason.ToolCalls,
                    "length" => ChatFinishReason.Length,
                    "content_filter" => ChatFinishReason.ContentFilter,
                    _ => null,
                };
            }

            if (c0.TryGetProperty("message", out var msg))
            {
                if (msg.TryGetProperty("content", out var ce) && ce.ValueKind == JsonValueKind.String)
                {
                    var contentStr = ce.GetString();
                    if (!string.IsNullOrEmpty(contentStr))
                        responseMessage.Contents.Add(new TextContent(contentStr));
                }

                if (msg.TryGetProperty("tool_calls", out var tcs) && tcs.ValueKind == JsonValueKind.Array)
                {
                    foreach (var tc in tcs.EnumerateArray())
                    {
                        var callId = tc.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
                            ? idEl.GetString() ?? Guid.NewGuid().ToString("N")
                            : Guid.NewGuid().ToString("N");

                        string name = "";
                        string argsJson = "{}";
                        if (tc.TryGetProperty("function", out var fn))
                        {
                            if (fn.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String)
                                name = n.GetString() ?? "";
                            if (fn.TryGetProperty("arguments", out var a))
                                argsJson = a.ValueKind == JsonValueKind.String
                                    ? a.GetString() ?? "{}"
                                    : a.GetRawText();
                        }

                        IDictionary<string, object?>? args = null;
                        try
                        {
                            args = JsonSerializer.Deserialize<Dictionary<string, object?>>(argsJson, Json);
                        }
                        catch
                        {
                            args = new Dictionary<string, object?> { ["_raw"] = argsJson };
                        }

                        responseMessage.Contents.Add(new FunctionCallContent(callId, name, args));
                    }
                }
            }
        }

        int promptTokens = 0, completionTokens = 0;
        if (root.TryGetProperty("usage", out var u))
        {
            if (u.TryGetProperty("prompt_tokens", out var p) && p.ValueKind == JsonValueKind.Number)
                promptTokens = p.GetInt32();
            if (u.TryGetProperty("completion_tokens", out var cEl) && cEl.ValueKind == JsonValueKind.Number)
                completionTokens = cEl.GetInt32();
        }

        var response = new ChatResponse(responseMessage)
        {
            ModelId = modelId,
            FinishReason = finishReason,
            Usage = new UsageDetails
            {
                InputTokenCount = promptTokens,
                OutputTokenCount = completionTokens,
                TotalTokenCount = promptTokens + completionTokens,
            },
        };

        return response;
    }

    // ---- auth & helpers ----

    private void ApplyAuthHeaders(HttpRequestMessage req)
    {
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        if (!req.Headers.Contains("Copilot-Integration-Id"))
            req.Headers.Add("Copilot-Integration-Id", _integrationId);
        if (!req.Headers.Contains("Accept"))
            req.Headers.Add("Accept", "application/json");
    }

    private static bool LooksLikeGithubPat(string token)
        => token.StartsWith("ghp_", StringComparison.Ordinal)
        || token.StartsWith("github_pat_", StringComparison.Ordinal);

    /// <summary>
    /// Try to auto-select a tool-capable model by listing available models.
    /// Returns null if the endpoint is unreachable or no tool-capable model found.
    /// </summary>
    private static string? AutoSelectModel(string token, string integrationId, Uri endpoint)
    {
        try
        {
            using var http = new HttpClient();
            var url = new Uri(Combine(endpoint, "models"));
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Headers.Add("Copilot-Integration-Id", integrationId);
            req.Headers.Add("Accept", "application/json");

            var resp = http.Send(req);
            if (!resp.IsSuccessStatusCode) return null;

            var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                return null;

            // Prefer GPT-4o-mini as a good default for agent mode
            foreach (var m in data.EnumerateArray())
            {
                var id = m.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
                    ? idEl.GetString() : null;
                if (id is not null && id.Contains("gpt-4o-mini", StringComparison.OrdinalIgnoreCase))
                    return id;
            }

            // Fall back to first model
            foreach (var m in data.EnumerateArray())
            {
                var id = m.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
                    ? idEl.GetString() : null;
                if (id is not null) return id;
            }
        }
        catch
        {
            // Auto-selection is best-effort
        }
        return null;
    }

    private static string Combine(Uri baseUri, string path)
    {
        var b = baseUri.ToString();
        if (!b.EndsWith('/')) b += "/";
        return b + path.TrimStart('/');
    }

    private static async Task BackoffAsync(int attempt, CancellationToken ct)
    {
        var ms = (int)(200 * Math.Pow(2, attempt - 1));
        await Task.Delay(ms, ct).ConfigureAwait(false);
    }

    private static string HashMessages(IReadOnlyList<ChatMessage> messages)
    {
        var sb = new StringBuilder();
        foreach (var m in messages)
        {
            sb.Append(m.Role.Value).Append('\x1f').Append(m.Text ?? "").Append('\x1e');
        }
        return Sha256Hex(sb.ToString());
    }

    private static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private string Redact(string? s)
    {
        if (string.IsNullOrEmpty(s)) return s ?? string.Empty;
        var redacted = s;
        if (!string.IsNullOrEmpty(_token))
            redacted = redacted.Replace(_token, "***REDACTED***", StringComparison.Ordinal);
        redacted = TokenRedactor.Redact(redacted);
        return redacted;
    }
}
