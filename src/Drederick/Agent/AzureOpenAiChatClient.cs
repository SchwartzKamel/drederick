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
/// <see cref="IChatClient"/> implementation backed by the Azure OpenAI
/// chat-completions endpoint. Reuses the same auth / deployment-mapping /
/// retry logic as <see cref="AzureOpenAiLlmClient"/> but serializes the
/// full <see cref="ChatMessage"/> graph — including structured
/// <see cref="FunctionCallContent"/> and <see cref="FunctionResultContent"/>
/// — so the Microsoft Agent Framework's automatic tool loop works correctly.
///
/// <para>Thread-safe after construction.</para>
/// </summary>
public sealed class AzureOpenAiChatClient : IChatClient
{
    public const string DefaultApiVersion = "2024-10-21";
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly Uri _endpoint;
    private readonly AzureOpenAiAuth _auth;
    private readonly AuditLog _audit;
    private readonly IReadOnlyDictionary<string, string> _deploymentMap;
    private readonly string _apiVersion;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly string _modelId;

    /// <summary>The logical model ID this client will use.</summary>
    public string ModelId => _modelId;

    public AzureOpenAiChatClient(
        string endpoint,
        AzureOpenAiAuth auth,
        AuditLog audit,
        string modelId,
        IReadOnlyDictionary<string, string>? deploymentMap = null,
        string apiVersion = DefaultApiVersion,
        HttpClient? http = null)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) throw new ArgumentException("endpoint required", nameof(endpoint));
        if (!Uri.TryCreate(endpoint.TrimEnd('/'), UriKind.Absolute, out var parsed))
            throw new ArgumentException("endpoint must be an absolute URI", nameof(endpoint));
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);
        _endpoint = parsed;
        _auth = auth ?? throw new ArgumentNullException(nameof(auth));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _modelId = modelId;
        _deploymentMap = deploymentMap ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        _apiVersion = string.IsNullOrWhiteSpace(apiVersion) ? DefaultApiVersion : apiVersion;

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
    /// Construct from environment variables. Returns <c>null</c> if required
    /// env is missing.
    ///
    /// <para>Env: <c>AZURE_OPENAI_ENDPOINT</c>, <c>AZURE_OPENAI_API_KEY</c>
    /// or <c>AZURE_OPENAI_BEARER_TOKEN</c>, optional
    /// <c>AZURE_OPENAI_API_VERSION</c> and <c>AZURE_OPENAI_DEPLOYMENT_MAP</c>.</para>
    /// </summary>
    public static AzureOpenAiChatClient? TryCreateFromEnvironment(
        AuditLog audit,
        IReadOnlyDictionary<string, string>? deploymentMap = null,
        string? modelId = null)
    {
        var endpoint = Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT");
        if (string.IsNullOrWhiteSpace(endpoint)) return null;

        var apiKey = Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY");
        var bearer = Environment.GetEnvironmentVariable("AZURE_OPENAI_BEARER_TOKEN");

        AzureOpenAiAuth auth;
        if (!string.IsNullOrWhiteSpace(apiKey))
            auth = new AzureOpenAiAuth.ApiKey(apiKey!);
        else if (!string.IsNullOrWhiteSpace(bearer))
            auth = new AzureOpenAiAuth.Bearer(bearer!);
        else
            return null;

        var apiVersion = Environment.GetEnvironmentVariable("AZURE_OPENAI_API_VERSION");
        if (string.IsNullOrWhiteSpace(apiVersion)) apiVersion = DefaultApiVersion;

        // Merge env-based deployment map with any passed from CLI options
        var envMap = AzureOpenAiLlmClient.ParseDeploymentMap(
            Environment.GetEnvironmentVariable("AZURE_OPENAI_DEPLOYMENT_MAP"));
        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in envMap) merged[kv.Key] = kv.Value;
        if (deploymentMap is not null)
            foreach (var kv in deploymentMap) merged[kv.Key] = kv.Value;

        // Model: explicit > DREDERICK_MODEL > first deployment key > gpt-4o
        if (string.IsNullOrWhiteSpace(modelId))
        {
            modelId = merged.Keys.FirstOrDefault() ?? "gpt-4o";
        }

        return new AzureOpenAiChatClient(endpoint!, auth, audit, modelId!, merged, apiVersion!);
    }

    internal string ResolveDeployment(string modelId)
        => _deploymentMap.TryGetValue(modelId, out var d) ? d : modelId;

    // ---- IChatClient implementation ----

    public async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageList = messages.ToList();
        var toolsFromOptions = options?.Tools;

        var deployment = ResolveDeployment(_modelId);
        var promptDigest = HashMessages(messageList);
        var toolNames = toolsFromOptions is null
            ? Array.Empty<string>()
            : toolsFromOptions.Select(t => t.Name).ToArray();

        _audit.Record("azure_openai.agent.chat.start", new Dictionary<string, object?>
        {
            ["logical_model"] = _modelId,
            ["deployment"] = deployment,
            ["endpoint"] = _endpoint.ToString(),
            ["api_version"] = _apiVersion,
            ["prompt_sha256"] = promptDigest,
            ["message_count"] = messageList.Count,
            ["tool_count"] = toolNames.Length,
            ["tool_names"] = toolNames,
            ["auth_mode"] = _auth is AzureOpenAiAuth.ApiKey ? "api_key" : "bearer",
        });

        // Azure takes deployment from URL; omit "model" from body.
        var body = BuildRequestBody(messageList, toolsFromOptions, includeModel: false);
        var url = BuildChatUrl(deployment);

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
                _audit.Record("azure_openai.agent.chat.retry", new Dictionary<string, object?>
                {
                    ["logical_model"] = _modelId,
                    ["deployment"] = deployment,
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
                var msg = (int)statusCode == 401
                    ? $"Azure OpenAI auth failed (401). Check AZURE_OPENAI_API_KEY or bearer token: {Redact(snippet)}"
                    : Redact($"{(int)statusCode}: {snippet}");
                throw new CopilotLlmException(statusCode, _modelId, msg);
            }

            _audit.Record("azure_openai.agent.chat.retry", new Dictionary<string, object?>
            {
                ["logical_model"] = _modelId,
                ["deployment"] = deployment,
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

        _audit.Record("azure_openai.agent.chat.finish", new Dictionary<string, object?>
        {
            ["logical_model"] = _modelId,
            ["deployment"] = deployment,
            ["endpoint"] = _endpoint.ToString(),
            ["api_version"] = _apiVersion,
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
        throw new NotSupportedException("Streaming is not supported by AzureOpenAiChatClient.");
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
        IList<AITool>? tools,
        bool includeModel = true)
    {
        var msgArr = new JsonArray();
        foreach (var msg in messages)
        {
            msgArr.Add(SerializeMessage(msg));
        }

        var obj = new JsonObject
        {
            ["messages"] = msgArr,
        };
        if (includeModel) obj["model"] = _modelId;

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

        var functionCalls = msg.Contents.OfType<FunctionCallContent>().ToList();
        var functionResults = msg.Contents.OfType<FunctionResultContent>().ToList();

        if (functionResults.Count > 0)
        {
            var result = functionResults[0];
            obj["role"] = "tool";
            obj["tool_call_id"] = result.CallId;
            obj["content"] = result.Result?.ToString() ?? "";
            return obj;
        }

        if (functionCalls.Count > 0)
        {
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

        return new ChatResponse(responseMessage)
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
    }

    // ---- helpers ----

    internal Uri BuildChatUrl(string deployment)
    {
        var b = _endpoint.ToString().TrimEnd('/');
        var path = $"{b}/openai/deployments/{Uri.EscapeDataString(deployment)}/chat/completions?api-version={Uri.EscapeDataString(_apiVersion)}";
        return new Uri(path);
    }

    private void ApplyAuthHeaders(HttpRequestMessage req)
    {
        switch (_auth)
        {
            case AzureOpenAiAuth.ApiKey k:
                if (!req.Headers.Contains("api-key")) req.Headers.Add("api-key", k.Value);
                break;
            case AzureOpenAiAuth.Bearer b:
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", b.Token);
                break;
        }
        if (!req.Headers.Contains("Accept"))
            req.Headers.Add("Accept", "application/json");
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
        var secret = _auth switch
        {
            AzureOpenAiAuth.ApiKey k => k.Value,
            AzureOpenAiAuth.Bearer b => b.Token,
            _ => null,
        };
        if (!string.IsNullOrEmpty(secret))
            redacted = redacted.Replace(secret, "***REDACTED***", StringComparison.Ordinal);
        redacted = TokenRedactor.Redact(redacted);
        return redacted;
    }
}
