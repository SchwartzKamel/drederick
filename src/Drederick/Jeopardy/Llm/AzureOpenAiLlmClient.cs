using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Microsoft.Extensions.AI;

namespace Drederick.Jeopardy.Llm;

/// <summary>
/// Auth mode for <see cref="AzureOpenAiLlmClient"/>. Either an Azure OpenAI
/// <c>api-key</c> header value, or a pre-fetched Entra ID (Azure AD) bearer
/// token for the <c>https://cognitiveservices.azure.com/.default</c> scope.
/// Operators wanting Entra ID are expected to acquire the token out-of-band
/// (e.g. <c>az account get-access-token --resource …</c>) so this assembly
/// doesn't take a hard dependency on <c>Azure.Identity</c>.
/// </summary>
public abstract record AzureOpenAiAuth
{
    private AzureOpenAiAuth() { }

    public sealed record ApiKey(string Value) : AzureOpenAiAuth
    {
        public string Value { get; } = string.IsNullOrWhiteSpace(Value)
            ? throw new ArgumentException("api key required", nameof(Value))
            : Value;
    }

    public sealed record Bearer(string Token) : AzureOpenAiAuth
    {
        public string Token { get; } = string.IsNullOrWhiteSpace(Token)
            ? throw new ArgumentException("bearer token required", nameof(Token))
            : Token;
    }
}

/// <summary>
/// Azure OpenAI chat-completions client. URL shape:
/// <c>POST {endpoint}/openai/deployments/{deployment}/chat/completions?api-version={apiVersion}</c>.
///
/// <para>Supports both <c>api-key</c> and Entra ID bearer auth. The
/// <c>modelId</c> passed to <see cref="ChatAsync"/> is a logical id
/// (e.g. <c>gpt-5.4</c>); it is mapped to an Azure deployment via the
/// optional constructor dictionary. Missing entries fall through to the
/// logical id as the deployment name — the common case when operators
/// name their deployment identically to the model.</para>
///
/// <para>Thread-safe. Shares the same no-plaintext audit contract as
/// <see cref="CopilotLlmClient"/>: prompts and tool arguments are recorded
/// as SHA-256 digests only.</para>
/// </summary>
public sealed class AzureOpenAiLlmClient : ICopilotLlmClient, IDisposable
{
    public const string DefaultApiVersion = "2024-10-21";

    private readonly Uri _endpoint;
    private readonly AzureOpenAiAuth _auth;
    private readonly AuditLog _audit;
    private readonly IReadOnlyDictionary<string, string> _deploymentMap;
    private readonly string _apiVersion;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    public AzureOpenAiLlmClient(
        string endpoint,
        AzureOpenAiAuth auth,
        AuditLog audit,
        IReadOnlyDictionary<string, string>? deploymentMap = null,
        string apiVersion = DefaultApiVersion,
        HttpClient? http = null)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) throw new ArgumentException("endpoint required", nameof(endpoint));
        if (!Uri.TryCreate(endpoint.TrimEnd('/'), UriKind.Absolute, out var parsed))
            throw new ArgumentException("endpoint must be an absolute URI", nameof(endpoint));
        _endpoint = parsed;
        _auth = auth ?? throw new ArgumentNullException(nameof(auth));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
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
    /// Construct a client from environment variables. Returns <c>null</c> if
    /// neither <c>AZURE_OPENAI_API_KEY</c> nor <c>AZURE_OPENAI_BEARER_TOKEN</c>
    /// is set, or if <c>AZURE_OPENAI_ENDPOINT</c> is missing.
    ///
    /// <para>Env:</para>
    /// <list type="bullet">
    ///   <item><c>AZURE_OPENAI_ENDPOINT</c> — e.g. <c>https://my-resource.openai.azure.com</c>.</item>
    ///   <item><c>AZURE_OPENAI_API_KEY</c> — api-key auth (preferred when set).</item>
    ///   <item><c>AZURE_OPENAI_BEARER_TOKEN</c> — pre-fetched Entra ID access token.</item>
    ///   <item><c>AZURE_OPENAI_API_VERSION</c> — optional override, default <c>2024-10-21</c>.</item>
    ///   <item><c>AZURE_OPENAI_DEPLOYMENT_MAP</c> — optional <c>logical=deployment,logical2=deployment2</c>.</item>
    /// </list>
    /// </summary>
    public static AzureOpenAiLlmClient? TryCreateFromEnvironment(AuditLog audit)
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

        var deploymentMap = ParseDeploymentMap(Environment.GetEnvironmentVariable("AZURE_OPENAI_DEPLOYMENT_MAP"));

        return new AzureOpenAiLlmClient(endpoint!, auth, audit, deploymentMap, apiVersion!);
    }

    internal static IReadOnlyDictionary<string, string> ParseDeploymentMap(string? raw)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw)) return map;
        foreach (var pair in raw!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0 || eq == pair.Length - 1) continue;
            var key = pair[..eq].Trim();
            var val = pair[(eq + 1)..].Trim();
            if (key.Length > 0 && val.Length > 0) map[key] = val;
        }
        return map;
    }

    internal string ResolveDeployment(string modelId)
        => _deploymentMap.TryGetValue(modelId, out var d) ? d : modelId;

    /// <inheritdoc />
    public Task<IReadOnlyList<CopilotModel>> ListModelsAsync(CancellationToken ct)
    {
        // Azure data-plane has no clean deployment-enumeration endpoint; the
        // management plane requires ARM auth. Surface the configured map.
        var list = new List<CopilotModel>(_deploymentMap.Count);
        foreach (var key in _deploymentMap.Keys)
        {
            list.Add(new CopilotModel(key, InferFamily(key), null, SupportsTools: true));
        }
        return Task.FromResult<IReadOnlyList<CopilotModel>>(list);
    }

    private static string InferFamily(string id)
    {
        if (id.StartsWith("gpt-", StringComparison.OrdinalIgnoreCase)) return "openai-gpt";
        if (id.StartsWith("o1", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("o3", StringComparison.OrdinalIgnoreCase)) return "openai-gpt";
        return "openai-gpt";
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

        var deployment = ResolveDeployment(modelId);
        var promptDigest = HashPrompt(messages);
        var toolNames = tools is null ? Array.Empty<string>() : tools.Select(t => t.Name).ToArray();

        _audit.Record("azure_openai.chat.start", new Dictionary<string, object?>
        {
            ["logical_model"] = modelId,
            ["deployment"] = deployment,
            ["endpoint"] = _endpoint.ToString(),
            ["api_version"] = _apiVersion,
            ["prompt_sha256"] = promptDigest,
            ["message_count"] = messages.Count,
            ["tool_count"] = toolNames.Length,
            ["tool_names"] = toolNames,
            ["auth_mode"] = _auth is AzureOpenAiAuth.ApiKey ? "api_key" : "bearer",
        });

        // Azure takes the deployment from the URL; omit "model" from the body
        // to avoid confusing older API versions that error on unexpected fields.
        var body = CopilotLlmClient.BuildChatRequestBody(modelId, messages, tools, includeModel: false);
        var url = BuildChatUrl(deployment);

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
                _audit.Record("azure_openai.chat.retry", new Dictionary<string, object?>
                {
                    ["logical_model"] = modelId,
                    ["deployment"] = deployment,
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
                var msg = (int)statusCode == 401
                    ? $"Azure OpenAI auth failed (401). Check AZURE_OPENAI_API_KEY or bearer token, and that the endpoint/deployment match the tenant: {Redact(snippet)}"
                    : Redact($"{(int)statusCode}: {snippet}");
                throw new CopilotLlmException(statusCode, modelId, msg);
            }

            _audit.Record("azure_openai.chat.retry", new Dictionary<string, object?>
            {
                ["logical_model"] = modelId,
                ["deployment"] = deployment,
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
            parsed = CopilotLlmClient.ParseChatResponse(modelId, respBody, sw.Elapsed);
        }
        finally
        {
            resp.Dispose();
        }

        var toolArgDigests = parsed.ToolCalls.Select(tc => Sha256Hex(tc.ArgumentsJson)).ToArray();
        _audit.Record("azure_openai.chat.finish", new Dictionary<string, object?>
        {
            ["logical_model"] = modelId,
            ["deployment"] = deployment,
            ["endpoint"] = _endpoint.ToString(),
            ["api_version"] = _apiVersion,
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

    /// <summary>Redact the configured secret plus generic token patterns.</summary>
    internal string Redact(string? s)
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

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }
}
