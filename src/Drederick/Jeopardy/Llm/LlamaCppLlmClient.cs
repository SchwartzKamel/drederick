using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Microsoft.Extensions.AI;

namespace Drederick.Jeopardy.Llm;

/// <summary>Static description of a locally loaded llama.cpp model.</summary>
/// <remarks>
/// <para>
/// <see cref="SupportsTools"/> must be set explicitly by the operator. Many
/// local open-weights models (Qwen-Coder, DeepSeek-Coder, Mistral-Large, Llama
/// 3.x Instruct with the right chat template) support OpenAI-compatible
/// function calling when <c>llama-server</c> is started with
/// <c>--jinja</c>, but most others silently ignore the <c>tools</c> array and
/// emit free-form text. To avoid confusing the model, the client drops the
/// <c>tools</c> array entirely when <c>SupportsTools</c> is <c>false</c>.
/// </para>
/// </remarks>
public sealed record LlamaCppModelConfig(string Id, bool SupportsTools, long? ContextWindow);

/// <summary>
/// <see cref="ICopilotLlmClient"/> implementation backed by a local
/// <c>llama-server</c> process (llama.cpp's OpenAI-wire-compatible HTTP server).
///
/// <para>This is the <b>escape hatch provider</b>: use it for airgapped CTFs,
/// offline dev boxes, or when you specifically want to drive an open-weights
/// model (Qwen-Coder, DeepSeek-Coder, Llama 3.x, Mistral, etc.). For day-to-day
/// operation on a networked workstation the Microsoft-stack providers (Azure
/// OpenAI, GitHub Copilot) are the preferred path.</para>
///
/// <para>Target wire format: <c>POST {baseUrl}/v1/chat/completions</c> and
/// <c>GET {baseUrl}/v1/models</c>. llama.cpp accepts the full OpenAI schema
/// including the <c>model</c> routing field, so we keep it unlike the Azure
/// OpenAI deployment-routed variant.</para>
///
/// <para>Tool-calling: per <see cref="LlamaCppModelConfig.SupportsTools"/>. When
/// the configured (or discovered) entry reports <c>false</c> the <c>tools</c>
/// array is dropped from the request body entirely. Models discovered via
/// <c>/v1/models</c> default to <c>SupportsTools=false</c> for safety.</para>
///
/// <para>Audit: every chat emits <c>llamacpp.chat.start</c> and
/// <c>llamacpp.chat.finish</c>. Prompts and tool arguments are recorded as
/// SHA-256 digests only — plaintext prompts never reach the audit log.</para>
///
/// <para>Environment (<see cref="TryCreateFromEnvironment"/>):</para>
/// <list type="bullet">
///   <item><c>LLAMACPP_URL</c> — base URL, default <c>http://127.0.0.1:8080</c>.</item>
///   <item><c>LLAMACPP_BEARER_TOKEN</c> — optional bearer token for reverse-proxy-protected servers.</item>
///   <item><c>LLAMACPP_MODELS</c> — optional comma-separated modelIds; if absent, models are discovered via <c>/v1/models</c> at first use.</item>
/// </list>
///
/// <para>Thread-safe. Parallel <see cref="ChatAsync"/> calls are safe; no
/// shared mutable state.</para>
/// </summary>
public sealed class LlamaCppLlmClient : ICopilotLlmClient, IDisposable
{
    public static readonly Uri DefaultBaseUrl = new("http://127.0.0.1:8080");

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly Uri _baseUrl;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly string? _bearerToken;
    private readonly IReadOnlyDictionary<string, LlamaCppModelConfig>? _configuredModels;

    public LlamaCppLlmClient(
        Uri baseUrl,
        AuditLog audit,
        IReadOnlyList<LlamaCppModelConfig>? models = null,
        string? bearerToken = null,
        HttpClient? http = null)
    {
        _baseUrl = baseUrl ?? throw new ArgumentNullException(nameof(baseUrl));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _bearerToken = string.IsNullOrWhiteSpace(bearerToken) ? null : bearerToken;

        if (models is { Count: > 0 })
        {
            var dict = new Dictionary<string, LlamaCppModelConfig>(StringComparer.Ordinal);
            foreach (var m in models) dict[m.Id] = m;
            _configuredModels = dict;
        }

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
    /// Construct a client from environment. Returns <c>null</c> only if
    /// <c>LLAMACPP_URL</c> is set but unparseable; otherwise always returns an
    /// instance (llama.cpp is the "always available, no setup needed" provider).
    /// A client whose <c>llama-server</c> isn't running will fail at first
    /// <see cref="ChatAsync"/> with a descriptive <see cref="CopilotLlmException"/>.
    /// </summary>
    public static LlamaCppLlmClient? TryCreateFromEnvironment(AuditLog audit)
    {
        var urlEnv = Environment.GetEnvironmentVariable("LLAMACPP_URL");
        Uri baseUrl;
        if (string.IsNullOrWhiteSpace(urlEnv))
        {
            baseUrl = DefaultBaseUrl;
        }
        else if (!Uri.TryCreate(urlEnv, UriKind.Absolute, out var parsed))
        {
            return null;
        }
        else
        {
            baseUrl = parsed;
        }

        var bearer = Environment.GetEnvironmentVariable("LLAMACPP_BEARER_TOKEN");
        var modelsEnv = Environment.GetEnvironmentVariable("LLAMACPP_MODELS");
        IReadOnlyList<LlamaCppModelConfig>? models = null;
        if (!string.IsNullOrWhiteSpace(modelsEnv))
        {
            var list = new List<LlamaCppModelConfig>();
            foreach (var piece in modelsEnv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                list.Add(new LlamaCppModelConfig(piece, SupportsTools: false, ContextWindow: null));
            }
            if (list.Count > 0) models = list;
        }

        return new LlamaCppLlmClient(baseUrl, audit, models, bearer);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<CopilotModel>> ListModelsAsync(CancellationToken ct)
    {
        if (_configuredModels is { Count: > 0 })
        {
            var list = new List<CopilotModel>(_configuredModels.Count);
            foreach (var m in _configuredModels.Values)
                list.Add(new CopilotModel(m.Id, "llamacpp-local", m.ContextWindow, m.SupportsTools));
            return list;
        }

        var url = new Uri(Combine(_baseUrl, "v1/models"));
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        ApplyAuthHeaders(req);

        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex) when (IsConnectionRefused(ex))
        {
            // Connection refused on /v1/models is benign — llama-server may not
            // be running yet, or the operator may be warming it up. Return
            // empty; a later ChatAsync will surface the actionable error.
            return Array.Empty<CopilotModel>();
        }
        catch (SocketException)
        {
            return Array.Empty<CopilotModel>();
        }

        using var _ = resp;
        if (resp.StatusCode == HttpStatusCode.NotFound)
        {
            // Some slim builds don't expose /v1/models. Treat as "unknown".
            return Array.Empty<CopilotModel>();
        }

        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            // Don't throw on model-listing failure — the operator can still
            // chat by modelId. Return empty.
            return Array.Empty<CopilotModel>();
        }

        return ParseModels(body);
    }

    internal static IReadOnlyList<CopilotModel> ParseModels(string json)
    {
        var list = new List<CopilotModel>();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var arr = root.TryGetProperty("data", out var dataEl) ? dataEl : root;
        if (arr.ValueKind != JsonValueKind.Array) return list;
        foreach (var m in arr.EnumerateArray())
        {
            if (!m.TryGetProperty("id", out var idEl)) continue;
            var id = idEl.GetString();
            if (string.IsNullOrWhiteSpace(id)) continue;
            list.Add(new CopilotModel(id!, "llamacpp-local", ContextWindow: null, SupportsTools: false));
        }
        return list;
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

        // Tool-calling gating: unknown model => conservative no-tools.
        bool supportsTools = false;
        if (_configuredModels is not null && _configuredModels.TryGetValue(modelId, out var cfg))
            supportsTools = cfg.SupportsTools;

        var effectiveTools = supportsTools ? tools : null;

        var promptDigest = CopilotLlmClient.HashPrompt(messages);
        var toolNames = effectiveTools is null ? Array.Empty<string>() : effectiveTools.Select(t => t.Name).ToArray();

        _audit.Record("llamacpp.chat.start", new Dictionary<string, object?>
        {
            ["model"] = modelId,
            ["prompt_sha256"] = promptDigest,
            ["message_count"] = messages.Count,
            ["tool_count"] = toolNames.Length,
            ["tool_names"] = toolNames,
            ["base_url"] = _baseUrl.ToString(),
            ["tools_stripped"] = tools is { Count: > 0 } && !supportsTools,
        });

        var body = CopilotLlmClient.BuildChatRequestBody(modelId, messages, effectiveTools);
        var url = new Uri(Combine(_baseUrl, "v1/chat/completions"));

        var sw = Stopwatch.StartNew();
        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        ApplyAuthHeaders(req);

        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (HttpRequestException ex) when (IsConnectionRefused(ex))
        {
            throw new CopilotLlmException(null, modelId,
                $"llama-server unreachable at {_baseUrl}; is `llama-server` running?", ex);
        }
        catch (SocketException ex)
        {
            throw new CopilotLlmException(null, modelId,
                $"llama-server unreachable at {_baseUrl}; is `llama-server` running?", ex);
        }
        catch (Exception ex)
        {
            throw new CopilotLlmException(null, modelId, ex.Message, ex);
        }

        using var _d = resp;
        var respBody = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            var snippet = respBody is null ? string.Empty : respBody[..Math.Min(512, respBody.Length)];
            throw new CopilotLlmException(resp.StatusCode, modelId, $"{(int)resp.StatusCode}: {snippet}");
        }

        sw.Stop();
        var parsed = CopilotLlmClient.ParseChatResponse(modelId, respBody, sw.Elapsed);

        var toolArgDigests = parsed.ToolCalls.Select(tc => CopilotLlmClient.Sha256Hex(tc.ArgumentsJson)).ToArray();
        _audit.Record("llamacpp.chat.finish", new Dictionary<string, object?>
        {
            ["model"] = modelId,
            ["prompt_sha256"] = promptDigest,
            ["prompt_tokens"] = parsed.PromptTokens,
            ["completion_tokens"] = parsed.CompletionTokens,
            ["elapsed_ms"] = (long)parsed.Elapsed.TotalMilliseconds,
            ["finish_reason"] = parsed.FinishReason,
            ["tool_calls_count"] = parsed.ToolCalls.Count,
            ["tool_argument_digests"] = toolArgDigests,
            ["base_url"] = _baseUrl.ToString(),
        });

        return parsed;
    }

    // ---- helpers ----

    private void ApplyAuthHeaders(HttpRequestMessage req)
    {
        if (_bearerToken is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _bearerToken);
        if (!req.Headers.Contains("Accept"))
            req.Headers.Add("Accept", "application/json");
    }

    private static string Combine(Uri baseUri, string path)
    {
        var b = baseUri.ToString();
        if (!b.EndsWith('/')) b += "/";
        return b + path.TrimStart('/');
    }

    private static bool IsConnectionRefused(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException!)
        {
            if (e is SocketException se &&
                (se.SocketErrorCode == SocketError.ConnectionRefused
                 || se.SocketErrorCode == SocketError.HostUnreachable
                 || se.SocketErrorCode == SocketError.NetworkUnreachable
                 || se.SocketErrorCode == SocketError.TimedOut))
            {
                return true;
            }
            if (e.InnerException is null) break;
        }
        return false;
    }

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }
}
