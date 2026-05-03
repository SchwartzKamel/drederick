using Drederick.Audit;
using Drederick.Cli;

namespace Drederick.Jeopardy.Llm;

/// <summary>
/// Which LLM backend the Jeopardy solver swarm talks to. Mirrors the
/// provider switch exposed by the Web UI session form
/// (<c>JeopardySessionManager</c>) so <c>ctf-solve</c> operators can pick
/// the same three backends without editing code.
/// </summary>
public enum LlmProvider
{
    /// <summary>
    /// Autodetect: probe Copilot → Azure → OpenAI and pick the first that
    /// is configured. The new default — keeps the champ from blindly
    /// throwing a punch with the wrong glove on. Use <c>--llm-provider=auto</c>
    /// to opt back in explicitly.
    /// </summary>
    Auto = 0,
    /// <summary>GitHub Copilot SDK / Copilot-direct API.</summary>
    Copilot,
    /// <summary>Azure OpenAI deployment-routed client.</summary>
    Azure,
    /// <summary>Local <c>llama-server</c> (escape hatch / offline).</summary>
    LlamaCpp,
    /// <summary>Legacy raw OpenAI (<c>OPENAI_API_KEY</c>).</summary>
    OpenAi,
}

/// <summary>
/// Builds an <see cref="ICopilotLlmClient"/> for the selected
/// <see cref="LlmProvider"/>. Per-provider config comes from
/// <see cref="CommandLineOptions"/> (CLI flags) with a fall-through to the
/// provider's own <c>TryCreateFromEnvironment</c> semantics.
///
/// <para>Secrets (API keys, bearer tokens, OAuth tokens) are NEVER written
/// to <c>stderr</c> or otherwise surfaced by this factory — only
/// presence/absence of the relevant env vars. Each client's own
/// redaction layer (<see cref="TokenRedactor"/>) still applies to
/// audit records and exception messages.</para>
/// </summary>
public static class LlmProviderFactory
{
    /// <summary>
    /// Parse a provider string (from a CLI flag or a Web UI form value).
    /// Accepts <c>auto</c> (default), <c>copilot</c>, <c>azure</c>,
    /// <c>llamacpp</c> / <c>llama-cpp</c> / <c>llama.cpp</c>, and
    /// <c>openai</c>. Unknown values throw <see cref="ArgumentException"/>;
    /// null / empty returns the <see cref="LlmProvider.Auto"/> default
    /// (probes copilot → azure → openai and picks the first configured).
    /// </summary>
    public static LlmProvider Parse(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return LlmProvider.Auto;
        return raw.Trim().ToLowerInvariant() switch
        {
            "auto" or "autodetect" or "detect" => LlmProvider.Auto,
            "copilot" or "github-copilot" or "gh-copilot" => LlmProvider.Copilot,
            "azure" or "azure-openai" or "aoai" => LlmProvider.Azure,
            "llamacpp" or "llama-cpp" or "llama.cpp" or "local" => LlmProvider.LlamaCpp,
            "openai" or "oai" => LlmProvider.OpenAi,
            _ => throw new ArgumentException(
                $"unknown LLM provider '{raw}'; valid: auto | copilot | azure | llamacpp | openai"),
        };
    }

    /// <summary>
    /// Resolve <see cref="LlmProvider.Auto"/> by probing in priority order:
    /// Copilot (env tokens / <c>gh auth token</c>) → Azure (endpoint + auth
    /// env presence) → OpenAI (<c>OPENAI_API_KEY</c>). Returns the first
    /// ready provider. If none are ready returns
    /// <see cref="LlmProvider.Auto"/> as a sentinel (caller treats as
    /// "nothing configured"). Explicit (non-Auto) requests are passed
    /// through unchanged — operator intent wins.
    ///
    /// <para>Probes are cheap: env-var presence checks plus, for Copilot,
    /// a single <c>gh auth token</c> invocation. No live HTTP probes to
    /// Azure / OpenAI. Decision is recorded as
    /// <c>llm.provider.autodetect</c> with <c>selected</c> + <c>source</c>
    /// + <c>attempted</c> so operators can grep <c>audit.jsonl</c>. No
    /// secret values are recorded.</para>
    /// </summary>
    public static LlmProvider Resolve(
        LlmProvider requested,
        AuditLog audit,
        bool allowGitHubCliAuth = true)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (requested != LlmProvider.Auto) return requested;

        // 1. Copilot — most operators are here.
        var (copilotToken, copilotSource) = CopilotAuthTokenResolver.ResolveToken(allowGitHubCliAuth, audit);
        if (!string.IsNullOrWhiteSpace(copilotToken))
        {
            audit.Record("llm.provider.autodetect", new Dictionary<string, object?>
            {
                ["selected"] = "copilot",
                ["source"] = copilotSource.ToString(),
                ["attempted"] = new[] { "copilot" },
            });
            return LlmProvider.Copilot;
        }

        // 2. Azure — env presence only, no live probe.
        var azureEndpoint = Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT");
        var azureApiKey = Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY");
        var azureBearer = Environment.GetEnvironmentVariable("AZURE_OPENAI_BEARER_TOKEN");
        var azureUseEntra = string.Equals(
            Environment.GetEnvironmentVariable("AZURE_OPENAI_USE_ENTRA"),
            "1", StringComparison.Ordinal);
        // Match TryCreateAzure semantics: USE_ENTRA alone is not enough —
        // it requires a pre-fetched bearer too. Otherwise the factory
        // would refuse and we'd be misleading the operator.
        var azureAuthReady = !string.IsNullOrWhiteSpace(azureApiKey)
            || !string.IsNullOrWhiteSpace(azureBearer)
            || (azureUseEntra && !string.IsNullOrWhiteSpace(azureBearer));
        if (!string.IsNullOrWhiteSpace(azureEndpoint) && azureAuthReady)
        {
            var authKind = !string.IsNullOrWhiteSpace(azureApiKey) ? "api_key"
                : !string.IsNullOrWhiteSpace(azureBearer) ? "bearer"
                : "entra";
            audit.Record("llm.provider.autodetect", new Dictionary<string, object?>
            {
                ["selected"] = "azure",
                ["source"] = $"env:{authKind}",
                ["attempted"] = new[] { "copilot", "azure" },
            });
            return LlmProvider.Azure;
        }

        // 3. OpenAI — legacy fallback.
        var openAiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
        if (!string.IsNullOrWhiteSpace(openAiKey))
        {
            audit.Record("llm.provider.autodetect", new Dictionary<string, object?>
            {
                ["selected"] = "openai",
                ["source"] = "env:OPENAI_API_KEY",
                ["attempted"] = new[] { "copilot", "azure", "openai" },
            });
            return LlmProvider.OpenAi;
        }

        audit.Record("llm.provider.autodetect", new Dictionary<string, object?>
        {
            ["selected"] = "none",
            ["attempted"] = new[] { "copilot", "azure", "openai" },
        });
        return LlmProvider.Auto; // sentinel — nothing configured
    }

    /// <summary>
    /// Construct the client for <paramref name="provider"/>. Returns
    /// <c>null</c> on missing / invalid config after writing a clear,
    /// actionable error to <paramref name="stderr"/> (no secrets). The
    /// returned instance owns its internal <c>HttpClient</c> and must be
    /// disposed by the caller.
    /// </summary>
    public static ICopilotLlmClient? Create(
        LlmProvider provider,
        CommandLineOptions opts,
        AuditLog audit,
        TextWriter? stderr = null,
        bool allowGitHubCliAuth = true)
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentNullException.ThrowIfNull(audit);
        stderr ??= Console.Error;

        provider = Resolve(provider, audit, allowGitHubCliAuth);
        if (provider == LlmProvider.Auto)
        {
            stderr.WriteLine(
                "llm-provider=auto: no provider configured. "
                + "Run `gh auth login --web` for Copilot, or export "
                + "AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY for Azure, "
                + "or OPENAI_API_KEY for raw OpenAI.");
            return null;
        }

        switch (provider)
        {
            case LlmProvider.Copilot:
                return CreateCopilot(audit, stderr, allowGitHubCliAuth);
            case LlmProvider.Azure:
                return CreateAzure(opts, audit, stderr);
            case LlmProvider.LlamaCpp:
                return CreateLlamaCpp(opts, audit, stderr);
            case LlmProvider.OpenAi:
                stderr.WriteLine(
                    "llm-provider=openai: the Jeopardy swarm does not currently "
                    + "support raw OpenAI. Use --llm-provider=copilot or =azure.");
                return null;
            default:
                stderr.WriteLine($"llm-provider: unsupported provider enum value '{provider}'.");
                return null;
        }
    }

    private static ICopilotLlmClient? CreateCopilot(
        AuditLog audit,
        TextWriter stderr,
        bool allowGitHubCliAuth)
    {
        var c = CopilotLlmClient.TryCreateFromEnvironment(audit, allowGitHubCliAuth);
        if (c is null)
        {
            stderr.WriteLine(
                "llm-provider=copilot: no OAuth token found. "
                + "Run `gh auth login --web` or set one of COPILOT_TOKEN, GH_TOKEN, or GITHUB_TOKEN.");
        }
        return c;
    }

    private static ICopilotLlmClient? CreateAzure(
        CommandLineOptions opts, AuditLog audit, TextWriter stderr)
    {
        var endpoint = !string.IsNullOrWhiteSpace(opts.AzureEndpoint)
            ? opts.AzureEndpoint
            : Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT");
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            stderr.WriteLine(
                "llm-provider=azure: endpoint missing. "
                + "Pass --azure-endpoint=<url> or export AZURE_OPENAI_ENDPOINT.");
            return null;
        }
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out _))
        {
            stderr.WriteLine(
                $"llm-provider=azure: endpoint '{endpoint}' is not an absolute URL.");
            return null;
        }

        var apiKey = Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY");
        var bearer = Environment.GetEnvironmentVariable("AZURE_OPENAI_BEARER_TOKEN");
        var useEntra = string.Equals(
            Environment.GetEnvironmentVariable("AZURE_OPENAI_USE_ENTRA"),
            "1", StringComparison.Ordinal);

        AzureOpenAiAuth auth;
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            auth = new AzureOpenAiAuth.ApiKey(apiKey!);
        }
        else if (!string.IsNullOrWhiteSpace(bearer))
        {
            auth = new AzureOpenAiAuth.Bearer(bearer!);
        }
        else if (useEntra)
        {
            stderr.WriteLine(
                "llm-provider=azure: AZURE_OPENAI_USE_ENTRA=1 but no AZURE_OPENAI_BEARER_TOKEN. "
                + "Pre-fetch a token with 'az account get-access-token --resource https://cognitiveservices.azure.com' "
                + "and export AZURE_OPENAI_BEARER_TOKEN.");
            return null;
        }
        else
        {
            stderr.WriteLine(
                "llm-provider=azure: no auth. Export AZURE_OPENAI_API_KEY, "
                + "AZURE_OPENAI_BEARER_TOKEN, or AZURE_OPENAI_USE_ENTRA=1 (with a pre-fetched bearer).");
            return null;
        }

        var apiVersion = !string.IsNullOrWhiteSpace(opts.AzureApiVersion)
            ? opts.AzureApiVersion
            : Environment.GetEnvironmentVariable("AZURE_OPENAI_API_VERSION");
        if (string.IsNullOrWhiteSpace(apiVersion)) apiVersion = AzureOpenAiLlmClient.DefaultApiVersion;

        // CLI flags override env entries for the same logical model id.
        var envMap = AzureOpenAiLlmClient.ParseDeploymentMap(
            Environment.GetEnvironmentVariable("AZURE_OPENAI_DEPLOYMENT_MAP"));
        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in envMap) merged[kv.Key] = kv.Value;
        foreach (var kv in opts.AzureDeploymentMap) merged[kv.Key] = kv.Value;

        // `AZURE_OPENAI_DEPLOYMENT` (single-deployment shorthand) is also
        // honored so doctor/env-only setups work without the CSV map.
        var single = Environment.GetEnvironmentVariable("AZURE_OPENAI_DEPLOYMENT");
        if (!string.IsNullOrWhiteSpace(single) && merged.Count == 0)
        {
            // Register under a wildcard key won't help (map is exact-match);
            // register the deployment as itself so a --models entry matching
            // the deployment name resolves correctly.
            merged[single!] = single!;
        }

        return new AzureOpenAiLlmClient(endpoint!, auth, audit, merged, apiVersion!);
    }

    private static ICopilotLlmClient? CreateLlamaCpp(
        CommandLineOptions opts, AuditLog audit, TextWriter stderr)
    {
        var rawUrl = !string.IsNullOrWhiteSpace(opts.LlamaCppUrl)
            ? opts.LlamaCppUrl
            : Environment.GetEnvironmentVariable("LLAMACPP_URL");

        Uri baseUrl;
        if (string.IsNullOrWhiteSpace(rawUrl))
        {
            baseUrl = LlamaCppLlmClient.DefaultBaseUrl;
        }
        else if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var parsed))
        {
            stderr.WriteLine(
                $"llm-provider=llamacpp: --llamacpp-url '{rawUrl}' is not a valid absolute URL.");
            return null;
        }
        else
        {
            baseUrl = parsed;
        }

        var bearer = Environment.GetEnvironmentVariable("LLAMACPP_BEARER_TOKEN");

        // CLI --llamacpp-model wins over LLAMACPP_MODELS env. Each
        // `modelId=modelName` registers both sides as aliases for the same
        // LlamaCppModelConfig so `--models <either-side>` works.
        IReadOnlyList<LlamaCppModelConfig>? models = null;
        if (opts.LlamaCppModels.Count > 0)
        {
            var list = new List<LlamaCppModelConfig>();
            foreach (var kv in opts.LlamaCppModels)
            {
                list.Add(new LlamaCppModelConfig(kv.Key, SupportsTools: false, ContextWindow: null));
                if (!string.IsNullOrWhiteSpace(kv.Value)
                    && !string.Equals(kv.Key, kv.Value, StringComparison.Ordinal))
                {
                    list.Add(new LlamaCppModelConfig(kv.Value, SupportsTools: false, ContextWindow: null));
                }
            }
            models = list;
        }
        else
        {
            var envModels = Environment.GetEnvironmentVariable("LLAMACPP_MODELS");
            if (!string.IsNullOrWhiteSpace(envModels))
            {
                var list = new List<LlamaCppModelConfig>();
                foreach (var piece in envModels.Split(',',
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    list.Add(new LlamaCppModelConfig(piece, SupportsTools: false, ContextWindow: null));
                }
                if (list.Count > 0) models = list;
            }
        }

        return new LlamaCppLlmClient(baseUrl, audit, models, bearer);
    }
}
