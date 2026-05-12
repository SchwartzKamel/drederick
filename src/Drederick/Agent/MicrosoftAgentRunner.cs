using System.Text;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Drederick.Memory;
using Drederick.Recon;
using Drederick.Scaffolding;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using OpenAI;
using OpenAI.Chat;

namespace Drederick.Agent;

/// <summary>
/// Microsoft Agent Framework runner. Wraps an <see cref="IChatClient"/>
/// as an <see cref="AIAgent"/>, exposes recon and exploit tools as
/// <see cref="AIFunction"/>s, and gives the agent a strongly-worded system
/// prompt pinning it to scoped reconnaissance and exploitation.
///
/// Scope enforcement lives inside every tool, not in this class. The LLM
/// cannot circumvent the allow-list by instructing itself to ignore it.
/// </summary>
public sealed class MicrosoftAgentRunner : IReconAgentRunner
{
    private readonly AuditLog _audit;
    private readonly IChatClient _chatClient;
    private readonly string _modelId;
    private readonly LlmExploitTools? _exploitTools;
    private readonly LlmNotebookTool? _notebook;
    // --- htb-llm-exploit-planning ---
    // Optional GAP-052 LLM exploit planner. Surfaced to the agent as an
    // AIFunction named `llm_exploit_plan` when wired. Null-gated.
    private LlmExploitPlanner? _llmExploitPlanner;
    // --- end htb-llm-exploit-planning ---

    public MicrosoftAgentRunner(
        AuditLog audit,
        IChatClient chatClient,
        string modelId,
        LlmExploitTools? exploitTools = null,
        LlmNotebookTool? notebook = null)
    {
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(chatClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);
        _audit = audit;
        _chatClient = chatClient;
        _modelId = modelId;
        _exploitTools = exploitTools;
        _notebook = notebook;
    }

    /// <summary>Attach / replace the offensive-tool bundle exposed to the LLM.</summary>
    public MicrosoftAgentRunner WithExploitTools(LlmExploitTools exploitTools) =>
        new(_audit, _chatClient, _modelId, exploitTools, _notebook);

    /// <summary>Attach / replace the LLM fight notebook tool.</summary>
    public MicrosoftAgentRunner WithNotebook(LlmNotebookTool notebook) =>
        new(_audit, _chatClient, _modelId, _exploitTools, notebook);

    // --- htb-llm-exploit-planning ---
    /// <summary>
    /// Attach the GAP-052 LLM exploit planner. Exposes a single
    /// <c>llm_exploit_plan</c> <see cref="AIFunction"/> to the agent that
    /// wraps <see cref="LlmExploitPlanner.PlanAsync"/>. Scope and shell-
    /// metachar validation live inside the planner; this surface is purely
    /// registration.
    /// </summary>
    public MicrosoftAgentRunner WithLlmExploitPlanner(LlmExploitPlanner planner)
    {
        ArgumentNullException.ThrowIfNull(planner);
        _llmExploitPlanner = planner;
        return this;
    }
    // --- end htb-llm-exploit-planning ---

    /// <summary>
    /// In-fight scaffolding (briefing.md + attack-graph.yaml). When set,
    /// activation events fire at run start and the user message is
    /// augmented with assumed-breach material, priority hints, and
    /// anti-goals. See LOADER_SPEC §4.
    /// </summary>
    public ScaffoldingContext? Scaffolding { get; set; }

    /// <summary>
    /// Factory: build a runner from the selected LLM provider. Supports the
    /// official Copilot SDK, Azure OpenAI, and legacy raw OpenAI. Returns
    /// <c>null</c> if the provider's required environment is not configured.
    /// </summary>
    public static IReconAgentRunner? TryCreateFromProvider(
        LlmProvider provider,
        IReadOnlyDictionary<string, string>? azureDeploymentMap,
        AuditLog audit,
        LlmExploitTools? exploitTools = null,
        bool allowGitHubCliAuth = true,
        LlmNotebookTool? notebook = null)
    {
        ArgumentNullException.ThrowIfNull(audit);
        provider = LlmProviderFactory.Resolve(provider, audit, allowGitHubCliAuth);
        if (provider == LlmProvider.Auto) return null; // sentinel: nothing configured

        var model = Environment.GetEnvironmentVariable("DREDERICK_MODEL");

        switch (provider)
        {
            case LlmProvider.Copilot:
                return CopilotSdkAgentRunner.TryCreateFromEnvironment(
                    audit,
                    model,
                    exploitTools,
                    allowGitHubCliAuth,
                    notebook);

            case LlmProvider.Azure:
                {
                    var azure = AzureOpenAiChatClient.TryCreateFromEnvironment(audit, azureDeploymentMap, model);
                    if (azure is null) return null;
                    return new MicrosoftAgentRunner(audit, azure, azure.ModelId, exploitTools, notebook);
                }

            case LlmProvider.LlamaCpp:
                // Most local models lack reliable function calling. Fail fast
                // rather than silently dropping tools in agent mode.
                return null;

            case LlmProvider.OpenAi:
            default:
                {
                    // Legacy OpenAI path
                    var apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
                    if (string.IsNullOrWhiteSpace(apiKey)) return null;
                    model ??= "gpt-4o-mini";
                    var openAi = new OpenAIClient(apiKey);
                    var chat = openAi.GetChatClient(model);
                    return new MicrosoftAgentRunner(audit, chat.AsIChatClient(), model, exploitTools, notebook);
                }
        }
    }

    /// <summary>
    /// Factory: build an <see cref="IChatClient"/> from the selected LLM provider
    /// without wrapping it in a runner. Used by ancillary subsystems (e.g. the
    /// autopilot cve-lead → LLM-author bridge) that need raw chat access with
    /// a custom tool surface, distinct from the recon agent's full toolbox.
    /// Returns <c>null</c> if the provider's required environment is not
    /// configured (no API key / no token / unsupported provider).
    /// Mirrors the provider switch in <see cref="TryCreateFromProvider"/>.
    /// </summary>
    public static (IChatClient Client, string ModelId)? TryCreateChatClient(
        LlmProvider provider,
        IReadOnlyDictionary<string, string>? azureDeploymentMap,
        AuditLog audit,
        bool allowGitHubCliAuth = true)
    {
        ArgumentNullException.ThrowIfNull(audit);
        provider = LlmProviderFactory.Resolve(provider, audit, allowGitHubCliAuth);
        if (provider == LlmProvider.Auto) return null;

        var model = Environment.GetEnvironmentVariable("DREDERICK_MODEL");
        switch (provider)
        {
            case LlmProvider.Copilot:
                {
                    var (token, source) = CopilotAuthTokenResolver.ResolveToken(allowGitHubCliAuth, audit);
                    if (string.IsNullOrWhiteSpace(token)) return null;
                    audit.Record("copilot.direct.auth.ready", new Dictionary<string, object?>
                    {
                        ["source"] = source.ToString(),
                    });
                    model ??= CopilotSdkAgentRunner.DefaultModelId;
                    var copilotChat = new AzureOpenAiChatClient(
                        "https://api.githubcopilot.com",
                        new AzureOpenAiAuth.Bearer(token),
                        audit,
                        model,
                        copilotMode: true);
                    return (copilotChat, model);
                }

            case LlmProvider.Azure:
                {
                    var azure = AzureOpenAiChatClient.TryCreateFromEnvironment(audit, azureDeploymentMap, model);
                    if (azure is null) return null;
                    return (azure, azure.ModelId);
                }

            case LlmProvider.LlamaCpp:
                return null;

            case LlmProvider.OpenAi:
            default:
                {
                    var apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
                    if (string.IsNullOrWhiteSpace(apiKey)) return null;
                    model ??= "gpt-4o-mini";
                    var openAi = new OpenAIClient(apiKey);
                    var chat = openAi.GetChatClient(model);
                    return (chat.AsIChatClient(), model);
                }
        }
    }

    /// <summary>Legacy factory: build an OpenAI-backed runner from environment configuration.</summary>
    [Obsolete("Use TryCreateFromProvider for multi-provider support.")]
    public static MicrosoftAgentRunner? TryCreateFromEnvironment(AuditLog audit)
    {
        var apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
        if (string.IsNullOrWhiteSpace(apiKey)) return null;
        var model = Environment.GetEnvironmentVariable("DREDERICK_MODEL") ?? "gpt-4o-mini";
        var openAi = new OpenAIClient(apiKey);
        var chat = openAi.GetChatClient(model);
        return new MicrosoftAgentRunner(audit, chat.AsIChatClient(), model);
    }

    public async Task RunAsync(
        IReadOnlyList<string> targets,
        ReconToolbox tools,
        KnowledgeBase prior,
        CancellationToken ct)
    {
        _audit.Record("runner.start", new Dictionary<string, object?>
        {
            ["runner"] = nameof(MicrosoftAgentRunner),
            ["model"] = _modelId,
            ["targets"] = targets,
        });

        IList<AITool> aiTools = LlmToolCatalog.BuildAiTools(tools, _exploitTools, _notebook);

        // --- htb-llm-exploit-planning ---
        if (_llmExploitPlanner is not null)
        {
            aiTools.Add(AIFunctionFactory.Create(_llmExploitPlanner.PlanAsync, name: "llm_exploit_plan"));
        }
        // --- end htb-llm-exploit-planning ---

        // Wrap the chat client with FunctionInvokingChatClient.
        // NOTE: AllowConcurrentInvocation disabled — Claude via Copilot API
        // requires strict tool_use→tool_result ordering in conversation history.
        var funcClient = new FunctionInvokingChatClient(_chatClient);

        AIAgent agent = funcClient.AsAIAgent(
            instructions: BuildSystemPrompt(),
            name: "drederick",
            description: "Authorized-lab recon agent",
            tools: aiTools);

        var session = await agent.CreateSessionAsync(ct).ConfigureAwait(false);
        Scaffolding?.ActivateKnownNodes();
        var userMessage = BuildUserMessage(targets, prior, Scaffolding);

        AgentResponse response;
        try
        {
            response = await agent.RunAsync(userMessage, session, options: null, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _audit.Record("runner.agent_error", new Dictionary<string, object?>
            {
                ["error"] = ex.Message,
            });
            throw;
        }

        _audit.Record("runner.agent_response", new Dictionary<string, object?>
        {
            ["text_len"] = response.Text?.Length ?? 0,
            ["finish_reason"] = response.FinishReason?.ToString(),
        });

        if (!string.IsNullOrEmpty(response.Text))
        {
            Console.WriteLine();
            Console.WriteLine("--- agent summary ---");
            Console.WriteLine(response.Text);
            Console.WriteLine("---------------------");
        }

        tools.Finalize(targets);
        _audit.Record("runner.finish", new Dictionary<string, object?>
        {
            ["tool_calls"] = tools.ToolCallsTotal,
        });
    }

    internal static string BuildSystemPrompt() =>
        """
        You are Drederick, a full-auto offensive security harness operating
        against authorized lab / CTF / sanctioned red-team targets. Every
        target in the user message is already inside the operator's declared
        scope; the tool layer is the authorization boundary and re-checks
        scope on every call you make.

        Reference: .github/copilot-instructions.md — "full-auto offensive
        security harness for authorized lab / CTF / red-team targets". Your
        job is to compromise in-scope targets fast: enumerate widely,
        exploit aggressively, pivot when reachable, and extract flags.

        Recon tools: nmap_scan, http_probe, tls_probe, dns_probe, and (when
        wired) smb_probe, ftp_probe, ssh_probe, snmp_probe, ldap_probe,
        rpc_probe, kerberos_probe, dns_zone_transfer,
        http_content_discovery, tls_cipher_enum.

        Offensive tools (when wired):
          - exploit_plan: ask for a deterministic fight-card for a target.
          - execute_cred_spray: one (user, password) attempt against an
            auth-bearing service. Requires --allow-cred-attacks and
            --acknowledge-lockout-risk.
          - run_post_ex_linux / run_post_ex_windows: enumerate a host
            through an established session.
          - pivot_and_scan: sweep an internal CIDR from inside a session.
          - extract_flags_from_dir: surface captured flags from out/.
          - run_multi_stage: drive preflight → PoC → stager → payload →
            handler → record as one chain.

        Rules you MUST follow:
          - You MAY execute exploits, credential attacks, post-ex
            enumeration, and payload delivery — but ONLY against targets
            supplied in the user message. The tool layer rejects anything
            else; do not waste calls on targets it will refuse.
          - You MUST NOT fabricate targets, invent IPs, or attempt to
            escape scope by re-phrasing, encoding, or any other
            workaround. The scope check is load-bearing and unreachable
            from here.
          - Passwords the operator supplies may be forwarded verbatim to
            execute_cred_spray; the wrapper hashes them before audit.
          - If a tool returns {"error": "permission_denied", ...},
            acknowledge the required flag and move on — do not retry.
          - If a tool returns {"error": "budget_exceeded", ...}, stop
            invoking that tool against that target.

        Plan adaptively: recon → fingerprint → plan (exploit_plan) →
        exploit → post-ex → pivot → repeat. When finished, respond with a
        factual summary: open ports, service versions, captured creds
        (by SHA-256 only), opened sessions, and any flags extracted.

        Forcing function — DO NOT stop after recon. A fight that ends
        with only enumeration is a loss. Before you respond with a final
        summary, you MUST do at least ONE of the following:
          1. Call exploit_plan for each target and act on every action it
             returns whose required permission flag is enabled. If
             exploit_plan returns zero actions, that is a signal to widen
             recon (e.g., http_content_discovery, tls_cipher_enum,
             additional protocol probes) and try again — not to stop.
          2. For every auth-bearing service you observed (ssh, ftp,
             smb/microsoft-ds, winrm/5985, rdp/3389, mssql/1433, mysql,
             postgres, ldap, http with login forms) call
             execute_cred_spray with at least one (user, password) pair
             — lab defaults if --allow-cred-attacks is set, captured
             creds otherwise.
          3. For any session you opened, call run_post_ex_linux or
             run_post_ex_windows and extract_flags_from_dir.
          4. If permission flags forbid every offensive action, say so
             explicitly in the summary and name the missing flag — that
             is the only acceptable "recon-only" outcome.
        Native HTTP/TLS probes that succeeded are PROOF a port is open
        even when nmap reports nothing — treat them as targets, not
        artifacts. JobTwo r4 lost because nmap returned [] and the
        runner stopped; the planner now harvests ports from every
        signal, and so should you.

        Vhost-routed apps (GAP-032 / facts.htb fight): If an http_probe
        returns 3xx → Location with a hostname (e.g. status=302,
        final_url=http://facts.htb/login), you MUST retry the probe
        with that hostname as the target — IP-only requests cannot
        reach vhost-routed apps and you will only see the redirect
        bounce, never the real content. http_probe accepts hostname
        targets; the resolved IP is what scope authorizes, and the
        hostname is automatically sent in Host: + SNI. When a
        hostname is in scope (resolves to a scope IP), prefer the
        hostname over the bare IP for HTTP requests — it gives you
        the actual application surface.

        Flag extraction paths (GAP-034 nudge): when calling
        extract_flags_from_dir, pass the configured `out_root` value
        as the `dir` parameter (or a sub-path under it). The tool
        refuses any path that resolves outside `out_root` (audit:
        extract_flags_from_dir.refused, code=path_outside_out). When in
        doubt, use the absolute `out_root` value to avoid path_outside_out
        rejections that waste planner turns.

        In-fight scaffolding (LOADER_SPEC). If the user message contains
        an "In-fight scaffolding" block, the operator has supplied
        briefing.md and/or attack-graph.yaml. Treat it as authoritative
        intel for THIS fight: (a) every assumed-breach artifact MUST be
        consumed by at least one tool call or you must explicitly state
        the tool is unavailable — silently ignoring it is a contract
        violation; (b) priority hints are ordered tie-breakers; (c)
        anti-goals are HARD blockers, never schedule a matching action;
        (d) bias your first 5 actions toward consuming the assumed-
        breach artifact. If scaffolding is absent, behave as before.
        """;

    internal static string BuildUserMessage(IReadOnlyList<string> targets, KnowledgeBase prior)
        => BuildUserMessage(targets, prior, null);

    internal static string BuildUserMessage(
        IReadOnlyList<string> targets,
        KnowledgeBase prior,
        ScaffoldingContext? scaffolding)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Targets (all inside authorized scope):");
        foreach (var t in targets)
        {
            sb.Append("  - ").Append(t);
            sb.Append("   [prior: ").Append(prior.Digest(t)).AppendLine("]");
        }
        sb.AppendLine();
        sb.AppendLine("Goal: COMPROMISE each target. Enumerate widely, then exploit. ");
        sb.AppendLine("A fight that stops at enumeration is a loss — see the forcing");
        sb.AppendLine("function in your system instructions. Use the tools; do not guess.");
        sb.AppendLine("Capture flags, open sessions, escalate where you can, and report");
        sb.AppendLine("punches thrown — not just punches considered.");
        if (scaffolding is { IsActive: true })
        {
            sb.Append(scaffolding.BuildPriorContext());
        }
        return sb.ToString();
    }
}
