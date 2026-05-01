using System.Text;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Drederick.Memory;
using Drederick.Recon;
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

    public MicrosoftAgentRunner(
        AuditLog audit,
        IChatClient chatClient,
        string modelId,
        LlmExploitTools? exploitTools = null)
    {
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(chatClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);
        _audit = audit;
        _chatClient = chatClient;
        _modelId = modelId;
        _exploitTools = exploitTools;
    }

    /// <summary>Attach / replace the offensive-tool bundle exposed to the LLM.</summary>
    public MicrosoftAgentRunner WithExploitTools(LlmExploitTools exploitTools) =>
        new(_audit, _chatClient, _modelId, exploitTools);

    /// <summary>
    /// Factory: build a runner from the selected LLM provider. Supports Copilot
    /// SDK, Azure OpenAI, and legacy raw OpenAI. Returns <c>null</c> if the
    /// provider's required environment is not configured.
    /// </summary>
    public static MicrosoftAgentRunner? TryCreateFromProvider(
        LlmProvider provider,
        IReadOnlyDictionary<string, string>? azureDeploymentMap,
        AuditLog audit,
        bool allowGitHubCliAuth = true)
    {
        var model = Environment.GetEnvironmentVariable("DREDERICK_MODEL");

        switch (provider)
        {
            case LlmProvider.Copilot:
                {
                    var copilot = CopilotChatClient.TryCreateFromEnvironment(audit, model, allowGitHubCliAuth);
                    if (copilot is null) return null;
                    return new MicrosoftAgentRunner(audit, copilot, copilot.ModelId);
                }

            case LlmProvider.Azure:
                {
                    var azure = AzureOpenAiChatClient.TryCreateFromEnvironment(audit, azureDeploymentMap, model);
                    if (azure is null) return null;
                    return new MicrosoftAgentRunner(audit, azure, azure.ModelId);
                }

            case LlmProvider.LlamaCpp:
                // Most local models lack reliable function calling. Fail fast
                // rather than silently dropping tools in agent mode.
                return null;

            default:
                {
                    // Legacy OpenAI path
                    var apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
                    if (string.IsNullOrWhiteSpace(apiKey)) return null;
                    model ??= "gpt-4o-mini";
                    var openAi = new OpenAIClient(apiKey);
                    var chat = openAi.GetChatClient(model);
                    return new MicrosoftAgentRunner(audit, chat.AsIChatClient(), model);
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

        IList<AITool> aiTools = new List<AITool>
        {
            AIFunctionFactory.Create(tools.NmapScanAsync, name: "nmap_scan"),
            AIFunctionFactory.Create(tools.HttpProbeAsync, name: "http_probe"),
            AIFunctionFactory.Create(tools.TlsProbeAsync, name: "tls_probe"),
            AIFunctionFactory.Create(tools.DnsProbeAsync, name: "dns_probe"),
        };

        // Extended scanner surface: only expose a tool if the underlying
        // scanner was registered on the toolbox (callers may construct a
        // toolbox with just the original four). We detect by IReconTool.Name.
        void AddIf(string toolName, AITool t)
        {
            if (tools.Tools.Any(x => x.Name == toolName)) aiTools.Add(t);
        }
        AddIf("smb", AIFunctionFactory.Create(tools.SmbProbeAsync, name: "smb_probe"));
        AddIf("ftp", AIFunctionFactory.Create(tools.FtpProbeAsync, name: "ftp_probe"));
        AddIf("ssh", AIFunctionFactory.Create(tools.SshProbeAsync, name: "ssh_probe"));
        AddIf("snmp", AIFunctionFactory.Create(tools.SnmpProbeAsync, name: "snmp_probe"));
        AddIf("ldap", AIFunctionFactory.Create(tools.LdapProbeAsync, name: "ldap_probe"));
        AddIf("rpc", AIFunctionFactory.Create(tools.RpcProbeAsync, name: "rpc_probe"));
        AddIf("kerberos", AIFunctionFactory.Create(tools.KerberosProbeAsync, name: "kerberos_probe"));
        AddIf("dns-axfr", AIFunctionFactory.Create(tools.DnsZoneTransferAsync, name: "dns_zone_transfer"));
        AddIf("http-content-discovery",
            AIFunctionFactory.Create(tools.HttpContentDiscoveryAsync, name: "http_content_discovery"));
        AddIf("tls-cipher-enum",
            AIFunctionFactory.Create(tools.TlsCipherEnumAsync, name: "tls_cipher_enum"));

        // --- llm-exploit-wiring ---
        // Offensive surface (exploit, credential spray, post-ex, pivot,
        // multi-stage chain, flag extraction). Each AIFunction re-checks
        // scope internally and consults RunPermissions before touching
        // anything. Null-gated on the underlying tool being wired.
        if (_exploitTools is not null)
        {
            foreach (var t in _exploitTools.BuildAiTools()) aiTools.Add(t);
        }
        // --- end llm-exploit-wiring ---

        AIAgent agent = _chatClient.AsAIAgent(
            instructions: BuildSystemPrompt(),
            name: "drederick",
            description: "Authorized-lab recon agent",
            tools: aiTools);

        var session = await agent.CreateSessionAsync(ct).ConfigureAwait(false);
        var userMessage = BuildUserMessage(targets, prior);

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
        """;

    private static string BuildUserMessage(IReadOnlyList<string> targets, KnowledgeBase prior)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Targets (all inside authorized scope):");
        foreach (var t in targets)
        {
            sb.Append("  - ").Append(t);
            sb.Append("   [prior: ").Append(prior.Digest(t)).AppendLine("]");
        }
        sb.AppendLine();
        sb.AppendLine("Goal: enumerate services on each target, identify notable findings, ");
        sb.AppendLine("and write a remediation-focused summary. Use the tools; do not guess.");
        return sb.ToString();
    }
}
