using System.Text;
using Drederick.Audit;
using Drederick.Memory;
using Drederick.Recon;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using OpenAI;
using OpenAI.Chat;

namespace Drederick.Agent;

/// <summary>
/// Microsoft Agent Framework runner. Wraps an OpenAI <see cref="ChatClient"/>
/// as an <see cref="AIAgent"/>, exposes the four recon tools as
/// <see cref="AIFunction"/>s, and gives the agent a strongly-worded system
/// prompt pinning it to scoped, non-exploitative reconnaissance.
///
/// Scope enforcement lives inside every tool, not in this class. The LLM
/// cannot circumvent the allow-list by instructing itself to ignore it.
/// </summary>
public sealed class MicrosoftAgentRunner : IReconAgentRunner
{
    private readonly AuditLog _audit;
    private readonly ChatClient _chatClient;
    private readonly string _modelId;

    public MicrosoftAgentRunner(AuditLog audit, ChatClient chatClient, string modelId)
    {
        _audit = audit;
        _chatClient = chatClient;
        _modelId = modelId;
    }

    /// <summary>Factory: build an OpenAI-backed runner from environment configuration.</summary>
    public static MicrosoftAgentRunner? TryCreateFromEnvironment(AuditLog audit)
    {
        var apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
        if (string.IsNullOrWhiteSpace(apiKey)) return null;
        var model = Environment.GetEnvironmentVariable("DREDERICK_MODEL") ?? "gpt-4o-mini";
        var openAi = new OpenAIClient(apiKey);
        var chat = openAi.GetChatClient(model);
        return new MicrosoftAgentRunner(audit, chat, model);
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

    private static string BuildSystemPrompt() =>
        """
        You are Drederick, an authorized-lab reconnaissance agent. You operate
        against targets that the operator owns or is explicitly authorized to
        assess (HTB / CTF / sanctioned red-team engagement).

        You have four tools: nmap_scan, http_probe, tls_probe, dns_probe.
        Use them adaptively:
          - Start with dns_probe and nmap_scan (top ports) for each target.
          - When nmap_scan reports open web-style services, call http_probe.
          - When nmap_scan reports TLS-bearing services, call tls_probe.
          - If top-port nmap finds nothing, retry once with ports="1-65535".
          - Do not re-run the same tool on the same target more than a handful
            of times; the tool layer enforces a budget.

        Hard constraints:
          - You MUST NOT attempt exploitation, brute force, credential
            stuffing, payload delivery, or lateral movement.
          - You MUST NOT fabricate tool output or targets. Every target must
            already be in the user's message; the tool layer refuses anything
            else.
          - If a tool returns a scope error, stop touching that target and
            continue with the others.

        When finished, respond with a short, factual summary: for each target
        list open ports, notable service versions, any expired or soon-to-expire
        TLS certificates, and missing HTTP security headers. Include remediation
        suggestions for defenders. Do not suggest exploits.
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
