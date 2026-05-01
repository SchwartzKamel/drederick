using Drederick.Recon;
using Microsoft.Extensions.AI;

namespace Drederick.Agent;

internal static class LlmToolCatalog
{
    internal static List<AIFunction> BuildAiFunctions(ReconToolbox tools, LlmExploitTools? exploitTools)
    {
        ArgumentNullException.ThrowIfNull(tools);

        var aiTools = new List<AIFunction>
        {
            AIFunctionFactory.Create(tools.NmapScanAsync, name: "nmap_scan"),
            AIFunctionFactory.Create(tools.HttpProbeAsync, name: "http_probe"),
            AIFunctionFactory.Create(tools.TlsProbeAsync, name: "tls_probe"),
            AIFunctionFactory.Create(tools.DnsProbeAsync, name: "dns_probe"),
        };

        void AddIf(string toolName, AIFunction function)
        {
            if (tools.Tools.Any(x => x.Name == toolName)) aiTools.Add(function);
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
        if (exploitTools is not null)
        {
            aiTools.AddRange(exploitTools.BuildAiFunctions());
        }
        // --- end llm-exploit-wiring ---

        return aiTools;
    }

    internal static IList<AITool> BuildAiTools(ReconToolbox tools, LlmExploitTools? exploitTools) =>
        BuildAiFunctions(tools, exploitTools).Cast<AITool>().ToArray();
}
