using Drederick.Agent;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class ReconToolboxRegistrationTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-toolbox-reg-{Guid.NewGuid():N}.jsonl");

    private static (ReconToolbox toolbox, AuditLog audit) BuildFullToolbox()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var audit = new AuditLog(NewAuditPath());
        var nmap = new NmapTool(scope, audit);
        var http = new HttpProbeTool(scope, audit);
        var tls = new TlsProbeTool(scope, audit);
        var dns = new DnsProbeTool(scope, audit);
        var smb = new SmbTool(scope, audit);
        var ftp = new FtpTool(scope, audit);
        var ssh = new SshTool(scope, audit);
        var snmp = new SnmpTool(scope, audit);
        var ldap = new LdapTool(scope, audit);
        var rpc = new RpcTool(scope, audit);
        var kerberos = new KerberosTool(scope, audit);
        var dnsAxfr = new DnsZoneTransferTool(scope, audit);
        var hcd = new HttpContentDiscoveryTool(scope, audit);
        var tlsCipher = new TlsCipherEnumTool(scope, audit);
        var tb = new ReconToolbox(
            new IReconTool[] { nmap, http, tls, dns, smb, ftp, ssh, snmp, ldap, rpc, kerberos, dnsAxfr, hcd, tlsCipher },
            audit);
        return (tb, audit);
    }

    [Fact]
    public void All_Ten_New_Tools_Are_Registered()
    {
        var (tb, audit) = BuildFullToolbox();
        using (audit)
        {
            var names = tb.Tools.Select(t => t.Name).ToHashSet();
            foreach (var expected in new[]
                {
                    "smb", "ftp", "ssh", "snmp", "ldap", "rpc", "kerberos",
                    "dns-axfr", "http-content-discovery", "tls-cipher-enum",
                })
            {
                Assert.Contains(expected, names);
            }
            // Plus the original four.
            Assert.Equal(14, tb.Tools.Count);
        }
    }

    [Fact]
    public void Every_New_Tool_Has_Nonempty_Name_And_Description()
    {
        var (tb, audit) = BuildFullToolbox();
        using (audit)
        {
            foreach (var t in tb.Tools)
            {
                Assert.False(string.IsNullOrWhiteSpace(t.Name), $"tool has empty Name: {t.GetType().Name}");
                Assert.False(string.IsNullOrWhiteSpace(t.Description), $"tool has empty Description: {t.GetType().Name}");
            }
        }
    }

    [Fact]
    public async Task ToolBudget_Meters_New_Tool_Invocations()
    {
        // Budget of 1 per (target,tool) triggers on the second call.
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var nmap = new NmapTool(scope, audit);
        var http = new HttpProbeTool(scope, audit);
        var tls = new TlsProbeTool(scope, audit);
        var dns = new DnsProbeTool(scope, audit);
        // FtpTool with a connect factory that never actually talks to a server:
        // first call returns a banner-ready stream we immediately dispose, the
        // metering check fires before the second call reaches the network path.
        var ftp = new FtpTool(scope, audit,
            connectFactory: (_, _, _) => Task.FromResult<Stream>(new MemoryStream(System.Text.Encoding.ASCII.GetBytes("220 stub\r\n"))));
        var tb = new ReconToolbox(
            new IReconTool[] { nmap, http, tls, dns, ftp },
            audit,
            new ToolBudget(PerTargetPerTool: 1, MaxTotalCalls: 100));

        // First call consumes the budget; result is irrelevant (we just need the
        // charge to land). Swallow any inner tool error.
        try { await tb.FtpProbeAsync("10.10.10.5", 21); } catch { }

        // Second call must throw due to budget exhaustion.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => tb.FtpProbeAsync("10.10.10.5", 21));
    }

    [Fact]
    public async Task ValidatePort_Rejects_OutOfRange()
    {
        var (tb, audit) = BuildFullToolbox();
        using (audit)
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => tb.SshProbeAsync("10.10.10.5", 0));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => tb.SshProbeAsync("10.10.10.5", 70000));
        }
    }

    [Fact]
    public async Task HttpContentDiscovery_Rejects_NonHttpUrl()
    {
        var (tb, audit) = BuildFullToolbox();
        using (audit)
        {
            await Assert.ThrowsAsync<ArgumentException>(
                () => tb.HttpContentDiscoveryAsync("ftp://10.10.10.5"));
        }
    }

    // --- AdaptiveRunner dispatch plan ---

    private static NmapPort Port(int n, string svc, string proto = "tcp")
        => new() { Port = n, Service = svc, Protocol = proto };

    [Theory]
    [InlineData(445, "microsoft-ds", "smb")]
    [InlineData(139, "netbios-ssn", "smb")]
    [InlineData(21, "ftp", "ftp")]
    [InlineData(22, "ssh", "ssh")]
    [InlineData(389, "ldap", "ldap")]
    [InlineData(389, "ldap", "kerberos")]
    [InlineData(636, "ldaps", "ldap")]
    [InlineData(636, "ldaps", "kerberos")]
    [InlineData(111, "sunrpc", "rpc")]
    [InlineData(111, "rpcbind", "rpc")]
    public void DispatchPlan_Routes_Service_To_Tool(int port, string service, string expectedToolName)
    {
        var plan = AdaptiveRunner.BuildDispatchPlan(new[] { Port(port, service) }, enableContentDiscovery: false);
        Assert.Contains(plan, a => a.ToolName == expectedToolName && a.Port == port);
    }

    [Fact]
    public void DispatchPlan_Snmp_Only_When_Udp_Or_Labelled_Snmp()
    {
        // Labelled service "snmp" is sufficient even on tcp (nmap rarely runs -sU by default,
        // so we treat the service name as ground truth).
        var byLabel = AdaptiveRunner.BuildDispatchPlan(new[] { Port(161, "snmp") }, enableContentDiscovery: false);
        Assert.Contains(byLabel, a => a.ToolName == "snmp");

        // UDP port with a fuzzier service name also triggers.
        var byProto = AdaptiveRunner.BuildDispatchPlan(new[] { Port(161, "snmp-trap", "udp") }, enableContentDiscovery: false);
        Assert.Contains(byProto, a => a.ToolName == "snmp");

        // A tcp port with an unrelated service name does NOT trigger snmp.
        var neither = AdaptiveRunner.BuildDispatchPlan(new[] { Port(80, "http") }, enableContentDiscovery: false);
        Assert.DoesNotContain(neither, a => a.ToolName == "snmp");
    }

    [Fact]
    public void DispatchPlan_Tls_Port_Fans_Out_To_Tls_Http_And_CipherEnum()
    {
        var plan = AdaptiveRunner.BuildDispatchPlan(new[] { Port(443, "https") }, enableContentDiscovery: false);
        Assert.Contains(plan, a => a.ToolName == "tls" && a.Port == 443);
        Assert.Contains(plan, a => a.ToolName == "http" && a.Port == 443 && a.UseTls);
        Assert.Contains(plan, a => a.ToolName == "tls-cipher-enum" && a.Port == 443);
    }

    [Fact]
    public void DispatchPlan_ContentDiscovery_Gated_By_Flag()
    {
        var off = AdaptiveRunner.BuildDispatchPlan(new[] { Port(80, "http") }, enableContentDiscovery: false);
        Assert.DoesNotContain(off, a => a.ToolName == "http-content-discovery");

        var on = AdaptiveRunner.BuildDispatchPlan(new[] { Port(80, "http") }, enableContentDiscovery: true);
        Assert.Contains(on, a => a.ToolName == "http-content-discovery" && a.Port == 80 && !a.UseTls);

        // On TLS port, content discovery uses https.
        var onTls = AdaptiveRunner.BuildDispatchPlan(new[] { Port(443, "https") }, enableContentDiscovery: true);
        Assert.Contains(onTls, a => a.ToolName == "http-content-discovery" && a.Port == 443 && a.UseTls);
    }

    [Fact]
    public void DispatchPlan_Does_Not_Auto_Dispatch_Dns_Axfr()
    {
        // DNS zone transfer requires an explicit nameserver IP and is never
        // routed by the deterministic runner.
        var plan = AdaptiveRunner.BuildDispatchPlan(new[] { Port(53, "domain") }, enableContentDiscovery: true);
        Assert.DoesNotContain(plan, a => a.ToolName == "dns-axfr");
    }
}
