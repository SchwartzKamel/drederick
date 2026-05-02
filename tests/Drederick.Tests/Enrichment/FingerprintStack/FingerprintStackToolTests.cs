using Drederick.Audit;
using Drederick.Enrichment.FingerprintStack;
using Drederick.Enrichment.FingerprintStack.Signals;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Enrichment.FingerprintStack;

public class FingerprintStackToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-fp-{Guid.NewGuid():N}.jsonl"));

    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var tool = new FingerprintStackTool(scope, NewAudit(),
            new FaviconCorpus(new Dictionary<string, FaviconCorpusEntry>()),
            handlerFactory: null);

        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.FingerprintHostAsync("8.8.8.8", new HostFinding { Target = "8.8.8.8" }));
    }

    [Fact]
    public async Task IntegratesBanner_Tls_HttpHeader_Without_NetworkAccess()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var corpus = new FaviconCorpus(new Dictionary<string, FaviconCorpusEntry>());

        // Handler should never be hit because no Http URL is set on the finding.
        var tool = new FingerprintStackTool(scope, NewAudit(), corpus, handlerFactory: null);

        var finding = new HostFinding { Target = "10.10.10.5" };
        finding.Nmap = new NmapResult
        {
            OpenPorts = new List<NmapPort>
            {
                new() { Port = 443, Protocol = "tcp", Service = "https",
                        Product = "nginx", Version = "1.18.0", Extra = "(Ubuntu)" },
            },
        };
        finding.Tls.Add(new TlsResult
        {
            Port = 443,
            Subject = "CN=plesk.example.com",
            Issuer = "CN=Let's Encrypt R3",
            SubjectAltNames = new List<string> { "plesk.example.com" },
        });

        var reports = await tool.FingerprintHostAsync("10.10.10.5", finding);
        var report = Assert.Single(reports);
        Assert.Equal(443, report.Port);

        Assert.Contains(report.Candidates, c => c.Product == "nginx" && c.Version == "1.18.0");
        Assert.Contains(report.Candidates, c => c.Vendor == "plesk" && c.Product == "plesk");
        Assert.All(report.Candidates, c => Assert.StartsWith("cpe:2.3:a:", c.Cpe));
    }

    [Fact]
    public async Task EmptyFinding_ReturnsNoReports_WithoutError()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var tool = new FingerprintStackTool(scope, NewAudit(),
            new FaviconCorpus(new Dictionary<string, FaviconCorpusEntry>()),
            handlerFactory: null);

        var finding = new HostFinding { Target = "10.10.10.5" };
        var reports = await tool.FingerprintHostAsync("10.10.10.5", finding);
        Assert.Empty(reports);
    }

    [Fact]
    public void Tool_Implements_IReconTool_With_StableName()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var tool = new FingerprintStackTool(scope, NewAudit());
        Assert.Equal("fingerprint-stack", tool.Name);
        Assert.False(string.IsNullOrWhiteSpace(tool.Description));
    }
}
