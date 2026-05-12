using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Cms;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Cms;

public class MagentoSignatureTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-magento-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    [Fact]
    public void Detects_FromMageCookiesAndMediaCatalog()
    {
        const string html = """
            <html><head><script>Mage.Cookies = {};</script>
            <script>var BASE_URL = "/";</script></head>
            <body><img src="/media/catalog/product/cache/x.jpg"/>
            <link href="/static/version1700000000/frontend/x/css/styles.css"/></body></html>
            """;
        var fp = MagentoSignature.Detect(
            html,
            cookieNames: new[] { "frontend", "X-Magento-Vary" },
            headers: "Set-Cookie: frontend=abc; path=/\n",
            path: "/");

        Assert.NotNull(fp);
        Assert.Equal("magento", fp!.Vendor);
        Assert.Equal("magento", fp.Product);
        Assert.True(fp.Confidence >= 2);
        Assert.Contains(fp.Signals, s => s.Contains("Mage.Cookies", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DoesNotMatch_SuiteCrmFixture()
    {
        const string s = """
            <html><head><title>SuiteCRM</title></head>
            <body><a href="index.php?module=Users&amp;action=Login">in</a></body></html>
            """;
        var fp = MagentoSignature.Detect(s, cookieNames: null, headers: null, path: "/");
        Assert.Null(fp);
    }

    [Fact]
    public void CveCorpus_ContainsCosmicSting()
    {
        Assert.True(CmsCveCorpus.AppliesTo("magento", "magento"));
        Assert.True(CmsCveCorpus.AppliesTo("adobe", "commerce"));
        var matches = CmsCveCorpus.Match("magento", "magento", "2.4.6");
        Assert.Contains(matches, m => m.CveId == "CVE-2024-34102");
        // Pre-auth RCE CVE-2022-24086 (Magento <= 2.3.7) shouldn't fire on a
        // 2.4.6 fingerprint — version-range filter must drop it.
        Assert.DoesNotContain(matches, m => m.CveId == "CVE-2022-24086");
    }

    [Fact]
    public void AuditEvent_CmsFingerprintMagento_Recorded()
    {
        var audit = NewAudit(out var path);
        try
        {
            var fp = MagentoSignature.Detect(
                @"<script>Mage.Cookies = {};</script><img src=""/media/catalog/product/x.jpg""/>",
                cookieNames: new[] { "frontend" },
                headers: null,
                path: "/",
                audit: audit,
                target: "10.0.0.5");
            Assert.NotNull(fp);
        }
        finally { audit.Dispose(); }

        var lines = File.ReadAllLines(path);
        Assert.Contains(lines, l =>
            l.Contains("\"event\":\"cms.fingerprint\"", StringComparison.Ordinal)
            && l.Contains("magento", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CmsFingerprintTool_OutOfScopeTarget_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var auditPath = Path.Combine(Path.GetTempPath(), $"drederick-magento-scope-{Guid.NewGuid():N}.jsonl");
        using var audit = new AuditLog(auditPath);
        var handler = new CountingHandler();
        var tool = new CmsFingerprintTool(
            scope, audit,
            dnsResolver: null,
            handlerFactory: _ => handler,
            corpus: null,
            timeout: TimeSpan.FromSeconds(2));

        await Assert.ThrowsAsync<ScopeException>(
            () => tool.FingerprintAsync("8.8.8.8", 80));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public void BuildEntry_RegistersUnderStableName()
    {
        var entry = MagentoSignature.BuildEntry();
        Assert.Equal(MagentoSignature.EntryName, entry.Name);
        Assert.Equal("cpe:2.3:a:magento:magento:{version}:*:*:*:*:*:*:*", entry.CpeTemplate);
        Assert.Contains("frontend", entry.Signals.Cookies);
        Assert.True(entry.ConfidenceRequired >= 2);
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                Content = new StringContent("", Encoding.UTF8, "text/plain"),
            });
        }
    }
}
