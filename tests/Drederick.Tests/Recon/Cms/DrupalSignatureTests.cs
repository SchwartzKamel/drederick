using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Cms;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Cms;

public class DrupalSignatureTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-drupal-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    [Fact]
    public void Detects_FromXGeneratorHeader()
    {
        const string html = """
            <html><head><meta name="generator" content="Drupal 9 (https://www.drupal.org)"/></head>
            <body><script>window.drupalSettings = {};</script>
            <a href="/sites/default/files/x.png">x</a></body></html>
            """;
        const string headers = "X-Generator: Drupal 9 (https://www.drupal.org)\n";
        var fp = DrupalSignature.Detect(
            html,
            cookieNames: new[] { "SESSabcdef0123456789ab" },
            headers: headers,
            path: "/");

        Assert.NotNull(fp);
        Assert.Equal("drupal", fp!.Vendor);
        Assert.Equal("drupal", fp.Product);
        Assert.True(fp.Confidence >= 2);
        Assert.Contains(fp.Signals, s => s.Contains("X-Generator", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DoesNotMatch_MagentoFixture()
    {
        const string m = """
            <html><head><script>Mage.Cookies = {};</script></head>
            <body><img src="/media/catalog/product/x.jpg"/></body></html>
            """;
        var fp = DrupalSignature.Detect(m, cookieNames: new[] { "frontend" }, headers: null, path: "/");
        Assert.Null(fp);
    }

    [Fact]
    public void CveCorpus_ContainsDrupalgeddon()
    {
        Assert.True(CmsCveCorpus.AppliesTo("drupal", "drupal"));
        var matches = CmsCveCorpus.Match("drupal", "drupal", "7.58");
        Assert.Contains(matches, m => m.CveId == "CVE-2018-7600");
        var laterRest = CmsCveCorpus.Match("drupal", "drupal", "8.6.10");
        Assert.Contains(laterRest, m => m.CveId == "CVE-2019-6340");
    }

    [Fact]
    public void AuditEvent_CmsFingerprintDrupal_Recorded()
    {
        var audit = NewAudit(out var path);
        try
        {
            var fp = DrupalSignature.Detect(
                @"<meta name=""generator"" content=""Drupal 9""/><a href=""/sites/default/files/x"">x</a>",
                cookieNames: new[] { "SESSabcdef0123456789aa" },
                headers: "X-Generator: Drupal 9\n",
                path: "/",
                audit: audit,
                target: "10.0.0.5");
            Assert.NotNull(fp);
        }
        finally { audit.Dispose(); }

        var lines = File.ReadAllLines(path);
        Assert.Contains(lines, l =>
            l.Contains("\"event\":\"cms.fingerprint\"", StringComparison.Ordinal)
            && l.Contains("drupal", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CmsFingerprintTool_OutOfScopeTarget_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var auditPath = Path.Combine(Path.GetTempPath(), $"drederick-drupal-scope-{Guid.NewGuid():N}.jsonl");
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
        var entry = DrupalSignature.BuildEntry();
        Assert.Equal(DrupalSignature.EntryName, entry.Name);
        Assert.Equal("cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*", entry.CpeTemplate);
        Assert.Contains("Drupal", entry.Signals.MetaGenerator);
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
