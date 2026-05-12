using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Cms;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Cms;

public class SuiteCrmSignatureTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-suitecrm-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    [Fact]
    public void Detects_FromTitleAndLoginUrl()
    {
        const string html = """
            <html><head><title>SuiteCRM</title></head>
            <body><a href="index.php?module=Users&amp;action=Login">Login</a>
            <script>SUGAR.themes = {};</script>
            <link rel="stylesheet" href="/cache/themes/SuiteP/css/style.css"/>
            </body></html>
            """;
        var fp = SuiteCrmSignature.Detect(
            html,
            cookieNames: new[] { "PHPSESSID" },
            headers: null,
            path: "/");

        Assert.NotNull(fp);
        Assert.Equal("salesagility", fp!.Vendor);
        Assert.Equal("suitecrm", fp.Product);
        Assert.True(fp.Confidence >= 2);
        Assert.StartsWith("cpe:2.3:a:salesagility:suitecrm:", fp.Cpe);
    }

    [Fact]
    public void DoesNotMatch_WordPressFixture()
    {
        const string wp = """
            <html><head><meta name="generator" content="WordPress 6.4.1"/></head>
            <body><a href="/wp-login.php">in</a></body></html>
            """;
        var fp = SuiteCrmSignature.Detect(
            wp, cookieNames: new[] { "wordpress_logged_in_xx" }, headers: null, path: "/");
        Assert.Null(fp);
    }

    [Fact]
    public void CveCorpus_AppliesToSuiteCrm()
    {
        Assert.True(CmsCveCorpus.AppliesTo("salesagility", "suitecrm"));
        Assert.True(CmsCveCorpus.AppliesTo(null, "suitecrm"));
        var matches = CmsCveCorpus.Match("salesagility", "suitecrm", "7.14.2");
        Assert.Contains(matches, m => m.CveId == "CVE-2023-6886");
    }

    [Fact]
    public void AuditEvent_CmsFingerprintSuiteCrm_Recorded()
    {
        var audit = NewAudit(out var path);
        try
        {
            var fp = SuiteCrmSignature.Detect(
                @"<title>SuiteCRM</title><a href=""index.php?module=Users&action=Login"">x</a>",
                cookieNames: null,
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
            && l.Contains("suitecrm", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CmsFingerprintTool_OutOfScopeTarget_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var auditPath = Path.Combine(Path.GetTempPath(), $"drederick-suitecrm-scope-{Guid.NewGuid():N}.jsonl");
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
        var entry = SuiteCrmSignature.BuildEntry();
        Assert.Equal(SuiteCrmSignature.EntryName, entry.Name);
        Assert.Equal("cpe:2.3:a:salesagility:suitecrm:{version}:*:*:*:*:*:*:*", entry.CpeTemplate);
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
