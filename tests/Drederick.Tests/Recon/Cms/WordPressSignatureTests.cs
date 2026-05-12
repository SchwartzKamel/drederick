using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Cms;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Cms;

public class WordPressSignatureTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-wp-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    [Fact]
    public void Detects_FromGeneratorAndCookies()
    {
        const string html = """
            <html><head><meta name="generator" content="WordPress 6.4.1"/>
            <link rel="stylesheet" href="/wp-content/themes/x/style.css"/></head>
            <body><a href="/wp-login.php">Log in</a></body></html>
            """;
        var fp = WordPressSignature.Detect(
            html,
            cookieNames: new[] { "wordpress_logged_in_abc", "wp-settings-1" },
            headers: "X-Powered-By: PHP/8.2\n",
            path: "/");

        Assert.NotNull(fp);
        Assert.Equal("wordpress", fp!.Vendor);
        Assert.Equal("wordpress", fp.Product);
        Assert.Equal("6.4.1", fp.Version);
        Assert.Equal("cpe:2.3:a:wordpress:wordpress:6.4.1:*:*:*:*:*:*:*", fp.Cpe);
        Assert.True(fp.Confidence >= 2);
        Assert.Contains(fp.Signals, s => s.Contains("generator", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DoesNotMatch_JoomlaFixture()
    {
        const string j = """
            <html><head><meta name="generator" content="Joomla! - Open Source CMS"/></head>
            <body><a href="/administrator/">admin</a></body></html>
            """;
        var fp = WordPressSignature.Detect(j, cookieNames: null, headers: null, path: "/");
        Assert.Null(fp);
    }

    [Fact]
    public void CveCorpus_ContainsHeadliners()
    {
        Assert.True(CmsCveCorpus.AppliesTo("wordpress", "wordpress"));
        Assert.True(CmsCveCorpus.AppliesTo(null, "wordpress"));
        var matches = CmsCveCorpus.Match("wordpress", "wordpress", "4.7.1");
        Assert.Contains(matches, m => m.CveId == "CVE-2017-1001000");
        // Unknown version → all WordPress entries (false-positive bias).
        var unknown = CmsCveCorpus.Match("wordpress", "wordpress", null);
        Assert.True(unknown.Count >= 6);
    }

    [Fact]
    public void AuditEvent_CmsFingerprintWordPress_Recorded()
    {
        var audit = NewAudit(out var path);
        try
        {
            var fp = WordPressSignature.Detect(
                @"<meta name=""generator"" content=""WordPress 6.4.1""/><a href=""/wp-login.php"">x</a>",
                cookieNames: new[] { "wordpress_logged_in_xx" },
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
            && l.Contains("wordpress", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CmsFingerprintTool_OutOfScopeTarget_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var auditPath = Path.Combine(Path.GetTempPath(), $"drederick-wp-scope-{Guid.NewGuid():N}.jsonl");
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
        var entry = WordPressSignature.BuildEntry();
        Assert.Equal(WordPressSignature.EntryName, entry.Name);
        Assert.Equal("cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*", entry.CpeTemplate);
        Assert.Contains("WordPress", entry.Signals.MetaGenerator);
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
