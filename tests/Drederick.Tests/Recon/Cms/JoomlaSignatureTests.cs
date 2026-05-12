using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Cms;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Cms;

public class JoomlaSignatureTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-joomla-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    [Fact]
    public void Detects_FromGeneratorAndAdministratorLink()
    {
        const string html = """
            <html><head><meta name="generator" content="Joomla! - Open Source CMS 4.2.7"/></head>
            <body><a href="/administrator/">admin</a>
            <script src="/media/system/js/core.js"></script></body></html>
            """;
        var fp = JoomlaSignature.Detect(
            html,
            cookieNames: new[] { "a1b2c3d4e5f60718293a4b5c6d7e8f90" },
            headers: null,
            path: "/");

        Assert.NotNull(fp);
        Assert.Equal("joomla", fp!.Vendor);
        Assert.Equal("joomla!", fp.Product);
        Assert.StartsWith("cpe:2.3:a:joomla:joomla\\!:", fp.Cpe);
        Assert.True(fp.Confidence >= 2);
    }

    [Fact]
    public void DoesNotMatch_DrupalFixture()
    {
        const string d = """
            <html><head><meta name="generator" content="Drupal 9 (https://www.drupal.org)"/></head>
            <body><a href="/sites/default/files/x">x</a></body></html>
            """;
        var fp = JoomlaSignature.Detect(d, cookieNames: null, headers: "X-Generator: Drupal 9\n", path: "/");
        Assert.Null(fp);
    }

    [Fact]
    public void CveCorpus_AppliesToJoomla()
    {
        Assert.True(CmsCveCorpus.AppliesTo("joomla", "joomla!"));
        Assert.True(CmsCveCorpus.AppliesTo(null, "joomla"));
        var matches = CmsCveCorpus.Match("joomla", "joomla!", "4.2.7");
        Assert.Contains(matches, m => m.CveId == "CVE-2023-23752");
    }

    [Fact]
    public void AuditEvent_CmsFingerprintJoomla_Recorded()
    {
        var audit = NewAudit(out var path);
        try
        {
            var fp = JoomlaSignature.Detect(
                @"<meta name=""generator"" content=""Joomla! 4.2.7""/><a href=""/administrator/"">a</a>",
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
            && l.Contains("joomla", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CmsFingerprintTool_OutOfScopeTarget_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var auditPath = Path.Combine(Path.GetTempPath(), $"drederick-joomla-scope-{Guid.NewGuid():N}.jsonl");
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
        var entry = JoomlaSignature.BuildEntry();
        Assert.Equal(JoomlaSignature.EntryName, entry.Name);
        Assert.Equal(@"cpe:2.3:a:joomla:joomla\!:{version}:*:*:*:*:*:*:*", entry.CpeTemplate);
        Assert.Contains("Joomla", entry.Signals.MetaGenerator);
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
