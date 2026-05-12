using System.Net;
using System.Net.Http;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Cms;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Cms;

public class PterodactylSignatureTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-pterodactyl-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    [Fact]
    public void Detects_FromMinimalHtmlAndCookie()
    {
        const string html = """
            <html><head><title>Pterodactyl</title>
            <link rel="manifest" href="/assets/manifest.json"/></head>
            <body><div id="pterodactyl"></div></body></html>
            """;
        var fp = PterodactylSignature.Detect(
            html,
            cookieNames: new[] { "pterodactyl_session", "XSRF-TOKEN" },
            headers: "Server: nginx\n",
            path: "/");

        Assert.NotNull(fp);
        Assert.Equal("pterodactyl", fp!.Vendor);
        Assert.Equal("panel", fp.Product);
        Assert.True(fp.Confidence >= 2);
        Assert.Contains(fp.Signals, s => s.Contains("pterodactyl_session", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(fp.Signals, s => s.Contains("manifest.json", StringComparison.OrdinalIgnoreCase));
        Assert.StartsWith("cpe:2.3:a:pterodactyl:panel:", fp.Cpe);
    }

    [Fact]
    public void Detects_VersionFromAdminFooterAndManifest()
    {
        var fixturePath = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "tests", "fixtures", "cms", "pterodactyl-panel-1.11.10.html");
        string html;
        if (File.Exists(fixturePath))
        {
            html = File.ReadAllText(fixturePath);
        }
        else
        {
            // Fallback synthetic body — keeps the test runnable when the
            // fixture isn't present in the publish layout.
            html = """
                <html><head><title>Pterodactyl</title>
                <link rel="manifest" href="/assets/manifest.json"/></head>
                <body><!-- Pterodactyl Panel v1.11.10 --></body></html>
                """;
        }

        var fp = PterodactylSignature.Detect(
            html,
            cookieNames: new[] { "pterodactyl_session" },
            headers: null,
            path: "/");
        Assert.NotNull(fp);
        Assert.Equal("1.11.10", fp!.Version);
        Assert.Equal("cpe:2.3:a:pterodactyl:panel:1.11.10:*:*:*:*:*:*:*", fp.Cpe);

        var manifestFp = PterodactylSignature.Detect(
            html: """
                <html><head><title>Pterodactyl Panel</title>
                <link rel="manifest" href="/assets/manifest.json"/>
                <script>window.SiteConfiguration = {"version":"1.11.7","name":"x"};</script>
                </head></html>
                """,
            cookieNames: new[] { "pterodactyl_session" },
            headers: null,
            path: "/");
        Assert.NotNull(manifestFp);
        Assert.Equal("1.11.7", manifestFp!.Version);
    }

    [Fact]
    public void DoesNotMatch_WordPressFixture()
    {
        const string wp = """
            <html><head><meta name="generator" content="WordPress 6.4.1"/>
            <link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css"/>
            </head><body>blog</body></html>
            """;
        var fp = PterodactylSignature.Detect(
            wp,
            cookieNames: new[] { "wordpress_logged_in_abc", "wp-settings-1" },
            headers: "Server: Apache\nX-Powered-By: PHP/8.2\n",
            path: "/");
        Assert.Null(fp);
    }

    [Fact]
    public void CveCorpus_AlwaysProducesFourEntries()
    {
        Assert.Equal(4, PterodactylCveCorpus.EntryCount);
        Assert.Equal(4, PterodactylCveCorpus.BuiltinEntries().Count);

        // AppliesTo accepts both panel + wings and product-only matches.
        Assert.True(PterodactylCveCorpus.AppliesTo("pterodactyl", "panel"));
        Assert.True(PterodactylCveCorpus.AppliesTo(null, "pterodactyl"));
        Assert.True(PterodactylCveCorpus.AppliesTo("pterodactyl", "wings"));
        Assert.False(PterodactylCveCorpus.AppliesTo("automattic", "wordpress"));

        // With a concrete version any panel-targeted entries inside their
        // <=1.11.10/<=1.11.11 ranges must fire.
        var panel = PterodactylCveCorpus.Match("1.11.10");
        Assert.Contains(panel, m => m.CveId == "GHSA-4r78-3w7p-c83p");
        Assert.Contains(panel, m => m.CveId == "GHSA-r394-9wq2-pf3v");
        Assert.Contains(panel, m => m.CveId == "CVE-2025-49132");

        // Unknown version → false-positive bias, all four entries emitted.
        var unknown = PterodactylCveCorpus.Match(null);
        Assert.Equal(4, unknown.Count);
        Assert.Contains(unknown, m => m.CveId == "CVE-2024-43791");

        // Out-of-range version → fixed builds drop out of the pack.
        var fixedBuild = PterodactylCveCorpus.Match("2.0.0");
        Assert.DoesNotContain(fixedBuild, m => m.CveId == "GHSA-4r78-3w7p-c83p");
    }

    [Fact]
    public void AuditEvent_CmsFingerprintPterodactyl_Recorded()
    {
        var audit = NewAudit(out var path);
        try
        {
            const string html = """
                <html><head><title>Pterodactyl</title>
                <link rel="manifest" href="/assets/manifest.json"/></head>
                <body><!-- Pterodactyl Panel v1.11.10 --></body></html>
                """;
            var fp = PterodactylSignature.Detect(
                html,
                cookieNames: new[] { "pterodactyl_session" },
                headers: null,
                path: "/",
                audit: audit,
                target: "10.0.0.5");
            Assert.NotNull(fp);
        }
        finally
        {
            audit.Dispose();
        }

        var lines = File.ReadAllLines(path);
        Assert.Contains(lines, l =>
            l.Contains("\"event\":\"cms.fingerprint\"", StringComparison.Ordinal)
            && l.Contains("pterodactyl", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CmsFingerprintTool_OutOfScopeTarget_Throws()
    {
        // Parent-tool scope invariant — the programmatic Pterodactyl
        // signature is registered into CmsFingerprintTool's corpus chain,
        // so out-of-scope requests must still be refused by the tool's
        // own _scope.Require gate (GAP-032 pattern). No requests should
        // ever leave the box.
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        var auditPath = Path.Combine(Path.GetTempPath(), $"drederick-pter-scope-{Guid.NewGuid():N}.jsonl");
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
    public void BuildEntry_RegistersInChainUnderStableName()
    {
        var entry = PterodactylSignature.BuildEntry();
        Assert.Equal(PterodactylSignature.EntryName, entry.Name);
        Assert.Equal("cpe:2.3:a:pterodactyl:panel:{version}:*:*:*:*:*:*:*", entry.CpeTemplate);
        Assert.Contains("pterodactyl_session", entry.Signals.Cookies);
        Assert.True(entry.ConfidenceRequired >= 2);
    }

    private static object ResolveBuildEntry()
    {
        return PterodactylSignature.BuildEntry();
    }

    private static string ResolveCpeTemplate(object entry)
    {
        return ((CmsFingerprintEntry)entry).CpeTemplate ?? string.Empty;
    }

    private static string ResolveEntryName(object entry)
    {
        return ((CmsFingerprintEntry)entry).Name;
    }

    [Fact]
    public void BuildEntry_NameMatchesPublicConstant()
    {
        var entry = ResolveBuildEntry();
        Assert.Equal(PterodactylSignature.EntryName, ResolveEntryName(entry));
        Assert.Equal("cpe:2.3:a:pterodactyl:panel:{version}:*:*:*:*:*:*:*", ResolveCpeTemplate(entry));
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
