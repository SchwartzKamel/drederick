using System.IO;
using System.Linq;
using Drederick.Audit;
using Drederick.Scaffolding;
using Xunit;

namespace Drederick.Tests.Scaffolding;

public class BriefingLoaderTests
{
    private static string FixturesDir =>
        Path.Combine(AppContext.BaseDirectory, "Scaffolding", "Fixtures");

    private static (BriefingDocument? doc, string auditPath) LoadFixture(string filename)
    {
        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"briefing-loader-{Guid.NewGuid():N}.jsonl");
        using var audit = new AuditLog(auditPath);
        var src = Path.Combine(FixturesDir, filename);
        var scopeDir = Path.GetTempPath();
        var doc = BriefingLoader.LoadOrAbsent(src, scopeDir, audit);
        audit.Dispose();
        return (doc, auditPath);
    }

    [Fact]
    public void LoadsPingpongFixture_ParsesAllSections()
    {
        var (doc, _) = LoadFixture("pingpong-briefing.md");
        Assert.NotNull(doc);
        Assert.Contains("Topology", doc!.SectionsParsed);
        Assert.Contains("Assumed-Breach Material", doc.SectionsParsed);
        Assert.Contains("Cornerman Directives", doc.SectionsParsed);
    }

    [Fact]
    public void ParsesAssumedBreachTable()
    {
        var (doc, _) = LoadFixture("pingpong-briefing.md");
        Assert.NotNull(doc);
        Assert.Equal(2, doc!.AssumedBreach.Count);
        Assert.Contains(doc.AssumedBreach, a => a.Path.Contains("c.roberts.pfx"));
    }

    [Fact]
    public void ParsesFrontmatter()
    {
        var (doc, _) = LoadFixture("pingpong-briefing.md");
        Assert.NotNull(doc);
        Assert.True(doc!.Frontmatter.ContainsKey("box"));
        Assert.Equal("pingpong", doc.Frontmatter["box"]);
    }

    [Fact]
    public void ParsesCornermanDoAndDont()
    {
        var (doc, _) = LoadFixture("pingpong-briefing.md");
        Assert.NotNull(doc);
        Assert.NotEmpty(doc!.CornermanDo);
        Assert.NotEmpty(doc.CornermanDont);
        Assert.Contains(doc.CornermanDont, d => d.Contains("password_spray"));
    }

    [Fact]
    public void EmitsBriefingIngestedEvent()
    {
        var (_, auditPath) = LoadFixture("pingpong-briefing.md");
        var content = File.ReadAllText(auditPath);
        Assert.Contains("\"event\":\"briefing.ingested\"", content);
        Assert.Contains("\"event\":\"briefing.discovered\"", content);
    }

    [Fact]
    public void EmitsBriefingAbsentWhenMissing()
    {
        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"briefing-absent-{Guid.NewGuid():N}.jsonl");
        using (var audit = new AuditLog(auditPath))
        {
            var doc = BriefingLoader.LoadOrAbsent(null, Path.GetTempPath(), audit);
            Assert.Null(doc);
        }
        var content = File.ReadAllText(auditPath);
        Assert.Contains("\"event\":\"briefing.absent\"", content);
    }
}
