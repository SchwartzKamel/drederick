using System.IO;
using System.Linq;
using Drederick.Audit;
using Drederick.Scaffolding;
using Xunit;

namespace Drederick.Tests.Scaffolding;

public class AttackGraphLoaderTests
{
    private static string FixturesDir =>
        Path.Combine(AppContext.BaseDirectory, "Scaffolding", "Fixtures");

    private static (AttackGraph? graph, string auditPath) Load(string filename)
    {
        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"attack-graph-{Guid.NewGuid():N}.jsonl");
        using var audit = new AuditLog(auditPath);
        var graph = AttackGraphLoader.LoadOrAbsent(
            Path.Combine(FixturesDir, filename), Path.GetTempPath(), audit);
        audit.Dispose();
        return (graph, auditPath);
    }

    [Fact]
    public void LoadsPingpongFixture()
    {
        var (g, _) = Load("pingpong-attack-graph.yaml");
        Assert.NotNull(g);
        Assert.Equal(1, g!.SchemaVersion);
        Assert.Equal("pingpong", g.Box);
        Assert.True(g.Nodes.Count >= 4);
        Assert.True(g.Edges.Count >= 1);
    }

    [Fact]
    public void EmitsAttackGraphLoadedEvent()
    {
        var (_, auditPath) = Load("pingpong-attack-graph.yaml");
        var content = File.ReadAllText(auditPath);
        Assert.Contains("\"event\":\"attack_graph.loaded\"", content);
        Assert.Contains("\"event\":\"attack_graph.discovered\"", content);
    }

    [Fact]
    public void ParsesPriorityHintsAndAntiGoals()
    {
        var (g, _) = Load("pingpong-attack-graph.yaml");
        Assert.NotNull(g);
        Assert.NotEmpty(g!.PriorityHints);
        Assert.Contains(g.PriorityHints, h => h.Prefer == "pkinit");
        Assert.NotEmpty(g.AntiGoals);
        Assert.Contains(g.AntiGoals, a => a.Patterns.Any(p => p.Contains("password_spray")));
    }

    [Fact]
    public void RejectsUnknownSchemaVersion()
    {
        var path = Path.Combine(AppContext.BaseDirectory,
            $"unknown-schema-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path,
            "schema_version: 99\nbox: dummy\nnodes: []\nedges: []\n");
        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"attack-graph-{Guid.NewGuid():N}.jsonl");
        using (var audit = new AuditLog(auditPath))
        {
            var g = AttackGraphLoader.LoadOrAbsent(path, Path.GetTempPath(), audit);
            Assert.Null(g);
        }
        var content = File.ReadAllText(auditPath);
        Assert.Contains("\"event\":\"attack_graph.skipped\"", content);
        Assert.Contains("version_unsupported", content);
    }

    [Fact]
    public void EmitsVocabUnknownForUnknownKind()
    {
        var path = Path.Combine(AppContext.BaseDirectory,
            $"odd-vocab-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path,
            "schema_version: 1\nbox: x\nnodes:\n  - id: weird\n    kind: martian\n    state: known\nedges: []\n");
        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"attack-graph-{Guid.NewGuid():N}.jsonl");
        using (var audit = new AuditLog(auditPath))
        {
            var g = AttackGraphLoader.LoadOrAbsent(path, Path.GetTempPath(), audit);
            Assert.NotNull(g);
        }
        var content = File.ReadAllText(auditPath);
        Assert.Contains("\"event\":\"attack_graph.vocab.unknown\"", content);
        Assert.Contains("martian", content);
    }
}
