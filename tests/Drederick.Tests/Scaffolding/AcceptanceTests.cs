using System.IO;
using System.Linq;
using Drederick.Audit;
using Drederick.Scaffolding;
using Xunit;

namespace Drederick.Tests.Scaffolding;

/// <summary>
/// LOADER_SPEC §6 acceptance suite, encoded as xUnit assertions
/// over a synthetic audit.jsonl produced by running the full
/// scaffolding loader pipeline on the pingpong fixture.
/// </summary>
public class AcceptanceTests
{
    private static string FixturesDir =>
        Path.Combine(AppContext.BaseDirectory, "Scaffolding", "Fixtures");

    private (string auditPath, ScaffoldingContext ctx) Run()
    {
        var scopeDir = Path.Combine(AppContext.BaseDirectory,
            $"scope-{Guid.NewGuid():N}");
        Directory.CreateDirectory(scopeDir);
        var scopeFile = Path.Combine(scopeDir, "scope.yaml");
        File.WriteAllText(scopeFile, "version: 1\nallow:\n  - 10.10.0.0/24\n");
        File.Copy(Path.Combine(FixturesDir, "pingpong-briefing.md"),
            Path.Combine(scopeDir, "briefing.md"));
        File.Copy(Path.Combine(FixturesDir, "pingpong-attack-graph.yaml"),
            Path.Combine(scopeDir, "attack-graph.yaml"));

        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"acceptance-{Guid.NewGuid():N}.jsonl");
        ScaffoldingContext ctx;
        using (var audit = new AuditLog(auditPath))
        {
            ctx = ScaffoldingDiscovery.Load(scopeFile, null, null, false, audit);
            ctx.ActivateKnownNodes();
            ctx.RejectIfAntiGoal("password_spray:dc01:445");
            _ = ctx.PriorityFor("pkinit:dc01:88");
        }
        return (auditPath, ctx);
    }

    [Fact]
    public void ExactlyOneBriefingIngested()
    {
        var (path, _) = Run();
        var lines = File.ReadAllLines(path);
        var count = lines.Count(l => l.Contains("\"event\":\"briefing.ingested\""));
        Assert.Equal(1, count);
    }

    [Fact]
    public void ExactlyOneAttackGraphLoaded()
    {
        var (path, _) = Run();
        var lines = File.ReadAllLines(path);
        var count = lines.Count(l => l.Contains("\"event\":\"attack_graph.loaded\""));
        Assert.Equal(1, count);
    }

    [Fact]
    public void NoFallback127Event()
    {
        var (path, _) = Run();
        var content = File.ReadAllText(path);
        Assert.DoesNotContain("\"event\":\"vpn.htb_host.fallback_127\"", content);
    }

    [Fact]
    public void EveryKnownNodeIsActivated()
    {
        var (path, ctx) = Run();
        var content = File.ReadAllText(path);
        foreach (var node in ctx.Graph!.Nodes
            .Where(n => string.Equals(n.State, "known", StringComparison.OrdinalIgnoreCase)))
        {
            Assert.Contains($"\"node_id\":\"{node.Id}\"", content);
        }
    }

    [Fact]
    public void AntiGoalBlockEmittedWhenMatched()
    {
        var (path, _) = Run();
        var content = File.ReadAllText(path);
        Assert.Contains("\"event\":\"attack_graph.anti_goal.blocked\"", content);
    }

    [Fact]
    public void PriorityHintAppliedEmitted()
    {
        var (path, _) = Run();
        var content = File.ReadAllText(path);
        Assert.Contains("\"event\":\"attack_graph.priority_hint.applied\"", content);
    }

    [Fact]
    public void AssumedBreachArtifactSurfacedAsBriefingSource()
    {
        var (path, _) = Run();
        var content = File.ReadAllText(path);
        Assert.Contains("\"source\":\"briefing\"", content);
    }
}
