using System.IO;
using System.Linq;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Scaffolding;
using Xunit;

namespace Drederick.Tests.Scaffolding;

/// <summary>
/// GAP-049 (htb-pivot-blind, Part 2): the briefing's <c>## 1. Topology</c>
/// table must pre-seed <c>attack_graph.node.activated source: briefing</c>
/// audit events so the planner has a target set even when direct scans
/// see nothing through the cornerman's chisel SOCKS hop.
/// </summary>
public class BriefingTopologySeedTests
{
    private static string FixturesDir =>
        Path.Combine(AppContext.BaseDirectory, "Scaffolding", "Fixtures");

    private static (BriefingDocument? doc, string auditPath) LoadFixture(string filename)
    {
        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"topology-seed-{Guid.NewGuid():N}.jsonl");
        using var audit = new AuditLog(auditPath);
        var src = Path.Combine(FixturesDir, filename);
        var doc = BriefingLoader.LoadOrAbsent(src, Path.GetTempPath(), audit);
        audit.Dispose();
        return (doc, auditPath);
    }

    private static System.Collections.Generic.List<JsonElement> ReadEvents(string path)
    {
        var events = new System.Collections.Generic.List<JsonElement>();
        if (!File.Exists(path)) return events;
        foreach (var line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            events.Add(doc.RootElement.Clone());
        }
        return events;
    }

    [Fact]
    public void ParsesTopologyTable_FromPterodactylFixture()
    {
        var (doc, _) = LoadFixture(Path.Combine("briefing", "pterodactyl-trimmed.md"));
        Assert.NotNull(doc);
        Assert.Equal(3, doc!.TopologyEntries.Count);
        var hosts = doc.TopologyEntries.Select(e => e.Hostname).ToList();
        Assert.Contains("pterodactyl.htb", hosts);
        Assert.Contains("panel.pterodactyl.htb", hosts);
        Assert.Contains("play.pterodactyl.htb", hosts);
        var pter = doc.TopologyEntries.First(e => e.Hostname == "pterodactyl.htb");
        Assert.Equal("10.129.31.77", pter.Ip);
        Assert.Contains("Public site", pter.Role!);
    }

    [Fact]
    public void ActivateKnownNodes_EmitsBriefingSourcedEvent_PerTopologyRow()
    {
        var (doc, _) = LoadFixture(Path.Combine("briefing", "pterodactyl-trimmed.md"));
        Assert.NotNull(doc);

        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"topology-activate-{System.Guid.NewGuid():N}.jsonl");
        using (var audit = new AuditLog(auditPath))
        {
            var ctx = new ScaffoldingContext(doc, graph: null, audit);
            ctx.ActivateKnownNodes();
        }

        var activated = ReadEvents(auditPath)
            .Where(e => e.GetProperty("event").GetString() == "attack_graph.node.activated")
            .Where(e => e.TryGetProperty("source", out var s) && s.GetString() == "briefing")
            .Where(e => e.TryGetProperty("kind", out var k) && k.GetString() == "host")
            .ToList();

        Assert.Equal(3, activated.Count);
        var ids = activated.Select(e => e.GetProperty("node_id").GetString()).ToHashSet();
        Assert.Contains("pterodactyl.htb", ids);
        Assert.Contains("panel.pterodactyl.htb", ids);
        Assert.Contains("play.pterodactyl.htb", ids);
        File.Delete(auditPath);
    }

    [Fact]
    public void ActivateKnownNodes_Idempotent()
    {
        var (doc, _) = LoadFixture(Path.Combine("briefing", "pterodactyl-trimmed.md"));
        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"topology-idempotent-{System.Guid.NewGuid():N}.jsonl");
        using (var audit = new AuditLog(auditPath))
        {
            var ctx = new ScaffoldingContext(doc, graph: null, audit);
            ctx.ActivateKnownNodes();
            ctx.ActivateKnownNodes();
        }
        var count = ReadEvents(auditPath)
            .Count(e => e.GetProperty("event").GetString() == "attack_graph.node.activated"
                        && e.TryGetProperty("source", out var s) && s.GetString() == "briefing");
        Assert.Equal(3, count);
        File.Delete(auditPath);
    }

    [Fact]
    public void ParsesTopologyTable_DedupesByHostname()
    {
        var dup = "## 1. Topology\n\n| Hostname | IP |\n|---|---|\n| a.htb | 1.1.1.1 |\n| a.htb | 2.2.2.2 |\n| b.htb | 3.3.3.3 |\n";
        var entries = BriefingLoader.ParseTopologyTable(dup).ToList();
        Assert.Equal(2, entries.Count);
        Assert.Equal("a.htb", entries[0].Hostname);
        Assert.Equal("1.1.1.1", entries[0].Ip);
        Assert.Equal("b.htb", entries[1].Hostname);
    }

    [Fact]
    public void ParsesTopologyTable_SkipsRowsWithEmptyHostname()
    {
        var malformed = "## 1. Topology\n\n| Hostname | IP |\n|---|---|\n|  | 1.1.1.1 |\n| good.htb | 2.2.2.2 |\n";
        var entries = BriefingLoader.ParseTopologyTable(malformed).ToList();
        Assert.Single(entries);
        Assert.Equal("good.htb", entries[0].Hostname);
    }

    [Fact]
    public void ActivateKnownNodes_EmitsNoBriefingEvents_WhenTopologyAbsent()
    {
        var (doc, _) = LoadFixture("pingpong-briefing.md");
        Assert.NotNull(doc);
        Assert.Empty(doc!.TopologyEntries); // no markdown table in this fixture
        var auditPath = Path.Combine(AppContext.BaseDirectory,
            $"topology-absent-{System.Guid.NewGuid():N}.jsonl");
        using (var audit = new AuditLog(auditPath))
        {
            var ctx = new ScaffoldingContext(doc, graph: null, audit);
            ctx.ActivateKnownNodes();
        }
        var briefingActivations = ReadEvents(auditPath)
            .Count(e => e.GetProperty("event").GetString() == "attack_graph.node.activated"
                        && e.TryGetProperty("source", out var s) && s.GetString() == "briefing"
                        && e.TryGetProperty("kind", out var k) && k.GetString() == "host");
        Assert.Equal(0, briefingActivations);
        File.Delete(auditPath);
    }
}
