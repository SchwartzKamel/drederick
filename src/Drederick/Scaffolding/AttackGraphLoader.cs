using Drederick.Audit;
using YamlDotNet.RepresentationModel;

namespace Drederick.Scaffolding;

/// <summary>
/// Discovers and parses <c>attack-graph.yaml</c> per
/// <c>machines/SCAFFOLDING/LOADER_SPEC.md</c> §2 + §3.2.
/// </summary>
public static class AttackGraphLoader
{
    private const int CurrentSchemaVersion = 1;

    private static readonly HashSet<string> KnownKinds = new(StringComparer.OrdinalIgnoreCase)
    { "host", "service", "credential", "session", "flag", "identity", "artifact" };
    private static readonly HashSet<string> KnownStates = new(StringComparer.OrdinalIgnoreCase)
    { "unknown", "suspected", "known", "owned", "blocked" };

    public static AttackGraph? LoadOrAbsent(
        string? overridePath,
        string scopeDir,
        AuditLog audit)
    {
        string? path = null;
        if (!string.IsNullOrWhiteSpace(overridePath) && File.Exists(overridePath)) path = overridePath;
        if (path is null)
        {
            var candidate = Path.Combine(scopeDir, "attack-graph.yaml");
            if (File.Exists(candidate)) path = candidate;
        }
        if (path is null) return null;

        string text;
        try { text = File.ReadAllText(path); }
        catch (Exception ex)
        {
            audit.Record("attack_graph.skipped", new Dictionary<string, object?>
            {
                ["path"] = path,
                ["reason"] = "missing",
                ["error"] = ex.Message,
            });
            return null;
        }

        var sha = BriefingLoader.Sha256(text);
        audit.Record("attack_graph.discovered", new Dictionary<string, object?>
        {
            ["path"] = path,
            ["sha256"] = sha,
        });

        YamlMappingNode root;
        try
        {
            var stream = new YamlStream();
            stream.Load(new StringReader(text));
            if (stream.Documents.Count == 0)
                throw new FormatException("empty document");
            root = (YamlMappingNode)stream.Documents[0].RootNode;
        }
        catch (Exception ex)
        {
            audit.Record("attack_graph.skipped", new Dictionary<string, object?>
            {
                ["path"] = path,
                ["reason"] = "invalid",
                ["error"] = ex.Message,
            });
            return null;
        }

        int schemaVersion;
        try { schemaVersion = int.Parse(Scalar(root, "schema_version") ?? "0"); }
        catch
        {
            audit.Record("attack_graph.skipped", new Dictionary<string, object?>
            {
                ["path"] = path,
                ["reason"] = "invalid",
                ["error"] = "schema_version not an integer",
            });
            return null;
        }
        if (schemaVersion != CurrentSchemaVersion)
        {
            audit.Record("attack_graph.skipped", new Dictionary<string, object?>
            {
                ["path"] = path,
                ["reason"] = "version_unsupported",
                ["error"] = schemaVersion.ToString(),
            });
            return null;
        }

        var box = Scalar(root, "box") ?? "";
        var nodes = new List<AttackGraphNode>();
        if (root.Children.TryGetValue(new YamlScalarNode("nodes"), out var nodesNode) && nodesNode is YamlSequenceNode nseq)
        {
            foreach (var n in nseq.Children.OfType<YamlMappingNode>())
            {
                var id = Scalar(n, "id") ?? "";
                var kind = Scalar(n, "kind") ?? "";
                var state = Scalar(n, "state") ?? "";
                if (!string.IsNullOrEmpty(kind) && !KnownKinds.Contains(kind))
                    audit.Record("attack_graph.vocab.unknown", new Dictionary<string, object?>
                    { ["field"] = "kind", ["value"] = kind, ["node_id"] = id });
                if (!string.IsNullOrEmpty(state) && !KnownStates.Contains(state))
                    audit.Record("attack_graph.vocab.unknown", new Dictionary<string, object?>
                    { ["field"] = "state", ["value"] = state, ["node_id"] = id });
                var method = Scalar(n, "method");
                nodes.Add(new AttackGraphNode(
                    id, kind, state,
                    StringList(n, "requires"),
                    StringList(n, "yields"),
                    Scalar(n, "artifact"),
                    Scalar(n, "note"),
                    method,
                    Scalar(n, "tool")));
            }
        }

        var edges = new List<AttackGraphEdge>();
        if (root.Children.TryGetValue(new YamlScalarNode("edges"), out var edgesNode) && edgesNode is YamlSequenceNode eseq)
        {
            foreach (var e in eseq.Children.OfType<YamlMappingNode>())
            {
                edges.Add(new AttackGraphEdge(
                    Scalar(e, "from") ?? "",
                    Scalar(e, "to") ?? "",
                    Scalar(e, "method"),
                    Scalar(e, "note")));
            }
        }

        var hints = new List<PriorityHint>();
        if (root.Children.TryGetValue(new YamlScalarNode("priority_hints"), out var hNode) && hNode is YamlSequenceNode hseq)
        {
            foreach (var h in hseq.Children.OfType<YamlMappingNode>())
            {
                hints.Add(new PriorityHint(
                    Scalar(h, "prefer") ?? "",
                    Scalar(h, "over"),
                    Scalar(h, "reason"),
                    Scalar(h, "applies_to_action")));
            }
        }

        var antis = new List<AntiGoal>();
        if (root.Children.TryGetValue(new YamlScalarNode("anti_goals"), out var aNode) && aNode is YamlSequenceNode aseq)
        {
            foreach (var a in aseq.Children.OfType<YamlMappingNode>())
            {
                antis.Add(new AntiGoal(
                    Scalar(a, "id") ?? Scalar(a, "name") ?? "",
                    Scalar(a, "reason") ?? "",
                    StringList(a, "patterns").Concat(StringList(a, "match")).ToList()));
            }
        }

        AttackBudget? budget = null;
        if (root.Children.TryGetValue(new YamlScalarNode("budget"), out var bNode) && bNode is YamlMappingNode bMap)
        {
            int? mm = int.TryParse(Scalar(bMap, "max_minutes"), out var mmv) ? mmv : null;
            int? ma = int.TryParse(Scalar(bMap, "max_actions"), out var mav) ? mav : null;
            budget = new AttackBudget(mm, ma);
        }

        var graph = new AttackGraph(
            schemaVersion, box, nodes, edges, hints, antis, budget,
            Scalar(root, "generated_by"),
            Scalar(root, "last_updated"),
            path, sha);

        audit.Record("attack_graph.loaded", new Dictionary<string, object?>
        {
            ["path"] = path,
            ["sha256"] = sha,
            ["schema_version"] = schemaVersion,
            ["node_count"] = nodes.Count,
            ["edge_count"] = edges.Count,
        });
        return graph;
    }

    private static string? Scalar(YamlMappingNode m, string key)
    {
        if (m.Children.TryGetValue(new YamlScalarNode(key), out var v) && v is YamlScalarNode s)
            return s.Value;
        return null;
    }

    private static List<string> StringList(YamlMappingNode m, string key)
    {
        var list = new List<string>();
        if (m.Children.TryGetValue(new YamlScalarNode(key), out var v) && v is YamlSequenceNode seq)
        {
            foreach (var e in seq.Children.OfType<YamlScalarNode>())
                if (e.Value is not null) list.Add(e.Value);
        }
        return list;
    }
}
