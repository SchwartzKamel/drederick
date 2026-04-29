using System.Text.Json;
using System.Text.Json.Serialization;
using Drederick.Exploit;
using Drederick.Recon;

namespace Drederick.Memory;

/// <summary>
/// A host discovered from inside a pivot session. Kept in <see cref="KnowledgeBase.PivotFindings"/>
/// so a later run can focus on the pivot-reachable subnet without re-sweeping it.
/// </summary>
public sealed class PivotKbEntry
{
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("ip")] public string Ip { get; set; } = "";
    [JsonPropertyName("reachable")] public bool Reachable { get; set; }
    [JsonPropertyName("open_ports")] public List<int> OpenPorts { get; set; } = new();
    [JsonPropertyName("banner")] public string? Banner { get; set; }
    [JsonPropertyName("discovered_at")] public string DiscoveredAt { get; set; } = "";
}

/// <summary>
/// Cross-run knowledge base. The agent reads prior findings on startup and
/// persists updated findings when the run completes. This is how the harness
/// "learns from findings and engages" across invocations: a subsequent run
/// against the same targets starts with yesterday's map in hand, so the agent
/// can focus on deltas, unexplored services, and expired certs rather than
/// re-discovering the entire surface.
/// </summary>
public sealed class KnowledgeBase
{
    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("updated")]
    public string Updated { get; set; } = DateTimeOffset.UtcNow.ToString("o");

    [JsonPropertyName("hosts")]
    public Dictionary<string, HostFinding> Hosts { get; set; } = new();

    [JsonPropertyName("pivot_findings")]
    public List<PivotKbEntry> PivotFindings { get; set; } = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    // Guards mutation of <see cref="Hosts"/> so concurrent <see cref="Merge"/>
    // calls from the worker pool are safe. Reads on a quiesced KB (post-pool)
    // are lock-free because all writers have joined by then, but we take the
    // lock in Merge / Save for belt-and-braces.
    private readonly Lock _gate = new();

    public static KnowledgeBase Load(string path)
    {
        if (!File.Exists(path)) return new KnowledgeBase();
        try
        {
            var text = File.ReadAllText(path);
            return JsonSerializer.Deserialize<KnowledgeBase>(text, JsonOpts) ?? new KnowledgeBase();
        }
        catch (JsonException)
        {
            // Corrupt memory must not take down a run; start fresh.
            return new KnowledgeBase();
        }
    }

    public void Save(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        string json;
        lock (_gate)
        {
            Updated = DateTimeOffset.UtcNow.ToString("o");
            json = JsonSerializer.Serialize(this, JsonOpts);
        }
        File.WriteAllText(path, json);
    }

    /// <summary>Merge new findings into the knowledge base. New data supersedes old for overlapping fields.</summary>
    public void Merge(IEnumerable<HostFinding> findings)
    {
        lock (_gate)
        {
            foreach (var f in findings)
            {
                Hosts[f.Target] = f;
            }
        }
    }

    /// <summary>
    /// Record a host discovered from inside a pivot session. The finding is tagged
    /// <c>source: "session:&lt;id&gt;"</c> so a consumer can filter pivot-derived
    /// discoveries from externally-scanned hosts.
    /// </summary>
    public void AddPivotFinding(string sourceSessionId, PivotTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        var entry = new PivotKbEntry
        {
            Source = $"session:{sourceSessionId}",
            Ip = target.Ip,
            Reachable = target.Reachable,
            OpenPorts = target.OpenPorts.ToList(),
            Banner = target.Banner,
            DiscoveredAt = DateTimeOffset.UtcNow.ToString("o"),
        };
        lock (_gate)
        {
            PivotFindings.Add(entry);
        }
    }

    /// <summary>Pivot findings whose <c>Source</c> tag matches <paramref name="sourceTag"/> (e.g. <c>session:abc</c>).</summary>
    public IReadOnlyList<PivotKbEntry> FindPivotsBySource(string sourceTag)
    {
        lock (_gate)
        {
            return PivotFindings.Where(p => p.Source == sourceTag).ToList();
        }
    }

    /// <summary>A short human-readable digest of prior knowledge for a target, suitable for agent context.</summary>
    public string Digest(string target)
    {
        if (!Hosts.TryGetValue(target, out var f)) return "(no prior findings)";
        var openPorts = f.Nmap?.OpenPorts ?? [];
        if (openPorts.Count == 0) return $"prior scan at {f.Finished}: no open ports";
        var parts = openPorts.Select(p => $"{p.Port}/{p.Service ?? "?"}");
        return $"prior scan at {f.Finished}: " + string.Join(", ", parts);
    }

    /// <summary>Record the successful execution of an Empire module on a target.</summary>
    public void RecordEmpireModuleSuccess(string host, string moduleName, string output)
    {
        lock (_gate)
        {
            if (!Hosts.TryGetValue(host, out var finding))
            {
                finding = new HostFinding { Target = host };
                Hosts[host] = finding;
            }

            if (finding.EmpireModuleResults == null)
                finding.EmpireModuleResults = new();

            finding.EmpireModuleResults.Add(new()
            {
                ModuleName = moduleName,
                Output = output,
                ExecutedAt = DateTimeOffset.UtcNow.ToString("o"),
                Success = true
            });
        }
    }
}
