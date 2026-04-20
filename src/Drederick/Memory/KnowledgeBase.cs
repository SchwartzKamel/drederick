using System.Text.Json;
using System.Text.Json.Serialization;
using Drederick.Recon;

namespace Drederick.Memory;

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

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

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
        Updated = DateTimeOffset.UtcNow.ToString("o");
        File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOpts));
    }

    /// <summary>Merge new findings into the knowledge base. New data supersedes old for overlapping fields.</summary>
    public void Merge(IEnumerable<HostFinding> findings)
    {
        foreach (var f in findings)
        {
            Hosts[f.Target] = f;
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
}
