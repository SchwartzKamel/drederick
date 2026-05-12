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

    /// <summary>
    /// SharpHound / BloodHound ingest output. Populated by
    /// <see cref="Drederick.Memory.SharpHoundIngest"/> and consumed by
    /// the planner to prioritize follow-ups (kerberoastable users get
    /// fed to <c>KerberoastTool</c>; AS-REP-roastable users get fed to
    /// <c>AsRepRoastTool</c>; unconstrained-delegation hosts move to
    /// the front of the post-ex queue).
    /// </summary>
    [JsonPropertyName("bloodhound")]
    public BloodhoundFindings? Bloodhound { get; set; }
    /// Cross-host engagement-wide facts. Used by chain-template
    /// substitution as the third (and final) lookup tier behind per-
    /// host findings and per-service findings. Example keys:
    /// <c>engagement.name</c>, <c>operator.callsign</c>,
    /// <c>payloads.wp_image</c>.
    /// </summary>
    [JsonPropertyName("globals")]
    public Dictionary<string, string> Globals { get; set; } = new(StringComparer.Ordinal);

    // --- htb-briefing-loader-recon-seed ---
    /// <summary>
    /// Operator-supplied briefing seed (targets, users, credentials,
    /// constraints, notes). Populated by
    /// <see cref="MergeFromBriefing"/> before recon starts. Targets in
    /// the briefing are hints — they do NOT grant scope; tools still
    /// re-check via <c>_scope.Require</c>. Plaintext passwords are
    /// never stored — only SHA-256 digests. See
    /// <see cref="BriefingLoader"/>.
    /// </summary>
    [JsonPropertyName("briefing")]
    public BriefingSeed? Briefing { get; set; }
    // --- end htb-briefing-loader-recon-seed ---

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

    /// <summary>
    /// Ingest a SharpHound zip into the knowledge base. The full
    /// <see cref="BloodhoundFindings"/> is stored under
    /// <see cref="Bloodhound"/>; subsequent calls append into the
    /// existing bucket so multiple SharpHound runs can be merged.
    /// Thread-safe.
    /// </summary>
    public BloodhoundIngestResult IngestSharpHoundZip(string zipPath)
    {
        lock (_gate)
        {
            Bloodhound ??= new BloodhoundFindings();
            return SharpHoundIngest.IngestZip(zipPath, Bloodhound);
        }
    }

    /// <summary>
    /// Ingest a single SharpHound JSON file. Same merge semantics as
    /// <see cref="IngestSharpHoundZip"/>.
    /// </summary>
    public BloodhoundIngestResult IngestSharpHoundJsonFile(string jsonPath)
    {
        lock (_gate)
        {
            Bloodhound ??= new BloodhoundFindings();
            return SharpHoundIngest.IngestJsonFile(jsonPath, Bloodhound);
        }
    }

    /// <summary>
    /// Source tier that satisfied a <see cref="TryResolve"/> call. Used
    /// by the chain-template KB substitution layer to audit *where* a
    /// value came from without recording the value itself.
    /// </summary>
    public enum ResolveSource
    {
        NotFound = 0,
        TargetFindings = 1,
        ServiceFindings = 2,
        Globals = 3,
    }

    /// <summary>
    /// Resolve a dotted KB path against the standard tiers used by
    /// chain-template <c>{kb.&lt;path&gt;}</c> substitution:
    /// per-target findings → per-service findings (via the
    /// <c>services.&lt;port&gt;.</c> key prefix on the host findings
    /// dictionary) → engagement <see cref="Globals"/>.
    ///
    /// Built-in synthetics are exposed for typed fields so chain
    /// templates can reference <c>cms.name</c> / <c>cms.version</c>
    /// without the recon side having to also flat-write them — the
    /// <see cref="Drederick.Recon.CmsFinding"/> already populated by
    /// the CMS fingerprinter is consulted directly.
    ///
    /// Returns the source tier on hit; <see cref="ResolveSource.NotFound"/>
    /// when no tier carries the path.
    /// </summary>
    public ResolveSource TryResolve(string targetHost, int? servicePort, string dottedPath, out string? value)
    {
        value = null;
        if (string.IsNullOrEmpty(dottedPath)) return ResolveSource.NotFound;
        lock (_gate)
        {
            if (!string.IsNullOrEmpty(targetHost) && Hosts.TryGetValue(targetHost, out var hf))
            {
                if (servicePort.HasValue)
                {
                    var svcKey = $"services.{servicePort.Value}.{dottedPath}";
                    if (hf.Findings.TryGetValue(svcKey, out var svcVal))
                    {
                        value = svcVal;
                        return ResolveSource.ServiceFindings;
                    }
                }
                if (hf.Findings.TryGetValue(dottedPath, out var hostVal))
                {
                    value = hostVal;
                    return ResolveSource.TargetFindings;
                }
                if (TryResolveBuiltinSynthetic(hf, dottedPath, out var synthVal))
                {
                    value = synthVal;
                    return ResolveSource.TargetFindings;
                }
            }
            if (Globals.TryGetValue(dottedPath, out var gVal))
            {
                value = gVal;
                return ResolveSource.Globals;
            }
        }
        return ResolveSource.NotFound;
    }

    private static bool TryResolveBuiltinSynthetic(HostFinding hf, string dottedPath, out string? value)
    {
        value = null;
        // CMS fingerprint: cms.name / cms.version / cms.base_url /
        // cms.confidence — first match (highest-confidence is sorted
        // first by the fingerprinter; we just take element 0).
        if (dottedPath.StartsWith("cms.", StringComparison.Ordinal)
            && hf.CmsFingerprint.Count > 0)
        {
            var first = hf.CmsFingerprint[0];
            var leaf = dottedPath["cms.".Length..];
            switch (leaf)
            {
                case "base_url": value = first.BaseUrl; return true;
            }
            if (first.Matches.Count > 0)
            {
                var m = first.Matches[0];
                switch (leaf)
                {
                    case "name": value = m.Name; return true;
                    case "version": value = m.Version ?? ""; return true;
                    case "confidence": value = m.Confidence.ToString(System.Globalization.CultureInfo.InvariantCulture); return true;
                }
            }
        }
        return false;
    }

    // --- htb-briefing-delta-proposed --- (GAP-051)
    /// <summary>
    /// Fired when a high-signal finding is observed (severity &gt;= High
    /// or a CVE match was added). Subscribers — typically
    /// <see cref="Drederick.Briefing.DeltaEmitter"/> — turn the delta
    /// into a <c>briefing.delta.proposed</c> audit event. Additive
    /// hook: invocation is opt-in via <see cref="RaiseHighSignal"/>
    /// and does not change <see cref="Merge"/> semantics.
    /// </summary>
    public event Action<Drederick.Briefing.BriefingDelta>? OnHighSignalFinding;

    /// <summary>
    /// Notify subscribers of a high-signal delta. No-op when no
    /// listeners are attached. Callers are responsible for ensuring
    /// the delta carries only metadata (no plaintext credentials).
    /// </summary>
    public void RaiseHighSignal(Drederick.Briefing.BriefingDelta delta)
    {
        ArgumentNullException.ThrowIfNull(delta);
        OnHighSignalFinding?.Invoke(delta);
    }
    // --- end htb-briefing-delta-proposed ---

    // --- htb-briefing-loader-recon-seed ---
    /// <summary>
    /// Merge a <see cref="BriefingSeed"/> into the knowledge base. The
    /// seed replaces any previously-stored briefing for this run. Users
    /// and constraints are also surfaced into <see cref="Globals"/>
    /// under <c>briefing.users.*</c> / <c>briefing.constraints.*</c>
    /// so chain-template KB substitution can reach them via the
    /// existing globals tier. The seed itself is the authoritative
    /// store.
    /// </summary>
    public void MergeFromBriefing(BriefingSeed seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        lock (_gate)
        {
            Briefing = seed;
            Globals["briefing.source_path"] = seed.SourcePath;
            Globals["briefing.sha256"] = seed.Sha256;
            Globals["briefing.target_count"] = seed.Targets.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
            Globals["briefing.user_count"] = seed.Users.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
            Globals["briefing.cred_count"] = seed.Credentials.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
            for (int i = 0; i < seed.Users.Count; i++)
            {
                Globals[$"briefing.users.{i}"] = seed.Users[i];
            }
            for (int i = 0; i < seed.Constraints.Count; i++)
            {
                Globals[$"briefing.constraints.{i}"] = seed.Constraints[i];
            }
        }
    }
    // --- end htb-briefing-loader-recon-seed ---

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
