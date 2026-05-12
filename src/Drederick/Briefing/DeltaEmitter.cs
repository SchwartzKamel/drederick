using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Drederick.Audit;

namespace Drederick.Briefing;

/// <summary>
/// Emits <see cref="BriefingDelta"/> events for the operator briefing
/// pane (GAP-051). Filters by <see cref="Threshold"/>, audits each
/// admitted delta as <c>briefing.delta.proposed</c> with a SHA-256
/// digest of <see cref="BriefingDelta.EvidenceRefs"/>, and appends
/// the delta as a JSON line to <see cref="JsonlPath"/>
/// (default <c>out/briefing-deltas.jsonl</c>).
/// <para>
/// Thread-safe. No plaintext credentials, session tokens, or captured
/// secret material ever traverse this emitter — the
/// <see cref="BriefingDelta"/> type has no field to carry them, and
/// the audit payload records only the evidence digest and the typed
/// metadata.
/// </para>
/// </summary>
public sealed class DeltaEmitter
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
    };

    private readonly AuditLog _audit;
    private readonly Lock _gate = new();

    public string JsonlPath { get; }

    /// <summary>Minimum severity admitted. Defaults to
    /// <see cref="BriefingSeverity.High"/>.</summary>
    public BriefingSeverity Threshold { get; }

    public DeltaEmitter(AuditLog audit, string jsonlPath, BriefingSeverity threshold = BriefingSeverity.High)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (string.IsNullOrWhiteSpace(jsonlPath))
            throw new ArgumentException("jsonlPath must be non-empty", nameof(jsonlPath));
        _audit = audit;
        JsonlPath = jsonlPath;
        Threshold = threshold;

        var dir = Path.GetDirectoryName(jsonlPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }

    /// <summary>
    /// Submit a delta for emission. Deltas below
    /// <see cref="Threshold"/> are dropped silently and return
    /// <c>false</c>. Admitted deltas are written to the JSONL file
    /// and audited as <c>briefing.delta.proposed</c>.
    /// </summary>
    public bool Emit(BriefingDelta delta)
    {
        ArgumentNullException.ThrowIfNull(delta);
        if (delta.Severity < Threshold) return false;

        var evidenceHash = ComputeEvidenceSha256(delta.EvidenceRefs);
        var line = JsonSerializer.Serialize(new
        {
            timestamp = delta.Timestamp,
            target = delta.Target,
            kind = delta.Kind.ToString(),
            severity = delta.Severity.ToString(),
            summary = delta.SummaryText,
            evidence_refs = delta.EvidenceRefs,
            evidence_sha256 = evidenceHash,
            credential_count = delta.CredentialCount,
        }, JsonOpts);

        lock (_gate)
        {
            File.AppendAllText(JsonlPath, line + Environment.NewLine);
        }

        _audit.Record("briefing.delta.proposed", new Dictionary<string, object?>
        {
            ["target"] = delta.Target,
            ["kind"] = delta.Kind.ToString(),
            ["severity"] = delta.Severity.ToString(),
            ["summary"] = delta.SummaryText,
            ["evidence_sha256"] = evidenceHash,
            ["evidence_ref_count"] = delta.EvidenceRefs.Count,
            ["credential_count"] = delta.CredentialCount,
        });

        return true;
    }

    /// <summary>
    /// Subscribe this emitter to a finding stream. The supplied
    /// classifier converts a raw finding into a candidate delta
    /// (or <c>null</c> to skip). Wiring helper for the adaptive /
    /// autopilot pipeline; tests exercise <see cref="Emit"/>
    /// directly.
    /// </summary>
    public void Attach<TFinding>(Action<Action<TFinding>> subscribe, Func<TFinding, BriefingDelta?> classify)
    {
        ArgumentNullException.ThrowIfNull(subscribe);
        ArgumentNullException.ThrowIfNull(classify);
        subscribe(f =>
        {
            var d = classify(f);
            if (d is not null) Emit(d);
        });
    }

    private static string ComputeEvidenceSha256(IReadOnlyList<string> refs)
    {
        // Canonical form: NUL-joined refs in submitted order. NUL is
        // chosen because it cannot appear in any of the ref shapes we
        // accept (paths, audit ids, hex digests) so concatenation is
        // injection-free.
        var joined = refs.Count == 0 ? string.Empty : string.Join('\0', refs);
        var bytes = Encoding.UTF8.GetBytes(joined);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
