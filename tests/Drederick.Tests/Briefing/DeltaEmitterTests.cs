using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Briefing;
using Drederick.Memory;
using Xunit;

namespace Drederick.Tests.Briefing;

public sealed class DeltaEmitterTests : IDisposable
{
    private readonly string _root;
    private readonly string _auditPath;
    private readonly string _jsonlPath;
    private readonly AuditLog _audit;

    public DeltaEmitterTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "drederick-briefing-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _auditPath = Path.Combine(_root, "audit.jsonl");
        _jsonlPath = Path.Combine(_root, "briefing-deltas.jsonl");
        _audit = new AuditLog(_auditPath);
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_root, recursive: true); } catch { /* best-effort */ }
    }

    private DeltaEmitter NewEmitter(BriefingSeverity threshold = BriefingSeverity.High) =>
        new DeltaEmitter(_audit, _jsonlPath, threshold);

    [Fact]
    public void HighSeverity_Finding_Emits_Delta()
    {
        var emitter = NewEmitter();
        var delta = new BriefingDelta
        {
            Target = "10.10.10.5",
            Kind = BriefingDeltaKind.CveMatch,
            Severity = BriefingSeverity.High,
            SummaryText = "CVE-2024-1234 matched on httpd/2.4.49",
            EvidenceRefs = new() { "audit:abc123", "out/10.10.10.5/http.json" },
        };

        var admitted = emitter.Emit(delta);

        Assert.True(admitted);
        Assert.True(File.Exists(_jsonlPath));
        var line = File.ReadAllText(_jsonlPath).Trim();
        Assert.Contains("\"target\":\"10.10.10.5\"", line);
        Assert.Contains("\"kind\":\"CveMatch\"", line);
        Assert.Contains("\"severity\":\"High\"", line);
    }

    [Fact]
    public void LowSeverity_Finding_Is_Suppressed_By_Default_Threshold()
    {
        var emitter = NewEmitter();
        var delta = new BriefingDelta
        {
            Target = "10.10.10.5",
            Kind = BriefingDeltaKind.CveMatch,
            Severity = BriefingSeverity.Medium,
            SummaryText = "noisy advisory",
            EvidenceRefs = new() { "audit:zzz" },
        };

        var admitted = emitter.Emit(delta);

        Assert.False(admitted);
        Assert.False(File.Exists(_jsonlPath)); // never opened
        var auditText = File.ReadAllText(_auditPath);
        Assert.DoesNotContain("briefing.delta.proposed", auditText);
    }

    [Fact]
    public void Threshold_Is_Configurable_Down_To_Medium()
    {
        var emitter = NewEmitter(BriefingSeverity.Medium);
        var delta = new BriefingDelta
        {
            Target = "10.10.10.6",
            Kind = BriefingDeltaKind.PrivescPath,
            Severity = BriefingSeverity.Medium,
            SummaryText = "sudo NOPASSWD finding",
            EvidenceRefs = new() { "out/10.10.10.6/sudoers" },
        };

        Assert.True(emitter.Emit(delta));
        Assert.Contains("PrivescPath", File.ReadAllText(_jsonlPath));
    }

    [Fact]
    public void Emitted_Delta_Appears_In_Audit_Log()
    {
        var emitter = NewEmitter();
        emitter.Emit(new BriefingDelta
        {
            Target = "10.10.10.7",
            Kind = BriefingDeltaKind.NewSession,
            Severity = BriefingSeverity.Critical,
            SummaryText = "Meterpreter session opened",
            EvidenceRefs = new() { "out/sessions/session-1.json" },
        });

        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("briefing.delta.proposed", auditText);
        Assert.Contains("\"target\":\"10.10.10.7\"", auditText);
        Assert.Contains("\"kind\":\"NewSession\"", auditText);
        Assert.Contains("\"severity\":\"Critical\"", auditText);
        Assert.Contains("evidence_sha256", auditText);
    }

    [Fact]
    public void Plaintext_Credential_Never_Appears_In_Delta_Or_Audit()
    {
        const string canary = "S3cretP@ssw0rdCANARY_xyz123";
        var emitter = NewEmitter();

        // For new_credential we record only the count + safe evidence
        // references — never the plaintext value. The BriefingDelta
        // type intentionally has no field that could carry it.
        emitter.Emit(new BriefingDelta
        {
            Target = "10.10.10.8",
            Kind = BriefingDeltaKind.NewCredential,
            Severity = BriefingSeverity.High,
            SummaryText = "captured 1 credential for svc_sql",
            // Evidence ref intentionally references a digest, not the value.
            EvidenceRefs = new() { "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canary))).ToLowerInvariant() },
            CredentialCount = 1,
        });

        var auditText = File.ReadAllText(_auditPath);
        var jsonlText = File.ReadAllText(_jsonlPath);

        Assert.DoesNotContain(canary, auditText);
        Assert.DoesNotContain(canary, jsonlText);
        Assert.Contains("\"credential_count\":1", jsonlText);
    }

    [Fact]
    public void Evidence_Sha256_Is_Stable_And_Hex()
    {
        var emitter = NewEmitter();
        var refs = new List<string> { "audit:1", "audit:2", "out/foo.json" };
        emitter.Emit(new BriefingDelta
        {
            Target = "10.10.10.9",
            Kind = BriefingDeltaKind.Loot,
            Severity = BriefingSeverity.High,
            SummaryText = "loot file collected",
            EvidenceRefs = refs,
        });

        var expected = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\0', refs)))
        ).ToLowerInvariant();

        var line = File.ReadAllText(_jsonlPath);
        Assert.Contains($"\"evidence_sha256\":\"{expected}\"", line);
        Assert.Matches("\"evidence_sha256\":\"[0-9a-f]{64}\"", line);
    }

    [Fact]
    public void Emitter_Is_Thread_Safe_Under_Concurrent_Emit()
    {
        var emitter = NewEmitter();
        const int workers = 16;
        const int perWorker = 25;
        var errors = new ConcurrentBag<Exception>();

        Parallel.For(0, workers, w =>
        {
            for (int i = 0; i < perWorker; i++)
            {
                try
                {
                    emitter.Emit(new BriefingDelta
                    {
                        Target = $"10.10.10.{w}",
                        Kind = BriefingDeltaKind.CveMatch,
                        Severity = BriefingSeverity.High,
                        SummaryText = $"finding {w}-{i}",
                        EvidenceRefs = new() { $"audit:{w}-{i}" },
                    });
                }
                catch (Exception ex) { errors.Add(ex); }
            }
        });

        Assert.Empty(errors);
        var lines = File.ReadAllLines(_jsonlPath);
        Assert.Equal(workers * perWorker, lines.Length);
        // Every line must be valid JSON terminated by a single newline —
        // no torn writes from concurrent appends.
        foreach (var line in lines)
        {
            Assert.StartsWith("{", line);
            Assert.EndsWith("}", line);
        }
    }

    [Fact]
    public void KnowledgeBase_OnHighSignalFinding_Routes_To_Emitter()
    {
        var emitter = NewEmitter();
        var kb = new KnowledgeBase();
        kb.OnHighSignalFinding += d => emitter.Emit(d);

        kb.RaiseHighSignal(new BriefingDelta
        {
            Target = "10.10.10.10",
            Kind = BriefingDeltaKind.CveMatch,
            Severity = BriefingSeverity.Critical,
            SummaryText = "RCE matched",
            EvidenceRefs = new() { "audit:rce-1" },
        });

        Assert.Contains("briefing.delta.proposed", File.ReadAllText(_auditPath));
    }
}
