using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests.Autopilot;

/// <summary>
/// GAP-031 — unit tests for <see cref="AutopilotCoverageGuard"/>. Verifies
/// that for every fingerprinted CVE the guard either guarantees a
/// <c>nuclei</c> + <c>msfrc</c> candidate or records a
/// <c>autopilot.planner.coverage_gap</c> audit event.
/// </summary>
public class AutopilotCoverageGuardTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"coverage-guard-{Guid.NewGuid():N}.jsonl");

    private static HostFinding Host(string target = "10.10.10.5") => new() { Target = target };

    private static ExploitAction NucleiAction(string cve, int port = 80) => new()
    {
        Tool = "nuclei",
        Target = "10.10.10.5",
        Port = port,
        Url = $"http://10.10.10.5:{port}",
        CveId = cve,
        Artifact = "/cache/nuclei/" + cve + ".yaml",
        Priority = 500,
    };

    private static ExploitAction MsfAction(string cve, int port = 80) => new()
    {
        Tool = "msfrc",
        Target = "10.10.10.5",
        Port = port,
        Module = "exploit/multi/http/foo",
        CveId = cve,
        Priority = 490,
    };

    private static ExploitAction CveLeadAction(string cve, int port = 80) => new()
    {
        Tool = "cve-lead",
        Target = "10.10.10.5",
        Port = port,
        Url = $"http://10.10.10.5:{port}",
        CveId = cve,
        Priority = 250,
    };

    private static AutopilotCoverageGuard Make(
        AuditLog audit,
        Func<string, IReadOnlyList<string>>? nuclei = null,
        Func<string, IReadOnlyList<string>>? msf = null)
        => new AutopilotCoverageGuard(
            audit,
            cveId => nuclei?.Invoke(cveId) ?? Array.Empty<string>(),
            cveId => msf?.Invoke(cveId) ?? Array.Empty<string>());

    private static bool AuditContains(string path, string evt)
    {
        if (!File.Exists(path)) return false;
        foreach (var line in File.ReadAllLines(path))
        {
            if (line.Contains($"\"event\":\"{evt}\"", StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static int CountAudit(string path, string evt)
    {
        if (!File.Exists(path)) return 0;
        return File.ReadAllLines(path)
            .Count(l => l.Contains($"\"event\":\"{evt}\"", StringComparison.Ordinal));
    }

    [Fact]
    public void Zero_Cves_Skips_Coverage_Check_Entirely()
    {
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);
        var guard = Make(audit);
        var input = new List<ExploitAction>
        {
            new() { Tool = "password-spray", Target = "10.10.10.5", Port = 445, Priority = 200 },
        };

        var result = guard.EnsureCoverage(Host(), input);

        Assert.Equal(input.Count, result.Count);
        Assert.False(AuditContains(auditPath, "autopilot.planner.coverage_gap"));
    }

    [Fact]
    public void All_Cves_Covered_Emits_No_Gap_And_No_Injection()
    {
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);
        var guard = Make(audit);
        var input = new List<ExploitAction>
        {
            NucleiAction("CVE-2024-0001"),
            MsfAction("CVE-2024-0001"),
        };

        var result = guard.EnsureCoverage(Host(), input);

        Assert.Equal(2, result.Count);
        Assert.False(AuditContains(auditPath, "autopilot.planner.coverage_gap"));
    }

    [Fact]
    public void Missing_Nuclei_With_Cached_Template_Injects_And_No_Gap()
    {
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);
        var guard = Make(audit,
            nuclei: cve => new[] { "/cache/nuclei/" + cve + ".yaml" });

        var input = new List<ExploitAction> { MsfAction("CVE-2024-0002") };
        var result = guard.EnsureCoverage(Host(), input);

        Assert.Contains(result, a => a.Tool == "nuclei" && a.CveId == "CVE-2024-0002"
                                  && a.Reason.Contains("GAP-031"));
        Assert.False(AuditContains(auditPath, "autopilot.planner.coverage_gap"));
    }

    [Fact]
    public void Missing_Nuclei_With_No_Cached_Template_Emits_Gap()
    {
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);
        var guard = Make(audit);

        var input = new List<ExploitAction> { MsfAction("CVE-2024-0003") };
        var result = guard.EnsureCoverage(Host(), input);

        Assert.DoesNotContain(result, a => a.Tool == "nuclei");
        Assert.True(AuditContains(auditPath, "autopilot.planner.coverage_gap"));
        var line = File.ReadAllLines(auditPath)
            .First(l => l.Contains("coverage_gap", StringComparison.Ordinal));
        Assert.Contains("\"missing_label\":\"nuclei\"", line, StringComparison.Ordinal);
        Assert.Contains("CVE-2024-0003", line, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_Msf_With_Cached_Module_Injects_And_No_Gap()
    {
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);
        var guard = Make(audit,
            msf: cve => new[] { "exploit/multi/http/whatever_" + cve });

        var input = new List<ExploitAction> { NucleiAction("CVE-2024-0004") };
        var result = guard.EnsureCoverage(Host(), input);

        Assert.Contains(result, a => a.Tool == "msfrc" && a.CveId == "CVE-2024-0004"
                                  && a.Reason.Contains("GAP-031"));
        Assert.False(AuditContains(auditPath, "autopilot.planner.coverage_gap"));
    }

    [Fact]
    public void Missing_Msf_With_No_Cached_Module_Emits_Gap()
    {
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);
        var guard = Make(audit);

        var input = new List<ExploitAction> { NucleiAction("CVE-2024-0005") };
        var result = guard.EnsureCoverage(Host(), input);

        Assert.DoesNotContain(result, a => a.Tool == "msfrc");
        Assert.True(AuditContains(auditPath, "autopilot.planner.coverage_gap"));
        var line = File.ReadAllLines(auditPath)
            .First(l => l.Contains("coverage_gap", StringComparison.Ordinal));
        Assert.Contains("\"missing_label\":\"msf\"", line, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_Both_Emits_Gap_With_Both_Label()
    {
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);
        var guard = Make(audit);

        var input = new List<ExploitAction> { CveLeadAction("CVE-2024-0006") };
        var result = guard.EnsureCoverage(Host(), input);

        Assert.DoesNotContain(result, a => a.Tool == "nuclei");
        Assert.DoesNotContain(result, a => a.Tool == "msfrc");
        Assert.True(AuditContains(auditPath, "autopilot.planner.coverage_gap"));
        var line = File.ReadAllLines(auditPath)
            .First(l => l.Contains("coverage_gap", StringComparison.Ordinal));
        Assert.Contains("\"missing_label\":\"both\"", line, StringComparison.Ordinal);
        Assert.Contains("CVE-2024-0006", line, StringComparison.Ordinal);
    }

    [Fact]
    public void Guard_Never_Adds_Payload_Or_Cred_Candidates()
    {
        // Even with rich lookups, the guard only emits ExecPocs candidates;
        // it never synthesizes credential attacks, payload drops, or DoS.
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);
        var guard = Make(audit,
            nuclei: _ => new[] { "/cache/nuclei/foo.yaml" },
            msf: _ => new[] { "exploit/multi/http/foo" });

        var input = new List<ExploitAction> { CveLeadAction("CVE-2024-0007") };
        var result = guard.EnsureCoverage(Host(), input);

        var injected = result.Where(a => a.Reason.Contains("GAP-031")).ToList();
        Assert.NotEmpty(injected);
        Assert.All(injected, a =>
        {
            Assert.True(a.Tool is "nuclei" or "msfrc",
                $"guard emitted unexpected tool: {a.Tool}");
            Assert.Equal("ExecPocs", a.Category);
            Assert.Null(a.Cred);
        });
    }

    [Fact]
    public void Multiple_Cves_Each_Evaluated_Independently()
    {
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);
        var guard = Make(audit,
            nuclei: cve => cve == "CVE-2024-1001"
                ? new[] { "/cache/nuclei/a.yaml" }
                : Array.Empty<string>());

        var input = new List<ExploitAction>
        {
            // CVE-1001: msf already there, nuclei will be injected → covered.
            MsfAction("CVE-2024-1001"),
            // CVE-1002: nothing → gap (both).
            CveLeadAction("CVE-2024-1002", port: 8080),
        };
        var result = guard.EnsureCoverage(Host(), input);

        Assert.Contains(result, a => a.Tool == "nuclei" && a.CveId == "CVE-2024-1001");
        Assert.Equal(1, CountAudit(auditPath, "autopilot.planner.coverage_gap"));
    }

    [Fact]
    public void Null_Args_Throw()
    {
        using var audit = new AuditLog(NewAuditPath());
        var guard = Make(audit);
        Assert.Throws<ArgumentNullException>(() => guard.EnsureCoverage(null!, new List<ExploitAction>()));
        Assert.Throws<ArgumentNullException>(() => guard.EnsureCoverage(Host(), null!));
    }
}
