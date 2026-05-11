using System.Collections.Concurrent;
using System.Reflection;
using Drederick.Agent;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// GAP-051: validates the vhost-fuzz auto-schedule path inside
/// <see cref="AdaptiveRunner.ScheduleFuzzAsync"/> and the apex-derivation
/// helper that backs it.
/// </summary>
public class AdaptiveRunnerVhostAutoScheduleTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-arvas-{Guid.NewGuid():N}.jsonl");

    private static Scope.Scope NewScope() => ScopeLoader.Parse("10.10.10.0/24", "192.168.1.0/24");

    /// <summary>Records every Run/RunShell call and replays a canned response.</summary>
    private sealed class StubProcessRunner : IProcessRunner
    {
        public List<(string file, string args)> Calls { get; } = new();
        public int ExitCode { get; init; }
        public string StdOut { get; init; } = "";
        public string StdErr { get; init; } = "";

        public (int, string, string) Run(string file, string arguments, int timeoutSeconds)
        {
            Calls.Add((file, arguments));
            return (ExitCode, StdOut, StdErr);
        }

        public (int, string, string) RunShell(string commandLine, int timeoutSeconds)
        {
            Calls.Add(("shell", commandLine));
            return (ExitCode, StdOut, StdErr);
        }
    }

    private static void SeedFinding(ReconToolbox tools, HostFinding finding)
    {
        // _findings is private. Reach in via reflection so we can drive
        // ScheduleFuzzAsync without standing up a real scan pipeline.
        var field = typeof(ReconToolbox).GetField("_findings",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        var dict = (ConcurrentDictionary<string, HostFinding>)field!.GetValue(tools)!;
        dict[finding.Target] = finding;
    }

    private static ReconToolbox NewReconToolbox(Scope.Scope scope, AuditLog audit)
    {
        var nmap = new NmapTool(scope, audit);
        var http = new HttpProbeTool(scope, audit);
        var tls = new TlsProbeTool(scope, audit);
        var dns = new DnsProbeTool(scope, audit);
        return new ReconToolbox(nmap, http, tls, dns, audit);
    }

    [Theory]
    [InlineData("panel.pterodactyl.htb", "pterodactyl.htb")]
    [InlineData("admin.dev.pterodactyl.htb", "pterodactyl.htb")]
    [InlineData("pterodactyl.htb", "pterodactyl.htb")]
    [InlineData("PANEL.Pterodactyl.HTB", "pterodactyl.htb")]
    [InlineData("a.b.c.d", "c.d")]
    [InlineData("singlehost", "singlehost")]
    [InlineData("10.10.10.5", "10.10.10.5")]      // IP literal passes through
    [InlineData("::1", "::1")]                     // IPv6 literal passes through
    [InlineData(".panel.example.htb.", "example.htb")]  // strips edge dots
    public void DeriveApexDomain_Returns_Last_Two_Labels(string input, string expected)
    {
        Assert.Equal(expected, AdaptiveRunner.DeriveApexDomain(input));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void DeriveApexDomain_Returns_Empty_For_Blank_Input(string input)
    {
        Assert.Equal(string.Empty, AdaptiveRunner.DeriveApexDomain(input));
    }

    [Fact]
    public async Task ScheduleFuzzAsync_AutoSchedules_VhostFuzz_When_VhostRequired_Detected()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var recon = NewReconToolbox(scope, audit);
            var stubRunner = new StubProcessRunner { ExitCode = 1, StdErr = "no results" };
            var vhost = new VhostFuzzTool(scope, audit, "ffuf", stubRunner);
            var fuzz = new FuzzToolbox(new IFuzzTool[] { vhost }, audit);

            const string target = "10.10.10.50";
            SeedFinding(recon, new HostFinding
            {
                Target = target,
                Started = DateTimeOffset.UtcNow.ToString("o"),
                Nmap = new NmapResult
                {
                    OpenPorts = { new NmapPort { Port = 80, Protocol = "tcp", Service = "http" } },
                },
                Http =
                {
                    new HttpResult
                    {
                        Url = $"http://{target}:80/",
                        VhostRequired = true,
                        VhostHostname = "panel.pterodactyl.htb",
                    },
                },
            });

            var runner = new AdaptiveRunner(audit);
            await runner.ScheduleFuzzAsync(new[] { target }, recon, fuzz, CancellationToken.None);

            var lines = await File.ReadAllLinesAsync(auditPath);
            // The auto-schedule loop dispatches one vhost-fuzz call. The
            // underlying tool's _scope.Require may refuse the apex hostname
            // (Scope.Require only accepts IP literals), in which case the
            // Try wrapper records runner.fuzz.error with tool=vhost-fuzz.
            // Either way, we assert that the auto-schedule path fired.
            var vhostEvents = lines.Where(l =>
                l.Contains("\"vhost-fuzz.start\"") ||
                (l.Contains("\"runner.fuzz.error\"") && l.Contains("\"vhost-fuzz\""))).ToList();
            Assert.Single(vhostEvents);
            Assert.Contains("pterodactyl.htb", string.Join("\n", lines));
        }
        finally
        {
            try { File.Delete(auditPath); } catch { }
        }
    }

    [Fact]
    public async Task ScheduleFuzzAsync_Dedupes_Multiple_Vhosts_Sharing_Apex()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var recon = NewReconToolbox(scope, audit);
            var stubRunner = new StubProcessRunner { ExitCode = 1 };
            var vhost = new VhostFuzzTool(scope, audit, "ffuf", stubRunner);
            var fuzz = new FuzzToolbox(new IFuzzTool[] { vhost }, audit);

            const string target = "10.10.10.50";
            SeedFinding(recon, new HostFinding
            {
                Target = target,
                Started = DateTimeOffset.UtcNow.ToString("o"),
                Nmap = new NmapResult
                {
                    OpenPorts = { new NmapPort { Port = 80, Protocol = "tcp", Service = "http" } },
                },
                Http =
                {
                    new HttpResult { Url = $"http://{target}:80/", VhostRequired = true, VhostHostname = "panel.pterodactyl.htb" },
                    new HttpResult { Url = $"http://{target}:80/", VhostRequired = true, VhostHostname = "admin.pterodactyl.htb" },
                    new HttpResult { Url = $"http://{target}:80/", VhostRequired = true, VhostHostname = "dev.pterodactyl.htb" },
                },
            });

            var runner = new AdaptiveRunner(audit);
            await runner.ScheduleFuzzAsync(new[] { target }, recon, fuzz, CancellationToken.None);

            var lines = await File.ReadAllLinesAsync(auditPath);
            // Three vhost detections share the same apex (pterodactyl.htb)
            // — dedup must collapse to a single dispatch (start OR error).
            var vhostEvents = lines.Where(l =>
                l.Contains("\"vhost-fuzz.start\"") ||
                (l.Contains("\"runner.fuzz.error\"") && l.Contains("\"vhost-fuzz\""))).ToList();
            Assert.Single(vhostEvents);
        }
        finally
        {
            try { File.Delete(auditPath); } catch { }
        }
    }

    [Fact]
    public async Task ScheduleFuzzAsync_Skips_Vhost_When_Apex_Is_IP_Literal()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var recon = NewReconToolbox(scope, audit);
            var stubRunner = new StubProcessRunner { ExitCode = 1 };
            var vhost = new VhostFuzzTool(scope, audit, "ffuf", stubRunner);
            var fuzz = new FuzzToolbox(new IFuzzTool[] { vhost }, audit);

            const string target = "10.10.10.50";
            SeedFinding(recon, new HostFinding
            {
                Target = target,
                Started = DateTimeOffset.UtcNow.ToString("o"),
                Nmap = new NmapResult
                {
                    OpenPorts = { new NmapPort { Port = 80, Protocol = "tcp", Service = "http" } },
                },
                Http =
                {
                    // VhostHostname is itself an IP literal — should NOT auto-schedule.
                    new HttpResult { Url = $"http://{target}:80/", VhostRequired = true, VhostHostname = "10.10.10.99" },
                },
            });

            var runner = new AdaptiveRunner(audit);
            await runner.ScheduleFuzzAsync(new[] { target }, recon, fuzz, CancellationToken.None);

            var lines = await File.ReadAllLinesAsync(auditPath);
            Assert.DoesNotContain(lines, l => l.Contains("\"vhost-fuzz.start\""));
        }
        finally
        {
            try { File.Delete(auditPath); } catch { }
        }
    }

    [Fact]
    public async Task ScheduleFuzzAsync_Does_Not_Schedule_When_VhostRequired_False()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var recon = NewReconToolbox(scope, audit);
            var stubRunner = new StubProcessRunner { ExitCode = 1 };
            var vhost = new VhostFuzzTool(scope, audit, "ffuf", stubRunner);
            var fuzz = new FuzzToolbox(new IFuzzTool[] { vhost }, audit);

            const string target = "10.10.10.50";
            SeedFinding(recon, new HostFinding
            {
                Target = target,
                Started = DateTimeOffset.UtcNow.ToString("o"),
                Nmap = new NmapResult
                {
                    OpenPorts = { new NmapPort { Port = 80, Protocol = "tcp", Service = "http" } },
                },
                Http = { new HttpResult { Url = $"http://{target}:80/", VhostRequired = false } },
            });

            var runner = new AdaptiveRunner(audit);
            await runner.ScheduleFuzzAsync(new[] { target }, recon, fuzz, CancellationToken.None);

            var lines = await File.ReadAllLinesAsync(auditPath);
            Assert.DoesNotContain(lines, l => l.Contains("\"vhost-fuzz.start\""));
        }
        finally
        {
            try { File.Delete(auditPath); } catch { }
        }
    }
}
