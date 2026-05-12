using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Fuzz;

/// <summary>
/// htb-llm-vhost-fuzz-surface (GAP-051): unit tests for the standalone
/// <see cref="VhostAutoScheduler"/> used by both <c>AdaptiveRunner</c>'s
/// inline auto-schedule path and the LLM tool surface.
/// </summary>
public class VhostAutoSchedulerTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-vas-{Guid.NewGuid():N}.jsonl");

    private static Scope.Scope NewScope() => ScopeLoader.Parse("10.10.10.0/24");

    private sealed class StubProcessRunner : IProcessRunner
    {
        public List<(string file, string args)> Calls { get; } = new();
        public int ExitCode { get; init; } = 1;
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

    private static VhostFuzzTool NewVhostTool(Scope.Scope scope, AuditLog audit) =>
        new(scope, audit, "ffuf", new StubProcessRunner { ExitCode = 1, StdErr = "no results" });

    // -------------------------------------------------------------------
    // 1. Apex extraction — "last two labels" heuristic.
    // -------------------------------------------------------------------
    [Theory]
    [InlineData("panel.pterodactyl.htb", "pterodactyl.htb")]
    [InlineData("a.b.c.example.com", "example.com")]
    [InlineData("admin.dev.staging.foo.local", "foo.local")]
    [InlineData("two.labels.htb", "labels.htb")]
    [InlineData("PANEL.Pterodactyl.HTB", "pterodactyl.htb")]
    [InlineData(".panel.example.htb.", "example.htb")]
    [InlineData("pterodactyl.htb", "pterodactyl.htb")]
    [InlineData("singlehost", "singlehost")]
    [InlineData("10.10.10.5", "10.10.10.5")]
    [InlineData("::1", "::1")]
    [InlineData("", "")]
    [InlineData("   ", "")]
    public void DeriveApex_Returns_Last_Two_Labels_Or_Passthrough(string input, string expected)
    {
        Assert.Equal(expected, VhostAutoScheduler.DeriveApex(input));
    }

    // -------------------------------------------------------------------
    // 2. ScheduleAsync queues vhost-fuzz against the derived apex.
    // -------------------------------------------------------------------
    [Fact]
    public async Task ScheduleAsync_Queues_VhostFuzz_For_Derived_Apex()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(scope, audit, vhost);

            var outcome = await sched.ScheduleAsync(
                "panel.pterodactyl.htb", 80, "http", CancellationToken.None);

            // Inner ProbeAsync calls Scope.Require on the apex hostname,
            // which only accepts IP literals; we expect ScopeRefused (the
            // apex isn't an IP and isn't in our IP-based scope).
            Assert.True(
                outcome is VhostScheduleOutcome.Queued or VhostScheduleOutcome.ScopeRefused,
                $"Expected Queued or ScopeRefused, got {outcome}");

            var lines = await File.ReadAllLinesAsync(auditPath);
            Assert.Contains(lines, l => l.Contains("\"vhost.auto_schedule.queue\""));
            Assert.Contains(lines, l => l.Contains("pterodactyl.htb"));
            Assert.Equal(1, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    // -------------------------------------------------------------------
    // 3. Dedup: same apex twice = one queue.
    // -------------------------------------------------------------------
    [Fact]
    public async Task ScheduleAsync_Dedupes_Same_Apex_Same_Port()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(scope, audit, vhost);

            await sched.ScheduleAsync("panel.pterodactyl.htb", 80, "http");
            var outcome2 = await sched.ScheduleAsync("admin.pterodactyl.htb", 80, "http");
            var outcome3 = await sched.ScheduleAsync("dev.pterodactyl.htb", 80, "http");

            Assert.Equal(VhostScheduleOutcome.Duplicate, outcome2);
            Assert.Equal(VhostScheduleOutcome.Duplicate, outcome3);
            Assert.Equal(1, sched.QueuedCount);

            var lines = await File.ReadAllLinesAsync(auditPath);
            var queueEvents = lines.Where(l => l.Contains("\"vhost.auto_schedule.queue\"")).ToList();
            Assert.Single(queueEvents);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    // -------------------------------------------------------------------
    // 4. Empty apex (single-label hostname) → no-op gracefully.
    // -------------------------------------------------------------------
    [Theory]
    [InlineData("singlehost")]
    public async Task ScheduleAsync_Skips_Single_Label_Apex(string fqdn)
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(scope, audit, vhost);

            var outcome = await sched.ScheduleAsync(fqdn, 80, "http");

            Assert.Equal(VhostScheduleOutcome.SingleLabelApex, outcome);
            Assert.Equal(0, sched.QueuedCount);
            var lines = await File.ReadAllLinesAsync(auditPath);
            Assert.Contains(lines, l => l.Contains("\"vhost.auto_schedule.skip\""));
            Assert.DoesNotContain(lines, l => l.Contains("\"vhost.auto_schedule.queue\""));
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ScheduleAsync_Skips_Empty_Apex(string fqdn)
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(scope, audit, vhost);

            var outcome = await sched.ScheduleAsync(fqdn, 80, "http");

            Assert.Equal(VhostScheduleOutcome.EmptyApex, outcome);
            Assert.Equal(0, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    // -------------------------------------------------------------------
    // 5. IP-literal apex skipped.
    // -------------------------------------------------------------------
    [Fact]
    public async Task ScheduleAsync_Skips_IP_Literal_Apex()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(scope, audit, vhost);

            var outcome = await sched.ScheduleAsync("10.10.10.50", 80, "http");

            Assert.Equal(VhostScheduleOutcome.ApexIsIp, outcome);
            Assert.Equal(0, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    // -------------------------------------------------------------------
    // 6. Wordlist override via constructor (--vhost-wordlist flag path).
    // -------------------------------------------------------------------
    [Fact]
    public void WordlistName_Defaults_To_Subdomains_Top1m_5000()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(scope, audit, vhost);
            Assert.Equal("subdomains-top1m-5000.txt", sched.WordlistName);
            Assert.Equal(VhostAutoScheduler.DefaultWordlistName, sched.WordlistName);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void WordlistName_Override_Respected()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(
                scope, audit, vhost, wordlistName: "custom-vhosts.txt");
            Assert.Equal("custom-vhosts.txt", sched.WordlistName);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public async Task ScheduleAsync_Records_Wordlist_Name_In_Audit()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(
                scope, audit, vhost, wordlistName: "operator-override.txt");

            await sched.ScheduleAsync("foo.example.htb", 8080, "https");

            var lines = await File.ReadAllLinesAsync(auditPath);
            var queueLine = lines.FirstOrDefault(l => l.Contains("\"vhost.auto_schedule.queue\""));
            Assert.NotNull(queueLine);
            Assert.Contains("operator-override.txt", queueLine!);
            Assert.Contains("example.htb", queueLine!);
            Assert.Contains("8080", queueLine!);
            Assert.Contains("https", queueLine!);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    // -------------------------------------------------------------------
    // 7. Dedup is keyed by (apex, port, scheme) — different ports queue.
    // -------------------------------------------------------------------
    [Fact]
    public async Task ScheduleAsync_Different_Ports_Are_Not_Deduped()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(scope, audit, vhost);

            await sched.ScheduleAsync("panel.foo.htb", 80, "http");
            await sched.ScheduleAsync("panel.foo.htb", 8080, "http");
            await sched.ScheduleAsync("panel.foo.htb", 443, "https");

            Assert.Equal(3, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void HasQueued_Reports_Dedup_State()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var vhost = NewVhostTool(scope, audit);
            var sched = new VhostAutoScheduler(scope, audit, vhost);

            Assert.False(sched.HasQueued("foo.htb", 80));
            sched.ScheduleAsync("panel.foo.htb", 80, "http").GetAwaiter().GetResult();
            Assert.True(sched.HasQueued("foo.htb", 80, "http"));
            Assert.False(sched.HasQueued("foo.htb", 81, "http"));
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }
}
