using System.Net;
using System.Net.Http;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Http;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Http;

/// <summary>
/// GAP-057 / htb-content-discovery-vhost-aware: unit tests for the
/// <see cref="VhostContentDiscoveryScheduler"/> — structural analog of
/// the <c>VhostAutoScheduler</c> for content discovery.
/// </summary>
public class VhostContentDiscoverySchedulerTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-vcds-{Guid.NewGuid():N}.jsonl");

    private static Scope.Scope NewScope() => ScopeLoader.Parse("10.10.10.0/24");

    private sealed class StubHandler : HttpMessageHandler
    {
        public int CallCount;
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCount);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                Content = new ByteArrayContent(Array.Empty<byte>()),
            });
        }
    }

    private static HttpContentDiscoveryTool NewContentTool(Scope.Scope scope, AuditLog audit)
    {
        var http = new HttpClient(new StubHandler());
        return new HttpContentDiscoveryTool(
            scope, audit, http, wordlist: new[] { "admin" }, rateLimitRps: 1000);
    }

    [Fact]
    public async Task ScheduleAsync_Throws_When_Host_Out_Of_Scope()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            await Assert.ThrowsAsync<ScopeException>(() =>
                sched.ScheduleAsync("1.2.3.4", "panel.foo.htb", 80, "http"));
            Assert.Equal(0, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public async Task ScheduleAsync_Records_ScheduledForVhost_Audit_Event()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            var outcome = await sched.ScheduleAsync(
                "10.10.10.50", "panel.pterodactyl.htb", 80, "http");

            // Inner ProbeAsync calls scope.Require on the vhost hostname,
            // which fails for an IP-only scope; ScopeRefused is the
            // expected real-plumbing outcome.
            Assert.Equal(ContentDiscoveryScheduleOutcome.ScopeRefused, outcome);

            var lines = await File.ReadAllLinesAsync(auditPath);
            Assert.Contains(lines, l => l.Contains("\"content_discovery.scheduled_for_vhost\""));
            Assert.Contains(lines, l => l.Contains("panel.pterodactyl.htb"));
            Assert.Contains(lines, l => l.Contains("10.10.10.50"));
            Assert.Equal(1, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public async Task ScheduleAsync_Dedupes_Same_Host_Vhost_Port_Scheme()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            await sched.ScheduleAsync("10.10.10.50", "panel.foo.htb", 80, "http");
            var second = await sched.ScheduleAsync("10.10.10.50", "panel.foo.htb", 80, "http");
            var third = await sched.ScheduleAsync(
                "10.10.10.50", "PANEL.foo.HTB", 80, "http");

            Assert.Equal(ContentDiscoveryScheduleOutcome.Duplicate, second);
            Assert.Equal(ContentDiscoveryScheduleOutcome.Duplicate, third);
            Assert.Equal(1, sched.QueuedCount);

            var lines = await File.ReadAllLinesAsync(auditPath);
            var queueEvents = lines
                .Where(l => l.Contains("\"content_discovery.scheduled_for_vhost\"")
                            && !l.Contains(".skip")
                            && !l.Contains(".scope_refused")
                            && !l.Contains(".error"))
                .ToList();
            Assert.Single(queueEvents);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public async Task ScheduleAsync_Different_Vhosts_On_Same_Host_Queue_Separately()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            await sched.ScheduleAsync("10.10.10.50", "panel.foo.htb", 80, "http");
            await sched.ScheduleAsync("10.10.10.50", "admin.foo.htb", 80, "http");
            await sched.ScheduleAsync("10.10.10.50", "panel.foo.htb", 8080, "http");
            await sched.ScheduleAsync("10.10.10.50", "panel.foo.htb", 443, "https");

            Assert.Equal(4, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ScheduleAsync_Rejects_Empty_Vhost(string vhost)
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            var outcome = await sched.ScheduleAsync("10.10.10.50", vhost, 80, "http");

            Assert.Equal(ContentDiscoveryScheduleOutcome.EmptyVhost, outcome);
            Assert.Equal(0, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ScheduleAsync_Rejects_Empty_Host(string host)
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            var outcome = await sched.ScheduleAsync(host, "panel.foo.htb", 80, "http");

            Assert.Equal(ContentDiscoveryScheduleOutcome.EmptyHost, outcome);
            Assert.Equal(0, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Theory]
    [InlineData("10.10.10.50")]
    [InlineData("::1")]
    public async Task ScheduleAsync_Rejects_IP_Literal_Vhost(string vhost)
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            var outcome = await sched.ScheduleAsync("10.10.10.50", vhost, 80, "http");

            Assert.Equal(ContentDiscoveryScheduleOutcome.VhostIsIp, outcome);
            Assert.Equal(0, sched.QueuedCount);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void Profile_Defaults_To_RaftMedium()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            Assert.Equal(ContentDiscoveryProfile.RaftMedium, sched.Profile);
            Assert.False(sched.ExtensionFanout);
            Assert.Empty(sched.EffectiveExtensions);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void ExtensionFanout_When_Enabled_Exposes_Default_List()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(
                scope, audit, content,
                profile: ContentDiscoveryProfile.RaftLarge,
                extensionFanout: true);

            Assert.Equal(ContentDiscoveryProfile.RaftLarge, sched.Profile);
            Assert.True(sched.ExtensionFanout);
            Assert.Equal(
                ContentDiscoveryProfiles.DefaultExtensionFanout.ToArray(),
                sched.EffectiveExtensions.ToArray());
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public async Task ScheduleAsync_Records_Profile_And_ExtensionFanout_In_Audit()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(
                scope, audit, content,
                profile: ContentDiscoveryProfile.RaftMedium,
                extensionFanout: true);

            await sched.ScheduleAsync("10.10.10.50", "panel.foo.htb", 443, "https");

            var lines = await File.ReadAllLinesAsync(auditPath);
            var queueLine = lines.FirstOrDefault(l =>
                l.Contains("\"content_discovery.scheduled_for_vhost\"")
                && !l.Contains(".skip")
                && !l.Contains(".scope_refused"));
            Assert.NotNull(queueLine);
            Assert.Contains("raft-medium", queueLine!);
            Assert.Contains("\"extension_fanout\"", queueLine!);
            Assert.Contains("https://panel.foo.htb:443/", queueLine!);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public async Task HasQueued_Reports_Dedup_State()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            Assert.False(sched.HasQueued("10.10.10.50", "panel.foo.htb", 80));
            await sched.ScheduleAsync("10.10.10.50", "panel.foo.htb", 80, "http");
            Assert.True(sched.HasQueued("10.10.10.50", "panel.foo.htb", 80, "http"));
            Assert.False(sched.HasQueued("10.10.10.50", "panel.foo.htb", 81, "http"));
            Assert.False(sched.HasQueued("10.10.10.51", "panel.foo.htb", 80, "http"));
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void HasQueued_Returns_False_For_Empty_Inputs(string empty)
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            using var content = NewContentTool(scope, audit);
            var sched = new VhostContentDiscoveryScheduler(scope, audit, content);

            Assert.False(sched.HasQueued(empty, "panel.foo.htb", 80));
            Assert.False(sched.HasQueued("10.10.10.50", empty, 80));
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }
}
