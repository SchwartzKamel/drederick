using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Fuzz;

public class VhostFuzzToolTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-vhost-{Guid.NewGuid():N}.jsonl");

    private static Scope.Scope NewScope()
    {
        return ScopeLoader.Parse("10.10.10.0/24");
    }

    [Fact]
    public async Task Throws_When_BaseUrl_OutOfScope()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new VhostFuzzTool(scope, audit, "ffuf", runner);

        await Assert.ThrowsAsync<ScopeException>(async () =>
        {
            await tool.ProbeAsync("http://192.168.1.1/", "target.com");
        });

        // Should not have called ffuf at all
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Throws_When_Apex_Has_ShellMetachar()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new VhostFuzzTool(scope, audit, "ffuf", runner);

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("http://10.10.10.5/", "target.com;rm");
        });

        Assert.Contains("shell metacharacters", ex.Message);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Rejects_CustomWordlist_With_PathTraversal()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new VhostFuzzTool(scope, audit, "ffuf", runner);
        var opts = new VhostFuzzOptions
        {
            CustomWordlist = "../etc/passwd",
        };

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("http://10.10.10.5/", "target.com", opts);
        });

        Assert.Contains("path traversal", ex.Message);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Parses_Ffuf_Json_Output()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());

        // Read the fixture
        var fixturePath = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "Fuzz", "fixtures", "ffuf-sample.json");
        var fixtureJson = await File.ReadAllTextAsync(fixturePath);

        var runner = new RecordingProcessRunner()
            .OnRun(
                (file, args) => file.Contains("ffuf"),
                exit: 0,
                stdout: fixtureJson,
                stderr: "");

        // Create a temp wordlist in the current directory (not /tmp)
        var tempWordlist = Path.Combine(Directory.GetCurrentDirectory(), $"test-wordlist-{Guid.NewGuid():N}.txt");
        await File.WriteAllLinesAsync(tempWordlist, new[] { "admin", "staging", "dev" });

        try
        {
            var tool = new VhostFuzzTool(scope, audit, "ffuf", runner);
            var opts = new VhostFuzzOptions
            {
                CustomWordlist = tempWordlist,
                AutoBaseline = false, // skip HTTP baseline request
            };

            var result = await tool.ProbeAsync("http://10.10.10.100/", "target.com", opts);

            Assert.Null(result.Error);
            Assert.Equal(3, result.Hits.Count);

            var adminHit = result.Hits.First(h => h.Vhost == "admin.target.com");
            Assert.Equal(200, adminHit.Status);
            Assert.Equal(1024, adminHit.Size);
            Assert.Null(adminHit.RedirectTo);

            var stagingHit = result.Hits.First(h => h.Vhost == "staging.target.com");
            Assert.Equal(302, stagingHit.Status);
            Assert.Equal(512, stagingHit.Size);
            Assert.Equal("https://staging.target.com/login", stagingHit.RedirectTo);

            var devHit = result.Hits.First(h => h.Vhost == "dev.target.com");
            Assert.Equal(401, devHit.Status);
            Assert.Equal(256, devHit.Size);
        }
        finally
        {
            if (File.Exists(tempWordlist)) File.Delete(tempWordlist);
        }
    }

    [Fact]
    public async Task Audit_Records_Start_And_Finish_Events()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);

        var fixtureJson = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Fuzz", "fixtures", "ffuf-sample.json"));

        var runner = new RecordingProcessRunner()
            .OnRun((file, args) => file.Contains("ffuf"), 0, fixtureJson, "");

        var tempWordlist = Path.Combine(Directory.GetCurrentDirectory(), $"test-wordlist-{Guid.NewGuid():N}.txt");
        await File.WriteAllLinesAsync(tempWordlist, new[] { "admin", "staging", "dev" });

        try
        {
            var tool = new VhostFuzzTool(scope, audit, "ffuf", runner);
            var opts = new VhostFuzzOptions
            {
                CustomWordlist = tempWordlist,
                AutoBaseline = false,
            };

            await tool.ProbeAsync("http://10.10.10.100/", "target.com", opts);

            audit.Dispose(); // flush

            var lines = await File.ReadAllLinesAsync(auditPath);
            Assert.Contains(lines, l => l.Contains("vhost-fuzz.start"));
            Assert.Contains(lines, l => l.Contains("vhost-fuzz.finish"));
        }
        finally
        {
            if (File.Exists(tempWordlist)) File.Delete(tempWordlist);
            if (File.Exists(auditPath)) File.Delete(auditPath);
        }
    }

    [Fact]
    public async Task Rejects_Apex_With_Dollar_Sign()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new VhostFuzzTool(scope, audit, "ffuf", runner);

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("http://10.10.10.5/", "target.com$foo");
        });

        Assert.Contains("shell metacharacters", ex.Message);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Rejects_Apex_With_Backticks()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new VhostFuzzTool(scope, audit, "ffuf", runner);

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("http://10.10.10.5/", "target`whoami`.com");
        });

        Assert.Contains("shell metacharacters", ex.Message);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Rejects_Apex_With_Ampersand()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new VhostFuzzTool(scope, audit, "ffuf", runner);

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("http://10.10.10.5/", "target.com&echo");
        });

        Assert.Contains("shell metacharacters", ex.Message);
        Assert.Empty(runner.Calls);
    }
}
