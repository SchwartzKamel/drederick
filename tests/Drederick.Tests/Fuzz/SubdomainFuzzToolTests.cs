using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Fuzz;

public class SubdomainFuzzToolTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-subdomain-{Guid.NewGuid():N}.jsonl");

    private static Scope.Scope NewScope()
    {
        return ScopeLoader.Parse("1.0.0.0/24\n1.1.1.0/24\n8.8.8.0/24");
    }

    [Fact]
    public async Task Throws_When_Apex_Invalid()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new SubdomainFuzzTool(scope, audit, "gobuster", "dnsx", runner);

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("not a domain;");
        });

        Assert.Contains("Invalid apex domain", ex.Message);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Parses_Gobuster_Output()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());

        var fixturePath = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "Fuzz", "fixtures", "gobuster-sample.txt");
        var fixtureOutput = await File.ReadAllTextAsync(fixturePath);

        var runner = new RecordingProcessRunner()
            .OnRun(
                (file, args) => file.Contains("gobuster"),
                exit: 0,
                stdout: fixtureOutput,
                stderr: "");

        var tempWordlist = Path.Combine(Directory.GetCurrentDirectory(), $"test-wordlist-{Guid.NewGuid():N}.txt");
        await File.WriteAllLinesAsync(tempWordlist, new[] { "admin", "staging", "dev", "api" });

        try
        {
            var tool = new SubdomainFuzzTool(scope, audit, "gobuster", "dnsx", runner);
            var opts = new SubdomainFuzzOptions
            {
                CustomWordlist = tempWordlist,
            };

            // Note: This test will fail if DNS resolution is required and the domain doesn't resolve.
            // For testing, we'll use a domain that resolves to an in-scope IP.
            // In practice, we'd mock DNS resolution, but for now we'll use "one.one.one.one" which resolves to 1.1.1.1
            var result = await tool.ProbeAsync("one.one.one.one", opts);

            Assert.Null(result.Error);
            Assert.Equal(4, result.Subdomains.Count);
            Assert.Contains("admin.target.com", result.Subdomains);
            Assert.Contains("staging.target.com", result.Subdomains);
            Assert.Contains("dev.target.com", result.Subdomains);
            Assert.Contains("api.target.com", result.Subdomains);
        }
        finally
        {
            if (File.Exists(tempWordlist)) File.Delete(tempWordlist);
        }
    }

    [Fact]
    public async Task Falls_Back_To_Dnsx_When_Gobuster_Missing()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());

        var dnsxFixturePath = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "Fuzz", "fixtures", "dnsx-sample.txt");
        var dnsxOutput = await File.ReadAllTextAsync(dnsxFixturePath);

        var runner = new RecordingProcessRunner()
            // Gobuster fails
            .OnRun((file, args) => file.Contains("gobuster"), 127, "", "command not found")
            // dnsx succeeds
            .OnRun((file, args) => file.Contains("dnsx"), 0, dnsxOutput, "");

        var tempWordlist = Path.Combine(Directory.GetCurrentDirectory(), $"test-wordlist-{Guid.NewGuid():N}.txt");
        await File.WriteAllLinesAsync(tempWordlist, new[] { "admin", "www", "api" });

        try
        {
            var tool = new SubdomainFuzzTool(scope, audit, "gobuster", "dnsx", runner);
            var opts = new SubdomainFuzzOptions
            {
                CustomWordlist = tempWordlist,
            };

            var result = await tool.ProbeAsync("one.one.one.one", opts);

            Assert.Null(result.Error);
            Assert.Equal(5, result.Subdomains.Count);
            Assert.Contains("admin.target.com", result.Subdomains);
            Assert.Contains("www.target.com", result.Subdomains);

            // Verify both tools were attempted
            Assert.Contains(runner.Calls, c => c.FileOrCmd.Contains("gobuster"));
            Assert.Contains(runner.Calls, c => c.FileOrCmd.Contains("dnsx"));
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

        var fixtureOutput = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Fuzz", "fixtures", "gobuster-sample.txt"));

        var runner = new RecordingProcessRunner()
            .OnRun((file, args) => file.Contains("gobuster"), 0, fixtureOutput, "");

        var tempWordlist = Path.Combine(Directory.GetCurrentDirectory(), $"test-wordlist-{Guid.NewGuid():N}.txt");
        await File.WriteAllLinesAsync(tempWordlist, new[] { "admin", "staging", "dev", "api" });

        try
        {
            var tool = new SubdomainFuzzTool(scope, audit, "gobuster", "dnsx", runner);
            var opts = new SubdomainFuzzOptions
            {
                CustomWordlist = tempWordlist,
            };

            await tool.ProbeAsync("one.one.one.one", opts);

            audit.Dispose(); // flush

            var lines = await File.ReadAllLinesAsync(auditPath);
            Assert.Contains(lines, l => l.Contains("subdomain-fuzz.start"));
            Assert.Contains(lines, l => l.Contains("subdomain-fuzz.finish"));
        }
        finally
        {
            if (File.Exists(tempWordlist)) File.Delete(tempWordlist);
            if (File.Exists(auditPath)) File.Delete(auditPath);
        }
    }

    [Fact]
    public async Task Wordlist_Truncated_To_MaxWords()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());

        var runner = new RecordingProcessRunner()
            .OnRun((file, args) => file.Contains("gobuster"), 0, "Found: admin.target.com\n", "");

        // Create a wordlist with 100 words
        var tempWordlist = Path.Combine(Directory.GetCurrentDirectory(), $"test-wordlist-{Guid.NewGuid():N}.txt");
        var largeWordlist = Enumerable.Range(1, 100).Select(i => $"subdomain{i}").ToArray();
        await File.WriteAllLinesAsync(tempWordlist, largeWordlist);

        try
        {
            var tool = new SubdomainFuzzTool(scope, audit, "gobuster", "dnsx", runner);
            var opts = new SubdomainFuzzOptions
            {
                CustomWordlist = tempWordlist,
                MaxWords = 10, // Truncate to 10
            };

            var result = await tool.ProbeAsync("one.one.one.one", opts);

            // Should have tried only 10 words
            Assert.Equal(10, result.WordsTried);
        }
        finally
        {
            if (File.Exists(tempWordlist)) File.Delete(tempWordlist);

            // Clean up any truncated wordlist files
            var truncatedFiles = Directory.GetFiles(
                Directory.GetCurrentDirectory(),
                "subdomain-wordlist-*.txt");
            foreach (var file in truncatedFiles)
            {
                File.Delete(file);
            }
        }
    }

    [Fact]
    public async Task Rejects_CustomWordlist_With_PathTraversal()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new SubdomainFuzzTool(scope, audit, "gobuster", "dnsx", runner);
        var opts = new SubdomainFuzzOptions
        {
            CustomWordlist = "../etc/passwd",
        };

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("one.one.one.one", opts);
        });

        Assert.Contains("path traversal", ex.Message);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Rejects_Apex_With_Shell_Metacharacters()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new SubdomainFuzzTool(scope, audit, "gobuster", "dnsx", runner);

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("target.com;id");
        });

        Assert.Contains("Invalid apex domain", ex.Message);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Rejects_Apex_With_Backticks()
    {
        var scope = NewScope();
        using var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner();

        var tool = new SubdomainFuzzTool(scope, audit, "gobuster", "dnsx", runner);

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("target`whoami`.com");
        });

        Assert.Contains("Invalid apex domain", ex.Message);
        Assert.Empty(runner.Calls);
    }
}
