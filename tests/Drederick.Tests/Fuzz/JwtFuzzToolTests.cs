using Drederick.Audit;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Drederick.Tests;
using Xunit;

namespace Drederick.Tests.Fuzz;

public sealed class JwtFuzzToolTests
{
    private const string ValidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"jwt-fuzz-test-{Guid.NewGuid():N}.jsonl");

    [Fact]
    public async Task Throws_When_Url_OutOfScope()
    {
        // Arrange
        var scope = ScopeLoader.Parse("192.168.1.0/24");
        var audit = new AuditLog(NewAuditPath());
        var tool = new JwtFuzzTool(scope, audit);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<ScopeException>(async () =>
            await tool.ProbeAsync(ValidToken, "https://evil.com/api/login"));

        Assert.Contains("evil.com", ex.Message);
    }

    [Fact]
    public async Task Throws_When_Token_Malformed()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var audit = new AuditLog(NewAuditPath());
        var tool = new JwtFuzzTool(scope, audit);

        // Act & Assert - various malformed tokens
        var badTokens = new[]
        {
            "not.a.token!@#",
            "only.two",
            "has.four.segments.bad",
            "no-dots-at-all",
            "",
            "   ",
        };

        foreach (var badToken in badTokens)
        {
            var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
                await tool.ProbeAsync(badToken, "http://10.10.10.10/api/login"));

            Assert.Contains("Malformed JWT", ex.Message);
        }
    }

    [Fact]
    public async Task Throws_When_Url_Invalid()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var audit = new AuditLog(NewAuditPath());
        var tool = new JwtFuzzTool(scope, audit);

        // Act & Assert - various invalid URLs
        var badUrls = new[]
        {
            "not-a-url",
            "ftp://10.10.10.10/api",  // wrong scheme
            "//10.10.10.10/api",       // no scheme
            "10.10.10.10",             // not absolute
        };

        foreach (var badUrl in badUrls)
        {
            var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
                await tool.ProbeAsync(ValidToken, badUrl));

            Assert.Contains("Invalid target URL", ex.Message);
        }
    }

    [Fact]
    public async Task Rejects_HmacWordlist_With_PathTraversal()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var audit = new AuditLog(NewAuditPath());
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => true, 0, "clean scan");
        var tool = new JwtFuzzTool(scope, audit, runner: runner);

        var options = new JwtFuzzOptions
        {
            HmacWordlist = "/etc/../../../etc/passwd",
        };

        // Act & Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await tool.ProbeAsync(ValidToken, "http://10.10.10.10/api/login", options));

        Assert.Contains("path traversal", ex.Message);
    }

    [Fact]
    public async Task Detects_AlgNone_From_Output()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var audit = new AuditLog(NewAuditPath());

        var fixtureOutput = await File.ReadAllTextAsync(
            "tests/Drederick.Tests/Fuzz/fixtures/jwt-tool-alg-none.txt");

        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f.Contains("jwt_tool"), 0, stdout: fixtureOutput);

        var tool = new JwtFuzzTool(scope, audit, runner: runner);

        // Act
        var result = await tool.ProbeAsync(ValidToken, "http://10.10.10.10/api/login");

        // Assert
        Assert.Empty(result.Error ?? "");
        Assert.Contains(JwtVulnerability.AlgNone, result.Vulnerabilities);
        Assert.Single(result.Vulnerabilities);
    }

    [Fact]
    public async Task Detects_WeakHmacSecret_From_Output()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var audit = new AuditLog(NewAuditPath());

        var fixtureOutput = await File.ReadAllTextAsync(
            "tests/Drederick.Tests/Fuzz/fixtures/jwt-tool-weak-hmac.txt");

        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f.Contains("jwt_tool"), 0, stdout: fixtureOutput);

        var tool = new JwtFuzzTool(scope, audit, runner: runner);

        // Act
        var result = await tool.ProbeAsync(ValidToken, "http://10.10.10.10/api/login");

        // Assert
        Assert.Empty(result.Error ?? "");
        Assert.Contains(JwtVulnerability.WeakHmacSecret, result.Vulnerabilities);
        Assert.Single(result.Vulnerabilities);
    }

    [Fact]
    public async Task Detects_KeyConfusion_From_Output()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var audit = new AuditLog(NewAuditPath());

        var fixtureOutput = await File.ReadAllTextAsync(
            "tests/Drederick.Tests/Fuzz/fixtures/jwt-tool-key-confusion.txt");

        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f.Contains("jwt_tool"), 0, stdout: fixtureOutput);

        var tool = new JwtFuzzTool(scope, audit, runner: runner);

        // Act
        var result = await tool.ProbeAsync(ValidToken, "http://10.10.10.10/api/login");

        // Assert
        Assert.Empty(result.Error ?? "");
        Assert.Contains(JwtVulnerability.RsaToHsKeyConfusion, result.Vulnerabilities);
        Assert.Single(result.Vulnerabilities);
    }

    [Fact]
    public async Task Offline_Mode_Skips_Scope_Check()
    {
        // Arrange - scope that would reject any URL
        var scope = ScopeLoader.Parse("192.168.1.0/24");
        var audit = new AuditLog(NewAuditPath());

        var fixtureOutput = await File.ReadAllTextAsync(
            "tests/Drederick.Tests/Fuzz/fixtures/jwt-tool-clean.txt");

        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f.Contains("jwt_tool"), 0, stdout: fixtureOutput);

        var tool = new JwtFuzzTool(scope, audit, runner: runner);

        // Act - offline mode should NOT check scope
        var result = await tool.AnalyzeAsync(ValidToken);

        // Assert - should succeed even though no host would be in scope
        Assert.Equal("(offline)", result.Target);
        Assert.Empty(result.Vulnerabilities);
    }

    [Fact]
    public async Task Returns_Empty_Result_When_JwtTool_Missing()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var audit = new AuditLog(NewAuditPath());

        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f.Contains("jwt_tool"), 127, stderr: "jwt_tool: command not found");

        var tool = new JwtFuzzTool(scope, audit, runner: runner);

        // Act
        var result = await tool.ProbeAsync(ValidToken, "http://10.10.10.10/api/login");

        // Assert
        Assert.Equal("jwt_tool not found", result.Error);
        Assert.Empty(result.Vulnerabilities);
    }

    [Fact]
    public async Task Token_Digest_Used_Instead_Of_Plaintext()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var auditPath = NewAuditPath();
        var audit = new AuditLog(auditPath);

        var fixtureOutput = await File.ReadAllTextAsync(
            "tests/Drederick.Tests/Fuzz/fixtures/jwt-tool-clean.txt");

        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f.Contains("jwt_tool"), 0, stdout: fixtureOutput);

        var tool = new JwtFuzzTool(scope, audit, runner: runner);

        // Act
        await tool.ProbeAsync(ValidToken, "http://10.10.10.10/api/login");

        // Assert - audit file should have token_digest, not plaintext token
        var auditContent = await File.ReadAllTextAsync(auditPath);
        Assert.Contains("token_digest", auditContent);
        Assert.DoesNotContain(ValidToken, auditContent);  // Plaintext token should not appear
        Assert.Matches(@"""token_digest""\s*:\s*""[a-f0-9]{64}""", auditContent);  // SHA-256 is 64 hex chars
    }

    [Fact]
    public async Task Audit_Records_Start_And_Finish_Events()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var auditPath = NewAuditPath();
        var audit = new AuditLog(auditPath);

        var fixtureOutput = await File.ReadAllTextAsync(
            "tests/Drederick.Tests/Fuzz/fixtures/jwt-tool-clean.txt");

        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f.Contains("jwt_tool"), 0, stdout: fixtureOutput);

        var tool = new JwtFuzzTool(scope, audit, runner: runner);

        // Act
        await tool.ProbeAsync(ValidToken, "http://10.10.10.10/api/login");

        // Assert
        var auditContent = await File.ReadAllTextAsync(auditPath);
        Assert.Contains("jwt-fuzz.start", auditContent);
        Assert.Contains("jwt-fuzz.finish", auditContent);
        Assert.Contains(@"""mode"":""url""", auditContent);
        Assert.Contains("http://10.10.10.10/api/login", auditContent);
    }

    [Fact]
    public void Category_Is_Auth()
    {
        // Arrange
        var scope = ScopeLoader.Parse("10.0.0.0/8");
        var audit = new AuditLog(NewAuditPath());
        var tool = new JwtFuzzTool(scope, audit);

        // Assert
        Assert.Equal(FuzzCategory.Auth, tool.Category);
        Assert.Equal("jwt-fuzz", tool.Name);
    }
}
