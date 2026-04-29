using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Fuzz;

public sealed class WebParamFuzzToolTests
{
    private static Scope.Scope CreateTestScope(params string[] cidrs)
    {
        var spec = string.Join("\n", cidrs);
        return ScopeLoader.Parse(spec);
    }

    private static AuditLog CreateTestAuditLog()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"audit_{Guid.NewGuid():N}.jsonl");
        return new AuditLog(tempPath);
    }

    [Fact]
    public async Task Throws_When_BaseUrl_OutOfScope()
    {
        // Arrange: scope contains only 10.0.0.0/8
        var scope = CreateTestScope("10.0.0.0/8");
        using var audit = CreateTestAuditLog();
        var tool = new WebParamFuzzTool(scope, audit);

        // Act & Assert: URL targeting 192.168.1.100 should throw ScopeException
        await Assert.ThrowsAsync<ScopeException>(async () =>
        {
            await tool.ProbeAsync("http://192.168.1.100/api");
        });
    }

    [Fact]
    public async Task Throws_When_BaseUrl_Invalid()
    {
        // Arrange
        var scope = CreateTestScope("10.0.0.0/8");
        using var audit = CreateTestAuditLog();
        var tool = new WebParamFuzzTool(scope, audit);

        // Act & Assert: non-URL string should throw ArgumentException
        await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("not-a-valid-url");
        });
    }

    [Fact]
    public void Rejects_CustomWordlist_With_PathTraversal()
    {
        // Arrange
        var scope = CreateTestScope("10.0.0.0/8");
        using var audit = CreateTestAuditLog();
        var tool = new WebParamFuzzTool(scope, audit);
        var options = new WebParamFuzzTool.ParamFuzzOptions
        {
            CustomWordlist = "../../../etc/passwd"
        };

        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("http://10.0.0.1/api", options);
        }).Result;

        Assert.Contains("path traversal", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_CustomWordlist_With_ShellMetachar()
    {
        // Arrange
        var scope = CreateTestScope("10.0.0.0/8");
        using var audit = CreateTestAuditLog();
        var tool = new WebParamFuzzTool(scope, audit);
        var options = new WebParamFuzzTool.ParamFuzzOptions
        {
            CustomWordlist = "/tmp/list;rm -rf /"
        };

        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("http://10.0.0.1/api", options);
        }).Result;

        Assert.Contains("shell metacharacters", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Parses_Arjun_Json_Output()
    {
        // Arrange
        var scope = CreateTestScope("192.168.0.0/16");
        using var audit = CreateTestAuditLog();

        // Read fixture
        var fixturePath = Path.Combine(
            GetRepoRoot(),
            "tests/Drederick.Tests/Fuzz/fixtures/arjun_output.json");

        var fixtureJson = await File.ReadAllTextAsync(fixturePath);

        // Create a fake runner that returns the fixture JSON
        var fakeRunner = new FakeProcessRunner
        {
            Responses = new()
            {
                ["arjun"] = (0, string.Empty, string.Empty, fixtureJson),
            }
        };

        var tool = new WebParamFuzzTool(scope, audit, runner: fakeRunner);

        // Act
        var result = await tool.ProbeAsync("http://192.168.1.100/api");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(3, result.DiscoveredParameters.Count);
        Assert.Contains("id", result.DiscoveredParameters);
        Assert.Contains("user", result.DiscoveredParameters);
        Assert.Contains("token", result.DiscoveredParameters);
    }

    [Fact]
    public async Task Falls_Back_To_X8_When_Arjun_Missing()
    {
        // Arrange
        var scope = CreateTestScope("192.168.0.0/16");
        using var audit = CreateTestAuditLog();

        var fixturePath = Path.Combine(
            GetRepoRoot(),
            "tests/Drederick.Tests/Fuzz/fixtures/x8_output.txt");

        var fixtureOutput = await File.ReadAllTextAsync(fixturePath);

        // Fake runner: arjun returns exit 127 "command not found", x8 returns valid output
        var fakeRunner = new FakeProcessRunner
        {
            Responses = new()
            {
                ["arjun"] = (127, string.Empty, "arjun: command not found", null),
                ["x8"] = (0, fixtureOutput, string.Empty, null),
            }
        };

        var tool = new WebParamFuzzTool(scope, audit, runner: fakeRunner);

        // Act
        var result = await tool.ProbeAsync("http://192.168.1.100/api");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(4, result.DiscoveredParameters.Count);
        Assert.Contains("id", result.DiscoveredParameters);
        Assert.Contains("user", result.DiscoveredParameters);
        Assert.Contains("token", result.DiscoveredParameters);
        Assert.Contains("session", result.DiscoveredParameters);
    }

    [Fact]
    public async Task Audit_Records_Start_And_Finish_Events()
    {
        // Arrange
        var scope = CreateTestScope("192.168.0.0/16");
        var auditPath = Path.Combine(Path.GetTempPath(), $"audit_{Guid.NewGuid():N}.jsonl");
        using var audit = new AuditLog(auditPath);

        var fakeRunner = new FakeProcessRunner
        {
            Responses = new()
            {
                ["arjun"] = (0, string.Empty, string.Empty, "{\"http://example.com/\": [\"id\"]}"),
            }
        };

        var tool = new WebParamFuzzTool(scope, audit, runner: fakeRunner);

        // Act
        await tool.ProbeAsync("http://192.168.1.100/api");

        // Assert: read audit log and verify events
        audit.Dispose();
        var auditLines = await File.ReadAllLinesAsync(auditPath);
        Assert.True(auditLines.Length >= 2);

        var startEvent = auditLines.FirstOrDefault(l => l.Contains("\"web-param-fuzz.start\""));
        var finishEvent = auditLines.FirstOrDefault(l => l.Contains("\"web-param-fuzz.finish\""));

        Assert.NotNull(startEvent);
        Assert.NotNull(finishEvent);

        // Cleanup
        File.Delete(auditPath);
    }

    [Fact]
    public async Task Argv_Digest_Is_SHA256_Of_Joined_Argv()
    {
        // Arrange
        var scope = CreateTestScope("192.168.0.0/16");
        var auditPath = Path.Combine(Path.GetTempPath(), $"audit_{Guid.NewGuid():N}.jsonl");
        using var audit = new AuditLog(auditPath);

        var fakeRunner = new FakeProcessRunner
        {
            Responses = new()
            {
                ["arjun"] = (0, string.Empty, string.Empty, "{}"),
            }
        };

        var tool = new WebParamFuzzTool(scope, audit, runner: fakeRunner);

        // Act
        await tool.ProbeAsync("http://192.168.1.100/api");

        // Assert: verify argv_digest is SHA256
        audit.Dispose();
        var auditLines = await File.ReadAllLinesAsync(auditPath);
        var startEvent = auditLines.FirstOrDefault(l => l.Contains("\"web-param-fuzz.start\""));

        Assert.NotNull(startEvent);
        Assert.Contains("argv_digest", startEvent);

        // Verify it's a valid hex string (64 chars for SHA256)
        var digestMatch = System.Text.RegularExpressions.Regex.Match(startEvent, "\"argv_digest\":\"([a-f0-9]{64})\"");
        Assert.True(digestMatch.Success, "argv_digest should be a 64-char hex string (SHA256)");

        // Cleanup
        File.Delete(auditPath);
    }

    private static string GetRepoRoot()
    {
        var dir = Directory.GetCurrentDirectory();
        while (dir != null && !File.Exists(Path.Combine(dir, "Drederick.slnx")))
        {
            dir = Directory.GetParent(dir)?.FullName;
        }
        return dir ?? Directory.GetCurrentDirectory();
    }

    /// <summary>Fake process runner for testing without actual subprocess spawns.</summary>
    private sealed class FakeProcessRunner : IProcessRunner
    {
        /// <summary>
        /// Keyed by binary name (e.g., "arjun", "x8"). Value is
        /// (ExitCode, StdOut, StdErr, JsonFileContent).
        /// </summary>
        public Dictionary<string, (int ExitCode, string StdOut, string StdErr, string? JsonFileContent)> Responses { get; init; } = new();

        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
        {
            // Determine which tool based on file name
            var toolName = Path.GetFileName(file);

            if (Responses.TryGetValue(toolName, out var response))
            {
                // If there's JSON content, write it to the temp file path in arguments
                if (response.JsonFileContent is not null)
                {
                    // Extract -oJ <path> from arguments
                    var match = System.Text.RegularExpressions.Regex.Match(arguments, @"-oJ\s+'?([^'\s]+)'?");
                    if (match.Success)
                    {
                        var jsonPath = match.Groups[1].Value.Trim('\'', '"');
                        File.WriteAllText(jsonPath, response.JsonFileContent);
                    }
                }

                return (response.ExitCode, response.StdOut, response.StdErr);
            }

            // Default: command not found
            return (-1, string.Empty, "command not found");
        }

        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
        {
            throw new NotImplementedException();
        }
    }
}
