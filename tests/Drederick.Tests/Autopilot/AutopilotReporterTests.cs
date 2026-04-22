using Drederick.Autopilot;
using Xunit;

namespace Drederick.Tests.Autopilot;

public class AutopilotReporterTests
{
    private static string NewDir() =>
        Path.Combine(Path.GetTempPath(), $"autopilot-rep-{Guid.NewGuid():N}");

    [Fact]
    public void Writes_Markdown_With_Tatum_Banner()
    {
        var dir = NewDir();
        Directory.CreateDirectory(dir);
        try
        {
            var report = new AutopilotReport(
                Iterations: 2,
                Actions: new List<ExploitActionResult>
                {
                    new()
                    {
                        Action = new ExploitAction { Tool = "nuclei", Target = "10.10.10.5", Port = 80, Priority = 400, Reason = "test" },
                        Succeeded = true, DurationMs = 42,
                    },
                    new()
                    {
                        Action = new ExploitAction { Tool = "password-spray", Target = "10.10.10.5", Port = 445, Priority = 200, Reason = "spray" },
                        Skipped = true, SkipReason = "no perms", DurationMs = 1,
                    },
                },
                Flags: new List<FlagMatch>
                {
                    new("HTB{knockout}", FlagExtractor.Sha256Hex("HTB{knockout}"),
                        "htb-pattern", "nuclei:10.10.10.5:80"),
                },
                KnownCredentials: new List<CredentialRef>
                {
                    new() { User = "admin", Realm = null, PasswordSha256 = new string('a', 64) },
                });

            AutopilotReporter.Write(dir, report);
            var md = File.ReadAllText(Path.Combine(dir, "autopilot.md"));
            Assert.Contains("fight card", md, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Drederick E. Tatum", md);
            Assert.Contains("Knockouts", md);
            Assert.Contains("Round-by-round", md);
            Assert.Contains("Sparring partners", md);
            Assert.Contains("HTB{knockout}", md);

            var json = File.ReadAllText(Path.Combine(dir, "autopilot.json"));
            Assert.Contains("\"Iterations\"", json);
            Assert.Contains("HTB{knockout}", json);
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }

    [Fact]
    public void Markdown_Escapes_Pipes_In_Reason()
    {
        var dir = NewDir();
        Directory.CreateDirectory(dir);
        try
        {
            var report = new AutopilotReport(
                Iterations: 1,
                Actions: new List<ExploitActionResult>
                {
                    new()
                    {
                        Action = new ExploitAction
                        {
                            Tool = "nuclei", Target = "10.10.10.5", Port = 80, Priority = 400,
                            Reason = "pipes | in | reason",
                        },
                        Succeeded = true,
                    },
                },
                Flags: Array.Empty<FlagMatch>(),
                KnownCredentials: Array.Empty<CredentialRef>());

            AutopilotReporter.Write(dir, report);
            var md = File.ReadAllText(Path.Combine(dir, "autopilot.md"));
            Assert.Contains(@"pipes \| in \| reason", md);
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }
}
