using Drederick.Audit;
using Drederick.Cli;
using Xunit;

namespace Drederick.Tests;

public class InitCommandTests
{
    private static string NewScratch()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "init-scratch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static AuditLog NewAudit(string scratch)
        => new(Path.Combine(scratch, "audit.jsonl"));

    [Fact]
    public async Task InitSkipCredsSkipScope_RunsWithoutErrors()
    {
        var scratch = NewScratch();
        try
        {
            var audit = NewAudit(scratch);
            var input = new StringReader("n\n");
            var output = new StringWriter();
            var error = new StringWriter();

            var opts = new CommandLineOptions
            {
                InitSubcommand = true,
                InitSkipCreds = true,
                InitSkipScope = true,
                AssumeYes = false,
                OutputDir = scratch,
            };

            var cmd = new InitCommand(input, output, error, audit);
            var exitCode = await cmd.ExecuteAsync(opts);

            Assert.Equal(0, exitCode);
            var outStr = output.ToString();
            Assert.Contains("Welcome to Drederick", outStr);
            audit.Dispose();
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
        }
    }

    [Fact]
    public async Task InitSkipBothAndDeclineTools_PrintsNextSteps()
    {
        var scratch = NewScratch();
        try
        {
            var audit = NewAudit(scratch);
            var input = new StringReader("n\n");
            var output = new StringWriter();
            var error = new StringWriter();

            var opts = new CommandLineOptions
            {
                InitSubcommand = true,
                InitSkipCreds = true,
                InitSkipScope = true,
                AssumeYes = false,
                OutputDir = scratch,
            };

            var cmd = new InitCommand(input, output, error, audit);
            var exitCode = await cmd.ExecuteAsync(opts);

            Assert.Equal(0, exitCode);
            var outStr = output.ToString();
            Assert.Contains("Welcome to Drederick", outStr);
            Assert.Contains("Quick Start:", outStr);
            Assert.Contains("drederick doctor", outStr);
            Assert.Contains("drederick serve", outStr);
            audit.Dispose();
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
        }
    }

    [Fact]
    public async Task InitAuditsStartEvent()
    {
        var scratch = NewScratch();
        try
        {
            var audit = NewAudit(scratch);
            var input = new StringReader("n\n");
            var output = new StringWriter();
            var error = new StringWriter();

            var opts = new CommandLineOptions
            {
                InitSubcommand = true,
                InitSkipCreds = true,
                InitSkipScope = true,
                AssumeYes = false,
                OutputDir = scratch,
            };

            var cmd = new InitCommand(input, output, error, audit);
            await cmd.ExecuteAsync(opts);
            audit.Dispose();

            // Check audit log
            var auditPath = Path.Combine(scratch, "audit.jsonl");
            var lines = File.ReadAllLines(auditPath);
            Assert.NotEmpty(lines);
            var auditContent = string.Join("\n", lines);
            Assert.Contains("init.start", auditContent);
            Assert.Contains("init.finish", auditContent);
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
        }
    }

    [Fact]
    public async Task InitDeclineCredsSetup_ShowsCorrectMessage()
    {
        var scratch = NewScratch();
        try
        {
            var audit = NewAudit(scratch);
            var input = new StringReader("n\nn\n"); // Decline tools and creds
            var output = new StringWriter();
            var error = new StringWriter();

            var opts = new CommandLineOptions
            {
                InitSubcommand = true,
                InitSkipCreds = false,
                InitSkipScope = true,
                AssumeYes = false,
                OutputDir = scratch,
            };

            var cmd = new InitCommand(input, output, error, audit);
            var exitCode = await cmd.ExecuteAsync(opts);

            Assert.Equal(0, exitCode);
            var outStr = output.ToString();
            Assert.Contains("Skipping credential setup", outStr);
            audit.Dispose();
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
        }
    }

    [Fact]
    public async Task InitWelcomeMessage_IsDisplayed()
    {
        var scratch = NewScratch();
        try
        {
            var audit = NewAudit(scratch);
            var input = new StringReader("n\nn\n");
            var output = new StringWriter();
            var error = new StringWriter();

            var opts = new CommandLineOptions
            {
                InitSubcommand = true,
                InitSkipCreds = true,
                InitSkipScope = true,
                AssumeYes = false,
                OutputDir = scratch,
            };

            var cmd = new InitCommand(input, output, error, audit);
            await cmd.ExecuteAsync(opts);

            var outStr = output.ToString();
            Assert.Contains("Welcome to Drederick!", outStr);
            Assert.Contains("This wizard will help you set up the basics", outStr);
            Assert.Contains("drederick init", outStr);
            audit.Dispose();
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
        }
    }
}
