using Drederick.Cli;
using Xunit;

namespace Drederick.Tests.Cli;

/// <summary>
/// GAP-045 — locker-collision startup guard.
/// Convention: "Fresh locker, every fight" (README → Code of the Ring).
/// </summary>
public class LockerCollisionTests : IDisposable
{
    private readonly string _root;

    public LockerCollisionTests()
    {
        _root = Path.Combine(AppContext.BaseDirectory,
            "locker-collision-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string NewDir(string name)
    {
        var p = Path.Combine(_root, name);
        Directory.CreateDirectory(p);
        return p;
    }

    [Fact]
    public void NonexistentDir_ReturnsOk()
    {
        var dir = Path.Combine(_root, "does-not-exist-" + Guid.NewGuid().ToString("N"));
        var stderr = new StringWriter();

        var result = LockerCollisionGuard.Check(dir, allowLockerCollision: false);
        Assert.Equal(LockerCollisionGuard.Outcome.Ok, result.Outcome);

        var exit = LockerCollisionGuard.Apply(dir, allowLockerCollision: false, stderr);
        Assert.Null(exit);
        Assert.Equal(string.Empty, stderr.ToString());
    }

    [Fact]
    public void EmptyDir_StartsFine()
    {
        var dir = NewDir("empty");
        var stderr = new StringWriter();

        var result = LockerCollisionGuard.Check(dir, allowLockerCollision: false);
        Assert.Equal(LockerCollisionGuard.Outcome.Ok, result.Outcome);

        var exit = LockerCollisionGuard.Apply(dir, allowLockerCollision: false, stderr);
        Assert.Null(exit);
    }

    [Fact]
    public void EmptyAuditFile_StartsFine()
    {
        var dir = NewDir("empty-audit");
        File.WriteAllText(Path.Combine(dir, "audit.jsonl"), string.Empty);
        var stderr = new StringWriter();

        var result = LockerCollisionGuard.Check(dir, allowLockerCollision: false);
        Assert.Equal(LockerCollisionGuard.Outcome.Ok, result.Outcome);

        var exit = LockerCollisionGuard.Apply(dir, allowLockerCollision: false, stderr);
        Assert.Null(exit);
    }

    [Fact]
    public void NonEmptyAuditNoFlag_RefusesWithExitTwoAndMessage()
    {
        var dir = NewDir("collision-refused");
        File.WriteAllText(Path.Combine(dir, "audit.jsonl"), "{\"event\":\"prior.run\"}\n");
        var stderr = new StringWriter();

        var result = LockerCollisionGuard.Check(dir, allowLockerCollision: false);
        Assert.Equal(LockerCollisionGuard.Outcome.Refused, result.Outcome);
        Assert.NotNull(result.Message);
        Assert.Contains("GAP-045", result.Message);
        Assert.Contains("Fresh locker, every fight", result.Message);
        Assert.Contains("--allow-locker-collision", result.Message);
        Assert.Contains(dir, result.Message);

        var exit = LockerCollisionGuard.Apply(dir, allowLockerCollision: false, stderr);
        Assert.Equal(2, exit);
        var emitted = stderr.ToString();
        Assert.Contains("GAP-045", emitted);
        Assert.Contains("Fresh locker, every fight", emitted);
        Assert.Contains("--allow-locker-collision", emitted);
    }

    [Fact]
    public void NonEmptyAuditWithFlag_StartsAndRecordsCollisionEvent()
    {
        var dir = NewDir("collision-allowed");
        var auditPath = Path.Combine(dir, "audit.jsonl");
        File.WriteAllText(auditPath, "{\"event\":\"prior.run\"}\n");
        var preLen = new FileInfo(auditPath).Length;

        var result = LockerCollisionGuard.Check(dir, allowLockerCollision: true);
        Assert.Equal(LockerCollisionGuard.Outcome.Allowed, result.Outcome);
        Assert.Equal(preLen, result.ExistingAuditBytes);

        var stderr = new StringWriter();
        var exit = LockerCollisionGuard.Apply(dir, allowLockerCollision: true, stderr);
        Assert.Null(exit);

        // The Apply call must append a `locker.collision.allowed` event to
        // audit.jsonl without truncating the prior contents.
        var newLen = new FileInfo(auditPath).Length;
        Assert.True(newLen > preLen, "audit.jsonl must grow (append-only)");
        var lines = File.ReadAllLines(auditPath);
        Assert.Contains("prior.run", lines[0]);
        Assert.Contains(lines, l => l.Contains("locker.collision.allowed") && l.Contains("GAP-045"));
    }

    [Fact]
    public void CommandLineOptions_ParsesAllowLockerCollisionFlag()
    {
        var opts = CommandLineOptions.Parse(new[]
        {
            "--scope", "scope.yaml",
            "--target", "10.0.0.1",
            "--out", "out",
            "--allow-locker-collision",
        });
        Assert.True(opts.AllowLockerCollision);
    }

    [Fact]
    public void CommandLineOptions_DefaultsAllowLockerCollisionToFalse()
    {
        var opts = CommandLineOptions.Parse(new[]
        {
            "--scope", "scope.yaml",
            "--target", "10.0.0.1",
            "--out", "out",
        });
        Assert.False(opts.AllowLockerCollision);
    }
}
