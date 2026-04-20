using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class SnmpToolTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-snmp-{Guid.NewGuid():N}.jsonl");

    private sealed class QueueRunner : IProcessRunner
    {
        private readonly Queue<(int ExitCode, string StdOut, string StdErr)> _responses;
        public List<(string File, string Arguments)> Calls { get; } = new();

        public QueueRunner(params (int, string, string)[] responses)
        {
            _responses = new Queue<(int, string, string)>(responses);
        }

        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
        {
            Calls.Add((file, arguments));
            if (_responses.Count == 0) return (0, string.Empty, string.Empty);
            return _responses.Dequeue();
        }

        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
            => throw new NotSupportedException();
    }

    private const string PublicWalkOutput =
        ".1.3.6.1.2.1.1.1.0 = STRING: \"Linux gateway 6.1.0-13-amd64\"\n" +
        ".1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.8072.3.2.10\n" +
        ".1.3.6.1.2.1.1.3.0 = Timeticks: (123456) 0:20:34.56\n" +
        ".1.3.6.1.2.1.1.4.0 = STRING: \"admin@example.com\"\n" +
        ".1.3.6.1.2.1.1.5.0 = STRING: \"gateway\"\n" +
        ".1.3.6.1.2.1.1.6.0 = STRING: \"rack 4\"\n" +
        ".1.3.6.1.2.1.1.7.0 = INTEGER: 76\n";

    [Fact]
    public async Task ProbeAsync_Throws_When_Target_Out_Of_Scope()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner();
        var tool = new SnmpTool(scope, audit, runner, snmpwalkPath: "/bin/true");

        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("192.0.2.9"));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task ProbeAsync_Public_Works_Populates_System_Oids()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner((0, PublicWalkOutput, string.Empty));
        var tool = new SnmpTool(scope, audit, runner, snmpwalkPath: "/bin/true");

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.True(result.Reachable);
        Assert.Equal("public", result.Community);
        Assert.Null(result.Error);
        Assert.Equal(161, result.Port);
        Assert.Equal(7, result.SystemOids.Count);
        Assert.Equal("Linux gateway 6.1.0-13-amd64", result.SystemOids[".1.3.6.1.2.1.1.1.0"]);
        Assert.Equal(".1.3.6.1.4.1.8072.3.2.10", result.SystemOids[".1.3.6.1.2.1.1.2.0"]);
        Assert.Equal("gateway", result.SystemOids[".1.3.6.1.2.1.1.5.0"]);

        // Only one snmpwalk invocation on first-community success.
        Assert.Single(runner.Calls);
        var (file, args) = runner.Calls[0];
        Assert.Equal("/bin/true", file);
        Assert.Contains("-v2c", args);
        Assert.Contains("-c public", args);
        Assert.Contains("10.10.10.5:161", args);
        Assert.Contains("1.3.6.1.2.1.1", args);
    }

    [Fact]
    public async Task ProbeAsync_Public_Fails_Private_Works()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner(
            (1, "Timeout: No Response from 10.10.10.5", string.Empty),
            (0, PublicWalkOutput, string.Empty));
        var tool = new SnmpTool(scope, audit, runner, snmpwalkPath: "/bin/true");

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.True(result.Reachable);
        Assert.Equal("private", result.Community);
        Assert.Null(result.Error);
        Assert.NotEmpty(result.SystemOids);

        Assert.Equal(2, runner.Calls.Count);
        Assert.Contains("-c public", runner.Calls[0].Arguments);
        Assert.Contains("-c private", runner.Calls[1].Arguments);
    }

    [Fact]
    public async Task ProbeAsync_Both_Communities_Fail_Sets_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner(
            (1, "Timeout: No Response from 10.10.10.5", string.Empty),
            (1, string.Empty, "Timeout: No Response"));
        var tool = new SnmpTool(scope, audit, runner, snmpwalkPath: "/bin/true");

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.False(result.Reachable);
        Assert.Equal(string.Empty, result.Community);
        Assert.Empty(result.SystemOids);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Contains("Timeout", result.Error, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, runner.Calls.Count);
    }

    [Fact]
    public async Task ProbeAsync_When_Snmpwalk_Missing_Populates_Error_Cleanly()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner((-1, string.Empty, "snmpwalk: command not found"));
        var tool = new SnmpTool(scope, audit, runner, snmpwalkPath: "snmpwalk");

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.False(result.Reachable);
        Assert.Empty(result.SystemOids);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Contains("not found", result.Error, StringComparison.OrdinalIgnoreCase);
        // -1 is a runner-level failure; no point trying the second community.
        Assert.Single(runner.Calls);
    }
}
