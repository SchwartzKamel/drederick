using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class DnsZoneTransferToolTests
{
    private static string NewAuditPath()
        => Path.Combine(AppContext.BaseDirectory, $"dns-axfr-audit-{Guid.NewGuid():N}.jsonl");

    private sealed class FakeRunner : IProcessRunner
    {
        public List<(string File, string Args, int Timeout)> Calls { get; } = new();
        private readonly Func<string, string, (int, string, string)> _fn;
        public FakeRunner(Func<string, string, (int, string, string)> fn) { _fn = fn; }

        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
        {
            Calls.Add((file, arguments, timeoutSeconds));
            return _fn(file, arguments);
        }

        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
            => throw new NotSupportedException("AXFR tool must not invoke a shell.");
    }

    [Fact]
    public async Task Refuses_When_Nameserver_Out_Of_Scope()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new FakeRunner((_, _) => (0, "", ""));
        var tool = new DnsZoneTransferTool(scope, audit, digPath: "dig", runner: runner);

        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.ProbeAsync("example.com", nameserver: "8.8.8.8"));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Refuses_When_Nameserver_Not_Specified()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new FakeRunner((_, _) => (0, "", ""));
        var tool = new DnsZoneTransferTool(scope, audit, digPath: "dig", runner: runner);

        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.ProbeAsync("example.com", nameserver: null));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Successful_Transfer_Parses_Records()
    {
        const string digOutput = """

            ; <<>> DiG 9.18 <<>> AXFR example.com @10.10.10.5
            ;; global options: +cmd
            example.com.        3600    IN      SOA     ns1.example.com. admin.example.com. 2024 3600 600 86400 3600
            example.com.        3600    IN      NS      ns1.example.com.
            example.com.        3600    IN      NS      ns2.example.com.
            example.com.        3600    IN      A       10.10.10.20
            mail.example.com.   3600    IN      MX      10 mail.example.com.
            example.com.        3600    IN      SOA     ns1.example.com. admin.example.com. 2024 3600 600 86400 3600
            ;; Query time: 3 msec
            ;; SERVER: 10.10.10.5#53(10.10.10.5)
            """;

        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new FakeRunner((_, _) => (0, digOutput, ""));
        var tool = new DnsZoneTransferTool(scope, audit, digPath: "dig", runner: runner);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.True(result.Success);
        Assert.Null(result.Error);
        Assert.Equal("example.com", result.Domain);
        Assert.Equal("10.10.10.5", result.NameServer);
        Assert.Equal(6, result.Records.Count);
        Assert.All(result.Records, r => Assert.DoesNotContain(";", r));
        Assert.Contains(result.Records, r => r.Contains("SOA"));
        Assert.Contains(result.Records, r => r.Contains("\tA\t") || r.Contains(" A "));
        Assert.Contains(result.Records, r => r.Contains("MX"));
        Assert.Single(runner.Calls);
        Assert.Contains("AXFR example.com", runner.Calls[0].Args);
        Assert.Contains("@10.10.10.5", runner.Calls[0].Args);
    }

    [Fact]
    public async Task Refused_Transfer_Sets_Error_And_Success_False()
    {
        const string digOutput = """

            ; <<>> DiG 9.18 <<>> AXFR example.com @10.10.10.5
            ;; global options: +cmd
            ; Transfer failed.
            """;

        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new FakeRunner((_, _) => (0, digOutput, ""));
        var tool = new DnsZoneTransferTool(scope, audit, digPath: "dig", runner: runner);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.Contains("Transfer failed", result.Error);
        Assert.Empty(result.Records);
    }

    [Fact]
    public async Task Refused_Transfer_With_REFUSED_Rcode()
    {
        const string digOutput = """

            ; <<>> DiG 9.18 <<>> AXFR example.com @10.10.10.5
            ; Transfer failed.
            ;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 12345
            """;

        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new FakeRunner((_, _) => (0, digOutput, ""));
        var tool = new DnsZoneTransferTool(scope, audit, digPath: "dig", runner: runner);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.Empty(result.Records);
    }

    [Fact]
    public async Task Dig_Missing_Populates_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new FakeRunner((_, _) => (-1, "", "dig: command not found"));
        var tool = new DnsZoneTransferTool(scope, audit, digPath: "dig", runner: runner);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.Contains("dig", result.Error, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Records);
    }

    [Fact]
    public async Task Dig_Start_Failure_Populates_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new FakeRunner((_, _) =>
            throw new InvalidOperationException("failed to start dig"));
        var tool = new DnsZoneTransferTool(scope, audit, digPath: "dig", runner: runner);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.Contains("dig", result.Error, StringComparison.OrdinalIgnoreCase);
    }
}
