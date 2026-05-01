using System.Net;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class DnsZoneTransferToolTests
{
    private static string NewAuditPath()
        => Path.Combine(AppContext.BaseDirectory, $"dns-axfr-audit-{Guid.NewGuid():N}.jsonl");

    private sealed class StubAxfrProvider : IAxfrProvider
    {
        private readonly Func<string, IPAddress, AxfrOutcome> _fn;

        public List<(string Zone, IPAddress Ns)> Calls { get; } = new();

        public StubAxfrProvider(Func<string, IPAddress, AxfrOutcome> fn) { _fn = fn; }

        public Task<AxfrOutcome> QueryAsync(string zone, IPAddress nameserver, TimeSpan timeout, CancellationToken ct)
        {
            Calls.Add((zone, nameserver));
            return Task.FromResult(_fn(zone, nameserver));
        }
    }

    [Fact]
    public async Task Refuses_When_Nameserver_Out_Of_Scope()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var provider = new StubAxfrProvider((_, _) => new AxfrOutcome { Success = true });
        var tool = new DnsZoneTransferTool(scope, audit, provider: provider);

        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.ProbeAsync("example.com", nameserver: "8.8.8.8"));
        Assert.Empty(provider.Calls);
    }

    [Fact]
    public async Task Refuses_When_Nameserver_Not_Specified()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var provider = new StubAxfrProvider((_, _) => new AxfrOutcome { Success = true });
        var tool = new DnsZoneTransferTool(scope, audit, provider: provider);

        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.ProbeAsync("example.com", nameserver: null));
        Assert.Empty(provider.Calls);
    }

    [Fact]
    public async Task Successful_Transfer_Parses_Records()
    {
        var records = new[]
        {
            "example.com.\t3600\tIN\tSOA\tns1.example.com. admin.example.com. 2024 3600 600 86400 3600",
            "example.com.\t3600\tIN\tNS\tns1.example.com.",
            "example.com.\t3600\tIN\tNS\tns2.example.com.",
            "example.com.\t3600\tIN\tA\t10.10.10.20",
            "mail.example.com.\t3600\tIN\tMX\t10 mail.example.com.",
            "example.com.\t3600\tIN\tSOA\tns1.example.com. admin.example.com. 2024 3600 600 86400 3600",
        };

        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var provider = new StubAxfrProvider((_, _) => new AxfrOutcome
        {
            Success = true,
            Records = records,
        });
        var tool = new DnsZoneTransferTool(scope, audit, provider: provider);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.True(result.Success);
        Assert.Null(result.Error);
        Assert.Equal("example.com", result.Domain);
        Assert.Equal("10.10.10.5", result.NameServer);
        Assert.Equal(6, result.Records.Count);
        Assert.Contains(result.Records, r => r.Contains("SOA"));
        Assert.Contains(result.Records, r => r.Contains("\tA\t") || r.Contains(" A "));
        Assert.Contains(result.Records, r => r.Contains("MX"));
        Assert.Single(provider.Calls);
        Assert.Equal("example.com", provider.Calls[0].Zone);
        Assert.Equal(IPAddress.Parse("10.10.10.5"), provider.Calls[0].Ns);
    }

    [Fact]
    public async Task Refused_Transfer_Sets_Error_And_Success_False()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var provider = new StubAxfrProvider((_, _) => new AxfrOutcome
        {
            Success = false,
            Refused = true,
            Error = "zone transfer refused (Refused)",
        });
        var tool = new DnsZoneTransferTool(scope, audit, provider: provider);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.Contains("refused", result.Error, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Records);
    }

    [Fact]
    public async Task Refused_Transfer_With_REFUSED_Rcode()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var provider = new StubAxfrProvider((_, _) => new AxfrOutcome
        {
            Success = false,
            Refused = true,
            Error = "zone transfer refused (NotAuth)",
        });
        var tool = new DnsZoneTransferTool(scope, audit, provider: provider);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.Empty(result.Records);
    }

    [Fact]
    public async Task Provider_Error_Populates_Error_Field()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var provider = new StubAxfrProvider((_, _) => new AxfrOutcome
        {
            Success = false,
            Error = "connection timed out",
        });
        var tool = new DnsZoneTransferTool(scope, audit, provider: provider);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.Contains("timed out", result.Error, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Records);
    }

    [Fact]
    public async Task Provider_Returns_Zero_Records_Sets_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var provider = new StubAxfrProvider((_, _) => new AxfrOutcome
        {
            Success = false,
            Error = "no records returned",
        });
        var tool = new DnsZoneTransferTool(scope, audit, provider: provider);

        var result = await tool.ProbeAsync("example.com", "10.10.10.5");

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.Empty(result.Records);
    }
}
