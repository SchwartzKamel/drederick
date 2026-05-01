using System.Net;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using DnsClient;
using Xunit;

namespace Drederick.Tests.Recon;

public class NativeDnsToolTests
{
    private static string NewAuditPath()
        => Path.Combine(AppContext.BaseDirectory, $"dns-native-audit-{Guid.NewGuid():N}.jsonl");

    // --- Stub resolver returns canned records per (name, queryType) pair ---
    private sealed class StubDnsResolver : INativeDnsResolver
    {
        private readonly Dictionary<(string Name, QueryType Type), NativeDnsOutcome> _map;

        public StubDnsResolver(Dictionary<(string, QueryType), NativeDnsOutcome> map)
            => _map = map;

        public Task<NativeDnsOutcome> QueryRecordsAsync(string name, QueryType queryType, CancellationToken ct = default)
        {
            if (_map.TryGetValue((name, queryType), out var outcome))
                return Task.FromResult(outcome);
            return Task.FromResult(new NativeDnsOutcome { Records = Array.Empty<string>() });
        }
    }

    // --- Stub AXFR provider ---
    private sealed class StubAxfrProvider : IAxfrProvider
    {
        private readonly AxfrOutcome _outcome;
        public bool Called { get; private set; }

        public StubAxfrProvider(AxfrOutcome outcome) { _outcome = outcome; }

        public Task<AxfrOutcome> QueryAsync(string zone, IPAddress nameserver, TimeSpan timeout, CancellationToken ct)
        {
            Called = true;
            return Task.FromResult(_outcome);
        }
    }

    // -----------------------------------------------------------------------
    // 1. Out-of-scope target must throw ScopeException before any network call
    // -----------------------------------------------------------------------

    [Fact]
    public async Task OutOfScope_Target_Throws_ScopeException()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());
        var resolver = new StubDnsResolver(new Dictionary<(string, QueryType), NativeDnsOutcome>());
        var tool = new NativeDnsTool(scope, audit, resolver: resolver);

        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.QueryAsync("8.8.8.8", "ALL"));
    }

    [Fact]
    public async Task OutOfScope_Does_Not_Invoke_Resolver()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());

        var resolverCalled = false;
        var resolver = new StubDnsResolver(new Dictionary<(string, QueryType), NativeDnsOutcome>());
        // Wrap with a call-tracking decorator
        var tool = new NativeDnsTool(scope, audit,
            resolver: new CallTrackingResolver(resolver, () => resolverCalled = true));

        await Assert.ThrowsAsync<ScopeException>(() =>
            tool.QueryAsync("1.2.3.4", "ALL"));

        Assert.False(resolverCalled);
    }

    // -----------------------------------------------------------------------
    // 2. A-record resolution for in-scope host using stub resolver
    // -----------------------------------------------------------------------

    [Fact]
    public async Task A_Record_Resolution_Returns_Structured_Result()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());

        // PTR answer for 10.10.10.5 → lab.example.com
        const string ptrName = "5.10.10.10.in-addr.arpa";
        const string hostname = "lab.example.com";

        var resolverMap = new Dictionary<(string, QueryType), NativeDnsOutcome>
        {
            [(ptrName, QueryType.PTR)] = new()
            {
                Records = new[] { $"{ptrName}\t300\tIN\tPTR\t{hostname}." },
            },
            [(hostname, QueryType.A)] = new()
            {
                Records = new[] { $"{hostname}\t300\tIN\tA\t10.10.10.5" },
            },
        };

        var axfrStub = new StubAxfrProvider(new AxfrOutcome { Success = false, Error = "refused" });
        var tool = new NativeDnsTool(scope, audit,
            resolver: new StubDnsResolver(resolverMap),
            axfrProvider: axfrStub);

        var result = await tool.QueryAsync("10.10.10.5", "A");

        Assert.Equal("10.10.10.5", result.Target);
        Assert.Equal("A", result.QueryType);
        Assert.True(result.Records.ContainsKey("A"), "Expected A records in result");
        Assert.Contains(result.Records["A"], r => r.Contains("10.10.10.5"));
    }

    // -----------------------------------------------------------------------
    // 3. AXFR REFUSED → graceful result with error field set, no exception
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Axfr_Refused_Sets_Error_No_Exception()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());

        var axfrStub = new StubAxfrProvider(new AxfrOutcome
        {
            Success = false,
            Refused = true,
            Error = "zone transfer refused (Refused)",
        });

        var tool = new NativeDnsTool(scope, audit,
            resolver: new StubDnsResolver(new Dictionary<(string, QueryType), NativeDnsOutcome>()),
            axfrProvider: axfrStub);

        // Must not throw — a refused AXFR is expected and captured in the result
        var result = await tool.QueryAsync("10.10.10.5", "AXFR");

        Assert.Equal("10.10.10.5", result.Target);
        Assert.True(result.AxfrAttempted);
        Assert.False(result.AxfrSuccess);
        Assert.NotNull(result.AxfrError);
        Assert.Contains("refused", result.AxfrError, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.AxfrRecords);
    }

    // -----------------------------------------------------------------------
    // 4. ALL query type: PTR + forward records + AXFR attempted
    // -----------------------------------------------------------------------

    [Fact]
    public async Task All_QueryType_Runs_Multiple_Record_Types()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        using var audit = new AuditLog(NewAuditPath());

        const string ptrName = "5.10.10.10.in-addr.arpa";
        const string hostname = "ns.example.lab";

        var axfrRecords = new[]
        {
            "example.lab.\t3600\tIN\tSOA\tns.example.lab. admin.example.lab. 1 3600 600 86400 3600",
            "example.lab.\t3600\tIN\tA\t10.10.10.1",
        };

        var resolverMap = new Dictionary<(string, QueryType), NativeDnsOutcome>
        {
            [(ptrName, QueryType.PTR)] = new()
            {
                Records = new[] { $"{ptrName}\t300\tIN\tPTR\t{hostname}." },
            },
            [(hostname, QueryType.A)] = new()
            {
                Records = new[] { $"{hostname}\t300\tIN\tA\t10.10.10.5" },
            },
            [(hostname, QueryType.NS)] = new()
            {
                Records = new[] { $"example.lab.\t300\tIN\tNS\t{hostname}." },
            },
        };

        var axfrStub = new StubAxfrProvider(new AxfrOutcome
        {
            Success = true,
            Records = axfrRecords,
        });

        var tool = new NativeDnsTool(scope, audit,
            resolver: new StubDnsResolver(resolverMap),
            axfrProvider: axfrStub);

        var result = await tool.QueryAsync("10.10.10.5", "ALL");

        Assert.Equal("10.10.10.5", result.Target);
        Assert.True(result.Records.ContainsKey("PTR"), "Expected PTR records");
        Assert.True(result.Records.ContainsKey("A"), "Expected A records");
        Assert.True(result.AxfrAttempted);
        Assert.True(result.AxfrSuccess);
        Assert.Equal(2, result.AxfrRecords.Count);
        Assert.Contains(result.AxfrRecords, r => r.Contains("SOA"));
        Assert.True(axfrStub.Called);
    }

    // -----------------------------------------------------------------------
    // 5. Audit log receives start/finish events
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Audit_Records_Start_And_Finish_Events()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        var auditPath = NewAuditPath();
        using var audit = new AuditLog(auditPath);

        var tool = new NativeDnsTool(scope, audit,
            resolver: new StubDnsResolver(new Dictionary<(string, QueryType), NativeDnsOutcome>()),
            axfrProvider: new StubAxfrProvider(new AxfrOutcome { Success = false, Error = "refused" }));

        await tool.QueryAsync("10.10.10.5", "A");

        // Flush + check log file
        await Task.Delay(50); // tiny settle time for async append
        var lines = File.Exists(auditPath)
            ? await File.ReadAllLinesAsync(auditPath)
            : Array.Empty<string>();

        Assert.Contains(lines, l => l.Contains("dns-native.start"));
        Assert.Contains(lines, l => l.Contains("dns-native.finish"));
    }

    // --- helper: call-counting decorator --------------------------------

    private sealed class CallTrackingResolver : INativeDnsResolver
    {
        private readonly INativeDnsResolver _inner;
        private readonly Action _onCall;
        public CallTrackingResolver(INativeDnsResolver inner, Action onCall)
        {
            _inner = inner;
            _onCall = onCall;
        }
        public Task<NativeDnsOutcome> QueryRecordsAsync(string name, QueryType queryType, CancellationToken ct = default)
        {
            _onCall();
            return _inner.QueryRecordsAsync(name, queryType, ct);
        }
    }
}
