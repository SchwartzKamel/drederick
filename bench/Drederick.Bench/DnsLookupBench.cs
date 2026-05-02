using BenchmarkDotNet.Attributes;
using DnsClient;

namespace Drederick.Bench;

/// <summary>
/// Compares <c>DnsClient.NET</c> A-record resolution against shelling out to
/// <c>dig +short</c>. Resolver target is loopback (127.0.0.1), which is the
/// only address the bench's scope authorizes. The lookup may fail if no
/// resolver is listening — both arms are still timed comparably.
/// </summary>
[MemoryDiagnoser]
public class DnsLookupBench
{
    private const string QueryName = "localhost";
    private const string ResolverIp = "127.0.0.1";

    private LookupClient _client = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Sanity: the resolver target itself is in scope.
        BenchHelpers.LoopbackScope().Require(ResolverIp);
        var opts = new LookupClientOptions(System.Net.IPAddress.Parse(ResolverIp))
        {
            Timeout = TimeSpan.FromMilliseconds(500),
            Retries = 0,
            UseCache = false,
        };
        _client = new LookupClient(opts);
    }

    [Benchmark(Baseline = true, Description = "DnsClient A-record (native)")]
    public int Native()
    {
        try
        {
            var res = _client.Query(QueryName, QueryType.A);
            return res.Answers.Count;
        }
        catch
        {
            return 0;
        }
    }

    [SkippableBenchmark(Reason = "Requires `dig` on PATH", Description = "dig +short (subprocess)")]
    public string Subprocess()
    {
        if (!BenchHelpers.BinaryAvailable("dig")) return string.Empty;
        return BenchHelpers.RunAndCapture("dig", $"+short +time=1 +tries=1 @{ResolverIp} {QueryName}");
    }
}
