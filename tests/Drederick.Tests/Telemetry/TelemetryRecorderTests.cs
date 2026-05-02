using Drederick.Telemetry;
using Xunit;

namespace Drederick.Tests.Telemetry;

public sealed class TelemetryRecorderTests : IDisposable
{
    private readonly string _root;

    public TelemetryRecorderTests()
    {
        _root = Path.Combine(AppContext.BaseDirectory, "telemetry-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }
        catch { /* best-effort cleanup */ }
    }

    private string DbPath() => Path.Combine(_root, "telemetry.db");

    [Fact]
    public async Task RecordAsync_WritesRow()
    {
        await using var rec = new TelemetryRecorder(DbPath());
        await rec.RecordAsync(new TelemetryEvent
        {
            TechniqueId = "nativescan",
            TargetHost = "8.8.8.8",
            Outcome = TelemetryOutcome.Success,
            TimeMs = 42,
        });

        var rows = await CollectAsync(rec, new TelemetryQuery());
        Assert.Single(rows);
        Assert.Equal("nativescan", rows[0].TechniqueId);
        Assert.Equal(42, rows[0].TimeMs);
    }

    [Fact]
    public async Task SchemaCreation_IsIdempotent()
    {
        var path = DbPath();
        await using (var rec = new TelemetryRecorder(path))
        {
            await rec.RecordAsync(new TelemetryEvent { TechniqueId = "t1", Outcome = "success", TimeMs = 1 });
            await rec.RecordAsync(new TelemetryEvent { TechniqueId = "t2", Outcome = "fail", TimeMs = 2 });
        }
        await using (var rec2 = new TelemetryRecorder(path))
        {
            await rec2.RecordAsync(new TelemetryEvent { TechniqueId = "t3", Outcome = "error", TimeMs = 3 });
            var rows = await CollectAsync(rec2, new TelemetryQuery());
            Assert.Equal(3, rows.Count);
        }
    }

    [Fact]
    public async Task ConcurrentWrites_AllPersist()
    {
        await using var rec = new TelemetryRecorder(DbPath());
        const int N = 50;
        var tasks = Enumerable.Range(0, N).Select(i =>
            rec.RecordAsync(new TelemetryEvent
            {
                TechniqueId = $"t-{i % 5}",
                Outcome = TelemetryOutcome.Success,
                TimeMs = i,
            })).ToArray();
        await Task.WhenAll(tasks);

        var rows = await CollectAsync(rec, new TelemetryQuery());
        Assert.Equal(N, rows.Count);
    }

    [Fact]
    public async Task QueryAsync_FiltersWork()
    {
        await using var rec = new TelemetryRecorder(DbPath());
        await rec.RecordAsync(new TelemetryEvent { TechniqueId = "a", Service = "http", Outcome = "success", TimeMs = 1, FightId = "f1" });
        await rec.RecordAsync(new TelemetryEvent { TechniqueId = "b", Service = "ssh", Outcome = "fail", TimeMs = 2, FightId = "f1" });
        await rec.RecordAsync(new TelemetryEvent { TechniqueId = "a", Service = "http", Outcome = "success", TimeMs = 3, FightId = "f2" });

        var byTechnique = await CollectAsync(rec, new TelemetryQuery { TechniqueId = "a" });
        Assert.Equal(2, byTechnique.Count);

        var byFight = await CollectAsync(rec, new TelemetryQuery { FightId = "f1" });
        Assert.Equal(2, byFight.Count);

        var byOutcome = await CollectAsync(rec, new TelemetryQuery { Outcome = "fail" });
        Assert.Single(byOutcome);

        var byService = await CollectAsync(rec, new TelemetryQuery { Service = "ssh" });
        Assert.Single(byService);
    }

    [Theory]
    [InlineData("10.0.0.5", "10.0.0.0/24")]
    [InlineData("192.168.1.42", "192.168.1.0/24")]
    [InlineData("172.16.7.7", "172.16.7.0/24")]
    [InlineData("127.0.0.1", "127.0.0.0/24")]
    [InlineData("169.254.10.1", "169.254.10.0/24")]
    [InlineData("8.8.8.8", "8.8.8.8")]
    [InlineData("1.1.1.1", "1.1.1.1")]
    [InlineData("example.com", "example.com")]
    [InlineData(null, null)]
    public void RedactHost_RedactsPrivateNetworks(string? input, string? expected)
    {
        Assert.Equal(expected, TelemetryRecorder.RedactHost(input));
    }

    [Fact]
    public void RedactHost_RedactsIpv6Loopback()
    {
        var redacted = TelemetryRecorder.RedactHost("::1");
        Assert.NotNull(redacted);
        Assert.EndsWith("/48", redacted);
    }

    [Fact]
    public void RedactHost_RedactsUla()
    {
        var redacted = TelemetryRecorder.RedactHost("fd00::1234");
        Assert.NotNull(redacted);
        Assert.EndsWith("/48", redacted);
    }

    [Fact]
    public async Task Disabled_NoFileNoRows()
    {
        var path = DbPath();
        await using var rec = new TelemetryRecorder(path, enabled: false);
        await rec.RecordAsync(new TelemetryEvent { TechniqueId = "t", Outcome = "success", TimeMs = 1 });
        Assert.False(File.Exists(path));

        var rows = await CollectAsync(rec, new TelemetryQuery());
        Assert.Empty(rows);
    }

    [Fact]
    public async Task InvalidOutcome_Throws()
    {
        await using var rec = new TelemetryRecorder(DbPath());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            rec.RecordAsync(new TelemetryEvent { TechniqueId = "t", Outcome = "weird", TimeMs = 1 }));
    }

    [Fact]
    public async Task EmptyTechnique_Throws()
    {
        await using var rec = new TelemetryRecorder(DbPath());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            rec.RecordAsync(new TelemetryEvent { TechniqueId = "", Outcome = "success", TimeMs = 1 }));
    }

    [Fact]
    public async Task PersistedHostIsRedacted()
    {
        await using var rec = new TelemetryRecorder(DbPath());
        await rec.RecordAsync(new TelemetryEvent
        {
            TechniqueId = "t",
            TargetHost = "10.10.10.5",
            Outcome = "success",
            TimeMs = 1,
        });
        var rows = await CollectAsync(rec, new TelemetryQuery());
        Assert.Single(rows);
        Assert.Equal("10.10.10.0/24", rows[0].TargetHost);
    }

    [Fact]
    public void SchemaSql_ContainsExpectedTablesAndIndexes()
    {
        Assert.Contains("telemetry_events", TelemetryRecorder.SchemaSql);
        Assert.Contains("idx_telemetry_archetype_technique", TelemetryRecorder.SchemaSql);
        Assert.Contains("idx_telemetry_fight", TelemetryRecorder.SchemaSql);
        Assert.Contains("CHECK(outcome IN ('success','fail','error','skipped'))", TelemetryRecorder.SchemaSql);
    }

    private static async Task<List<TelemetryEvent>> CollectAsync(TelemetryRecorder rec, TelemetryQuery q)
    {
        var list = new List<TelemetryEvent>();
        await foreach (var ev in rec.QueryAsync(q))
            list.Add(ev);
        return list;
    }
}
