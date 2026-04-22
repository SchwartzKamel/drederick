using System.Text;
using Drederick.Audit;
using Drederick.Jeopardy.Bus;
using Xunit;

namespace Drederick.Tests.Jeopardy.Bus;

public sealed class SolverMessageBusTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-bus-{Guid.NewGuid():N}.jsonl");

    private static SolverInsight Mk(
        string chal,
        string solver = "claude@c1",
        InsightKind kind = InsightKind.Observation,
        string summary = "binary is 64-bit PIE with canary",
        params string[] tags) => new(
            ChallengeId: chal,
            SolverId: solver,
            ModelId: "claude-opus-4.7",
            Kind: kind,
            Summary: summary,
            DetailsSha256: null,
            Tags: tags,
            At: DateTimeOffset.UtcNow);

    private static async Task<List<SolverInsight>> CollectAsync(
        IAsyncEnumerable<SolverInsight> stream,
        int expected,
        CancellationToken ct,
        TimeSpan? timeout = null)
    {
        var list = new List<SolverInsight>();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(5));
        try
        {
            await foreach (var i in stream.WithCancellation(cts.Token))
            {
                list.Add(i);
                if (list.Count >= expected) break;
            }
        }
        catch (OperationCanceledException) { }
        return list;
    }

    [Fact]
    public async Task Publish_Subscribe_DeliversInsight()
    {
        var path = NewAuditPath();
        using var audit = new AuditLog(path);
        await using var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var stream = bus.Subscribe("c1", "s1", cts.Token);
        var collect = Task.Run(() => CollectAsync(stream, 1, cts.Token));
        await Task.Delay(50);
        await bus.PublishAsync(Mk("c1"), cts.Token);
        var got = await collect;

        Assert.Single(got);
        Assert.Equal("c1", got[0].ChallengeId);
    }

    [Fact]
    public async Task TwoSubscribers_SameChallenge_BothReceive()
    {
        using var audit = new AuditLog(NewAuditPath());
        await using var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var s1 = Task.Run(() => CollectAsync(bus.Subscribe("c1", "a", cts.Token), 2, cts.Token));
        var s2 = Task.Run(() => CollectAsync(bus.Subscribe("c1", "b", cts.Token), 2, cts.Token));
        await Task.Delay(80);

        await bus.PublishAsync(Mk("c1", summary: "one"), cts.Token);
        await bus.PublishAsync(Mk("c1", summary: "two"), cts.Token);

        var r1 = await s1;
        var r2 = await s2;
        Assert.Equal(2, r1.Count);
        Assert.Equal(2, r2.Count);
    }

    [Fact]
    public async Task DifferentChallenges_AreIsolated()
    {
        using var audit = new AuditLog(NewAuditPath());
        await using var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var sA = Task.Run(() => CollectAsync(bus.Subscribe("A", "sa", cts.Token), 1, cts.Token, TimeSpan.FromMilliseconds(500)));
        var sB = Task.Run(() => CollectAsync(bus.Subscribe("B", "sb", cts.Token), 1, cts.Token, TimeSpan.FromMilliseconds(500)));
        await Task.Delay(80);

        await bus.PublishAsync(Mk("A", summary: "only-A"), cts.Token);

        var resA = await sA;
        var resB = await sB;
        Assert.Single(resA);
        Assert.Equal("only-A", resA[0].Summary);
        Assert.Empty(resB);
    }

    [Fact]
    public async Task Dedup_DuplicatePublish_DroppedAndAudited()
    {
        var path = NewAuditPath();
        using var audit = new AuditLog(path);
        await using var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var collect = Task.Run(() => CollectAsync(bus.Subscribe("c1", "s", cts.Token), 1, cts.Token, TimeSpan.FromMilliseconds(600)));
        await Task.Delay(80);

        var i1 = Mk("c1", summary: "dup-me", tags: new[] { "t1", "t2" });
        var i2 = Mk("c1", summary: "dup-me", tags: new[] { "t2", "t1" }); // same content hash (sorted)
        await bus.PublishAsync(i1, cts.Token);
        await bus.PublishAsync(i2, cts.Token);

        var got = await collect;
        Assert.Single(got);

        audit.Dispose();
        var log = await File.ReadAllTextAsync(path);
        Assert.Contains("bus.dedup", log);
    }

    [Fact]
    public async Task History_ReturnsInsertionOrder()
    {
        using var audit = new AuditLog(NewAuditPath());
        await using var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        for (int i = 0; i < 4; i++)
        {
            await bus.PublishAsync(Mk("c1", summary: $"s-{i}"), cts.Token);
        }
        var h = bus.History("c1");
        Assert.Equal(4, h.Count);
        for (int i = 0; i < 4; i++) Assert.Equal($"s-{i}", h[i].Summary);
    }

    [Fact]
    public async Task PerChallengeCap_EvictsOldest()
    {
        using var audit = new AuditLog(NewAuditPath());
        await using var bus = new SolverMessageBus(audit, perChallengeCap: 5);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        for (int i = 0; i < 10; i++)
        {
            await bus.PublishAsync(Mk("c1", summary: $"s-{i}"), cts.Token);
        }
        var h = bus.History("c1");
        Assert.Equal(5, h.Count);
        Assert.Equal("s-5", h[0].Summary);
        Assert.Equal("s-9", h[4].Summary);
        Assert.Equal(5, bus.Count("c1"));
    }

    [Fact]
    public async Task Flag_Summary_NotInAudit_HashOnly()
    {
        var path = NewAuditPath();
        var flag = "flag{canary_bus_666}";
        using (var audit = new AuditLog(path))
        {
            await using var bus = new SolverMessageBus(audit);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await bus.PublishAsync(Mk("c1", kind: InsightKind.Flag, summary: flag), cts.Token);
        }
        var log = await File.ReadAllTextAsync(path);
        Assert.DoesNotContain(flag, log);
        Assert.Contains("summary_sha256", log);
        Assert.Contains("Flag", log);
    }

    [Fact]
    public async Task SlowSubscriber_DoesNotStall_OthersAndAudited()
    {
        var path = NewAuditPath();
        using var audit = new AuditLog(path);
        await using var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // fast subscriber reads eagerly
        var fastDone = Task.Run(() => CollectAsync(bus.Subscribe("c1", "fast", cts.Token), 200, cts.Token, TimeSpan.FromSeconds(8)));
        // slow subscriber: open but never iterate. We open by starting enumeration but blocking with a manual delay.
        var slowStarted = new TaskCompletionSource();
        var slowCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
        var slowTask = Task.Run(async () =>
        {
            await foreach (var _ in bus.Subscribe("c1", "slow", slowCts.Token))
            {
                if (!slowStarted.Task.IsCompleted) slowStarted.TrySetResult();
                // simulate slow reader: block long enough for overflow
                await Task.Delay(2000, slowCts.Token).ContinueWith(_ => { });
            }
        });

        await Task.Delay(150);

        // publish well beyond subscriber channel capacity (128)
        for (int i = 0; i < 200; i++)
        {
            await bus.PublishAsync(Mk("c1", summary: $"burst-{i}"), cts.Token);
        }

        var fast = await fastDone;
        Assert.Equal(200, fast.Count);

        slowCts.Cancel();
        try { await slowTask; } catch { }

        var log = await File.ReadAllTextAsync(path);
        Assert.Contains("bus.slow_subscriber", log);
    }

    [Fact]
    public async Task Subscribe_Cancellation_ExitsCleanly_AuditsClose()
    {
        var path = NewAuditPath();
        using var audit = new AuditLog(path);
        await using var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource();

        var task = Task.Run(async () =>
        {
            await foreach (var _ in bus.Subscribe("c1", "s", cts.Token))
            {
            }
        });
        await Task.Delay(100);
        cts.Cancel();
        await task; // should not throw

        audit.Dispose();
        var log = await File.ReadAllTextAsync(path);
        Assert.Contains("bus.subscribe.close", log);
    }

    [Fact]
    public async Task DisposeAsync_TerminatesSubscribers()
    {
        using var audit = new AuditLog(NewAuditPath());
        var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var sub = Task.Run(async () =>
        {
            await foreach (var _ in bus.Subscribe("c1", "s", cts.Token))
            {
            }
        });
        await Task.Delay(80);
        await bus.DisposeAsync();
        await sub; // terminates cleanly
    }

    [Fact]
    public async Task PushOperatorHint_PropagatesWithOperatorHintKind()
    {
        using var audit = new AuditLog(NewAuditPath());
        await using var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var collect = Task.Run(() => CollectAsync(bus.Subscribe("c1", "s", cts.Token), 1, cts.Token));
        await Task.Delay(80);

        await bus.PushOperatorHintAsync("c1", "try libc-2.31 offsets", tags: new[] { "libc:2.31" }, cts.Token);

        var got = await collect;
        Assert.Single(got);
        Assert.Equal(InsightKind.OperatorHint, got[0].Kind);
        Assert.Equal("operator", got[0].SolverId);
    }

    [Fact]
    public async Task RaceSafety_ManyPublishers_ManySubscribers_NoLoss()
    {
        using var audit = new AuditLog(NewAuditPath());
        await using var bus = new SolverMessageBus(audit);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        const int subs = 10;
        const int msgs = 50;

        var subTasks = Enumerable.Range(0, subs)
            .Select(i => Task.Run(() => CollectAsync(bus.Subscribe("c1", $"s{i}", cts.Token), msgs, cts.Token, TimeSpan.FromSeconds(10))))
            .ToArray();

        await Task.Delay(150);

        var pubTasks = Enumerable.Range(0, msgs)
            .Select(i => Task.Run(async () =>
                await bus.PublishAsync(Mk("c1", solver: $"p{i}", summary: $"msg-{i}"), cts.Token)))
            .ToArray();

        await Task.WhenAll(pubTasks);
        var results = await Task.WhenAll(subTasks);

        foreach (var r in results)
        {
            Assert.Equal(msgs, r.Count);
            Assert.Equal(msgs, r.Select(x => x.Summary).Distinct().Count());
        }
        Assert.Equal(msgs, bus.Count("c1"));
    }
}
