using Drederick.Audit;
using Drederick.Jeopardy.Coordinator;
using Drederick.Jeopardy.Ctfd;
using Drederick.Tests.Jeopardy.Coordinator.Fakes;
using Xunit;

namespace Drederick.Tests.Jeopardy.Coordinator;

public sealed class CtfdPollerTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly AuditLog _audit;

    public CtfdPollerTests()
    {
        _tmpDir = Path.Combine(AppContext.BaseDirectory, $"drederick-poller-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tmpDir);
        _audit = new AuditLog(Path.Combine(_tmpDir, "audit.jsonl"));
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_tmpDir, recursive: true); } catch { }
    }

    private static CtfdChallenge Chal(int id, string cat = "pwn", int value = 100, bool solved = false,
        IReadOnlyList<string>? tags = null, string? name = null)
        => new(id, name ?? $"chal-{id}", cat, value, "", Array.Empty<CtfdAttachment>(),
            tags ?? Array.Empty<string>(), null, solved);

    [Fact]
    public async Task FirstPoll_YieldsDiscoveredForAllChallenges()
    {
        var client = new FakeCtfdClient();
        client.Enqueue(new[] { Chal(1), Chal(2), Chal(3) });
        await using var poller = new CtfdPoller(client, _audit, TimeSpan.FromMilliseconds(5),
            delay: (_, _) => Task.CompletedTask);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var changes = new List<ChallengeChange>();
        await foreach (var c in poller.StreamAsync(cts.Token))
        {
            changes.Add(c);
            if (changes.Count >= 3) break;
        }
        Assert.Equal(3, changes.Count);
        Assert.All(changes, c => Assert.Equal(ChallengeChangeKind.Discovered, c.Kind));
    }

    [Fact]
    public async Task SolvedFlip_YieldsSolvedExternally()
    {
        var client = new FakeCtfdClient();
        client.Enqueue(new[] { Chal(1) });
        client.Enqueue(new[] { Chal(1, solved: true) });
        await using var poller = new CtfdPoller(client, _audit, TimeSpan.FromMilliseconds(5),
            delay: (_, _) => Task.CompletedTask);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var kinds = new List<ChallengeChangeKind>();
        await foreach (var c in poller.StreamAsync(cts.Token))
        {
            kinds.Add(c.Kind);
            if (kinds.Count >= 2) break;
        }
        Assert.Contains(ChallengeChangeKind.Discovered, kinds);
        Assert.Contains(ChallengeChangeKind.SolvedExternally, kinds);
    }

    [Fact]
    public async Task MetadataEdit_YieldsUpdated()
    {
        var client = new FakeCtfdClient();
        client.Enqueue(new[] { Chal(1, value: 100, tags: new[] { "a" }) });
        client.Enqueue(new[] { Chal(1, value: 250, tags: new[] { "a", "hard" }) });
        await using var poller = new CtfdPoller(client, _audit, TimeSpan.FromMilliseconds(5),
            delay: (_, _) => Task.CompletedTask);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var changes = new List<ChallengeChange>();
        await foreach (var c in poller.StreamAsync(cts.Token))
        {
            changes.Add(c);
            if (changes.Count >= 2) break;
        }
        Assert.Equal(ChallengeChangeKind.Discovered, changes[0].Kind);
        Assert.Equal(ChallengeChangeKind.Updated, changes[1].Kind);
        Assert.Equal(250, changes[1].Challenge.Value);
    }

    [Fact]
    public async Task StableSnapshot_EmitsNoUpdates()
    {
        var client = new FakeCtfdClient();
        client.Enqueue(new[] { Chal(1) });
        client.Enqueue(new[] { Chal(1) });
        client.Enqueue(new[] { Chal(1) });
        await using var poller = new CtfdPoller(client, _audit, TimeSpan.FromMilliseconds(5),
            delay: (_, _) => Task.CompletedTask);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var changes = new List<ChallengeChange>();
        try
        {
            await foreach (var c in poller.StreamAsync(cts.Token))
            {
                changes.Add(c);
            }
        }
        catch (OperationCanceledException) { }
        Assert.Single(changes);
        Assert.Equal(ChallengeChangeKind.Discovered, changes[0].Kind);
    }

    [Fact]
    public async Task DelayFunction_IsInvokedBetweenPolls()
    {
        var client = new FakeCtfdClient();
        client.Enqueue(new[] { Chal(1) });
        client.Enqueue(new[] { Chal(1), Chal(2) });
        int delayCalls = 0;
        await using var poller = new CtfdPoller(client, _audit, TimeSpan.FromMilliseconds(50),
            delay: (_, _) => { Interlocked.Increment(ref delayCalls); return Task.CompletedTask; });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var ids = new List<int>();
        await foreach (var c in poller.StreamAsync(cts.Token))
        {
            ids.Add(c.Challenge.Id);
            if (ids.Count >= 2) break;
        }
        Assert.Equal(new[] { 1, 2 }, ids.OrderBy(i => i).ToArray());
        Assert.True(delayCalls >= 1);
    }
}
