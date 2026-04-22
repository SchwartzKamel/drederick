using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Drederick.Audit;

namespace Drederick.Jeopardy.Bus;

public enum InsightKind
{
    Observation,
    Dead_End,
    Partial,
    Hypothesis,
    Flag,
    Error,
    OperatorHint,
    CoordinatorHint,
}

public sealed record SolverInsight(
    string ChallengeId,
    string SolverId,
    string ModelId,
    InsightKind Kind,
    string Summary,
    string? DetailsSha256,
    IReadOnlyList<string> Tags,
    DateTimeOffset At);

public interface ISolverMessageBus
{
    IAsyncEnumerable<SolverInsight> Subscribe(string challengeId, string solverId, CancellationToken ct);
    ValueTask PublishAsync(SolverInsight insight, CancellationToken ct);
    IReadOnlyList<SolverInsight> History(string challengeId);
    int Count(string challengeId);
}

/// <summary>
/// In-process cross-solver message bus scoped per Jeopardy challenge. Multiple
/// models racing on the same challenge share observations, dead-ends, partials,
/// and hypotheses so progress compounds instead of being duplicated. Every
/// publish / subscribe / dedup / slow-subscriber event is recorded to the
/// audit log; sensitive kinds (<see cref="InsightKind.Flag"/>) are audited as
/// SHA-256 only.
/// </summary>
public sealed class SolverMessageBus : ISolverMessageBus, IAsyncDisposable
{
    private const int SubscriberChannelCapacity = 128;
    private const int MaxSummaryChars = 512;

    private readonly AuditLog _audit;
    private readonly int _perChallengeCap;
    private readonly ConcurrentDictionary<string, ChallengeBus> _challenges = new();
    private readonly CancellationTokenSource _disposeCts = new();
    private int _disposed;

    public SolverMessageBus(AuditLog audit, int perChallengeCap = 512)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (perChallengeCap <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(perChallengeCap));
        }
        _audit = audit;
        _perChallengeCap = perChallengeCap;
    }

    public async IAsyncEnumerable<SolverInsight> Subscribe(
        string challengeId,
        string solverId,
        [EnumeratorCancellation] CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(challengeId);
        ArgumentException.ThrowIfNullOrEmpty(solverId);
        ThrowIfDisposed();

        var cb = _challenges.GetOrAdd(challengeId, _ => new ChallengeBus());
        var channel = Channel.CreateBounded<SolverInsight>(new BoundedChannelOptions(SubscriberChannelCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
        });
        var sub = new Subscriber(solverId, channel);

        lock (cb.Gate)
        {
            cb.Subscribers.Add(sub);
        }

        _audit.Record("bus.subscribe.open", new Dictionary<string, object?>
        {
            ["challenge_id"] = challengeId,
            ["solver_id"] = solverId,
        });

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _disposeCts.Token);
        try
        {
            while (true)
            {
                bool hasMore;
                try
                {
                    hasMore = await channel.Reader.WaitToReadAsync(linked.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    yield break;
                }
                if (!hasMore)
                {
                    yield break;
                }
                while (channel.Reader.TryRead(out var item))
                {
                    yield return item;
                }
            }
        }
        finally
        {
            lock (cb.Gate)
            {
                cb.Subscribers.Remove(sub);
            }
            channel.Writer.TryComplete();
            _audit.Record("bus.subscribe.close", new Dictionary<string, object?>
            {
                ["challenge_id"] = challengeId,
                ["solver_id"] = solverId,
                ["drop_count"] = Volatile.Read(ref sub.DropCount),
            });
        }
    }

    public ValueTask PublishAsync(SolverInsight insight, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(insight);
        ct.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        if (insight.Summary.Length > MaxSummaryChars)
        {
            throw new ArgumentException(
                $"Summary exceeds {MaxSummaryChars} chars; store long detail out-of-band and pass DetailsSha256.",
                nameof(insight));
        }

        var cb = _challenges.GetOrAdd(insight.ChallengeId, _ => new ChallengeBus());
        var contentHash = ComputeContentHash(insight);
        var summaryHash = Sha256Hex(insight.Summary);

        List<Subscriber> snapshot;
        lock (cb.Gate)
        {
            if (!cb.SeenHashes.Add(contentHash))
            {
                _audit.Record("bus.dedup", new Dictionary<string, object?>
                {
                    ["challenge_id"] = insight.ChallengeId,
                    ["solver_id"] = insight.SolverId,
                    ["kind"] = insight.Kind.ToString(),
                    ["summary_sha256"] = summaryHash,
                    ["tag_count"] = insight.Tags.Count,
                });
                return ValueTask.CompletedTask;
            }
            cb.History.AddLast(insight);
            while (cb.History.Count > _perChallengeCap)
            {
                cb.History.RemoveFirst();
            }
            snapshot = new List<Subscriber>(cb.Subscribers);
        }

        _audit.Record("bus.publish", new Dictionary<string, object?>
        {
            ["challenge_id"] = insight.ChallengeId,
            ["solver_id"] = insight.SolverId,
            ["kind"] = insight.Kind.ToString(),
            ["summary_sha256"] = summaryHash,
            ["tag_count"] = insight.Tags.Count,
        });

        foreach (var sub in snapshot)
        {
            if (!sub.Channel.Writer.TryWrite(insight))
            {
                var drops = Interlocked.Increment(ref sub.DropCount);
                if (Interlocked.CompareExchange(ref sub.SlowReported, 1, 0) == 0)
                {
                    _audit.Record("bus.slow_subscriber", new Dictionary<string, object?>
                    {
                        ["challenge_id"] = insight.ChallengeId,
                        ["solver_id"] = sub.SolverId,
                        ["drops"] = drops,
                    });
                }
            }
        }

        return ValueTask.CompletedTask;
    }

    public IReadOnlyList<SolverInsight> History(string challengeId)
    {
        ArgumentException.ThrowIfNullOrEmpty(challengeId);
        if (!_challenges.TryGetValue(challengeId, out var cb))
        {
            return Array.Empty<SolverInsight>();
        }
        lock (cb.Gate)
        {
            return cb.History.ToArray();
        }
    }

    public int Count(string challengeId)
    {
        ArgumentException.ThrowIfNullOrEmpty(challengeId);
        if (!_challenges.TryGetValue(challengeId, out var cb))
        {
            return 0;
        }
        lock (cb.Gate)
        {
            return cb.History.Count;
        }
    }

    public ValueTask PushOperatorHintAsync(string challengeId, string hint, IReadOnlyList<string>? tags, CancellationToken ct) =>
        PublishAsync(BuildHint(challengeId, "operator", InsightKind.OperatorHint, hint, tags), ct);

    public ValueTask PushCoordinatorHintAsync(string challengeId, string hint, IReadOnlyList<string>? tags, CancellationToken ct) =>
        PublishAsync(BuildHint(challengeId, "coordinator", InsightKind.CoordinatorHint, hint, tags), ct);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        try
        {
            _disposeCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
        foreach (var cb in _challenges.Values)
        {
            List<Subscriber> snapshot;
            lock (cb.Gate)
            {
                snapshot = new List<Subscriber>(cb.Subscribers);
            }
            foreach (var sub in snapshot)
            {
                sub.Channel.Writer.TryComplete();
            }
        }
        _disposeCts.Dispose();
        await Task.CompletedTask.ConfigureAwait(false);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(SolverMessageBus));
        }
    }

    private static SolverInsight BuildHint(string challengeId, string solverId, InsightKind kind, string hint, IReadOnlyList<string>? tags) =>
        new(
            ChallengeId: challengeId,
            SolverId: solverId,
            ModelId: solverId,
            Kind: kind,
            Summary: hint,
            DetailsSha256: null,
            Tags: tags ?? Array.Empty<string>(),
            At: DateTimeOffset.UtcNow);

    private static string ComputeContentHash(SolverInsight insight)
    {
        var sorted = insight.Tags.OrderBy(t => t, StringComparer.Ordinal);
        var material = $"{(int)insight.Kind}\n{insight.Summary}\n{string.Join(",", sorted)}";
        return Sha256Hex(material);
    }

    private static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private sealed class ChallengeBus
    {
        public readonly Lock Gate = new();
        public readonly LinkedList<SolverInsight> History = new();
        public readonly HashSet<string> SeenHashes = new();
        public readonly List<Subscriber> Subscribers = new();
    }

    private sealed class Subscriber
    {
        public readonly string SolverId;
        public readonly Channel<SolverInsight> Channel;
        public int DropCount;
        public int SlowReported;

        public Subscriber(string solverId, Channel<SolverInsight> channel)
        {
            SolverId = solverId;
            Channel = channel;
        }
    }
}
