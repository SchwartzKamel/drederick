using System.Runtime.CompilerServices;
using Drederick.Audit;
using Drederick.Jeopardy.Ctfd;

namespace Drederick.Jeopardy.Coordinator;

public enum ChallengeChangeKind
{
    Discovered,
    SolvedExternally,
    Updated,
}

public sealed record ChallengeChange(ChallengeChangeKind Kind, CtfdChallenge Challenge);

public interface ICtfdPoller : IAsyncDisposable
{
    IAsyncEnumerable<ChallengeChange> StreamAsync(CancellationToken ct);
}

/// <summary>
/// Polls the CTFd <c>/api/v1/challenges</c> endpoint at a fixed interval and
/// surfaces structural changes: first-sighting (<see cref="ChallengeChangeKind.Discovered"/>),
/// externally-solved flips (<see cref="ChallengeChangeKind.SolvedExternally"/>), and
/// metadata edits (<see cref="ChallengeChangeKind.Updated"/>). The network call is
/// already scope-gated inside <see cref="ICtfdClient"/>; this service only
/// diffs snapshots.
/// </summary>
public sealed class CtfdPoller : ICtfdPoller
{
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(5);

    private readonly ICtfdClient _ctfd;
    private readonly AuditLog _audit;
    private readonly TimeSpan _pollInterval;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private int _disposed;

    public CtfdPoller(ICtfdClient ctfd, AuditLog audit, TimeSpan? pollInterval = null)
        : this(ctfd, audit, pollInterval, null)
    {
    }

    internal CtfdPoller(
        ICtfdClient ctfd,
        AuditLog audit,
        TimeSpan? pollInterval,
        Func<TimeSpan, CancellationToken, Task>? delay)
    {
        _ctfd = ctfd ?? throw new ArgumentNullException(nameof(ctfd));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _pollInterval = pollInterval is { } p && p > TimeSpan.Zero ? p : DefaultPollInterval;
        _delay = delay ?? ((t, c) => Task.Delay(t, c));
    }

    public async IAsyncEnumerable<ChallengeChange> StreamAsync(
        [EnumeratorCancellation] CancellationToken ct)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            yield break;
        }

        _audit.Record("coordinator.poller.start", new Dictionary<string, object?>
        {
            ["poll_interval_ms"] = (long)_pollInterval.TotalMilliseconds,
        });

        var prior = new Dictionary<int, CtfdChallenge>();
        bool first = true;
        long pollCount = 0;

        while (!ct.IsCancellationRequested && Volatile.Read(ref _disposed) == 0)
        {
            IReadOnlyList<CtfdChallenge>? snapshot = null;
            try
            {
                snapshot = await _ctfd.ListChallengesAsync(ct).ConfigureAwait(false);
                pollCount++;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _audit.Record("coordinator.poller.error", new Dictionary<string, object?>
                {
                    ["error"] = ex.GetType().Name + ": " + ex.Message,
                });
            }

            if (snapshot is not null)
            {
                var changes = new List<ChallengeChange>();
                var currentIds = new HashSet<int>();
                foreach (var chal in snapshot)
                {
                    currentIds.Add(chal.Id);
                    if (!prior.TryGetValue(chal.Id, out var old))
                    {
                        changes.Add(new ChallengeChange(ChallengeChangeKind.Discovered, chal));
                    }
                    else
                    {
                        if (!old.Solved && chal.Solved)
                        {
                            changes.Add(new ChallengeChange(ChallengeChangeKind.SolvedExternally, chal));
                        }
                        else if (IsMetadataChanged(old, chal))
                        {
                            changes.Add(new ChallengeChange(ChallengeChangeKind.Updated, chal));
                        }
                    }
                    prior[chal.Id] = chal;
                }

                _audit.Record("coordinator.poller.tick", new Dictionary<string, object?>
                {
                    ["poll"] = pollCount,
                    ["snapshot_size"] = snapshot.Count,
                    ["changes"] = changes.Count,
                    ["first"] = first,
                });

                foreach (var c in changes)
                {
                    yield return c;
                }
                first = false;
            }

            try
            {
                await _delay(_pollInterval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _audit.Record("coordinator.poller.stop", new Dictionary<string, object?>
        {
            ["polls"] = pollCount,
        });
    }

    private static bool IsMetadataChanged(CtfdChallenge a, CtfdChallenge b)
    {
        if (a.Value != b.Value) return true;
        if (!string.Equals(a.Name, b.Name, StringComparison.Ordinal)) return true;
        if (!string.Equals(a.Category, b.Category, StringComparison.Ordinal)) return true;
        if (!string.Equals(a.Description, b.Description, StringComparison.Ordinal)) return true;
        if (a.Tags.Count != b.Tags.Count) return true;
        for (int i = 0; i < a.Tags.Count; i++)
        {
            if (!string.Equals(a.Tags[i], b.Tags[i], StringComparison.Ordinal)) return true;
        }
        return false;
    }

    public ValueTask DisposeAsync()
    {
        Interlocked.Exchange(ref _disposed, 1);
        return ValueTask.CompletedTask;
    }
}
