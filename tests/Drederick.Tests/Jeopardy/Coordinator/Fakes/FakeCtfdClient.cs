using System.Collections.Concurrent;
using Drederick.Jeopardy.Ctfd;

namespace Drederick.Tests.Jeopardy.Coordinator.Fakes;

/// <summary>
/// Scripted <see cref="ICtfdClient"/> for coordinator tests. Scripts are a
/// queue of snapshots that <see cref="ListChallengesAsync"/> yields in order;
/// the final snapshot is repeated for all subsequent polls. Detail lookups
/// fall back to the summary unless a detail is explicitly registered.
/// </summary>
internal sealed class FakeCtfdClient : ICtfdClient
{
    private readonly object _gate = new();
    private readonly Queue<IReadOnlyList<CtfdChallenge>> _snapshots = new();
    private IReadOnlyList<CtfdChallenge> _lastSnapshot = Array.Empty<CtfdChallenge>();
    private readonly ConcurrentDictionary<int, CtfdChallenge> _details = new();
    public int ListCalls;

    public void Enqueue(IReadOnlyList<CtfdChallenge> snapshot)
    {
        lock (_gate) _snapshots.Enqueue(snapshot);
    }

    public void SetDetail(CtfdChallenge chal) => _details[chal.Id] = chal;

    public Task<IReadOnlyList<CtfdChallenge>> ListChallengesAsync(CancellationToken ct)
    {
        Interlocked.Increment(ref ListCalls);
        IReadOnlyList<CtfdChallenge> snap;
        lock (_gate)
        {
            if (_snapshots.Count > 0)
            {
                _lastSnapshot = _snapshots.Dequeue();
            }
            snap = _lastSnapshot;
        }
        return Task.FromResult(snap);
    }

    public Task<CtfdChallenge> GetChallengeAsync(int id, CancellationToken ct)
    {
        if (_details.TryGetValue(id, out var d)) return Task.FromResult(d);
        IReadOnlyList<CtfdChallenge> snap;
        lock (_gate) snap = _lastSnapshot;
        foreach (var c in snap)
        {
            if (c.Id == id) return Task.FromResult(c);
        }
        throw new KeyNotFoundException("challenge " + id);
    }

    public Task<byte[]> DownloadAttachmentAsync(CtfdAttachment file, CancellationToken ct)
        => Task.FromResult(Array.Empty<byte>());

    public Task<CtfdSubmissionResult> SubmitFlagAsync(int challengeId, string flag, CancellationToken ct)
        => Task.FromResult(new CtfdSubmissionResult(false, false, "not-used", DateTimeOffset.UtcNow));

    public Task<IReadOnlyList<CtfdScoreboardEntry>> GetScoreboardAsync(CancellationToken ct)
        => Task.FromResult<IReadOnlyList<CtfdScoreboardEntry>>(Array.Empty<CtfdScoreboardEntry>());
}
