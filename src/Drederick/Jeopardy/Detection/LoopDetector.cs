using System.Collections.Concurrent;
using Drederick.Audit;
using Drederick.Jeopardy.Bus;

namespace Drederick.Jeopardy.Detection;

/// <summary>
/// A single solver action observed by <see cref="LoopDetector"/>. The caller
/// hashes the action body into <paramref name="FingerprintSha256"/>; the
/// detector never inspects raw action bodies. Recommended fingerprinting
/// rules for callers:
/// <list type="bullet">
///   <item><description><c>exec</c>: SHA-256 of the normalized shell command
///     (lowercased, collapsed whitespace, stripped of volatile
///     timestamp/pid substrings).</description></item>
///   <item><description><c>chat</c>: SHA-256 of the assistant's last message,
///     trimmed.</description></item>
///   <item><description><c>tool_call</c>: SHA-256 of
///     <c>tool_name || '\u001f' || arguments_json_normalized</c>.</description></item>
/// </list>
/// </summary>
public sealed record SolverAction(
    string SolverId,
    string ChallengeId,
    string ActionKind,
    string FingerprintSha256,
    DateTimeOffset At);

/// <summary>
/// Describes a detected solver loop. <see cref="LoopKind"/> is one of
/// <c>exact_repeat</c>, <c>ab_oscillation</c>, or <c>no_progress</c>.
/// </summary>
public sealed record LoopReport(
    string SolverId,
    string ChallengeId,
    string LoopKind,
    int Repetitions,
    TimeSpan Window);

public interface ILoopDetector
{
    void Observe(SolverAction action);
    LoopReport? CheckForLoop(string solverId, string challengeId);
    event Action<LoopReport>? LoopDetected;
}

/// <summary>
/// Detects repetitive solver behavior (exact repeats, A/B oscillation, and
/// "no progress" runs) and emits a <see cref="LoopDetected"/> signal that the
/// Jeopardy coordinator consumes to issue a hint. Thread-safe; no static
/// state — multiple detectors coexist independently.
/// </summary>
public sealed class LoopDetector : ILoopDetector
{
    private const int RingCapacity = 256;

    private readonly AuditLog _audit;
    private readonly int _exactRepeatThreshold;
    private readonly int _abOscillationThreshold;
    private readonly TimeSpan _window;
    private readonly Func<DateTimeOffset> _clock;
    private readonly ConcurrentDictionary<(string solverId, string challengeId), RingBuffer> _buffers = new();

    public event Action<LoopReport>? LoopDetected;

    public LoopDetector(
        AuditLog audit,
        int exactRepeatThreshold = 3,
        int abOscillationThreshold = 4,
        TimeSpan? windowOverride = null,
        Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (exactRepeatThreshold < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(exactRepeatThreshold));
        }
        if (abOscillationThreshold < 4 || (abOscillationThreshold % 2) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(abOscillationThreshold),
                "AB oscillation threshold must be even and >= 4.");
        }
        _audit = audit;
        _exactRepeatThreshold = exactRepeatThreshold;
        _abOscillationThreshold = abOscillationThreshold;
        _window = windowOverride ?? TimeSpan.FromMinutes(5);
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public void Observe(SolverAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentException.ThrowIfNullOrEmpty(action.SolverId);
        ArgumentException.ThrowIfNullOrEmpty(action.ChallengeId);
        ArgumentException.ThrowIfNullOrEmpty(action.FingerprintSha256);

        var key = (action.SolverId, action.ChallengeId);
        var buf = _buffers.GetOrAdd(key, _ => new RingBuffer(RingCapacity));

        LoopReport? report;
        lock (buf.Gate)
        {
            buf.Add(action, _clock() - _window);
            report = Detect(buf, action.SolverId, action.ChallengeId);
            if (report is not null)
            {
                buf.Reset();
            }
        }

        if (report is not null)
        {
            _audit.Record("loop.detected", new Dictionary<string, object?>
            {
                ["solver_id"] = report.SolverId,
                ["challenge_id"] = report.ChallengeId,
                ["kind"] = report.LoopKind,
                ["repetitions"] = report.Repetitions,
                ["window_seconds"] = (int)report.Window.TotalSeconds,
            });
            LoopDetected?.Invoke(report);
        }
    }

    public LoopReport? CheckForLoop(string solverId, string challengeId)
    {
        ArgumentException.ThrowIfNullOrEmpty(solverId);
        ArgumentException.ThrowIfNullOrEmpty(challengeId);

        if (!_buffers.TryGetValue((solverId, challengeId), out var buf))
        {
            return null;
        }
        lock (buf.Gate)
        {
            buf.Evict(_clock() - _window);
            return Detect(buf, solverId, challengeId);
        }
    }

    /// <summary>
    /// Records that a solver has published an insight of the given kind.
    /// <see cref="InsightKind.Partial"/> and <see cref="InsightKind.Flag"/>
    /// count as progress and suppress the <c>no_progress</c> rule until the
    /// buffer is reset.
    /// </summary>
    public void RecordInsight(string solverId, string challengeId, InsightKind kind)
    {
        ArgumentException.ThrowIfNullOrEmpty(solverId);
        ArgumentException.ThrowIfNullOrEmpty(challengeId);

        if (kind != InsightKind.Partial && kind != InsightKind.Flag)
        {
            return;
        }
        var key = (solverId, challengeId);
        var buf = _buffers.GetOrAdd(key, _ => new RingBuffer(RingCapacity));
        lock (buf.Gate)
        {
            buf.HasProgressInsight = true;
        }
    }

    private LoopReport? Detect(RingBuffer buf, string solverId, string challengeId)
    {
        buf.Evict(_clock() - _window);
        var items = buf.Snapshot();
        if (items.Length == 0)
        {
            return null;
        }

        // Rule 1: exact repeat of the most recent fingerprint.
        var last = items[^1].FingerprintSha256;
        int tailRun = 0;
        for (int i = items.Length - 1; i >= 0; i--)
        {
            if (items[i].FingerprintSha256 == last) tailRun++;
            else break;
        }
        if (tailRun >= _exactRepeatThreshold)
        {
            return new LoopReport(solverId, challengeId, "exact_repeat", tailRun, _window);
        }

        // Rule 2: AB oscillation over the trailing window.
        if (items.Length >= _abOscillationThreshold)
        {
            var a = items[^1].FingerprintSha256;
            var b = items[^2].FingerprintSha256;
            if (a != b)
            {
                int osc = 0;
                for (int i = items.Length - 1; i >= 0; i--)
                {
                    var expected = ((items.Length - 1 - i) % 2 == 0) ? a : b;
                    if (items[i].FingerprintSha256 == expected) osc++;
                    else break;
                }
                if (osc >= _abOscillationThreshold)
                {
                    return new LoopReport(solverId, challengeId, "ab_oscillation", osc, _window);
                }
            }
        }

        // Rule 3: no progress — many distinct fingerprints, zero insights.
        if (!buf.HasProgressInsight)
        {
            var distinct = new HashSet<string>(StringComparer.Ordinal);
            foreach (var a in items) distinct.Add(a.FingerprintSha256);
            if (distinct.Count >= 8)
            {
                return new LoopReport(solverId, challengeId, "no_progress", distinct.Count, _window);
            }
        }

        return null;
    }

    private sealed class RingBuffer
    {
        public readonly Lock Gate = new();
        private readonly SolverAction[] _items;
        private readonly int _capacity;
        private int _head; // index of oldest element
        private int _count;
        public bool HasProgressInsight;

        public RingBuffer(int capacity)
        {
            _capacity = capacity;
            _items = new SolverAction[capacity];
        }

        public void Add(SolverAction action, DateTimeOffset cutoff)
        {
            Evict(cutoff);
            if (_count < _capacity)
            {
                var idx = (_head + _count) % _capacity;
                _items[idx] = action;
                _count++;
            }
            else
            {
                _items[_head] = action;
                _head = (_head + 1) % _capacity;
            }
        }

        public void Evict(DateTimeOffset cutoff)
        {
            while (_count > 0 && _items[_head].At < cutoff)
            {
                _items[_head] = null!;
                _head = (_head + 1) % _capacity;
                _count--;
            }
        }

        public SolverAction[] Snapshot()
        {
            var result = new SolverAction[_count];
            for (int i = 0; i < _count; i++)
            {
                result[i] = _items[(_head + i) % _capacity];
            }
            return result;
        }

        public void Reset()
        {
            for (int i = 0; i < _capacity; i++) _items[i] = null!;
            _head = 0;
            _count = 0;
            HasProgressInsight = false;
        }
    }
}
