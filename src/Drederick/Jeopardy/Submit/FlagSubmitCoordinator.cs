using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Ctfd;

namespace Drederick.Jeopardy.Submit;

public sealed record FlagCandidate(
    int ChallengeId,
    string ChallengeName,
    string Flag,
    string SolverId,
    string ModelId,
    DateTimeOffset At);

public sealed record FlagOutcome(
    int ChallengeId,
    string Flag,
    bool Correct,
    bool AlreadySolved,
    string WinnerSolverId,
    string WinnerModelId,
    DateTimeOffset SubmittedAt,
    string? Message);

public interface IFlagSubmitCoordinator
{
    Task<FlagOutcome?> SubmitCandidateAsync(FlagCandidate candidate, CancellationToken ct);

    bool IsSolved(int challengeId);

    IReadOnlyList<FlagOutcome> Wins { get; }

    event Action<FlagOutcome>? ChallengeSolved;
}

/// <summary>
/// Serializes flag submissions to CTFd. Dedups by (challenge, SHA-256 of the
/// normalized flag), runs at most one submission per challenge at a time,
/// rate-limits retries, and broadcasts wins on the solver bus so the swarm
/// for that challenge can stop. The plaintext flag is passed only to the
/// underlying <see cref="ICtfdClient.SubmitFlagAsync"/> call; every audit
/// event records the flag by SHA-256 only.
/// </summary>
public sealed class FlagSubmitCoordinator : IFlagSubmitCoordinator
{
    public const string MinIntervalEnvVar = "DREDERICK_FLAG_SUBMIT_MIN_INTERVAL_MS";
    public const int DefaultMinIntervalMs = 500;

    private readonly ICtfdClient _ctfd;
    private readonly AuditLog _audit;
    private readonly ISolverMessageBus? _bus;
    private readonly TimeSpan _minInterval;

    private readonly ConcurrentDictionary<int, SemaphoreSlim> _locks = new();
    private readonly ConcurrentDictionary<int, ConcurrentDictionary<string, bool>> _submittedShas = new();
    private readonly ConcurrentDictionary<int, FlagOutcome> _wins = new();
    private readonly ConcurrentDictionary<int, long> _lastSubmitTicks = new();
    private readonly object _winsListGate = new();
    private readonly List<FlagOutcome> _winsList = new();

    public event Action<FlagOutcome>? ChallengeSolved;

    public FlagSubmitCoordinator(
        ICtfdClient ctfd,
        AuditLog audit,
        ISolverMessageBus? bus = null,
        TimeSpan? minInterval = null)
    {
        _ctfd = ctfd ?? throw new ArgumentNullException(nameof(ctfd));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _bus = bus;
        _minInterval = minInterval ?? ResolveMinInterval();
    }

    public IReadOnlyList<FlagOutcome> Wins
    {
        get
        {
            lock (_winsListGate)
            {
                return _winsList.ToArray();
            }
        }
    }

    public bool IsSolved(int challengeId) => _wins.ContainsKey(challengeId);

    public async Task<FlagOutcome?> SubmitCandidateAsync(FlagCandidate candidate, CancellationToken ct)
    {
        if (candidate is null) throw new ArgumentNullException(nameof(candidate));
        if (candidate.Flag is null) throw new ArgumentException("Flag must not be null.", nameof(candidate));

        var normalized = NormalizeFlag(candidate.Flag);
        var sha = Sha256Hex(normalized);

        // Fast-path: challenge already solved — short-circuit with no HTTP call.
        if (_wins.TryGetValue(candidate.ChallengeId, out var existingWin))
        {
            _audit.Record("flag.submit.already_solved", new Dictionary<string, object?>
            {
                ["challenge_id"] = candidate.ChallengeId,
                ["solver_id"] = candidate.SolverId,
                ["model_id"] = candidate.ModelId,
                ["flag_sha256"] = sha,
                ["winner_solver_id"] = existingWin.WinnerSolverId,
            });
            return existingWin with
            {
                AlreadySolved = true,
                SubmittedAt = DateTimeOffset.UtcNow,
            };
        }

        // Dedup: only the first (challenge, sha) proceeds. Subsequent same-sha
        // candidates — concurrent or not — are deduped and return null.
        var shaSet = _submittedShas.GetOrAdd(
            candidate.ChallengeId, _ => new ConcurrentDictionary<string, bool>());
        if (!shaSet.TryAdd(sha, true))
        {
            _audit.Record("flag.submit.dedup", new Dictionary<string, object?>
            {
                ["challenge_id"] = candidate.ChallengeId,
                ["solver_id"] = candidate.SolverId,
                ["model_id"] = candidate.ModelId,
                ["flag_sha256"] = sha,
            });
            return null;
        }

        var gate = _locks.GetOrAdd(candidate.ChallengeId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Re-check solved state now that we hold the per-challenge lock.
            if (_wins.TryGetValue(candidate.ChallengeId, out var winNow))
            {
                _audit.Record("flag.submit.already_solved", new Dictionary<string, object?>
                {
                    ["challenge_id"] = candidate.ChallengeId,
                    ["solver_id"] = candidate.SolverId,
                    ["model_id"] = candidate.ModelId,
                    ["flag_sha256"] = sha,
                    ["winner_solver_id"] = winNow.WinnerSolverId,
                });
                return winNow with
                {
                    AlreadySolved = true,
                    SubmittedAt = DateTimeOffset.UtcNow,
                };
            }

            await EnforceRateLimitAsync(candidate.ChallengeId, ct).ConfigureAwait(false);

            _audit.Record("flag.submit.start", new Dictionary<string, object?>
            {
                ["challenge_id"] = candidate.ChallengeId,
                ["solver_id"] = candidate.SolverId,
                ["model_id"] = candidate.ModelId,
                ["flag_sha256"] = sha,
            });

            var sw = Stopwatch.StartNew();
            CtfdSubmissionResult result;
            try
            {
                // The plaintext flag flows only into the HTTP client. Do not
                // wrap this call in any logging or try/catch that includes
                // `normalized` in its message — the CtfdClient itself audits
                // SHA-256 only.
                result = await _ctfd.SubmitFlagAsync(candidate.ChallengeId, normalized, ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _lastSubmitTicks[candidate.ChallengeId] = DateTime.UtcNow.Ticks;
                // Allow a retry with this same flag if the transport failed.
                shaSet.TryRemove(sha, out _);
                _audit.Record("flag.submit.finish", new Dictionary<string, object?>
                {
                    ["challenge_id"] = candidate.ChallengeId,
                    ["solver_id"] = candidate.SolverId,
                    ["model_id"] = candidate.ModelId,
                    ["flag_sha256"] = sha,
                    ["elapsed_ms"] = sw.ElapsedMilliseconds,
                    ["error"] = ex.GetType().Name,
                });
                throw;
            }
            _lastSubmitTicks[candidate.ChallengeId] = DateTime.UtcNow.Ticks;

            var outcome = new FlagOutcome(
                ChallengeId: candidate.ChallengeId,
                Flag: normalized,
                Correct: result.Correct,
                AlreadySolved: result.AlreadySolved,
                WinnerSolverId: candidate.SolverId,
                WinnerModelId: candidate.ModelId,
                SubmittedAt: result.SubmittedAt,
                Message: result.Message);

            if (result.Correct)
            {
                if (_wins.TryAdd(candidate.ChallengeId, outcome))
                {
                    lock (_winsListGate)
                    {
                        _winsList.Add(outcome);
                    }
                    _audit.Record("flag.submit.correct", new Dictionary<string, object?>
                    {
                        ["challenge_id"] = candidate.ChallengeId,
                        ["solver_id"] = candidate.SolverId,
                        ["model_id"] = candidate.ModelId,
                        ["flag_sha256"] = sha,
                        ["elapsed_ms"] = sw.ElapsedMilliseconds,
                    });
                    await PublishWinAsync(candidate, sha, ct).ConfigureAwait(false);
                    RaiseChallengeSolved(outcome);
                }
            }
            else if (result.AlreadySolved)
            {
                _audit.Record("flag.submit.already_solved", new Dictionary<string, object?>
                {
                    ["challenge_id"] = candidate.ChallengeId,
                    ["solver_id"] = candidate.SolverId,
                    ["model_id"] = candidate.ModelId,
                    ["flag_sha256"] = sha,
                    ["elapsed_ms"] = sw.ElapsedMilliseconds,
                });
            }
            else
            {
                _audit.Record("flag.submit.incorrect", new Dictionary<string, object?>
                {
                    ["challenge_id"] = candidate.ChallengeId,
                    ["solver_id"] = candidate.SolverId,
                    ["model_id"] = candidate.ModelId,
                    ["flag_sha256"] = sha,
                    ["elapsed_ms"] = sw.ElapsedMilliseconds,
                });
            }

            _audit.Record("flag.submit.finish", new Dictionary<string, object?>
            {
                ["challenge_id"] = candidate.ChallengeId,
                ["solver_id"] = candidate.SolverId,
                ["model_id"] = candidate.ModelId,
                ["flag_sha256"] = sha,
                ["correct"] = result.Correct,
                ["already_solved"] = result.AlreadySolved,
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
            });

            return outcome;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>
    /// Submit a batch of candidates. Candidates targeting different challenges
    /// run in parallel; candidates for the same challenge run serially through
    /// the same per-challenge gate <see cref="SubmitCandidateAsync"/> uses.
    /// </summary>
    public async Task<IReadOnlyList<FlagOutcome?>> SubmitBatchAsync(
        IEnumerable<FlagCandidate> candidates, CancellationToken ct)
    {
        if (candidates is null) throw new ArgumentNullException(nameof(candidates));
        var list = candidates.ToList();
        var tasks = list.Select(c => SubmitCandidateAsync(c, ct)).ToArray();
        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task EnforceRateLimitAsync(int challengeId, CancellationToken ct)
    {
        if (_minInterval <= TimeSpan.Zero) return;
        if (!_lastSubmitTicks.TryGetValue(challengeId, out var lastTicks)) return;

        var last = new DateTime(lastTicks, DateTimeKind.Utc);
        var elapsed = DateTime.UtcNow - last;
        var remaining = _minInterval - elapsed;
        if (remaining > TimeSpan.Zero)
        {
            await Task.Delay(remaining, ct).ConfigureAwait(false);
        }
    }

    private async Task PublishWinAsync(FlagCandidate candidate, string sha, CancellationToken ct)
    {
        if (_bus is null) return;
        var insight = new SolverInsight(
            ChallengeId: candidate.ChallengeId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            SolverId: candidate.SolverId,
            ModelId: candidate.ModelId,
            Kind: InsightKind.Flag,
            Summary: "flag.correct",
            DetailsSha256: sha,
            Tags: new[] { "flag", "correct", "stop-swarm" },
            At: DateTimeOffset.UtcNow);
        try
        {
            await _bus.PublishAsync(insight, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _audit.Record("flag.submit.bus_error", new Dictionary<string, object?>
            {
                ["challenge_id"] = candidate.ChallengeId,
                ["error"] = ex.GetType().Name,
            });
        }
    }

    private void RaiseChallengeSolved(FlagOutcome outcome)
    {
        var handler = ChallengeSolved;
        if (handler is null) return;
        foreach (var cb in handler.GetInvocationList().Cast<Action<FlagOutcome>>())
        {
            try { cb(outcome); }
            catch (Exception ex)
            {
                _audit.Record("flag.submit.handler_error", new Dictionary<string, object?>
                {
                    ["challenge_id"] = outcome.ChallengeId,
                    ["error"] = ex.GetType().Name,
                });
            }
        }
    }

    private static TimeSpan ResolveMinInterval()
    {
        var raw = Environment.GetEnvironmentVariable(MinIntervalEnvVar);
        if (!string.IsNullOrWhiteSpace(raw)
            && int.TryParse(raw, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var ms)
            && ms >= 0)
        {
            return TimeSpan.FromMilliseconds(ms);
        }
        return TimeSpan.FromMilliseconds(DefaultMinIntervalMs);
    }

    /// <summary>
    /// Trim surrounding whitespace and collapse runs of internal whitespace
    /// to a single space — but only in the region outside any <c>{...}</c>
    /// flag body. Contents inside braces are preserved verbatim so that a
    /// flag like <c>CTF{hello world}</c> is not corrupted. Never lowercases;
    /// CTFd flags are case-sensitive.
    /// </summary>
    public static string NormalizeFlag(string flag)
    {
        if (flag is null) throw new ArgumentNullException(nameof(flag));
        var trimmed = flag.Trim();
        if (trimmed.Length == 0) return string.Empty;

        var sb = new StringBuilder(trimmed.Length);
        int depth = 0;
        bool prevSpace = false;
        foreach (var c in trimmed)
        {
            if (c == '{')
            {
                depth++;
                sb.Append(c);
                prevSpace = false;
                continue;
            }
            if (c == '}')
            {
                if (depth > 0) depth--;
                sb.Append(c);
                prevSpace = false;
                continue;
            }
            if (depth > 0)
            {
                sb.Append(c);
                continue;
            }
            if (char.IsWhiteSpace(c))
            {
                if (!prevSpace)
                {
                    sb.Append(' ');
                    prevSpace = true;
                }
            }
            else
            {
                sb.Append(c);
                prevSpace = false;
            }
        }
        // After collapsing, trim any trailing single space created by the loop.
        if (sb.Length > 0 && sb[^1] == ' ') sb.Length--;
        return sb.ToString();
    }

    private static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
