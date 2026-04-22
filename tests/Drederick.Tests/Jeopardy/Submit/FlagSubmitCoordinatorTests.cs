using System.Collections.Concurrent;
using Drederick.Audit;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Submit;
using Xunit;

namespace Drederick.Tests.Jeopardy.Submit;

public class FlagSubmitCoordinatorTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(
            AppContext.BaseDirectory,
            $"flag-submit-audit-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static FlagCandidate Cand(
        int cid, string flag, string solver = "solver-a", string model = "gpt-x") =>
        new(cid, $"Chal{cid}", flag, solver, model, DateTimeOffset.UtcNow);

    private sealed class FakeCtfdClient : ICtfdClient
    {
        private readonly Dictionary<(int, string), CtfdSubmissionResult> _answers;
        public int SubmitCalls;
        public readonly ConcurrentBag<(int cid, string flag)> Submissions = new();
        public Func<Task>? BeforeSubmitHook;

        public FakeCtfdClient(Dictionary<(int, string), CtfdSubmissionResult> answers)
        {
            _answers = answers;
        }

        public async Task<CtfdSubmissionResult> SubmitFlagAsync(int challengeId, string flag, CancellationToken ct)
        {
            if (BeforeSubmitHook is not null) await BeforeSubmitHook().ConfigureAwait(false);
            Interlocked.Increment(ref SubmitCalls);
            Submissions.Add((challengeId, flag));
            if (_answers.TryGetValue((challengeId, flag), out var r)) return r;
            return new CtfdSubmissionResult(false, false, "incorrect", DateTimeOffset.UtcNow);
        }

        public Task<IReadOnlyList<CtfdChallenge>> ListChallengesAsync(CancellationToken ct)
            => throw new NotImplementedException();
        public Task<CtfdChallenge> GetChallengeAsync(int id, CancellationToken ct)
            => throw new NotImplementedException();
        public Task<byte[]> DownloadAttachmentAsync(CtfdAttachment file, CancellationToken ct)
            => throw new NotImplementedException();
        public Task<IReadOnlyList<CtfdScoreboardEntry>> GetScoreboardAsync(CancellationToken ct)
            => throw new NotImplementedException();
    }

    private static FakeCtfdClient FakeWith(params (int cid, string flag, bool correct)[] entries)
    {
        var d = new Dictionary<(int, string), CtfdSubmissionResult>();
        foreach (var (c, f, ok) in entries)
        {
            d[(c, f)] = new CtfdSubmissionResult(ok, false, ok ? "correct" : "incorrect", DateTimeOffset.UtcNow);
        }
        return new FakeCtfdClient(d);
    }

    [Fact]
    public async Task Submit_correct_flag_marks_solved_and_fires_event()
    {
        var audit = NewAudit(out _);
        var fake = FakeWith((1, "CTF{ok}", true));
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);
        FlagOutcome? evt = null;
        coord.ChallengeSolved += o => evt = o;

        var r = await coord.SubmitCandidateAsync(Cand(1, "CTF{ok}"), CancellationToken.None);

        Assert.NotNull(r);
        Assert.True(r!.Correct);
        Assert.True(coord.IsSolved(1));
        Assert.NotNull(evt);
        Assert.Equal(1, evt!.ChallengeId);
        Assert.Single(coord.Wins);
    }

    [Fact]
    public async Task Submit_incorrect_does_not_mark_solved_and_allows_different_retry()
    {
        var audit = NewAudit(out _);
        var fake = FakeWith((1, "CTF{right}", true));
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);

        var r1 = await coord.SubmitCandidateAsync(Cand(1, "CTF{wrong}"), CancellationToken.None);
        Assert.False(r1!.Correct);
        Assert.False(coord.IsSolved(1));

        var r2 = await coord.SubmitCandidateAsync(Cand(1, "CTF{right}"), CancellationToken.None);
        Assert.True(r2!.Correct);
        Assert.True(coord.IsSolved(1));
        Assert.Equal(2, fake.SubmitCalls);
    }

    [Fact]
    public async Task Same_flag_twice_is_deduped()
    {
        var audit = NewAudit(out _);
        var fake = FakeWith((1, "CTF{x}", false));
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);

        var r1 = await coord.SubmitCandidateAsync(Cand(1, "CTF{x}"), CancellationToken.None);
        var r2 = await coord.SubmitCandidateAsync(Cand(1, "CTF{x}"), CancellationToken.None);

        Assert.NotNull(r1);
        Assert.Null(r2);
        Assert.Equal(1, fake.SubmitCalls);
    }

    [Fact]
    public async Task Concurrent_same_flag_submits_only_one_http_call()
    {
        var audit = NewAudit(out _);
        var fake = FakeWith((1, "CTF{win}", true));
        var releaser = new TaskCompletionSource();
        fake.BeforeSubmitHook = () => releaser.Task;
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);

        var t1 = coord.SubmitCandidateAsync(Cand(1, "CTF{win}", "a"), CancellationToken.None);
        var t2 = coord.SubmitCandidateAsync(Cand(1, "CTF{win}", "b"), CancellationToken.None);
        // Give both tasks a chance to reach the dedup gate.
        await Task.Delay(50);
        releaser.SetResult();
        var rs = await Task.WhenAll(t1, t2);

        Assert.Equal(1, fake.SubmitCalls);
        // Exactly one non-null outcome.
        Assert.Single(rs, r => r is not null);
        Assert.True(coord.IsSolved(1));
    }

    [Fact]
    public async Task Already_solved_short_circuits_with_no_http()
    {
        var audit = NewAudit(out _);
        var fake = FakeWith((1, "CTF{a}", true));
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);

        await coord.SubmitCandidateAsync(Cand(1, "CTF{a}", "s1"), CancellationToken.None);
        var r = await coord.SubmitCandidateAsync(Cand(1, "CTF{other}", "s2"), CancellationToken.None);

        Assert.NotNull(r);
        Assert.True(r!.AlreadySolved);
        Assert.Equal("s1", r.WinnerSolverId);
        Assert.Equal(1, fake.SubmitCalls);
    }

    [Fact]
    public async Task Whitespace_variants_normalize_and_dedup()
    {
        var audit = NewAudit(out _);
        var fake = FakeWith((1, "CTF{abc}", false));
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);

        Assert.Equal("CTF{abc}", FlagSubmitCoordinator.NormalizeFlag("  CTF{abc}  "));
        Assert.Equal("CTF{abc}", FlagSubmitCoordinator.NormalizeFlag("\tCTF{abc}\n"));
        // Whitespace inside braces is preserved.
        Assert.Equal("CTF{a b c}", FlagSubmitCoordinator.NormalizeFlag("   CTF{a b c}   "));

        await coord.SubmitCandidateAsync(Cand(1, "  CTF{abc}  "), CancellationToken.None);
        var r2 = await coord.SubmitCandidateAsync(Cand(1, "\tCTF{abc}\n"), CancellationToken.None);
        Assert.Null(r2);
        Assert.Equal(1, fake.SubmitCalls);
    }

    [Fact]
    public async Task Case_sensitive_flags_are_distinct()
    {
        var audit = NewAudit(out _);
        var fake = FakeWith(
            (1, "CTF{abc}", false),
            (1, "ctf{abc}", false));
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);

        var r1 = await coord.SubmitCandidateAsync(Cand(1, "CTF{abc}"), CancellationToken.None);
        var r2 = await coord.SubmitCandidateAsync(Cand(1, "ctf{abc}"), CancellationToken.None);

        Assert.NotNull(r1);
        Assert.NotNull(r2);
        Assert.Equal(2, fake.SubmitCalls);
    }

    [Fact]
    public async Task Rate_limit_delays_second_submit_for_same_challenge()
    {
        var audit = NewAudit(out _);
        var fake = FakeWith((1, "CTF{a}", false), (1, "CTF{b}", false));
        var interval = TimeSpan.FromMilliseconds(300);
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: interval);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await coord.SubmitCandidateAsync(Cand(1, "CTF{a}"), CancellationToken.None);
        await coord.SubmitCandidateAsync(Cand(1, "CTF{b}"), CancellationToken.None);
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds >= 280,
            $"Expected >= ~interval, got {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task Plaintext_flag_canary_never_appears_in_audit_log()
    {
        const string canary = "flag{canary_submit_777}";
        var audit = NewAudit(out var path);
        var fake = FakeWith((1, canary, true));
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);

        await coord.SubmitCandidateAsync(Cand(1, canary), CancellationToken.None);
        // Dedup, already-solved, and another incorrect path — none may contain canary.
        await coord.SubmitCandidateAsync(Cand(1, canary), CancellationToken.None);
        await coord.SubmitCandidateAsync(Cand(1, "flag{other}"), CancellationToken.None);
        audit.Dispose();

        var text = File.ReadAllText(path);
        Assert.DoesNotContain(canary, text);
        Assert.DoesNotContain("canary_submit_777", text);
    }

    [Fact]
    public async Task Bus_receives_flag_insight_on_correct()
    {
        var audit = NewAudit(out _);
        await using var bus = new SolverMessageBus(audit);
        var fake = FakeWith((1, "CTF{ok}", true));
        var coord = new FlagSubmitCoordinator(fake, audit, bus, minInterval: TimeSpan.Zero);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var received = new List<SolverInsight>();
        var reader = Task.Run(async () =>
        {
            await foreach (var item in bus.Subscribe("1", "watcher", cts.Token))
            {
                received.Add(item);
                if (item.Kind == InsightKind.Flag) break;
            }
        });
        // Give subscriber time to register.
        await Task.Delay(50);

        await coord.SubmitCandidateAsync(Cand(1, "CTF{ok}"), CancellationToken.None);
        await reader.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Contains(received, i => i.Kind == InsightKind.Flag);
        // The published summary must not leak plaintext.
        var flagInsight = received.First(i => i.Kind == InsightKind.Flag);
        Assert.DoesNotContain("ok", flagInsight.Summary, StringComparison.Ordinal);
        Assert.False(string.IsNullOrEmpty(flagInsight.DetailsSha256));
    }

    [Fact]
    public async Task Concurrent_submits_across_different_challenges_are_isolated()
    {
        var audit = NewAudit(out _);
        var entries = new List<(int, string, bool)>();
        for (int i = 0; i < 20; i++) entries.Add((i, $"CTF{{win{i}}}", true));
        var fake = FakeWith(entries.ToArray());
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);

        var tasks = Enumerable.Range(0, 20)
            .Select(i => coord.SubmitCandidateAsync(Cand(i, $"CTF{{win{i}}}"), CancellationToken.None))
            .ToArray();
        var outcomes = await Task.WhenAll(tasks);

        Assert.All(outcomes, o => Assert.True(o!.Correct));
        for (int i = 0; i < 20; i++) Assert.True(coord.IsSolved(i));
        Assert.Equal(20, coord.Wins.Count);
        Assert.Equal(20, fake.SubmitCalls);
    }

    [Fact]
    public async Task ChallengeSolved_event_fires_exactly_once_per_challenge()
    {
        var audit = NewAudit(out _);
        var fake = FakeWith((1, "CTF{ok}", true));
        var coord = new FlagSubmitCoordinator(fake, audit, minInterval: TimeSpan.Zero);
        int count = 0;
        coord.ChallengeSolved += _ => Interlocked.Increment(ref count);

        await coord.SubmitCandidateAsync(Cand(1, "CTF{wrong}"), CancellationToken.None);
        await coord.SubmitCandidateAsync(Cand(1, "CTF{ok}"), CancellationToken.None);
        await coord.SubmitCandidateAsync(Cand(1, "CTF{another}"), CancellationToken.None);
        await coord.SubmitCandidateAsync(Cand(1, "CTF{ok}"), CancellationToken.None);

        Assert.Equal(1, count);
    }

    [Fact]
    public void Normalize_preserves_case_and_inner_whitespace()
    {
        Assert.Equal("FLAG{AbC_dEf}", FlagSubmitCoordinator.NormalizeFlag(" FLAG{AbC_dEf} "));
        Assert.Equal("FLAG{a b c}", FlagSubmitCoordinator.NormalizeFlag("FLAG{a b c}"));
        // Outside braces, runs of whitespace collapse to a single space.
        Assert.Equal("pre FLAG{x}", FlagSubmitCoordinator.NormalizeFlag("pre   FLAG{x}"));
    }

    [Fact]
    public async Task Env_var_overrides_min_interval()
    {
        var prev = Environment.GetEnvironmentVariable(FlagSubmitCoordinator.MinIntervalEnvVar);
        Environment.SetEnvironmentVariable(FlagSubmitCoordinator.MinIntervalEnvVar, "0");
        try
        {
            var audit = NewAudit(out _);
            var fake = FakeWith((1, "CTF{a}", false), (1, "CTF{b}", false));
            var coord = new FlagSubmitCoordinator(fake, audit);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await coord.SubmitCandidateAsync(Cand(1, "CTF{a}"), CancellationToken.None);
            await coord.SubmitCandidateAsync(Cand(1, "CTF{b}"), CancellationToken.None);
            sw.Stop();
            Assert.True(sw.ElapsedMilliseconds < 400, $"Expected fast, got {sw.ElapsedMilliseconds}ms");
        }
        finally
        {
            Environment.SetEnvironmentVariable(FlagSubmitCoordinator.MinIntervalEnvVar, prev);
        }
    }
}
