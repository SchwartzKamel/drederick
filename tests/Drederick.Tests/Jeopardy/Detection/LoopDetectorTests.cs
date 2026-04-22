using System.Collections.Concurrent;
using Drederick.Audit;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Detection;
using Xunit;

namespace Drederick.Tests.Jeopardy.Detection;

public sealed class LoopDetectorTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-loop-{Guid.NewGuid():N}.jsonl");

    private static string Fp(string s)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var b = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(s));
        return Convert.ToHexString(b);
    }

    private sealed class TestClock
    {
        public DateTimeOffset Now = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public DateTimeOffset Get() => Now;
        public void Advance(TimeSpan d) => Now += d;
    }

    private static (LoopDetector det, TestClock clk, AuditLog audit, string auditPath) Make(
        int exactRepeat = 3, int ab = 4, TimeSpan? window = null)
    {
        var clk = new TestClock();
        var path = NewAuditPath();
        var audit = new AuditLog(path);
        var det = new LoopDetector(audit, exactRepeat, ab, window ?? TimeSpan.FromMinutes(5), clk.Get);
        return (det, clk, audit, path);
    }

    [Fact]
    public void ExactRepeat_Three_Times_Fires()
    {
        var (det, clk, audit, _) = Make();
        LoopReport? got = null;
        det.LoopDetected += r => got = r;
        var fp = Fp("ls -la");
        for (int i = 0; i < 3; i++)
        {
            det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.NotNull(got);
        Assert.Equal("exact_repeat", got!.LoopKind);
        Assert.Equal("s1", got.SolverId);
        Assert.Equal("c1", got.ChallengeId);
        Assert.True(got.Repetitions >= 3);
        audit.Dispose();
    }

    [Fact]
    public void SameFingerprint_Twice_NoLoop()
    {
        var (det, clk, audit, _) = Make();
        int fires = 0;
        det.LoopDetected += _ => fires++;
        var fp = Fp("id");
        for (int i = 0; i < 2; i++)
        {
            det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.Equal(0, fires);
        audit.Dispose();
    }

    [Fact]
    public void AbOscillation_FourSteps_Fires()
    {
        var (det, clk, audit, _) = Make();
        LoopReport? got = null;
        det.LoopDetected += r => got = r;
        var a = Fp("A");
        var b = Fp("B");
        // B, A, B, A  (most recent = A, prior = B)
        foreach (var fp in new[] { b, a, b, a })
        {
            det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.NotNull(got);
        Assert.Equal("ab_oscillation", got!.LoopKind);
        audit.Dispose();
    }

    [Fact]
    public void NoProgress_EightDistinct_Fires()
    {
        var (det, clk, audit, _) = Make();
        LoopReport? got = null;
        det.LoopDetected += r => got = r;
        for (int i = 0; i < 8; i++)
        {
            det.Observe(new SolverAction("s1", "c1", "exec", Fp($"cmd-{i}"), clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.NotNull(got);
        Assert.Equal("no_progress", got!.LoopKind);
        Assert.Equal(8, got.Repetitions);
        audit.Dispose();
    }

    [Fact]
    public void NoProgress_Suppressed_By_Partial_Insight()
    {
        var (det, clk, audit, _) = Make();
        int fires = 0;
        det.LoopDetected += _ => fires++;
        det.RecordInsight("s1", "c1", InsightKind.Partial);
        for (int i = 0; i < 8; i++)
        {
            det.Observe(new SolverAction("s1", "c1", "exec", Fp($"cmd-{i}"), clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.Equal(0, fires);
        audit.Dispose();
    }

    [Fact]
    public void Different_Solvers_Independent()
    {
        var (det, clk, audit, _) = Make();
        int fires = 0;
        det.LoopDetected += _ => fires++;
        var fp = Fp("whoami");
        // 2x on s1, 2x on s2 — neither reaches threshold alone.
        for (int i = 0; i < 2; i++)
        {
            det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
            det.Observe(new SolverAction("s2", "c1", "exec", fp, clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.Equal(0, fires);
        audit.Dispose();
    }

    [Fact]
    public void Window_Expiry_Evicts_Old_Actions()
    {
        var (det, clk, audit, _) = Make(window: TimeSpan.FromMinutes(1));
        int fires = 0;
        det.LoopDetected += _ => fires++;
        var fp = Fp("nmap -sV");
        det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
        clk.Advance(TimeSpan.FromMinutes(2));
        det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
        clk.Advance(TimeSpan.FromSeconds(1));
        det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
        // Only 2 within window, not 3.
        Assert.Equal(0, fires);
        audit.Dispose();
    }

    [Fact]
    public void Event_Fires_Exactly_Once_Per_Loop()
    {
        var (det, clk, audit, _) = Make();
        int fires = 0;
        det.LoopDetected += _ => fires++;
        var fp = Fp("cat flag");
        for (int i = 0; i < 3; i++)
        {
            det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.Equal(1, fires);
        // Subsequent CheckForLoop after reset must not re-fire.
        var again = det.CheckForLoop("s1", "c1");
        Assert.Null(again);
        Assert.Equal(1, fires);
        audit.Dispose();
    }

    [Fact]
    public void Audit_LoopDetected_Has_Correct_Fields()
    {
        var (det, clk, audit, path) = Make();
        var fp = Fp("ping -c1 10.10.10.10");
        for (int i = 0; i < 3; i++)
        {
            det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        audit.Dispose();
        var lines = File.ReadAllLines(path);
        var match = lines.FirstOrDefault(l => l.Contains("\"loop.detected\""));
        Assert.NotNull(match);
        Assert.Contains("\"solver_id\":\"s1\"", match);
        Assert.Contains("\"challenge_id\":\"c1\"", match);
        Assert.Contains("\"kind\":\"exact_repeat\"", match);
        Assert.Contains("\"repetitions\":", match);
    }

    [Fact]
    public async Task Concurrent_Observe_Is_Consistent()
    {
        var (det, clk, audit, _) = Make();
        int fires = 0;
        det.LoopDetected += _ => Interlocked.Increment(ref fires);
        var fp = Fp("same");
        var tasks = new List<Task>();
        for (int i = 0; i < 100; i++)
        {
            tasks.Add(Task.Run(() =>
                det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now))));
        }
        await Task.WhenAll(tasks);
        // 100 identical observations: at least one loop fires, and the buffer
        // resets each time so we should see at least one and no exceptions.
        Assert.True(fires >= 1);
        audit.Dispose();
    }

    [Fact]
    public void Buffer_Resets_After_Detection()
    {
        var (det, clk, audit, _) = Make();
        int fires = 0;
        det.LoopDetected += _ => fires++;
        var fp = Fp("echo x");
        for (int i = 0; i < 3; i++)
        {
            det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.Equal(1, fires);
        // After reset, 2 more observations must not re-fire.
        for (int i = 0; i < 2; i++)
        {
            det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
            clk.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.Equal(1, fires);
        // A 3rd post-reset observation completes a new loop.
        det.Observe(new SolverAction("s1", "c1", "exec", fp, clk.Now));
        Assert.Equal(2, fires);
        audit.Dispose();
    }
}
