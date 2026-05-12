using System.Net.Sockets;
using System.Text.Json;
using Drederick.Agent;
using Drederick.Audit;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Agent;

public class FailureAwareRetryPolicyTests
{
    private static string NewAuditPath() =>
        Path.Combine(Path.GetTempPath(), $"drederick-retry-{Guid.NewGuid():N}.jsonl");

    private static string NewOutDir()
    {
        var d = Path.Combine(Path.GetTempPath(), $"drederick-retry-out-{Guid.NewGuid():N}");
        Directory.CreateDirectory(d);
        return d;
    }

    private static (FailureAwareRetryPolicy policy, AuditLog audit, List<TimeSpan> sleeps) Build(
        int maxAttempts = 4,
        Scope.Scope? scope = null,
        string? outDir = null)
    {
        var audit = new AuditLog(NewAuditPath());
        var sleeps = new List<TimeSpan>();
        var policy = new FailureAwareRetryPolicy(
            maxAttempts: maxAttempts,
            classifier: new ToolFailureClassifier(),
            audit: audit,
            scope: scope,
            outDir: outDir,
            sleep: (t, _) => { sleeps.Add(t); return Task.CompletedTask; });
        return (policy, audit, sleeps);
    }

    private static IEnumerable<Dictionary<string, JsonElement>> ReadAudit(AuditLog audit)
    {
        audit.Dispose();
        return File.ReadAllLines(audit.Path)
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .Select(l => JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(l)!);
    }

    [Fact]
    public async Task Recoverable_Failures_Retried()
    {
        var (policy, _, sleeps) = Build();
        int calls = 0;
        var outcome = await policy.ExecuteAsync<int>("nmap", "10.10.10.5", _ =>
        {
            calls++;
            if (calls < 3) throw new SocketException();
            return Task.FromResult(42);
        });
        Assert.True(outcome.Success);
        Assert.Equal(3, calls);
        Assert.Equal(42, outcome.Result);
        Assert.Equal(2, sleeps.Count);
    }

    [Fact]
    public async Task NonRecoverable_Failures_NotRetried()
    {
        var (policy, _, _) = Build();
        int calls = 0;
        var outcome = await policy.ExecuteAsync<int>("hydra", "10.10.10.5", _ =>
        {
            calls++;
            throw new InvalidOperationException("401 Unauthorized");
        });
        Assert.False(outcome.Success);
        Assert.Equal(1, calls);
        Assert.Equal("auth_failed", outcome.FinalFailure!.Kind);
    }

    [Fact]
    public async Task MaxAttempts_Respected()
    {
        var (policy, _, _) = Build(maxAttempts: 2);
        int calls = 0;
        var outcome = await policy.ExecuteAsync<int>("nmap", "10.10.10.5", _ =>
        {
            calls++;
            throw new SocketException();
        });
        Assert.False(outcome.Success);
        Assert.Equal(2, calls);
        Assert.Equal(2, outcome.AttemptsUsed);
    }

    [Fact]
    public async Task Backoff_Delay_Honored()
    {
        var (policy, _, sleeps) = Build(maxAttempts: 3);
        int calls = 0;
        await policy.ExecuteAsync<int>("nmap", "10.10.10.5", _ =>
        {
            calls++;
            throw new SocketException();
        });
        Assert.Equal(2, sleeps.Count);
        Assert.Equal(TimeSpan.FromSeconds(5), sleeps[0]);
        Assert.Equal(TimeSpan.FromSeconds(10), sleeps[1]);
    }

    [Fact]
    public async Task AggressivenessFactor_Decreases_PerAttempt()
    {
        var (policy, _, _) = Build(maxAttempts: 4);
        var factors = new List<double>();
        await policy.ExecuteAsync<int>("nmap", "10.10.10.5", ctx =>
        {
            factors.Add(ctx.AggressivenessFactor);
            throw new SocketException();
        });
        Assert.Equal(4, factors.Count);
        Assert.Equal(1.0, factors[0]);
        for (int i = 1; i < factors.Count; i++)
        {
            Assert.True(factors[i] < factors[i - 1]);
            Assert.InRange(factors[i], 0.05, 1.0);
        }
    }

    [Fact]
    public async Task Three_Transients_EscalateTo_TargetDead()
    {
        var (policy, audit, _) = Build(maxAttempts: 10);
        var outcome = await policy.ExecuteAsync<int>("nmap", "10.10.10.99", _ =>
        {
            throw new SocketException();
        });
        Assert.False(outcome.Success);
        Assert.Equal("target_dead", outcome.FinalFailure!.Kind);
        // 3 transient attempts + 1 escalated target_dead (non-recoverable, breaks).
        Assert.Equal(4, outcome.AttemptsUsed);

        var entries = ReadAudit(audit).ToList();
        Assert.Contains(entries, e => e["event"].GetString() == "retry.target_dead");
    }

    [Fact]
    public async Task LockoutMarker_Persisted_To_OutDir()
    {
        var outDir = NewOutDir();
        var (policy, _, _) = Build(outDir: outDir);
        await policy.ExecuteAsync<int>("hydra", "10.10.10.5", _ =>
        {
            throw new InvalidOperationException("account locked: too many failed attempts");
        });
        var path = Path.Combine(outDir, "10.10.10.5", "lockouts.json");
        Assert.True(File.Exists(path));
        var markers = JsonSerializer.Deserialize<List<LockoutMarker>>(File.ReadAllText(path))!;
        Assert.Single(markers);
        Assert.Equal("hydra", markers[0].ServiceProtocol);
        Assert.True(markers[0].CooldownUntil > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task LockoutMarker_RejectsRepeatAttempt_WithinCooldown()
    {
        var outDir = NewOutDir();
        var (policy, _, _) = Build(outDir: outDir);
        await policy.ExecuteAsync<int>("hydra", "10.10.10.5", _ =>
        {
            throw new InvalidOperationException("account locked");
        });

        int calls = 0;
        var second = await policy.ExecuteAsync<int>("hydra", "10.10.10.5", _ =>
        {
            calls++;
            return Task.FromResult(1);
        });
        Assert.False(second.Success);
        Assert.Equal(0, calls);
        Assert.Equal("account_lockout", second.FinalFailure!.Kind);
    }

    [Fact]
    public async Task Audit_RecordsAllAttempts_NoSecretLeakage()
    {
        var (policy, audit, _) = Build(maxAttempts: 3);
        const string canary = "P@ssw0rdShouldNotAppear-XYZZY";
        await policy.ExecuteAsync<int>("hydra", "10.10.10.5", _ =>
        {
            throw new SocketException($"connect failed with secret={canary}");
        });
        var entries = ReadAudit(audit).ToList();
        Assert.Equal(3, entries.Count(e => e["event"].GetString() == "retry.attempt"));
        Assert.Single(entries, e => e["event"].GetString() == "retry.exhausted");
        var raw = File.ReadAllText(audit.Path);
        Assert.DoesNotContain(canary, raw);
    }

    [Fact]
    public async Task RetryAfter_Header_Respected_OnRateLimit()
    {
        // Test classifier path directly — RetryContext doesn't carry HTTP headers.
        var classifier = new ToolFailureClassifier();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Retry-After"] = "7" };
        var c = classifier.Classify("http", null, null, "429 too many requests", responseHeaders: headers);
        Assert.Equal("rate_limited", c.Kind);
        Assert.Equal(TimeSpan.FromSeconds(7), c.SuggestedBackoff);

        // And make sure policy reads suggestion via classifier->exception path with "429" in message.
        var (policy, _, sleeps) = Build(maxAttempts: 2);
        await policy.ExecuteAsync<int>("http", "10.10.10.5", _ =>
        {
            throw new InvalidOperationException("HTTP 429 too many requests");
        });
        Assert.Single(sleeps);
        Assert.Equal(TimeSpan.FromSeconds(30), sleeps[0]); // default when no header
    }

    [Fact]
    public async Task ScopeException_NotRetried()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        var (policy, _, _) = Build(scope: scope);
        await Assert.ThrowsAsync<ScopeException>(() =>
            policy.ExecuteAsync<int>("nmap", "8.8.8.8", _ => Task.FromResult(1)));

        // Also: ScopeException thrown mid-work must propagate without retry.
        int calls = 0;
        await Assert.ThrowsAsync<ScopeException>(async () =>
        {
            await policy.ExecuteAsync<int>("nmap", "10.10.10.5", _ =>
            {
                calls++;
                throw new ScopeException("rejected mid-run");
            });
        });
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task CancellationToken_StopsRetry()
    {
        var (policy, _, _) = Build(maxAttempts: 10);
        using var cts = new CancellationTokenSource();
        int calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await policy.ExecuteAsync<int>("nmap", "10.10.10.5", _ =>
            {
                calls++;
                cts.Cancel();
                throw new SocketException();
            }, cts.Token);
        });
        Assert.Equal(1, calls);
    }
}
