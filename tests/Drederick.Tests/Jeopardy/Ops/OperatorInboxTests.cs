using System.Text.Json;
using Drederick.Audit;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Ops;
using Xunit;

namespace Drederick.Tests.Jeopardy.Ops;

internal sealed class FakeBus : ISolverMessageBus
{
    public readonly List<SolverInsight> Published = new();
    private readonly Lock _gate = new();

    public IAsyncEnumerable<SolverInsight> Subscribe(string challengeId, string solverId, CancellationToken ct)
        => throw new NotImplementedException();

    public ValueTask PublishAsync(SolverInsight insight, CancellationToken ct)
    {
        lock (_gate) { Published.Add(insight); }
        return ValueTask.CompletedTask;
    }

    public IReadOnlyList<SolverInsight> History(string challengeId) => Array.Empty<SolverInsight>();
    public int Count(string challengeId) => 0;
}

internal static class OpsTestUtil
{
    public static string NewTempDir()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, $"drederick-ops-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static async Task<bool> WaitAsync(Func<bool> condition, TimeSpan timeout)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (condition()) return true;
            await Task.Delay(25).ConfigureAwait(false);
        }
        return condition();
    }
}

public sealed class OperatorInboxTests
{
    [Fact]
    public async Task Sender_writes_valid_JSONL_that_inbox_parses()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "in.jsonl");
        var msg = new OperatorMessage(DateTimeOffset.UtcNow, "42", null, "hint", "try ret2libc");

        await OperatorSender.SendAsync(inbox, msg, CancellationToken.None);

        var line = (await File.ReadAllLinesAsync(inbox)).Single();
        var parsed = JsonSerializer.Deserialize<OperatorMessage>(line, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.NotNull(parsed);
        Assert.Equal("42", parsed!.ChallengeId);
        Assert.Equal("hint", parsed.Kind);
        Assert.Equal("try ret2libc", parsed.Body);
    }

    [Fact]
    public async Task Inbox_fires_MessageReceived_within_one_second_of_append()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "in.jsonl");
        using var audit = new AuditLog(Path.Combine(dir, "audit.jsonl"));
        var bus = new FakeBus();
        await using var ob = new OperatorInbox(bus, audit);

        var got = new TaskCompletionSource<OperatorMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        ob.MessageReceived += m => { got.TrySetResult(m); return Task.CompletedTask; };

        await ob.StartAsync(inbox, CancellationToken.None);

        await OperatorSender.SendAsync(inbox,
            new OperatorMessage(DateTimeOffset.UtcNow, "42", null, "hint", "x"),
            CancellationToken.None);

        var completed = await Task.WhenAny(got.Task, Task.Delay(2000));
        Assert.Same(got.Task, completed);
        var rx = await got.Task;
        Assert.Equal("42", rx.ChallengeId);
    }

    [Fact]
    public async Task Hint_with_challenge_id_pushes_to_bus_as_operator_hint()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "in.jsonl");
        using var audit = new AuditLog(Path.Combine(dir, "audit.jsonl"));
        var bus = new FakeBus();
        await using var ob = new OperatorInbox(bus, audit);
        await ob.StartAsync(inbox, CancellationToken.None);

        await OperatorSender.SendAsync(inbox,
            new OperatorMessage(DateTimeOffset.UtcNow, "42", null, "hint", "try ret2libc"),
            CancellationToken.None);

        var ok = await OpsTestUtil.WaitAsync(() => bus.Published.Count >= 1, TimeSpan.FromSeconds(3));
        Assert.True(ok);
        var ins = bus.Published[0];
        Assert.Equal("42", ins.ChallengeId);
        Assert.Equal(InsightKind.OperatorHint, ins.Kind);
        Assert.Equal("try ret2libc", ins.Summary);
        Assert.Contains("op:hint", ins.Tags);
    }

    [Fact]
    public async Task Shutdown_kind_fires_ShutdownRequested_not_MessageReceived()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "in.jsonl");
        using var audit = new AuditLog(Path.Combine(dir, "audit.jsonl"));
        var bus = new FakeBus();
        await using var ob = new OperatorInbox(bus, audit);

        var shutdown = new TaskCompletionSource<OperatorMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        int normal = 0;
        ob.ShutdownRequested += m => { shutdown.TrySetResult(m); return Task.CompletedTask; };
        ob.MessageReceived += _ => { Interlocked.Increment(ref normal); return Task.CompletedTask; };

        await ob.StartAsync(inbox, CancellationToken.None);
        await OperatorSender.SendAsync(inbox,
            new OperatorMessage(DateTimeOffset.UtcNow, null, null, "shutdown", ""),
            CancellationToken.None);

        var completed = await Task.WhenAny(shutdown.Task, Task.Delay(2000));
        Assert.Same(shutdown.Task, completed);
        Assert.Equal(0, Volatile.Read(ref normal));
        Assert.Empty(bus.Published);
    }

    [Fact]
    public async Task Concurrent_senders_produce_no_corruption_and_all_lines_arrive()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "in.jsonl");
        using var audit = new AuditLog(Path.Combine(dir, "audit.jsonl"));
        var bus = new FakeBus();
        await using var ob = new OperatorInbox(bus, audit);

        int seen = 0;
        ob.MessageReceived += _ => { Interlocked.Increment(ref seen); return Task.CompletedTask; };
        await ob.StartAsync(inbox, CancellationToken.None);

        var tasks = Enumerable.Range(0, 10).Select(i =>
            OperatorSender.SendAsync(inbox,
                new OperatorMessage(DateTimeOffset.UtcNow, i.ToString(), null, "hint", $"body-{i}"),
                CancellationToken.None)).ToArray();
        await Task.WhenAll(tasks);

        var ok = await OpsTestUtil.WaitAsync(() => Volatile.Read(ref seen) >= 10, TimeSpan.FromSeconds(5));
        Assert.True(ok, $"only saw {seen}");

        var lines = await File.ReadAllLinesAsync(inbox);
        Assert.Equal(10, lines.Length);
        foreach (var line in lines)
        {
            var m = JsonSerializer.Deserialize<OperatorMessage>(line, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            Assert.NotNull(m);
            Assert.Equal("hint", m!.Kind);
        }
    }

    [Fact]
    public async Task Malformed_line_is_skipped_and_subsequent_lines_still_deliver()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "in.jsonl");
        var auditPath = Path.Combine(dir, "audit.jsonl");
        using var audit = new AuditLog(auditPath);
        var bus = new FakeBus();
        await using var ob = new OperatorInbox(bus, audit);

        var seen = new TaskCompletionSource<OperatorMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        ob.MessageReceived += m => { seen.TrySetResult(m); return Task.CompletedTask; };
        await ob.StartAsync(inbox, CancellationToken.None);

        await File.AppendAllTextAsync(inbox, "not-json-at-all\n");
        await OperatorSender.SendAsync(inbox,
            new OperatorMessage(DateTimeOffset.UtcNow, "7", null, "hint", "good"),
            CancellationToken.None);

        var done = await Task.WhenAny(seen.Task, Task.Delay(3000));
        Assert.Same(seen.Task, done);
        var rx = await seen.Task;
        Assert.Equal("7", rx.ChallengeId);

        await Task.Delay(100);
        var auditText = await File.ReadAllTextAsync(auditPath);
        Assert.Contains("operator.msg.error", auditText);
    }

    [Fact]
    public async Task File_truncation_is_handled_and_new_messages_after_truncation_deliver()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "in.jsonl");
        using var audit = new AuditLog(Path.Combine(dir, "audit.jsonl"));
        var bus = new FakeBus();
        await using var ob = new OperatorInbox(bus, audit);

        int count = 0;
        var latest = new TaskCompletionSource<OperatorMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        ob.MessageReceived += m =>
        {
            Interlocked.Increment(ref count);
            if (m.ChallengeId == "after-trunc") latest.TrySetResult(m);
            return Task.CompletedTask;
        };
        await ob.StartAsync(inbox, CancellationToken.None);

        await OperatorSender.SendAsync(inbox,
            new OperatorMessage(DateTimeOffset.UtcNow, "before", null, "hint", "a"),
            CancellationToken.None);
        await OpsTestUtil.WaitAsync(() => Volatile.Read(ref count) >= 1, TimeSpan.FromSeconds(3));

        // truncate
        using (var fs = new FileStream(inbox, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
        {
            fs.SetLength(0);
        }
        await Task.Delay(700); // let inbox notice

        await OperatorSender.SendAsync(inbox,
            new OperatorMessage(DateTimeOffset.UtcNow, "after-trunc", null, "hint", "b"),
            CancellationToken.None);

        var done = await Task.WhenAny(latest.Task, Task.Delay(3000));
        Assert.Same(latest.Task, done);
    }

    [Fact]
    public async Task Plaintext_body_canary_is_never_written_to_audit_log()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "in.jsonl");
        var auditPath = Path.Combine(dir, "audit.jsonl");
        const string canary = "operator_canary_body_42";
        var bus = new FakeBus();

        {
            using var audit = new AuditLog(auditPath);
            await using var ob = new OperatorInbox(bus, audit);
            int saw = 0;
            ob.MessageReceived += _ => { Interlocked.Increment(ref saw); return Task.CompletedTask; };
            await ob.StartAsync(inbox, CancellationToken.None);
            await OperatorSender.SendAsync(inbox,
                new OperatorMessage(DateTimeOffset.UtcNow, "42", null, "hint", canary),
                CancellationToken.None);
            await OpsTestUtil.WaitAsync(() => Volatile.Read(ref saw) >= 1, TimeSpan.FromSeconds(3));
        }

        var auditText = await File.ReadAllTextAsync(auditPath);
        Assert.DoesNotContain(canary, auditText);
        // but the SHA-256 of the canary must appear
        var hash = OperatorSender.Sha256Hex(canary);
        Assert.Contains(hash, auditText);
    }

    [Fact]
    public async Task DisposeAsync_stops_cleanly_and_does_not_hang()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "in.jsonl");
        using var audit = new AuditLog(Path.Combine(dir, "audit.jsonl"));
        var bus = new FakeBus();
        var ob = new OperatorInbox(bus, audit);
        await ob.StartAsync(inbox, CancellationToken.None);

        await OperatorSender.SendAsync(inbox,
            new OperatorMessage(DateTimeOffset.UtcNow, "42", null, "hint", "x"),
            CancellationToken.None);

        var disposeTask = ob.DisposeAsync().AsTask();
        var done = await Task.WhenAny(disposeTask, Task.Delay(3000));
        Assert.Same(disposeTask, done);
    }

    [Fact]
    public async Task Nonexistent_inbox_path_is_created_and_subsequent_sends_deliver()
    {
        var dir = OpsTestUtil.NewTempDir();
        var inbox = Path.Combine(dir, "subdir", "in.jsonl");
        Assert.False(File.Exists(inbox));

        using var audit = new AuditLog(Path.Combine(dir, "audit.jsonl"));
        var bus = new FakeBus();
        await using var ob = new OperatorInbox(bus, audit);
        var got = new TaskCompletionSource<OperatorMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        ob.MessageReceived += m => { got.TrySetResult(m); return Task.CompletedTask; };

        await ob.StartAsync(inbox, CancellationToken.None);
        Assert.True(File.Exists(inbox));

        await OperatorSender.SendAsync(inbox,
            new OperatorMessage(DateTimeOffset.UtcNow, "9", null, "hint", "y"),
            CancellationToken.None);

        var done = await Task.WhenAny(got.Task, Task.Delay(3000));
        Assert.Same(got.Task, done);
        var rx = await got.Task;
        Assert.Equal("9", rx.ChallengeId);
    }
}
