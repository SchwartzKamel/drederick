using System.Collections.Concurrent;
using Drederick.Agent;
using Drederick.Audit;
using Drederick.Cli;
using Drederick.Memory;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests;

public class HostWorkerPoolTests
{
    [Fact]
    public async Task Host_Concurrency_Is_Honoured()
    {
        // 10 host targets, concurrency 3 -> at most 3 concurrent invocations.
        var targets = Enumerable.Range(0, 10).Select(i => $"10.0.0.{i}").ToList();
        var pool = new HostWorkerPool(hostConcurrency: 3, serviceConcurrency: 1);

        int inFlight = 0;
        int maxInFlight = 0;
        var gate = new object();

        await pool.RunAsync(targets, async (host, _, ct) =>
        {
            int now = Interlocked.Increment(ref inFlight);
            lock (gate) if (now > maxInFlight) maxInFlight = now;
            await Task.Delay(25, ct).ConfigureAwait(false);
            Interlocked.Decrement(ref inFlight);
        }, onHostError: null, CancellationToken.None);

        Assert.True(maxInFlight <= 3, $"max in-flight was {maxInFlight}, expected <= 3");
        Assert.True(maxInFlight >= 2, $"max in-flight was {maxInFlight}, expected parallelism > 1");
    }

    [Fact]
    public async Task Service_Concurrency_Is_Honoured()
    {
        var pool = new HostWorkerPool(hostConcurrency: 1, serviceConcurrency: 2);

        int inFlight = 0;
        int maxInFlight = 0;
        var gate = new object();

        await pool.RunAsync(new[] { "10.0.0.1" }, async (host, svcPool, ct) =>
        {
            for (int i = 0; i < 8; i++)
            {
                int port = 1000 + i;
                await svcPool.EnqueueAsync(new ScanJob(
                    Tool: null!, Target: host, Port: port,
                    Run: async token =>
                    {
                        int now = Interlocked.Increment(ref inFlight);
                        lock (gate) if (now > maxInFlight) maxInFlight = now;
                        await Task.Delay(25, token).ConfigureAwait(false);
                        Interlocked.Decrement(ref inFlight);
                    }),
                    ct).ConfigureAwait(false);
            }
        }, onHostError: null, CancellationToken.None);

        Assert.True(maxInFlight <= 2, $"max service in-flight was {maxInFlight}, expected <= 2");
    }

    [Fact]
    public async Task Bounded_Channel_Exerts_Backpressure_On_Producer()
    {
        // capacity == hostConcurrency == 2. Blocking consumers means writes
        // beyond 2 must wait until a slot frees.
        var pool = new HostWorkerPool(hostConcurrency: 2, serviceConcurrency: 1);
        var release = new TaskCompletionSource();
        var consumedFirstTwo = new TaskCompletionSource();
        int consumed = 0;

        var targets = Enumerable.Range(0, 10).Select(i => $"10.0.0.{i}").ToList();
        var observedTimes = new List<DateTimeOffset>();
        var enumerable = EnumerateWithTimestamps(targets, observedTimes);

        var task = pool.RunAsync(enumerable, async (host, _, ct) =>
        {
            if (Interlocked.Increment(ref consumed) == 2) consumedFirstTwo.TrySetResult();
            await release.Task.ConfigureAwait(false);
        }, onHostError: null, CancellationToken.None);

        // Give the producer a moment to write and block.
        await consumedFirstTwo.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Delay(100);

        // At this point producer should have written at most capacity + 2
        // in-flight = 4 items into the pipeline, not all 10.
        Assert.True(observedTimes.Count < targets.Count,
            $"producer wrote {observedTimes.Count} items while capacity=2 and 2 in-flight; expected back-pressure.");

        release.SetResult();
        await task;
    }

    private static IEnumerable<string> EnumerateWithTimestamps(
        IEnumerable<string> src, List<DateTimeOffset> observed)
    {
        foreach (var t in src)
        {
            lock (observed) observed.Add(DateTimeOffset.UtcNow);
            yield return t;
        }
    }

    [Fact]
    public async Task Cancellation_Drains_Gracefully()
    {
        var pool = new HostWorkerPool(hostConcurrency: 2, serviceConcurrency: 1);
        using var cts = new CancellationTokenSource();
        var targets = Enumerable.Range(0, 50).Select(i => $"10.0.0.{i}").ToList();

        var task = pool.RunAsync(targets, async (host, _, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
        }, onHostError: null, cts.Token);

        await Task.Delay(50);
        cts.Cancel();

        // Must not hang.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await task.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task KnowledgeBase_Is_Consistent_Under_Concurrent_Merges()
    {
        var kb = new KnowledgeBase();
        var pool = new HostWorkerPool(hostConcurrency: 8, serviceConcurrency: 4);
        var targets = Enumerable.Range(0, 100).Select(i => $"10.0.0.{i}").ToList();

        await pool.RunAsync(targets, async (host, _, ct) =>
        {
            await Task.Yield();
            kb.Merge(new[] { new HostFinding { Target = host, Started = "s", Finished = "f" } });
        }, onHostError: null, CancellationToken.None);

        Assert.Equal(100, kb.Hosts.Count);
        foreach (var t in targets)
            Assert.True(kb.Hosts.ContainsKey(t), $"missing {t}");
    }

    [Fact]
    public async Task AuditLog_Is_Consistent_Under_Concurrent_Writes()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".jsonl");
        try
        {
            using (var audit = new AuditLog(path))
            {
                var pool = new HostWorkerPool(hostConcurrency: 8, serviceConcurrency: 4);
                var targets = Enumerable.Range(0, 100).Select(i => $"10.0.0.{i}").ToList();
                await pool.RunAsync(targets, async (host, _, ct) =>
                {
                    await Task.Yield();
                    audit.Record("host.scan", new Dictionary<string, object?> { ["target"] = host });
                }, onHostError: null, CancellationToken.None);
            }
            var lines = File.ReadAllLines(path);
            Assert.Equal(100, lines.Length);
            // Each line must be a well-formed JSON object (no interleaved writes).
            foreach (var line in lines)
            {
                var doc = System.Text.Json.JsonDocument.Parse(line);
                Assert.Equal("host.scan", doc.RootElement.GetProperty("event").GetString());
            }
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public void Findings_Are_Emitted_In_Stable_Sorted_Order()
    {
        // Simulate the Program.cs emission order: findings collected in
        // arbitrary concurrent order must be sorted by target before emit.
        var findings = new ConcurrentBag<HostFinding>();
        Parallel.ForEach(new[] { "10.0.0.3", "10.0.0.1", "10.0.0.10", "10.0.0.2" },
            t => findings.Add(new HostFinding { Target = t }));

        var sorted = findings.OrderBy(f => f.Target, StringComparer.Ordinal).Select(f => f.Target).ToList();
        Assert.Equal(new[] { "10.0.0.1", "10.0.0.10", "10.0.0.2", "10.0.0.3" }, sorted);
    }

    [Fact]
    public void Cli_Rejects_HostConcurrency_Out_Of_Range()
    {
        Assert.Throws<ArgumentException>(() => CommandLineOptions.Parse(new[] { "--host-concurrency", "0" }));
        Assert.Throws<ArgumentException>(() => CommandLineOptions.Parse(new[] { "--host-concurrency", "33" }));
        Assert.Throws<ArgumentException>(() => CommandLineOptions.Parse(new[] { "--host-concurrency", "abc" }));
    }

    [Fact]
    public void Cli_Rejects_ServiceConcurrency_Out_Of_Range()
    {
        Assert.Throws<ArgumentException>(() => CommandLineOptions.Parse(new[] { "--service-concurrency", "0" }));
        Assert.Throws<ArgumentException>(() => CommandLineOptions.Parse(new[] { "--service-concurrency", "65" }));
    }

    [Fact]
    public void Cli_Accepts_Valid_Concurrency_Flags()
    {
        var o = CommandLineOptions.Parse(new[] {
            "--scope", "x",
            "--host-concurrency", "16",
            "--service-concurrency", "32",
        });
        Assert.Equal(16, o.HostConcurrency);
        Assert.Equal(32, o.ServiceConcurrency);
    }

    [Fact]
    public void Cli_Legacy_Parallel_Flag_Seeds_HostConcurrency()
    {
        var o = CommandLineOptions.Parse(new[] { "--scope", "x", "-j", "7" });
        Assert.Equal(7, o.HostConcurrency);
        Assert.Equal(7, o.Parallelism);
    }

    [Fact]
    public void Cli_Explicit_HostConcurrency_Wins_Over_Parallel()
    {
        var o = CommandLineOptions.Parse(new[] {
            "--scope", "x", "-j", "7", "--host-concurrency", "3",
        });
        Assert.Equal(3, o.HostConcurrency);
        Assert.Equal(7, o.Parallelism);
    }
}
