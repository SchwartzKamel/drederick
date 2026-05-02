using System.Net;
using System.Net.Sockets;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

public class HostDiscoveryToolTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-host-discovery-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static AuditLog NewAudit() => NewAudit(out _);

    // 1. Out-of-scope target → ScopeException, no socket opened.
    [Fact]
    public async Task Sweep_Throws_ScopeException_For_OutOfScope_Target()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new HostDiscoveryTool(scope, audit);

        await Assert.ThrowsAsync<ScopeException>(
            () => tool.SweepAsync(new[] { "192.0.2.5" }, ports: new[] { 80 }));
    }

    // 1b. Mixed in-/out-of-scope batch is rejected before any probe runs.
    [Fact]
    public async Task Sweep_Rejects_Mixed_InAndOutOfScope_Batch()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new HostDiscoveryTool(scope, audit);

        await Assert.ThrowsAsync<ScopeException>(
            () => tool.SweepAsync(new[] { "127.0.0.1", "192.0.2.5" }, ports: new[] { 80 }));
    }

    // 2. Live local listener → alive, listener port in RespondingPorts.
    [Fact]
    public async Task Sweep_Marks_Listening_Localhost_As_Alive()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new HostDiscoveryTool(scope, audit);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var listenerPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        // Background accept loop so connect attempts complete cleanly.
        using var accepting = new CancellationTokenSource();
        var acceptTask = Task.Run(async () =>
        {
            try
            {
                while (!accepting.IsCancellationRequested)
                {
                    var c = await listener.AcceptTcpClientAsync(accepting.Token);
                    c.Close();
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
        });

        try
        {
            // Pick a known-closed port + the live listener port. First-hit
            // wins, but RespondingPorts should contain the listener port.
            int closedPort;
            using (var tmp = new TcpListener(IPAddress.Loopback, 0))
            {
                tmp.Start();
                closedPort = ((IPEndPoint)tmp.LocalEndpoint).Port;
            }

            var results = await tool.SweepAsync(
                new[] { "127.0.0.1" },
                ports: new[] { closedPort, listenerPort },
                connectTimeoutMs: 1500,
                maxConcurrency: 8);

            Assert.Single(results);
            var r = results[0];
            Assert.Equal("127.0.0.1", r.Target);
            Assert.True(r.Alive);
            Assert.Contains(listenerPort, r.RespondingPorts);
        }
        finally
        {
            accepting.Cancel();
            listener.Stop();
            try { await acceptTask; } catch { }
        }
    }

    // 3. All-closed ports → not alive.
    [Fact]
    public async Task Sweep_Marks_Closed_Host_As_Not_Alive()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new HostDiscoveryTool(scope, audit);

        // Pick two ports that are known-closed (acquire then release).
        int p1, p2;
        using (var t1 = new TcpListener(IPAddress.Loopback, 0))
        using (var t2 = new TcpListener(IPAddress.Loopback, 0))
        {
            t1.Start(); t2.Start();
            p1 = ((IPEndPoint)t1.LocalEndpoint).Port;
            p2 = ((IPEndPoint)t2.LocalEndpoint).Port;
        }

        var results = await tool.SweepAsync(
            new[] { "127.0.0.1" },
            ports: new[] { p1, p2 },
            connectTimeoutMs: 500,
            maxConcurrency: 4);

        Assert.Single(results);
        var r = results[0];
        Assert.False(r.Alive);
        Assert.Empty(r.RespondingPorts);
        Assert.Null(r.Error);
    }

    // 4. Audit log records start and finish events.
    [Fact]
    public async Task Sweep_Audits_Start_And_Finish()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit(out var auditPath);
        var tool = new HostDiscoveryTool(scope, audit);

        int port;
        using (var tmp = new TcpListener(IPAddress.Loopback, 0))
        {
            tmp.Start();
            port = ((IPEndPoint)tmp.LocalEndpoint).Port;
        }

        try
        {
            await tool.SweepAsync(
                new[] { "127.0.0.1" },
                ports: new[] { port },
                connectTimeoutMs: 250,
                maxConcurrency: 2);
        }
        finally
        {
            audit.Dispose();
        }

        var lines = await File.ReadAllLinesAsync(auditPath);
        Assert.Contains(lines, l => l.Contains("\"event\":\"host-discovery.start\""));
        Assert.Contains(lines, l => l.Contains("\"event\":\"host-discovery.finish\""));
        File.Delete(auditPath);
    }

    // 5. Cancellation propagates.
    [Fact]
    public async Task Sweep_Respects_CancellationToken()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new HostDiscoveryTool(scope, audit);

        // Pick a closed port so each probe burns its full timeout.
        int closedPort;
        using (var tmp = new TcpListener(IPAddress.Loopback, 0))
        {
            tmp.Start();
            closedPort = ((IPEndPoint)tmp.LocalEndpoint).Port;
        }

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(50);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => tool.SweepAsync(
                Enumerable.Repeat("127.0.0.1", 64).ToList(),
                ports: new[] { closedPort },
                connectTimeoutMs: 5000,
                maxConcurrency: 4,
                ct: cts.Token));
    }

    // 6. Concurrency cap is honored.
    [Fact]
    public async Task Sweep_Bounded_Concurrency_Does_Not_Exceed_Cap()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new HostDiscoveryTool(scope, audit);

        // Closed port → every probe takes ~timeoutMs to fail, maximising
        // overlap so the observer sees real contention.
        int closedPort;
        using (var tmp = new TcpListener(IPAddress.Loopback, 0))
        {
            tmp.Start();
            closedPort = ((IPEndPoint)tmp.LocalEndpoint).Port;
        }

        const int cap = 16;
        var observed = 0;

        void Observe(int current)
        {
            // Cooperatively track high-water mark.
            int snapshot;
            do
            {
                snapshot = observed;
                if (current <= snapshot) return;
            }
            while (Interlocked.CompareExchange(ref observed, current, snapshot) != snapshot);
        }

        var targets = Enumerable.Repeat("127.0.0.1", 1024).ToList();

        var results = await tool.SweepWithObserverAsync(
            targets,
            ports: new[] { closedPort },
            connectTimeoutMs: 200,
            maxConcurrency: cap,
            inFlightObserver: Observe);

        Assert.Equal(1024, results.Count);
        Assert.True(observed <= cap,
            $"Observed in-flight {observed} exceeded cap {cap}");
        Assert.All(results, r => Assert.False(r.Alive));
    }

    // 7. RespondingPorts seeds downstream port-scan with what we found alive.
    [Fact]
    public async Task Sweep_RespondingPorts_Seeds_Downstream_PortScan()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new HostDiscoveryTool(scope, audit);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var listenerPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var accepting = new CancellationTokenSource();
        var acceptTask = Task.Run(async () =>
        {
            try
            {
                while (!accepting.IsCancellationRequested)
                {
                    var c = await listener.AcceptTcpClientAsync(accepting.Token);
                    c.Close();
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
        });

        try
        {
            // Single port, single target — deterministic shape assertion.
            var results = await tool.SweepAsync(
                new[] { "127.0.0.1" },
                ports: new[] { listenerPort },
                connectTimeoutMs: 1000,
                maxConcurrency: 4);

            Assert.Single(results);
            Assert.True(results[0].Alive);
            Assert.Equal(new[] { listenerPort }, results[0].RespondingPorts);
            Assert.True(results[0].ProbeDurationMs >= 0);
        }
        finally
        {
            accepting.Cancel();
            listener.Stop();
            try { await acceptTask; } catch { }
        }
    }
}
