using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Drederick.Host;
using Drederick.Web;
using Drederick.Web.Runs;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Drederick.Web.Tests;

/// <summary>
/// Tests for the <c>/api/runs</c> endpoint group. Uses a stubbed
/// <see cref="IRunExecutor"/> that never spawns real scanners and a canned
/// <see cref="ScopePathPolicy"/> whitelisting the per-test temp dir so the
/// handler can read a scope file we write there. Mirrors the invariant
/// guarantees of <c>DrederickHost</c>: per-target scope check, server-side
/// category grants, path-traversal guard, no plaintext scope_path in audit.
/// </summary>
public sealed class RunsEndpointsTests
{
    // Canary literal used for scope_path — must never appear in audit.jsonl.
    private const string CanaryScopeName = "CANARY-SCOPE-DO-NOT-LOG-xyz123";

    // ---- helpers ----

    /// <summary>
    /// Stub executor: blocks on the supplied CT until cancelled, emitting
    /// one ScanEvent immediately. Lets the cancel test assert the CTS was
    /// actually tripped.
    /// </summary>
    private sealed class BlockingStubExecutor : IRunExecutor
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Cancelled { get; private set; }

        public async Task<RunResult> RunAsync(
            Drederick.Scope.Scope scope,
            RunOptions options,
            IProgress<ScanEvent>? progress,
            CancellationToken ct)
        {
            progress?.Report(new ScanEvent(
                Kind: ScanEventKind.SessionStart,
                Timestamp: DateTimeOffset.UtcNow,
                Message: "stub-start"));
            Started.TrySetResult();

            try
            {
                await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                Cancelled = true;
                throw;
            }
            return new RunResult(0, 0, options.OutputDir, scope.Source);
        }
    }

    /// <summary>Fast-completing stub. Emits a handful of events, then returns.</summary>
    private sealed class FastStubExecutor : IRunExecutor
    {
        public int Calls;

        public Task<RunResult> RunAsync(
            Drederick.Scope.Scope scope,
            RunOptions options,
            IProgress<ScanEvent>? progress,
            CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            var now = DateTimeOffset.UtcNow;
            progress?.Report(new ScanEvent(ScanEventKind.SessionStart, now, Message: "start"));
            progress?.Report(new ScanEvent(ScanEventKind.ToolStart, now.AddMilliseconds(1), Tool: "nmap"));
            progress?.Report(new ScanEvent(ScanEventKind.ToolFinish, now.AddMilliseconds(2), Tool: "nmap"));
            progress?.Report(new ScanEvent(ScanEventKind.SessionEnd, now.AddMilliseconds(3), Message: "end"));
            return Task.FromResult(new RunResult(1, 3, options.OutputDir, scope.Source));
        }
    }

    private static string WriteScopeFile(string dir, string content)
    {
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "scope.txt");
        File.WriteAllText(path, content);
        return path;
    }

    private static RunsTestFactory MakeFactory(
        IRunExecutor executor,
        string? allowedRootOverride = null,
        IEnumerable<string>? grantedCategories = null)
    {
        var factory = new RunsTestFactory(
            executor,
            allowedRootOverride, // null → use factory.OutputDir
            grantedCategories ?? new[] { "recon" });
        return factory;
    }

    private sealed class RunsTestFactory : DrederickWebFactory
    {
        private readonly IRunExecutor _executor;
        private readonly string? _allowedRootOverride;
        private readonly IEnumerable<string> _grants;

        public RunsTestFactory(
            IRunExecutor executor,
            string? allowedRootOverride,
            IEnumerable<string> grants)
        {
            _executor = executor;
            _allowedRootOverride = allowedRootOverride;
            _grants = grants;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services =>
            {
                var toRemove = services
                    .Where(d => d.ServiceType == typeof(IRunExecutor)
                             || d.ServiceType == typeof(ScopePathPolicy)
                             || d.ServiceType == typeof(ServerCategoryGrants)
                             || d.ServiceType == typeof(RunManager))
                    .ToList();
                foreach (var d in toRemove) services.Remove(d);
                services.AddSingleton(_executor);
                var root = _allowedRootOverride ?? OutputDir;
                services.AddSingleton(new ScopePathPolicy(new[] { root }));
                services.AddSingleton(new ServerCategoryGrants(_grants));
                services.AddSingleton<RunManager>();
            });
        }
    }

    // ---- tests ----

    [Fact]
    public async Task Start_HappyPath_ReturnsRunId_202()
    {
        using var factory = MakeFactory(new FastStubExecutor());
        var scopePath = WriteScopeFile(factory.OutputDir, "10.10.10.0/24\n");
        using var client = factory.CreateClient();

        var body = new { scope_path = scopePath, targets = new[] { "10.10.10.5" } };
        var resp = await client.PostAsJsonAsync("/api/runs", body);

        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(Guid.TryParse(json.GetProperty("run_id").GetString(), out _));
        Assert.Equal("running", json.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Start_OutOfScopeTarget_Returns400_WithScopeException()
    {
        using var factory = MakeFactory(new FastStubExecutor());
        var scopePath = WriteScopeFile(factory.OutputDir, "10.10.10.0/24\n");
        using var client = factory.CreateClient();

        var body = new
        {
            scope_path = scopePath,
            targets = new[] { "10.10.10.5", "192.168.1.1" },
        };
        var resp = await client.PostAsJsonAsync("/api/runs", body);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("scope", json.GetProperty("error").GetString());
        var rejected = json.GetProperty("rejected_targets").EnumerateArray()
            .Select(e => e.GetString()).ToList();
        Assert.Contains("192.168.1.1", rejected);
        Assert.DoesNotContain("10.10.10.5", rejected);
    }

    [Fact]
    public async Task Start_UnauthorizedCategory_Returns403()
    {
        using var factory = MakeFactory(
            new FastStubExecutor(),
            allowedRootOverride: null,
            grantedCategories: new[] { "recon" });  // NO exec-pocs
        var scopePath = WriteScopeFile(factory.OutputDir, "10.10.10.0/24\n");
        using var client = factory.CreateClient();

        var body = new
        {
            scope_path = scopePath,
            targets = new[] { "10.10.10.5" },
            categories = new[] { "recon", "exec-pocs" },
        };
        var resp = await client.PostAsJsonAsync("/api/runs", body);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("category_not_granted", json.GetProperty("error").GetString());
    }

    [Fact]
    public async Task List_ReturnsActiveRuns()
    {
        using var factory = MakeFactory(new FastStubExecutor());
        var scopePath = WriteScopeFile(factory.OutputDir, "10.10.10.0/24\n");
        using var client = factory.CreateClient();

        var start = await client.PostAsJsonAsync("/api/runs",
            new { scope_path = scopePath, targets = new[] { "10.10.10.5" } });
        Assert.Equal(HttpStatusCode.Accepted, start.StatusCode);

        var listResp = await client.GetAsync("/api/runs");
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);
        var list = await listResp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(list.GetArrayLength() >= 1);
        Assert.Equal(1, list[0].GetProperty("target_count").GetInt32());
    }

    [Fact]
    public async Task Get_ReturnsSpecificRun()
    {
        using var factory = MakeFactory(new FastStubExecutor());
        var scopePath = WriteScopeFile(factory.OutputDir, "10.10.10.0/24\n");
        using var client = factory.CreateClient();

        var startResp = await client.PostAsJsonAsync("/api/runs",
            new { scope_path = scopePath, targets = new[] { "10.10.10.5" } });
        var started = await startResp.Content.ReadFromJsonAsync<JsonElement>();
        var runId = started.GetProperty("run_id").GetString();

        var getResp = await client.GetAsync($"/api/runs/{runId}");
        Assert.Equal(HttpStatusCode.OK, getResp.StatusCode);
        var rec = await getResp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(runId, rec.GetProperty("run_id").GetString());
        Assert.Equal(1, rec.GetProperty("target_count").GetInt32());
    }

    [Fact]
    public async Task Get_UnknownId_Returns404()
    {
        using var factory = MakeFactory(new FastStubExecutor());
        using var client = factory.CreateClient();

        var resp = await client.GetAsync($"/api/runs/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Delete_CancelsInFlightRun_ReturnsTriggeredCts()
    {
        var stub = new BlockingStubExecutor();
        using var factory = MakeFactory(stub);
        var scopePath = WriteScopeFile(factory.OutputDir, "10.10.10.0/24\n");
        using var client = factory.CreateClient();

        var startResp = await client.PostAsJsonAsync("/api/runs",
            new { scope_path = scopePath, targets = new[] { "10.10.10.5" } });
        var started = await startResp.Content.ReadFromJsonAsync<JsonElement>();
        var runId = started.GetProperty("run_id").GetString();

        // Wait for the executor to actually be running before we cancel.
        await stub.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var delResp = await client.DeleteAsync($"/api/runs/{runId}");
        Assert.Equal(HttpStatusCode.NoContent, delResp.StatusCode);

        // Give the cancellation handler a moment to propagate.
        for (int i = 0; i < 50 && !stub.Cancelled; i++)
            await Task.Delay(20);
        Assert.True(stub.Cancelled, "Executor never observed cancellation");
    }

    [Fact]
    public async Task Delete_AlreadyFinished_Returns404()
    {
        using var factory = MakeFactory(new FastStubExecutor());
        var scopePath = WriteScopeFile(factory.OutputDir, "10.10.10.0/24\n");
        using var client = factory.CreateClient();

        var startResp = await client.PostAsJsonAsync("/api/runs",
            new { scope_path = scopePath, targets = new[] { "10.10.10.5" } });
        var started = await startResp.Content.ReadFromJsonAsync<JsonElement>();
        var runId = started.GetProperty("run_id").GetString();

        // Poll until the run is marked completed.
        for (int i = 0; i < 100; i++)
        {
            var getResp = await client.GetAsync($"/api/runs/{runId}");
            var rec = await getResp.Content.ReadFromJsonAsync<JsonElement>();
            if (rec.GetProperty("status").GetString() == "completed") break;
            await Task.Delay(20);
        }

        var delResp = await client.DeleteAsync($"/api/runs/{runId}");
        Assert.Equal(HttpStatusCode.NotFound, delResp.StatusCode);
        var json = await delResp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("already_finished", json.GetProperty("error").GetString());
    }

    [Fact]
    public async Task LongPollEvents_BatchedByTimestamp()
    {
        using var factory = MakeFactory(new FastStubExecutor());
        var scopePath = WriteScopeFile(factory.OutputDir, "10.10.10.0/24\n");
        using var client = factory.CreateClient();

        var startResp = await client.PostAsJsonAsync("/api/runs",
            new { scope_path = scopePath, targets = new[] { "10.10.10.5" } });
        var started = await startResp.Content.ReadFromJsonAsync<JsonElement>();
        var runId = started.GetProperty("run_id").GetString();

        // Wait a moment for events to be recorded.
        JsonElement all = default;
        for (int i = 0; i < 100; i++)
        {
            var r = await client.GetAsync($"/api/runs/{runId}/events");
            all = await r.Content.ReadFromJsonAsync<JsonElement>();
            if (all.GetProperty("events").GetArrayLength() >= 4) break;
            await Task.Delay(20);
        }

        var events = all.GetProperty("events");
        Assert.True(events.GetArrayLength() >= 4);
        Assert.False(all.GetProperty("truncated").GetBoolean());

        // Use timestamp of first event as "since" → should trim it.
        var firstTs = events[0].GetProperty("timestamp").GetString();
        var sinceResp = await client.GetAsync(
            $"/api/runs/{runId}/events?since={Uri.EscapeDataString(firstTs!)}");
        Assert.Equal(HttpStatusCode.OK, sinceResp.StatusCode);
        var filtered = await sinceResp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(filtered.GetProperty("events").GetArrayLength()
                    < events.GetArrayLength());
    }

    [Fact]
    public async Task ScopePath_PathTraversal_Rejected()
    {
        // Allowed root is the factory's temp dir; submit an /etc path that
        // resolves outside it.
        using var factory = MakeFactory(new FastStubExecutor());
        // Re-wire with a tighter allowed-root = factory.OutputDir so we can
        // prove traversal is rejected even when the submitted path resolves
        // to an existing system file.
        using var trav = MakeFactory(new FastStubExecutor(), factory.OutputDir);
        using var client = trav.CreateClient();

        var body = new
        {
            scope_path = "../../../etc/passwd",
            targets = new[] { "10.10.10.5" },
        };
        var resp = await client.PostAsJsonAsync("/api/runs", body);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("scope_path_rejected", json.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Audit_NoPlaintextScopePath()
    {
        using var factory = MakeFactory(new FastStubExecutor());
        // Write a scope file whose *path* contains the canary literal, so we
        // can assert the plaintext never reaches audit.jsonl.
        var canaryDir = Path.Combine(factory.OutputDir, CanaryScopeName);
        var scopePath = WriteScopeFile(canaryDir, "10.10.10.0/24\n");
        using var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/api/runs",
            new { scope_path = scopePath, targets = new[] { "10.10.10.5" } });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        // Let the audit writer flush.
        await Task.Delay(100);

        var audit = File.ReadAllText(factory.AuditLogPath);
        Assert.DoesNotContain(CanaryScopeName, audit);
    }

    [Fact]
    public async Task Start_MalformedScopeFile_Returns400()
    {
        using var factory = MakeFactory(new FastStubExecutor());
        var scopePath = WriteScopeFile(factory.OutputDir, "not-an-ip\n");
        using var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/api/runs",
            new { scope_path = scopePath, targets = new[] { "10.10.10.5" } });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("scope_load_failed", json.GetProperty("error").GetString());
    }
}
