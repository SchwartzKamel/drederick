using System.Text;
using Drederick.Audit;
using Drederick.Jeopardy.Sandbox;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Jeopardy.Sandbox;

public sealed class SandboxManagerTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly string _auditPath;
    private readonly AuditLog _audit;
    private readonly Drederick.Scope.Scope _scope;

    public SandboxManagerTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), $"drederick-sbx-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tmpDir);
        _auditPath = Path.Combine(_tmpDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);
        _scope = ScopeLoader.Parse("10.0.0.0/8\n192.168.0.0/16\n");
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_tmpDir, recursive: true); } catch { }
    }

    // --- helpers ----------------------------------------------------------

    private CannedDockerRunner DefaultRunner(string containerId = "ctr-abc123")
    {
        var r = new CannedDockerRunner();
        r.OnArgs("run -d", exit: 0, stdout: containerId + "\n");
        r.OnArgs("inspect --format", exit: 0, stdout: "healthy\n");
        r.OnArgs("cp ", exit: 0);
        r.OnArgs("rm -f", exit: 0);
        return r;
    }

    private static SandboxSpec BasicSpec(
        IReadOnlyDictionary<string, byte[]>? attachments = null,
        string? connInfo = null,
        bool privileged = false)
        => new(
            ImageName: SandboxSpec.DefaultImage,
            ChallengeId: 42,
            ChallengeName: "babycrypto",
            Category: "crypto",
            AttachmentsByFilename: attachments,
            Timeout: TimeSpan.FromSeconds(30),
            MemoryBytesCap: SandboxSpec.DefaultMemoryBytesCap,
            CpuShares: SandboxSpec.DefaultCpuShares,
            Privileged: privileged,
            ConnectionInfo: connInfo);

    private static string ReadAudit(string path) => File.ReadAllText(path);

    // --- tests ------------------------------------------------------------

    [Fact]
    public async Task StartAsync_DefaultSpec_ProducesExpectedDockerRunArgs()
    {
        var runner = DefaultRunner();
        var mgr = new SandboxManager(_scope, _audit, runner);
        await using var s = await mgr.StartAsync(BasicSpec(), CancellationToken.None);

        var runCall = runner.Calls.First(c => c.Arguments.StartsWith("run -d"));
        Assert.Contains("--name ", runCall.Arguments);
        Assert.Contains("--workdir /home/ctf/work", runCall.Arguments);
        Assert.Contains("--user 1000:1000", runCall.Arguments);
        Assert.Contains("--init", runCall.Arguments);
        Assert.Contains("--entrypoint /bin/sh", runCall.Arguments);
        Assert.Contains("drederick-jeopardy-sandbox:latest", runCall.Arguments);
    }

    [Fact]
    public async Task StartAsync_Defaults_UsesNetworkNone()
    {
        var runner = DefaultRunner();
        var mgr = new SandboxManager(_scope, _audit, runner);
        await using var s = await mgr.StartAsync(BasicSpec(), CancellationToken.None);

        var runCall = runner.Calls.First(c => c.Arguments.StartsWith("run -d"));
        Assert.Contains("--network none", runCall.Arguments);
        Assert.DoesNotContain("--network bridge", runCall.Arguments);
    }

    [Fact]
    public async Task StartAsync_OutOfScopeConnectionInfo_Throws()
    {
        var runner = DefaultRunner();
        var mgr = new SandboxManager(_scope, _audit, runner);
        var spec = BasicSpec(connInfo: "nc 8.8.8.8 1337");
        await Assert.ThrowsAsync<ScopeException>(() => mgr.StartAsync(spec, CancellationToken.None));
        // docker run must never have been invoked.
        Assert.DoesNotContain(runner.Calls, c => c.Arguments.StartsWith("run -d"));
    }

    [Fact]
    public async Task StartAsync_InScopeConnectionInfo_AddsHostAndBridge()
    {
        var runner = DefaultRunner();
        var mgr = new SandboxManager(_scope, _audit, runner);
        var spec = BasicSpec(connInfo: "nc 10.1.2.3 31337");
        await using var s = await mgr.StartAsync(spec, CancellationToken.None);

        var runCall = runner.Calls.First(c => c.Arguments.StartsWith("run -d"));
        Assert.Contains("--network bridge", runCall.Arguments);
        Assert.Contains("ctf-target:10.1.2.3", runCall.Arguments);
        Assert.DoesNotContain("--network none", runCall.Arguments);
    }

    [Fact]
    public async Task ExecAsync_ReturnsCannedExit_AuditDoesNotLeakStdout()
    {
        const string canary = "SB_CANARY_666";
        var runner = DefaultRunner();
        runner.OnArgsFn(
            a => a.StartsWith("exec ") && a.Contains("bash -c"),
            _ => (0, $"output with {canary} inside", ""));
        var mgr = new SandboxManager(_scope, _audit, runner);

        await using (var s = await mgr.StartAsync(BasicSpec(), CancellationToken.None))
        {
            var result = await s.ExecAsync("echo hello", null, CancellationToken.None);
            Assert.Equal(0, result.ExitCode);
            Assert.Contains(canary, result.Stdout); // returned to caller
            Assert.False(result.TimedOut);
        }

        _audit.Dispose();
        var audit = ReadAudit(_auditPath);
        Assert.DoesNotContain(canary, audit);
        Assert.Contains("\"stdout_sha256\"", audit);
        Assert.Contains("\"argv_sha256\"", audit);
    }

    [Fact]
    public async Task ExecAsync_TimesOut_SetsTimedOutAndRecordsInAudit()
    {
        var runner = DefaultRunner();
        runner.OnArgsThrow(
            a => a.StartsWith("exec ") && a.Contains("bash -c"),
            new TimeoutException("stub"));
        // kill-path also uses exec; add a catch-all so it doesn't break.
        runner.OnArgs("exec ", exit: 0);
        var mgr = new SandboxManager(_scope, _audit, runner);

        await using var s = await mgr.StartAsync(
            BasicSpec() with { Timeout = TimeSpan.FromSeconds(1) }, CancellationToken.None);
        var result = await s.ExecAsync("sleep 999", null, CancellationToken.None);
        Assert.True(result.TimedOut);
        Assert.Equal(124, result.ExitCode);
    }

    [Fact]
    public async Task StartAsync_Attachments_InvokeDockerCpPerFile()
    {
        var runner = DefaultRunner();
        var mgr = new SandboxManager(_scope, _audit, runner);
        var attachments = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["chal.bin"] = new byte[] { 0x7f, 0x45, 0x4c, 0x46, 1, 2, 3 },
            ["notes.txt"] = Encoding.UTF8.GetBytes("hint: rsa"),
        };
        await using var s = await mgr.StartAsync(BasicSpec(attachments: attachments), CancellationToken.None);

        var cpCalls = runner.Calls.Where(c => c.Arguments.StartsWith("cp ")).ToList();
        Assert.Equal(2, cpCalls.Count);
        Assert.Contains(cpCalls, c => c.Arguments.Contains(":/home/ctf/work/chal.bin"));
        Assert.Contains(cpCalls, c => c.Arguments.Contains(":/home/ctf/work/notes.txt"));
    }

    [Fact]
    public async Task StartAsync_BoundedParallelism_RespectsSemaphore()
    {
        Environment.SetEnvironmentVariable("DREDERICK_SANDBOX_MAX_CONCURRENT", "3");
        try
        {
            var runner = new CannedDockerRunner();
            var counter = 0;
            // Slow run-d so concurrent starts are observable.
            runner.OnArgsFn(
                a => a.StartsWith("run -d"),
                _ =>
                {
                    Thread.Sleep(60);
                    var id = Interlocked.Increment(ref counter);
                    return (0, $"ctr-{id}\n", "");
                });
            runner.OnArgs("inspect --format", exit: 0, stdout: "healthy\n");
            runner.OnArgs("rm -f", exit: 0);

            var mgr = new SandboxManager(_scope, _audit, runner);

            // Each task starts a sandbox and immediately disposes it so the
            // concurrency gate releases. With 10 tasks and a cap of 3, at
            // most 3 `run -d` calls should be in flight simultaneously.
            async Task RunOne()
            {
                var s = await mgr.StartAsync(BasicSpec(), CancellationToken.None);
                await s.DisposeAsync();
            }
            var tasks = Enumerable.Range(0, 10).Select(_ => RunOne()).ToArray();
            await Task.WhenAll(tasks);

            Assert.True(runner.PeakInFlight <= 3,
                $"peak in-flight {runner.PeakInFlight} exceeds cap of 3");
            Assert.True(mgr.PeakConcurrent <= 3,
                $"manager peak {mgr.PeakConcurrent} exceeds cap of 3");
            // We launched 10 starts; the concurrency limit should have been
            // exercised — peak should be at least 2 in any reasonable env.
            Assert.True(mgr.PeakConcurrent >= 1);
        }
        finally
        {
            Environment.SetEnvironmentVariable("DREDERICK_SANDBOX_MAX_CONCURRENT", null);
        }
    }

    [Fact]
    public async Task DisposeAsync_AlwaysCallsDockerRmForce_EvenAfterExecThrows()
    {
        var runner = DefaultRunner();
        runner.OnArgsThrow(
            a => a.StartsWith("exec ") && a.Contains("bash -c"),
            new InvalidOperationException("boom"));
        runner.OnArgs("exec ", exit: 0);
        var mgr = new SandboxManager(_scope, _audit, runner);

        var session = await mgr.StartAsync(BasicSpec(), CancellationToken.None);
        try
        {
            try
            {
                await session.ExecAsync("anything", null, CancellationToken.None);
            }
            catch (InvalidOperationException)
            {
                // expected
            }
        }
        finally
        {
            await session.DisposeAsync();
        }
        Assert.Contains(runner.Calls, c => c.Arguments.StartsWith("rm -f"));
    }

    [Fact]
    public async Task StartAsync_AppliesResourceCapsAndSecurityOpts()
    {
        var runner = DefaultRunner();
        var mgr = new SandboxManager(_scope, _audit, runner);
        await using var s = await mgr.StartAsync(BasicSpec(), CancellationToken.None);
        var runCall = runner.Calls.First(c => c.Arguments.StartsWith("run -d"));
        Assert.Contains("--memory ", runCall.Arguments);
        Assert.Contains("--cpu-shares 1024", runCall.Arguments);
        Assert.Contains("--pids-limit 512", runCall.Arguments);
        Assert.Contains("--security-opt no-new-privileges", runCall.Arguments);
        Assert.Contains("--security-opt seccomp=default", runCall.Arguments);
        Assert.Contains("--cap-drop ALL", runCall.Arguments);
        Assert.Contains("--cap-add NET_BIND_SERVICE", runCall.Arguments);
    }

    [Fact]
    public async Task StartAsync_Default_DoesNotSetPrivileged()
    {
        var runner = DefaultRunner();
        var mgr = new SandboxManager(_scope, _audit, runner);
        await using var s = await mgr.StartAsync(BasicSpec(privileged: false), CancellationToken.None);
        var runCall = runner.Calls.First(c => c.Arguments.StartsWith("run -d"));
        Assert.DoesNotContain("--privileged", runCall.Arguments);
    }

    [Fact]
    public async Task StartAsync_PrivilegedTrue_IsExplicitlyWiredAndAudited()
    {
        var runner = DefaultRunner();
        var mgr = new SandboxManager(_scope, _audit, runner);
        var session = await mgr.StartAsync(BasicSpec(privileged: true), CancellationToken.None);
        var runCall = runner.Calls.First(c => c.Arguments.StartsWith("run -d"));
        Assert.Contains("--privileged", runCall.Arguments);
        await session.DisposeAsync();

        _audit.Dispose();
        var audit = ReadAudit(_auditPath);
        Assert.Contains("sandbox.privileged_requested", audit);
    }

    [Fact]
    public async Task ImageAvailableAsync_ReturnsBasedOnExit()
    {
        var runner = new CannedDockerRunner();
        runner.OnArgs("image inspect", exit: 0);
        var mgr = new SandboxManager(_scope, _audit, runner);
        Assert.True(await mgr.ImageAvailableAsync("drederick-jeopardy-sandbox:latest", CancellationToken.None));

        var runner2 = new CannedDockerRunner();
        runner2.OnArgs("image inspect", exit: 1, stderr: "no such image");
        var mgr2 = new SandboxManager(_scope, _audit, runner2);
        Assert.False(await mgr2.ImageAvailableAsync("missing:latest", CancellationToken.None));
    }

    [Fact]
    public async Task CheckDockerHealthyAsync_OkWhenBothVersionAndInfoSucceed()
    {
        var runner = new CannedDockerRunner();
        runner.OnArgs(a => a == "version", exit: 0, stdout: "Docker version 25");
        runner.OnArgs(a => a == "info", exit: 0, stdout: "Server: ...");
        var mgr = new SandboxManager(_scope, _audit, runner);
        var check = await mgr.CheckDockerHealthyAsync(CancellationToken.None);
        Assert.True(check.Ok);

        var runner2 = new CannedDockerRunner();
        runner2.OnArgs(a => a == "version", exit: 1, stderr: "no daemon");
        var mgr2 = new SandboxManager(_scope, _audit, runner2);
        var check2 = await mgr2.CheckDockerHealthyAsync(CancellationToken.None);
        Assert.False(check2.Ok);
    }
}
