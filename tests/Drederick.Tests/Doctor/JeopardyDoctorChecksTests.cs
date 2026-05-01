using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Doctor;

public class JeopardyDoctorChecksTests
{
    // --- helpers ---------------------------------------------------------

    private static string NewScratch()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "jeopardy-doctor-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private sealed class StubEnv : IEnvReader
    {
        public Dictionary<string, string?> Map { get; } = new();
        public string? Get(string name) => Map.TryGetValue(name, out var v) ? v : null;
    }

    private sealed class StubHttp : IHttpStatusProbe
    {
        public List<(string Url, IReadOnlyDictionary<string, string>? Headers)> Calls { get; } = new();
        public int NextStatus { get; set; } = 200;
        public Task<int> GetStatusAsync(string url, IReadOnlyDictionary<string, string>? headers, CancellationToken ct)
        {
            Calls.Add((url, headers));
            return Task.FromResult(NextStatus);
        }
    }

    private sealed class StubDisk : IDiskFreeReader
    {
        public long Bytes { get; set; } = long.MaxValue;
        public long AvailableBytes(string path) => Bytes;
    }

    private static (AuditLog, string) NewAudit()
    {
        var dir = NewScratch();
        var path = Path.Combine(dir, "audit.jsonl");
        return (new AuditLog(path), dir);
    }

    private static JeopardyDoctorDeps Deps(
        RecordingProcessRunner runner,
        StubEnv? env = null,
        StubHttp? http = null,
        StubDisk? disk = null,
        Scope.Scope? scope = null,
        bool allowCopilotHost = true)
    {
        var (audit, _) = NewAudit();
        return new JeopardyDoctorDeps(
            Audit: audit,
            Runner: runner,
            Env: env ?? new StubEnv(),
            Http: http ?? new StubHttp(),
            DiskFree: disk ?? new StubDisk { Bytes = long.MaxValue },
            Scope: scope,
            AllowCopilotHost: allowCopilotHost);
    }

    private static Task<DoctorCheckResult> Run(IDoctorCheck c, bool install = false, bool yes = true)
        => c.RunAsync(install, yes, new StringReader(""), new StringWriter(), CancellationToken.None);

    // --- 1. docker installed: fail on non-zero --------------------------

    [Fact]
    public async Task DockerInstalled_FailsWhenVersionExitsNonZero()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "docker" && a == "version", exit: 127, stderr: "command not found");
        var check = new DockerInstalledCheck(Deps(runner));
        var r = await Run(check);
        Assert.Equal("jeopardy.docker.installed", r.Id);
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("apt install docker.io", r.FixCommand);
    }

    // --- 2. docker installed: pass on zero ------------------------------

    [Fact]
    public async Task DockerInstalled_PassesWhenVersionExitsZero()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "docker" && a == "version", exit: 0, stdout: "Docker version 24.0.7, build afdd53b\n");
        var r = await Run(new DockerInstalledCheck(Deps(runner)));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.Contains("24.0.7", r.Detail);
    }

    // --- 3. sandbox image: fail + fix hint when inspect non-zero --------

    [Fact]
    public async Task SandboxImage_FailsWhenInspectNonZero_EmitsBuildCommand()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "docker" && a.Contains("image inspect"), exit: 1, stderr: "no such image");
        var r = await Run(new SandboxImageCheck(Deps(runner)), install: false);
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("docker build", r.FixCommand);
        Assert.Contains("Dockerfile.jeopardy-sandbox", r.FixCommand);
        Assert.Contains("drederick-jeopardy-sandbox:latest", r.FixCommand);
    }

    // --- 4. llm.token: any of three env vars passes ---------------------

    [Theory]
    [InlineData("COPILOT_TOKEN")]
    [InlineData("GH_TOKEN")]
    [InlineData("GITHUB_TOKEN")]
    public async Task LlmToken_PassesWhenAnyEnvVarIsSet(string name)
    {
        var runner = new RecordingProcessRunner();
        var env = new StubEnv();
        env.Map[name] = "sekret";
        var r = await Run(new LlmTokenCheck(Deps(runner, env: env)));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.Contains(name, r.Detail);
    }

    // --- 5. llm.token: COPILOT_TOKEN wins over GH_TOKEN -----------------

    [Fact]
    public async Task LlmToken_CopilotTokenPreferredOverGhToken()
    {
        var env = new StubEnv();
        env.Map["COPILOT_TOKEN"] = "copilot-wins";
        env.Map["GH_TOKEN"] = "gh-loses";
        env.Map["GITHUB_TOKEN"] = "github-loses";
        var r = await Run(new LlmTokenCheck(Deps(new RecordingProcessRunner(), env: env)));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.Contains("COPILOT_TOKEN", r.Detail);
        Assert.DoesNotContain("GH_TOKEN", r.Detail);
        Assert.DoesNotContain("GITHUB_TOKEN", r.Detail);
    }

    // --- 6. llm.reachable: mocked 200 passes ----------------------------

    [Fact]
    public async Task LlmReachable_PassesOn200()
    {
        var env = new StubEnv();
        env.Map["COPILOT_TOKEN"] = "t";
        var http = new StubHttp { NextStatus = 200 };
        var r = await Run(new LlmReachableCheck(Deps(new RecordingProcessRunner(), env: env, http: http, allowCopilotHost: true)));
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.Single(http.Calls);
        Assert.Contains("api.githubcopilot.com", http.Calls[0].Url);
        Assert.NotNull(http.Calls[0].Headers);
        Assert.True(http.Calls[0].Headers!.ContainsKey("Authorization"));
        Assert.Equal("drederick-cli", http.Calls[0].Headers!["Copilot-Integration-Id"]);
    }

    // --- 7. ctfd.configured: warns (not fails) when unset ---------------

    [Fact]
    public async Task CtfdConfigured_WarnsWhenUnset()
    {
        var r = await Run(new CtfdConfiguredCheck(Deps(new RecordingProcessRunner(), env: new StubEnv())));
        Assert.Equal(DoctorCheckStatus.Warn, r.Status);
        Assert.Contains("CTFD_URL", r.Detail);
    }

    // --- 8. scope.file: suggests drederick scope add when CTFd not in scope

    [Fact]
    public async Task ScopeFile_EmitsScopeAddSuggestionWhenCtfdHostNotInScope()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        var env = new StubEnv();
        // Use a literal IP so we don't hit DNS in unit tests.
        env.Map["CTFD_URL"] = "http://192.168.99.50:8000";
        var r = await Run(new ScopeFileCheck(Deps(new RecordingProcessRunner(), env: env, scope: scope)));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("drederick scope add", r.FixCommand ?? "");
        Assert.Contains("192.168.99.50", r.FixCommand ?? "");
    }

    // --- 9. --yes --install runs docker build via RunShell --------------

    [Fact]
    public async Task SandboxImage_YesInstallRunsDockerBuildWithoutPrompt()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "docker" && a.Contains("image inspect"), exit: 1, stderr: "no such image")
            .OnShell(c => c.StartsWith("docker build"), exit: 0, stdout: "Successfully built");
        var check = new SandboxImageCheck(Deps(runner));
        var r = await check.RunAsync(install: true, assumeYes: true, new StringReader(""), new StringWriter(), CancellationToken.None);
        Assert.Equal(DoctorCheckStatus.Pass, r.Status);
        Assert.True(r.FixApplied);
        Assert.Contains(runner.Calls, c => c.Kind == "shell" && c.Arguments.StartsWith("docker build"));
    }

    // --- 10. CTFd out-of-scope: scope exception surfaced, not crashed ---

    [Fact]
    public async Task CtfdReachable_OutOfScopeHostSurfacedAsFailure_NotCrash()
    {
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        var env = new StubEnv();
        env.Map["CTFD_URL"] = "http://192.168.77.50:8000";
        env.Map["CTFD_TOKEN"] = "t";
        var http = new StubHttp { NextStatus = 200 };
        var r = await Run(new CtfdReachableCheck(Deps(new RecordingProcessRunner(), env: env, http: http, scope: scope)));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        // http probe must NOT have been called — scope gate rejected first.
        Assert.Empty(http.Calls);
        Assert.Contains("scope", r.Detail.ToLowerInvariant());
    }

    // --- 11. Bonus: daemon check fix hint is non-sudo-executing ---------

    [Fact]
    public async Task DockerDaemon_FailHintMentionsManualSudo()
    {
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "docker" && a == "info", exit: 1, stderr: "Cannot connect to the Docker daemon");
        var r = await Run(new DockerDaemonCheck(Deps(runner)));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("systemctl start docker", r.FixCommand);
        Assert.Contains("usermod -aG docker", r.FixCommand);
    }

    // --- 12. disk.space: fails when below threshold --------------------

    [Fact]
    public async Task DiskSpace_FailsBelowThreshold()
    {
        var disk = new StubDisk { Bytes = 1L * 1024 * 1024 * 1024 }; // 1 GiB
        var r = await Run(new DiskSpaceCheck(Deps(new RecordingProcessRunner(), disk: disk)));
        Assert.Equal(DoctorCheckStatus.Fail, r.Status);
        Assert.Contains("10", r.Detail);
    }

    // --- 13. RunAllAsync groups results and never short-circuits -------

    [Fact]
    public async Task RunAllAsync_ContinuesPastFailures()
    {
        // Runner: docker version fails. Other checks should still run.
        var runner = new RecordingProcessRunner()
            .OnRun((f, a) => f == "docker", exit: 127, stderr: "nope");
        var env = new StubEnv();
        env.Map["COPILOT_TOKEN"] = "t";
        var http = new StubHttp { NextStatus = 200 };
        var deps = Deps(runner, env: env, http: http);
        var results = await JeopardyDoctorChecks.RunAllAsync(
            deps, install: false, assumeYes: true, new StringReader(""), new StringWriter(),
            CancellationToken.None);
        Assert.Equal(10, results.Count);
        // docker-related checks fail
        Assert.Equal(DoctorCheckStatus.Fail, results[0].Status); // docker.installed
        // llm.token still passes
        Assert.Equal(DoctorCheckStatus.Pass, results[4].Status);
    }
}
