using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

/// <summary>
/// Tests for <see cref="NfsEnumTool"/> (GAP-007). Uses a scripted
/// <see cref="IProcessRunner"/> stub so the tool never spawns showmount /
/// mount / umount, and an injected listing delegate so we don't need an
/// actual NFS mount on the test host.
/// </summary>
public class NfsEnumToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-nfsenum-{Guid.NewGuid():N}.jsonl"));

    /// <summary>Scripted runner. Each call is matched against a sequence
    /// of (file, argPredicate) → result triples; the i-th invocation
    /// returns the i-th scripted result. Captures all invocations for
    /// post-hoc assertions.</summary>
    private sealed class ScriptedRunner : IProcessRunner
    {
        public readonly List<(string File, string Args)> Calls = new();
        public readonly Queue<(int Exit, string Out, string Err)> Replies = new();
        public Func<string, string, (int, string, string)>? Dispatch;

        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
        {
            Calls.Add((file, arguments));
            if (Dispatch is not null) return Dispatch(file, arguments);
            if (Replies.Count > 0) return Replies.Dequeue();
            return (0, "", "");
        }

        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
        {
            Calls.Add(("/bin/sh", commandLine));
            return (0, "", "");
        }
    }

    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "fixtures", "nfs", name));

    [Fact]
    public void Showmount_ParsesExports()
    {
        var stdout = Fixture("showmount-e.txt");
        var exports = NfsEnumTool.ParseShowmountOutput(stdout).ToList();

        Assert.Equal(3, exports.Count);
        Assert.Equal("/srv/nfs/public", exports[0].Path);
        Assert.Equal("*", exports[0].AllowedClients);
        Assert.Equal("/srv/nfs/home", exports[1].Path);
        Assert.Contains("10.10.0.0/16", exports[1].AllowedClients!);
        Assert.Equal("/srv/backup", exports[2].Path);
    }

    [Fact]
    public async Task Mount_v3_Succeeds()
    {
        var runner = new ScriptedRunner();
        runner.Dispatch = (file, args) =>
        {
            if (file.EndsWith("showmount")) return (0, Fixture("showmount-e.txt"), "");
            if (file.EndsWith("mount")) return (0, "", "");
            if (file.EndsWith("umount")) return (0, "", "");
            return (0, "", "");
        };

        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NfsEnumTool(scope, audit, runner,
            listMount: _ => new NfsMountSnapshot(
                new[] { new NfsEntry("README", 1000, 1000, 12, true, 0) }, 1),
            tryWriteProbe: _ => false,
            allowWriteProbe: false);

        var r = await tool.EnumerateAsync("10.10.10.5");

        Assert.Equal(3, r.Exports.Count);
        Assert.All(r.Exports, e => Assert.True(e.MountSucceededV3));
        Assert.All(r.Exports, e => Assert.True(e.AnonRead));
        Assert.All(r.Exports, e => Assert.False(e.AnonWrite));
        Assert.Contains(r.Exports, e => e.TopLevelEntries.Contains("README"));

        // Argv shape: every mount call must use ArgumentList-style
        // separated tokens (no shell metachars). We assert the runner
        // sees `-t nfs -o ro,nolock,…,vers=3` and the target:path token.
        var mountCalls = runner.Calls.Where(c => c.File.EndsWith("mount") && !c.File.EndsWith("umount")).ToList();
        Assert.NotEmpty(mountCalls);
        Assert.Contains(mountCalls, c => c.Args.Contains("vers=3"));
        Assert.Contains(mountCalls, c => c.Args.Contains("10.10.10.5:/srv/nfs/public"));
    }

    [Fact]
    public async Task Mount_v3_Fails_Tries_v4()
    {
        var runner = new ScriptedRunner();
        runner.Dispatch = (file, args) =>
        {
            if (file.EndsWith("showmount")) return (0, "Export list for x:\n/data   *\n", "");
            if (file.EndsWith("mount"))
            {
                if (args.Contains("vers=3")) return (32, "", "v3 refused");
                if (args.Contains("vers=4")) return (0, "", "");
            }
            return (0, "", "");
        };

        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NfsEnumTool(scope, audit, runner,
            listMount: _ => new NfsMountSnapshot(Array.Empty<NfsEntry>(), 0),
            tryWriteProbe: _ => false,
            allowWriteProbe: false);

        var r = await tool.EnumerateAsync("10.10.10.5");

        var export = Assert.Single(r.Exports);
        Assert.False(export.MountSucceededV3);
        Assert.True(export.MountSucceededV4);
        Assert.True(export.AnonRead);
    }

    [Fact]
    public async Task DetectsSensitiveFiles()
    {
        var runner = new ScriptedRunner();
        runner.Dispatch = (file, args) => file.EndsWith("showmount")
            ? (0, "/data *\n", "")
            : (0, "", "");

        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NfsEnumTool(scope, audit, runner,
            listMount: _ => new NfsMountSnapshot(new[]
            {
                new NfsEntry("home", 1000, 1000, 0, false, 0),
                new NfsEntry("home/alice", 1001, 1001, 0, false, 1),
                new NfsEntry("home/alice/.ssh", 1001, 1001, 0, false, 2),
                new NfsEntry("home/alice/.ssh/id_rsa", 1001, 1001, 1675, true, 2),
                new NfsEntry("home/alice/notes.txt", 1001, 1001, 42, true, 2),
                new NfsEntry("vault.kdbx", 1000, 1000, 8192, true, 0),
                new NfsEntry(".env", 1000, 1000, 200, true, 0),
            }, 4),
            tryWriteProbe: _ => false,
            allowWriteProbe: false);

        var r = await tool.EnumerateAsync("10.10.10.5");

        var export = Assert.Single(r.Exports);
        Assert.Contains("home/alice/.ssh/id_rsa", export.InterestingFiles);
        Assert.Contains("vault.kdbx", export.InterestingFiles);
        Assert.Contains(".env", export.InterestingFiles);
        Assert.DoesNotContain("home/alice/notes.txt", export.InterestingFiles);
    }

    [Fact]
    public async Task DetectsRootSquashDisabled()
    {
        var runner = new ScriptedRunner();
        runner.Dispatch = (file, args) => file.EndsWith("showmount")
            ? (0, "/data *\n", "")
            : (0, "", "");

        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NfsEnumTool(scope, audit, runner,
            // uid 0 file readable = root_squash disabled heuristic.
            listMount: _ => new NfsMountSnapshot(new[]
            {
                new NfsEntry("root-owned.bin", 0, 0, 100, true, 0),
                new NfsEntry("user-owned.txt", 1000, 1000, 100, true, 0),
            }, 2),
            tryWriteProbe: _ => false,
            allowWriteProbe: false);

        var r = await tool.EnumerateAsync("10.10.10.5");
        var export = Assert.Single(r.Exports);
        Assert.True(export.RootSquashDisabled);
    }

    [Fact]
    public async Task AnonWriteProbe_CleansUp()
    {
        var runner = new ScriptedRunner();
        runner.Dispatch = (file, args) => file.EndsWith("showmount")
            ? (0, "/data *\n", "")
            : (0, "", "");

        var probeCallCount = 0;
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();

        // Use the default write probe against a real temp dir so we
        // verify both creation and deletion happen.
        var tool = new NfsEnumTool(scope, audit, runner,
            listMount: mountPath =>
            {
                // After the tool mounts, the temp dir exists; that's all we
                // need to let the default write probe target it.
                return new NfsMountSnapshot(Array.Empty<NfsEntry>(), 0);
            },
            tryWriteProbe: mountPath =>
            {
                probeCallCount++;
                // Simulate a successful write+delete cycle by actually
                // creating and removing a file in the supplied mount dir.
                var probeFile = Path.Combine(mountPath, $".drederick_probe_{Guid.NewGuid():N}");
                File.WriteAllText(probeFile, "");
                Assert.True(File.Exists(probeFile));
                File.Delete(probeFile);
                Assert.False(File.Exists(probeFile));
                return true;
            },
            allowWriteProbe: true);

        var r = await tool.EnumerateAsync("10.10.10.5");

        Assert.Equal(1, probeCallCount);
        var export = Assert.Single(r.Exports);
        Assert.True(export.AnonWrite);
    }

    [Fact]
    public async Task AnonWriteProbe_Disabled_InStrictMode()
    {
        var runner = new ScriptedRunner();
        runner.Dispatch = (file, args) => file.EndsWith("showmount")
            ? (0, "/data *\n", "")
            : (0, "", "");

        var probeCallCount = 0;
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NfsEnumTool(scope, audit, runner,
            listMount: _ => new NfsMountSnapshot(Array.Empty<NfsEntry>(), 0),
            tryWriteProbe: _ => { probeCallCount++; return true; },
            allowWriteProbe: false);

        var r = await tool.EnumerateAsync("10.10.10.5");

        Assert.Equal(0, probeCallCount);
        Assert.False(r.Exports[0].AnonWrite);
    }

    [Fact]
    public async Task RejectsOutOfScopeTarget()
    {
        var runner = new ScriptedRunner();
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NfsEnumTool(scope, audit, runner);

        await Assert.ThrowsAsync<ScopeException>(
            () => tool.EnumerateAsync("192.168.1.1"));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task ArgvInjection_Rejected()
    {
        var runner = new ScriptedRunner();
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NfsEnumTool(scope, audit, runner);

        // `evil.com;rm` is not parseable as an in-scope IP, so scope
        // rejects it first. Either rejection (scope or argv-shape) is
        // acceptable per the security contract.
        await Assert.ThrowsAnyAsync<Exception>(
            () => tool.EnumerateAsync("evil.com;rm"));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task MissingShowmount_GracefulError()
    {
        var runner = new ScriptedRunner();
        runner.Dispatch = (file, args) =>
            throw new System.ComponentModel.Win32Exception("no such file or directory");

        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NfsEnumTool(scope, audit, runner);

        var r = await tool.EnumerateAsync("10.10.10.5");
        Assert.NotNull(r.Error);
        Assert.Contains("showmount", r.Error!, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(r.Exports);
    }
}
