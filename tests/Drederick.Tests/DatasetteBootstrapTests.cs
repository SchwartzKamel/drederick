using Drederick.Audit;
using Drederick.Bundling;
using Drederick.Doctor;
using Xunit;

namespace Drederick.Tests;

public class DatasetteBootstrapTests
{
    private static string NewScratch()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "bootstrap-scratch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    // Mutable locator so install handlers can register post-install binaries.
    private sealed class MutableLocator : IToolLocator
    {
        public Dictionary<string, string> Map { get; } = new();
        public string? Which(string name) => Map.TryGetValue(name, out var p) ? p : null;
    }

    private static string MakeStubBinary(string dir, string name)
    {
        Directory.CreateDirectory(dir);
        var p = Path.Combine(dir, name);
        File.WriteAllText(p, "#!/bin/sh\necho stub $@\n");
#pragma warning disable CA1416
        File.SetUnixFileMode(p, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
#pragma warning restore CA1416
        return p;
    }

    private static AuditLog NewAudit(string scratch)
        => new(Path.Combine(scratch, "audit.jsonl"));

    // -----------------------------------------------------------------------

    [Fact]
    public async Task ExplicitPath_IsHonored_WhenFileExists()
    {
        var scratch = NewScratch();
        var explicitBin = MakeStubBinary(scratch, "datasette");
        using var audit = NewAudit(scratch);
        var loc = new MutableLocator();
        var runner = new RecordingProcessRunner();

        var opts = new BootstrapOptions(explicitBin, AutoInstall: false, AssumeYes: true,
            CacheDir: Path.Combine(scratch, "cache"));
        var resolved = await DatasetteBootstrap.EnsureAsync(
            opts, audit, CancellationToken.None, runner, loc,
            stdin: new StringReader(""), stdout: new StringWriter(), stdinIsTty: false);

        Assert.Equal(explicitBin, resolved);
        Assert.Empty(runner.Calls); // no subprocesses needed
    }

    [Fact]
    public async Task ExplicitPath_Missing_Throws()
    {
        var scratch = NewScratch();
        using var audit = NewAudit(scratch);
        var opts = new BootstrapOptions(
            ExplicitPath: Path.Combine(scratch, "nope"),
            AutoInstall: false, AssumeYes: true,
            CacheDir: Path.Combine(scratch, "cache"));
        await Assert.ThrowsAsync<DatasetteBootstrapException>(() =>
            DatasetteBootstrap.EnsureAsync(opts, audit, CancellationToken.None,
                new RecordingProcessRunner(), new MutableLocator(),
                new StringReader(""), new StringWriter(), stdinIsTty: false));
    }

    [Fact]
    public async Task PathBinary_IsPreferred_OverCachedVenv()
    {
        var scratch = NewScratch();
        // PATH has datasette.
        var pathBin = MakeStubBinary(Path.Combine(scratch, "path"), "datasette");
        // A cached venv also exists — must NOT be chosen over PATH.
        var cache = Path.Combine(scratch, "cache");
        var venvBin = Path.Combine(cache, "venv", "datasette", "bin");
        MakeStubBinary(venvBin, "datasette");

        var loc = new MutableLocator { Map = { ["datasette"] = pathBin } };
        using var audit = NewAudit(scratch);

        var opts = new BootstrapOptions(null, AutoInstall: false, AssumeYes: true, CacheDir: cache);
        var resolved = await DatasetteBootstrap.EnsureAsync(
            opts, audit, CancellationToken.None,
            new RecordingProcessRunner(), loc,
            new StringReader(""), new StringWriter(), stdinIsTty: false);

        Assert.Equal(pathBin, resolved);
    }

    [Fact]
    public async Task CachedVenvBinary_IsPreferred_OverInstall()
    {
        var scratch = NewScratch();
        var cache = Path.Combine(scratch, "cache");
        var venvBin = Path.Combine(cache, "venv", "datasette", "bin");
        var cached = MakeStubBinary(venvBin, "datasette");
        var loc = new MutableLocator(); // no PATH datasette, no uv, no pipx
        var runner = new RecordingProcessRunner();
        using var audit = NewAudit(scratch);

        var opts = new BootstrapOptions(null, AutoInstall: true, AssumeYes: true, CacheDir: cache);
        var resolved = await DatasetteBootstrap.EnsureAsync(
            opts, audit, CancellationToken.None, runner, loc,
            new StringReader(""), new StringWriter(), stdinIsTty: false);

        Assert.Equal(cached, resolved);
        Assert.Empty(runner.Calls); // cache hit — no install work
    }

    [Fact]
    public async Task Install_ViaUv_WhenUvOnPath()
    {
        var scratch = NewScratch();
        var cache = Path.Combine(scratch, "cache");
        var fakeHome = Path.Combine(scratch, "home");
        var localBin = Path.Combine(fakeHome, ".local", "bin");
        Directory.CreateDirectory(localBin);
        Environment.SetEnvironmentVariable("HOME", fakeHome);

        var loc = new MutableLocator { Map = { ["uv"] = "/usr/bin/uv" } };
        var runner = new RecordingProcessRunner();
        runner.OnRun((f, a) => f == "python3" && a == "--version", 0, "Python 3.11.2\n", "");
        // uv install side-effect: drop binary where ~/.local/bin is and register on locator.
        runner.OnRun(
            (f, a) => f == "uv" && a.Contains("tool install datasette"),
            () =>
            {
                MakeStubBinary(localBin, "datasette");
                loc.Map["datasette"] = Path.Combine(localBin, "datasette");
                return (0, "", "");
            });

        using var audit = NewAudit(scratch);
        var opts = new BootstrapOptions(null, AutoInstall: true, AssumeYes: true, CacheDir: cache);
        var resolved = await DatasetteBootstrap.EnsureAsync(
            opts, audit, CancellationToken.None, runner, loc,
            new StringReader(""), new StringWriter(), stdinIsTty: false);

        Assert.Equal(Path.Combine(localBin, "datasette"), resolved);
        Assert.Contains(runner.Calls, c => c.FileOrCmd == "uv" && c.Arguments.Contains("tool install datasette"));
        // Pointer file cached for next run.
        Assert.True(File.Exists(Path.Combine(cache, "bin", "datasette.path")));
    }

    [Fact]
    public async Task Install_ViaPipx_WhenPipxOnPathAndNoUv()
    {
        var scratch = NewScratch();
        var cache = Path.Combine(scratch, "cache");
        var fakeHome = Path.Combine(scratch, "home");
        var localBin = Path.Combine(fakeHome, ".local", "bin");
        Directory.CreateDirectory(localBin);
        Environment.SetEnvironmentVariable("HOME", fakeHome);

        var loc = new MutableLocator { Map = { ["pipx"] = "/usr/bin/pipx" } }; // no uv
        var runner = new RecordingProcessRunner();
        runner.OnRun((f, a) => f == "python3" && a == "--version", 0, "Python 3.10.0\n", "");
        runner.OnRun(
            (f, a) => f == "pipx" && a.Contains("install datasette"),
            () =>
            {
                MakeStubBinary(localBin, "datasette");
                loc.Map["datasette"] = Path.Combine(localBin, "datasette");
                return (0, "", "");
            });

        using var audit = NewAudit(scratch);
        var opts = new BootstrapOptions(null, AutoInstall: true, AssumeYes: true, CacheDir: cache);
        var resolved = await DatasetteBootstrap.EnsureAsync(
            opts, audit, CancellationToken.None, runner, loc,
            new StringReader(""), new StringWriter(), stdinIsTty: false);

        Assert.Equal(Path.Combine(localBin, "datasette"), resolved);
        Assert.Contains(runner.Calls, c => c.FileOrCmd == "pipx");
        Assert.DoesNotContain(runner.Calls, c => c.FileOrCmd == "uv");
    }

    [Fact]
    public async Task Install_ViaVenv_WhenNoUvNoPipx()
    {
        var scratch = NewScratch();
        var cache = Path.Combine(scratch, "cache");

        var loc = new MutableLocator(); // nothing but python3 invoked via 'python3' filename
        var runner = new RecordingProcessRunner();
        runner.OnRun((f, a) => f == "python3" && a == "--version", 0, "Python 3.12.1\n", "");
        runner.OnRun(
            (f, a) => f == "python3" && a.Contains("-m venv"),
            () =>
            {
                var venvBin = Path.Combine(DatasetteBootstrap.ManagedVenvDir(cache), "bin");
                Directory.CreateDirectory(venvBin);
                MakeStubBinary(venvBin, "pip");
                return (0, "", "");
            });
        runner.OnRun(
            (f, a) => f.EndsWith("/pip") && a.Contains("install") && a.Contains("datasette"),
            () =>
            {
                var venvBin = Path.Combine(DatasetteBootstrap.ManagedVenvDir(cache), "bin");
                MakeStubBinary(venvBin, "datasette");
                return (0, "", "");
            });

        using var audit = NewAudit(scratch);
        var opts = new BootstrapOptions(null, AutoInstall: true, AssumeYes: true, CacheDir: cache);
        var resolved = await DatasetteBootstrap.EnsureAsync(
            opts, audit, CancellationToken.None, runner, loc,
            new StringReader(""), new StringWriter(), stdinIsTty: false);

        Assert.Equal(DatasetteBootstrap.ManagedVenvBinary(cache), resolved);
    }

    [Fact]
    public async Task NoAutoInstall_ErrorsCleanly_WhenMissing()
    {
        var scratch = NewScratch();
        using var audit = NewAudit(scratch);
        var opts = new BootstrapOptions(null, AutoInstall: false, AssumeYes: true,
            CacheDir: Path.Combine(scratch, "cache"));
        var ex = await Assert.ThrowsAsync<DatasetteBootstrapException>(() =>
            DatasetteBootstrap.EnsureAsync(opts, audit, CancellationToken.None,
                new RecordingProcessRunner(), new MutableLocator(),
                new StringReader(""), new StringWriter(), stdinIsTty: false));
        Assert.Contains("no-auto-install", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task StdinNotTty_IsTreatedAsAutoYes()
    {
        var scratch = NewScratch();
        var cache = Path.Combine(scratch, "cache");
        var fakeHome = Path.Combine(scratch, "home");
        Directory.CreateDirectory(Path.Combine(fakeHome, ".local", "bin"));
        Environment.SetEnvironmentVariable("HOME", fakeHome);

        var loc = new MutableLocator { Map = { ["uv"] = "/usr/bin/uv" } };
        var runner = new RecordingProcessRunner();
        runner.OnRun((f, a) => f == "python3" && a == "--version", 0, "Python 3.11.0\n", "");
        runner.OnRun(
            (f, a) => f == "uv" && a.Contains("tool install datasette"),
            () =>
            {
                var bin = MakeStubBinary(Path.Combine(fakeHome, ".local", "bin"), "datasette");
                loc.Map["datasette"] = bin;
                return (0, "", "");
            });

        // AssumeYes=false, but stdin-is-tty=false must still proceed.
        var stdinReader = new StringReader(""); // no "y" waiting
        using var audit = NewAudit(scratch);
        var opts = new BootstrapOptions(null, AutoInstall: true, AssumeYes: false, CacheDir: cache);
        var resolved = await DatasetteBootstrap.EnsureAsync(
            opts, audit, CancellationToken.None, runner, loc,
            stdinReader, new StringWriter(), stdinIsTty: false);

        Assert.True(File.Exists(resolved));
    }

    [Fact]
    public async Task Python3Missing_ErrorsWithDoctorHint()
    {
        var scratch = NewScratch();
        var loc = new MutableLocator { Map = { ["uv"] = "/usr/bin/uv" } };
        var runner = new RecordingProcessRunner();
        runner.OnRunThrow((f, a) => f == "python3", new System.ComponentModel.Win32Exception("No such file"));

        using var audit = NewAudit(scratch);
        var opts = new BootstrapOptions(null, AutoInstall: true, AssumeYes: true,
            CacheDir: Path.Combine(scratch, "cache"));
        var ex = await Assert.ThrowsAsync<DatasetteBootstrapException>(() =>
            DatasetteBootstrap.EnsureAsync(opts, audit, CancellationToken.None, runner, loc,
                new StringReader(""), new StringWriter(), stdinIsTty: false));
        Assert.Contains("python3", ex.Message);
    }
}
