using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Doctor;

namespace Drederick.Jeopardy.Sandbox;

/// <summary>
/// Live sandbox session. All shell/file/snapshot operations flow through
/// <c>docker exec</c> or <c>docker cp</c>. Disposal force-removes the
/// container and releases a slot on the manager's concurrency gate.
/// </summary>
internal sealed class SandboxSession : ISandboxSession
{
    private readonly SandboxManager _manager;
    private readonly SandboxSpec _spec;
    private readonly IProcessRunner _docker;
    private readonly string _dockerBinary;
    private readonly AuditLog _audit;
    private int _disposed;

    public string ContainerId { get; }

    public string WorkDir => SandboxManager.WorkDirInContainer;

    internal SandboxSession(
        SandboxManager manager,
        string containerId,
        SandboxSpec spec)
    {
        _manager = manager;
        ContainerId = containerId;
        _spec = spec;

        // We re-read the manager's private state via the manager itself.
        _docker = manager.DockerRunnerForSession();
        _dockerBinary = manager.DockerBinaryForSession();
        _audit = manager.AuditForSession();
    }

    public async Task<SandboxExecResult> ExecAsync(string shellCommand, TimeSpan? timeout, CancellationToken ct)
    {
        ThrowIfDisposed();
        var effective = timeout ?? _spec.Timeout;
        var seconds = (int)Math.Max(1, Math.Ceiling(effective.TotalSeconds));

        // docker exec <id> bash -c 'wrapped'. We wrap the caller's command in
        // `set -o pipefail; <cmd>` so chained pipelines surface their failing
        // exit codes, and we pass it as a SINGLE argv element to docker — the
        // host shell never interprets it, so $(...) / backticks execute only
        // inside the container, which is the intended boundary.
        var wrapped = "set -o pipefail; " + shellCommand;
        var args =
            $"exec {SandboxManager.ShellQuote(ContainerId)} bash -c {SandboxManager.ShellQuote(wrapped)}";

        var argvDigest = SandboxManager.Sha256Hex(args);
        var sw = Stopwatch.StartNew();
        int exit;
        string stdout;
        string stderr;
        var timedOut = false;

        try
        {
            (exit, stdout, stderr) = await Task.Run(
                () => _docker.Run(_dockerBinary, args, seconds),
                ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            sw.Stop();
            exit = 124; // GNU timeout convention
            stdout = string.Empty;
            stderr = $"sandbox exec timed out after {seconds}s";
            timedOut = true;

            // Best-effort: kill any stuck processes in the container. The
            // docker-exec process itself was killed by the runner's timeout.
            try
            {
                var killArgs = $"exec {SandboxManager.ShellQuote(ContainerId)} /bin/sh -c \"pkill -9 -P 1 || true\"";
                await Task.Run(() =>
                {
                    try { _docker.Run(_dockerBinary, killArgs, 5); } catch { }
                }).ConfigureAwait(false);
            }
            catch { }
        }
        sw.Stop();

        var stdoutBytes = Encoding.UTF8.GetByteCount(stdout);
        var stderrBytes = Encoding.UTF8.GetByteCount(stderr);
        _audit.Record("sandbox.exec", new Dictionary<string, object?>
        {
            ["container"] = ContainerId,
            ["challenge_id"] = _spec.ChallengeId,
            ["argv_sha256"] = argvDigest,
            ["exit_code"] = exit,
            ["timed_out"] = timedOut,
            ["elapsed_ms"] = sw.ElapsedMilliseconds,
            ["stdout_sha256"] = SandboxManager.Sha256Hex(stdout),
            ["stdout_bytes"] = stdoutBytes,
            ["stderr_sha256"] = SandboxManager.Sha256Hex(stderr),
            ["stderr_bytes"] = stderrBytes,
        });

        return new SandboxExecResult(
            ExitCode: exit,
            Stdout: SandboxManager.Truncate(stdout, SandboxManager.StdoutTruncationBytes),
            Stderr: SandboxManager.Truncate(stderr, SandboxManager.StdoutTruncationBytes),
            Elapsed: sw.Elapsed,
            TimedOut: timedOut);
    }

    public async Task<byte[]> ReadFileAsync(string containerPath, long maxBytes, CancellationToken ct)
    {
        ThrowIfDisposed();
        if (maxBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maxBytes));

        var hostTmp = Path.Combine(Path.GetTempPath(),
            $"drederick-ctf-read-{Guid.NewGuid():N}");
        var args = $"cp {SandboxManager.ShellQuote($"{ContainerId}:{containerPath}")} {SandboxManager.ShellQuote(hostTmp)}";
        var argvDigest = SandboxManager.Sha256Hex(args);
        var sw = Stopwatch.StartNew();
        try
        {
            var (exit, _, stderr) = await Task.Run(
                () => _docker.Run(_dockerBinary, args, SandboxManager.DockerCommandTimeoutSeconds),
                ct).ConfigureAwait(false);
            sw.Stop();
            if (exit != 0)
            {
                _audit.Record("sandbox.read.failed", new Dictionary<string, object?>
                {
                    ["container"] = ContainerId,
                    ["challenge_id"] = _spec.ChallengeId,
                    ["path"] = containerPath,
                    ["argv_sha256"] = argvDigest,
                    ["exit_code"] = exit,
                    ["stderr_sha256"] = SandboxManager.Sha256Hex(stderr),
                });
                throw new IOException($"docker cp read failed (exit {exit}): {SandboxManager.Truncate(stderr, 200)}");
            }

            var info = new FileInfo(hostTmp);
            if (!info.Exists) throw new FileNotFoundException($"docker cp produced no file: {hostTmp}");
            if (info.Length > maxBytes)
            {
                _audit.Record("sandbox.read.oversize", new Dictionary<string, object?>
                {
                    ["container"] = ContainerId,
                    ["challenge_id"] = _spec.ChallengeId,
                    ["path"] = containerPath,
                    ["bytes"] = info.Length,
                    ["max_bytes"] = maxBytes,
                });
                throw new InvalidOperationException(
                    $"file {containerPath} is {info.Length} bytes, exceeds maxBytes {maxBytes}");
            }
            var bytes = await File.ReadAllBytesAsync(hostTmp, ct).ConfigureAwait(false);
            _audit.Record("sandbox.read", new Dictionary<string, object?>
            {
                ["container"] = ContainerId,
                ["challenge_id"] = _spec.ChallengeId,
                ["path"] = containerPath,
                ["argv_sha256"] = argvDigest,
                ["bytes"] = bytes.LongLength,
                ["content_sha256"] = SandboxManager.Sha256HexBytes(bytes),
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
            });
            return bytes;
        }
        finally
        {
            try { if (File.Exists(hostTmp)) File.Delete(hostTmp); } catch { }
        }
    }

    public async Task WriteFileAsync(string containerPath, byte[] bytes, CancellationToken ct)
    {
        ThrowIfDisposed();
        var hostTmp = Path.Combine(Path.GetTempPath(),
            $"drederick-ctf-write-{Guid.NewGuid():N}");
        try
        {
            await File.WriteAllBytesAsync(hostTmp, bytes, ct).ConfigureAwait(false);
            var args = $"cp {SandboxManager.ShellQuote(hostTmp)} {SandboxManager.ShellQuote($"{ContainerId}:{containerPath}")}";
            var argvDigest = SandboxManager.Sha256Hex(args);
            var sw = Stopwatch.StartNew();
            var (exit, _, stderr) = await Task.Run(
                () => _docker.Run(_dockerBinary, args, SandboxManager.DockerCommandTimeoutSeconds),
                ct).ConfigureAwait(false);
            sw.Stop();
            _audit.Record("sandbox.write", new Dictionary<string, object?>
            {
                ["container"] = ContainerId,
                ["challenge_id"] = _spec.ChallengeId,
                ["path"] = containerPath,
                ["argv_sha256"] = argvDigest,
                ["bytes"] = bytes.LongLength,
                ["content_sha256"] = SandboxManager.Sha256HexBytes(bytes),
                ["exit_code"] = exit,
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
            });
            if (exit != 0)
            {
                throw new IOException($"docker cp write failed (exit {exit}): {SandboxManager.Truncate(stderr, 200)}");
            }
        }
        finally
        {
            try { if (File.Exists(hostTmp)) File.Delete(hostTmp); } catch { }
        }
    }

    public async Task<string> SnapshotWorkDirAsync(string hostOutputPath, CancellationToken ct)
    {
        ThrowIfDisposed();
        var dir = Path.GetDirectoryName(Path.GetFullPath(hostOutputPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        // `docker cp <id>:<workdir> <hostpath>` copies the directory as a
        // tar archive when the destination is `-`. We use the directory-form
        // behavior to populate hostOutputPath.
        var args =
            $"cp {SandboxManager.ShellQuote($"{ContainerId}:{SandboxManager.WorkDirInContainer}")} {SandboxManager.ShellQuote(hostOutputPath)}";
        var argvDigest = SandboxManager.Sha256Hex(args);
        var sw = Stopwatch.StartNew();
        var (exit, _, stderr) = await Task.Run(
            () => _docker.Run(_dockerBinary, args, SandboxManager.DockerCommandTimeoutSeconds),
            ct).ConfigureAwait(false);
        sw.Stop();
        _audit.Record("sandbox.snapshot", new Dictionary<string, object?>
        {
            ["container"] = ContainerId,
            ["challenge_id"] = _spec.ChallengeId,
            ["host_path"] = hostOutputPath,
            ["argv_sha256"] = argvDigest,
            ["exit_code"] = exit,
            ["elapsed_ms"] = sw.ElapsedMilliseconds,
        });
        if (exit != 0)
        {
            throw new IOException($"docker cp snapshot failed (exit {exit}): {SandboxManager.Truncate(stderr, 200)}");
        }
        return hostOutputPath;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        try
        {
            _audit.Record("sandbox.finish", new Dictionary<string, object?>
            {
                ["container"] = ContainerId,
                ["challenge_id"] = _spec.ChallengeId,
            });
            await _manager.BestEffortRemoveAsync(ContainerId).ConfigureAwait(false);
        }
        finally
        {
            _manager.ReleaseSlot();
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) == 1)
            throw new ObjectDisposedException(nameof(SandboxSession));
    }
}
