using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Jeopardy.Sandbox;

/// <summary>
/// Creates, manages, and tears down Docker sandbox containers used by the
/// Jeopardy CTF solver. The sandbox itself is a local process isolation
/// boundary: <see cref="Scope.Scope"/> is NOT consulted for the image or
/// container. However, when a <see cref="SandboxSpec.ConnectionInfo"/> is
/// supplied that references a remote host, that host is scope-validated
/// before the container is granted network access to it.
///
/// Every sandbox action is recorded to the audit log. Stdout/stderr are
/// never logged verbatim; only a SHA-256 and byte length are recorded.
/// </summary>
public sealed class SandboxManager
{
    internal const string WorkDirInContainer = "/home/ctf/work";
    internal const int DefaultMaxConcurrent = 8;
    internal const int StdoutTruncationBytes = 256 * 1024;
    internal const int DockerCommandTimeoutSeconds = 60;
    internal const int DockerCleanupTimeoutSeconds = 5;
    internal const int HealthcheckTimeoutSeconds = 30;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly IProcessRunner _docker;
    private readonly string _dockerBinary;
    private readonly SemaphoreSlim _concurrencyGate;
    private int _currentInFlight;
    private int _peakInFlight;

    /// <summary>Peak observed concurrent in-flight sandbox sessions (for tests/observability).</summary>
    public int PeakConcurrent => Volatile.Read(ref _peakInFlight);

    public SandboxManager(Scope.Scope scope, AuditLog audit, IProcessRunner docker, string dockerBinary = "docker")
    {
        _scope = scope;
        _audit = audit;
        _docker = docker;
        _dockerBinary = dockerBinary;

        var envCap = Environment.GetEnvironmentVariable("DREDERICK_SANDBOX_MAX_CONCURRENT");
        var cap = DefaultMaxConcurrent;
        if (!string.IsNullOrWhiteSpace(envCap)
            && int.TryParse(envCap, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            && parsed > 0)
        {
            cap = parsed;
        }
        _concurrencyGate = new SemaphoreSlim(cap, cap);
    }

    // --- docker availability ----------------------------------------------

    public async Task<bool> ImageAvailableAsync(string imageName, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var args = $"image inspect {ShellQuote(imageName)}";
        var (exit, _, _) = await Task.Run(
            () => _docker.Run(_dockerBinary, args, DockerCommandTimeoutSeconds),
            ct).ConfigureAwait(false);
        return exit == 0;
    }

    public async Task BuildImageAsync(string imageName, string dockerfilePath, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var contextDir = Path.GetDirectoryName(Path.GetFullPath(dockerfilePath));
        if (string.IsNullOrEmpty(contextDir))
        {
            throw new ArgumentException("dockerfilePath must be a full path", nameof(dockerfilePath));
        }
        var args =
            $"build -f {ShellQuote(dockerfilePath)} -t {ShellQuote(imageName)} {ShellQuote(contextDir)}";
        _audit.Record("sandbox.build.start", new Dictionary<string, object?>
        {
            ["image"] = imageName,
            ["dockerfile"] = dockerfilePath,
            ["argv_sha256"] = Sha256Hex(args),
        });
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var (exit, _, stderr) = await Task.Run(
            () => _docker.Run(_dockerBinary, args, 3600),
            ct).ConfigureAwait(false);
        sw.Stop();
        _audit.Record("sandbox.build.finish", new Dictionary<string, object?>
        {
            ["image"] = imageName,
            ["exit_code"] = exit,
            ["elapsed_ms"] = sw.ElapsedMilliseconds,
            ["stderr_sha256"] = Sha256Hex(stderr),
            ["stderr_bytes"] = Encoding.UTF8.GetByteCount(stderr),
        });
        if (exit != 0)
        {
            throw new InvalidOperationException(
                $"docker build failed for {imageName} (exit {exit}). See audit log for stderr sha256.");
        }
    }

    public async Task<SandboxDoctorCheck> CheckDockerHealthyAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var (vexit, _, verr) = await Task.Run(
            () => _docker.Run(_dockerBinary, "version", 10),
            ct).ConfigureAwait(false);
        if (vexit != 0)
        {
            return new SandboxDoctorCheck(false, "docker-version",
                $"`{_dockerBinary} version` failed (exit {vexit}): {Truncate(verr, 200)}");
        }
        var (iexit, _, ierr) = await Task.Run(
            () => _docker.Run(_dockerBinary, "info", 10),
            ct).ConfigureAwait(false);
        if (iexit != 0)
        {
            return new SandboxDoctorCheck(false, "docker-info",
                $"`{_dockerBinary} info` failed (exit {iexit}): {Truncate(ierr, 200)}");
        }
        return new SandboxDoctorCheck(true, "docker", "docker daemon reachable");
    }

    // --- session lifecycle ------------------------------------------------

    public async Task<ISandboxSession> StartAsync(SandboxSpec spec, CancellationToken ct)
    {
        if (spec.Privileged)
        {
            // Invariant: privileged sandboxes must be explicit. We accept the
            // field so callers can set it deliberately, but we log a warning
            // and still apply all hardening. A future policy file could reject
            // it outright per environment.
            _audit.Record("sandbox.privileged_requested", new Dictionary<string, object?>
            {
                ["challenge_id"] = spec.ChallengeId,
                ["challenge"] = spec.ChallengeName,
            });
        }

        // Scope-validate the remote target BEFORE allocating the container.
        string? validatedRemoteHost = null;
        if (!string.IsNullOrWhiteSpace(spec.ConnectionInfo))
        {
            validatedRemoteHost = ExtractAndRequireInScopeHost(spec.ConnectionInfo);
        }

        await _concurrencyGate.WaitAsync(ct).ConfigureAwait(false);
        var peakSnapshot = Interlocked.Increment(ref _currentInFlight);
        UpdatePeak(peakSnapshot);

        string? containerId = null;
        try
        {
            var containerName = $"drederick-ctf-{spec.ChallengeId:D6}-{Guid.NewGuid():N}".ToLowerInvariant();
            var runArgs = BuildDockerRunArgs(spec, containerName, validatedRemoteHost);

            _audit.Record("sandbox.start", new Dictionary<string, object?>
            {
                ["challenge_id"] = spec.ChallengeId,
                ["challenge"] = spec.ChallengeName,
                ["category"] = spec.Category,
                ["image"] = spec.ImageName,
                ["container_name"] = containerName,
                ["argv_sha256"] = Sha256Hex(runArgs),
                ["remote_host"] = validatedRemoteHost,
            });

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var (exit, stdout, stderr) = await Task.Run(
                () => _docker.Run(_dockerBinary, runArgs, DockerCommandTimeoutSeconds),
                ct).ConfigureAwait(false);
            sw.Stop();

            if (exit != 0)
            {
                _audit.Record("sandbox.start.failed", new Dictionary<string, object?>
                {
                    ["challenge_id"] = spec.ChallengeId,
                    ["exit_code"] = exit,
                    ["stderr_sha256"] = Sha256Hex(stderr),
                    ["stderr_bytes"] = Encoding.UTF8.GetByteCount(stderr),
                    ["elapsed_ms"] = sw.ElapsedMilliseconds,
                });
                throw new InvalidOperationException(
                    $"docker run failed for challenge {spec.ChallengeId} (exit {exit}).");
            }

            containerId = stdout.Trim();
            if (containerId.Length == 0)
            {
                throw new InvalidOperationException("docker run returned empty container id");
            }

            // Inject attachments via `docker cp`. Each attachment is SHA-256'd
            // before injection for integrity auditing.
            if (spec.AttachmentsByFilename is { Count: > 0 })
            {
                var hostDir = Path.Combine(Path.GetTempPath(),
                    $"drederick-ctf-{spec.ChallengeId:D6}-{Guid.NewGuid():N}");
                Directory.CreateDirectory(hostDir);
                try
                {
                    foreach (var kv in spec.AttachmentsByFilename)
                    {
                        var safeName = SanitizeFilename(kv.Key);
                        var hostPath = Path.Combine(hostDir, safeName);
                        File.WriteAllBytes(hostPath, kv.Value);
                        var digest = Sha256HexBytes(kv.Value);
                        var cpArgs =
                            $"cp {ShellQuote(hostPath)} {ShellQuote($"{containerId}:{WorkDirInContainer}/{safeName}")}";
                        var (cpExit, _, cpErr) = await Task.Run(
                            () => _docker.Run(_dockerBinary, cpArgs, DockerCommandTimeoutSeconds),
                            ct).ConfigureAwait(false);
                        _audit.Record("sandbox.attach", new Dictionary<string, object?>
                        {
                            ["challenge_id"] = spec.ChallengeId,
                            ["container"] = containerId,
                            ["filename"] = safeName,
                            ["bytes"] = kv.Value.LongLength,
                            ["content_sha256"] = digest,
                            ["argv_sha256"] = Sha256Hex(cpArgs),
                            ["exit_code"] = cpExit,
                        });
                        if (cpExit != 0)
                        {
                            throw new InvalidOperationException(
                                $"docker cp failed for attachment {safeName} " +
                                $"(exit {cpExit}): {Truncate(cpErr, 200)}");
                        }
                    }
                }
                finally
                {
                    try { Directory.Delete(hostDir, recursive: true); } catch { }
                }
            }

            // Wait for healthcheck. For images with no HEALTHCHECK the docker
            // daemon returns an empty health state; we treat that as healthy.
            await WaitForHealthyAsync(containerId, HealthcheckTimeoutSeconds, ct).ConfigureAwait(false);

            return new SandboxSession(
                this,
                containerId,
                spec);
        }
        catch
        {
            // Best-effort cleanup on failure: release the semaphore and rm -f.
            if (containerId is not null)
            {
                await BestEffortRemoveAsync(containerId).ConfigureAwait(false);
            }
            Interlocked.Decrement(ref _currentInFlight);
            _concurrencyGate.Release();
            throw;
        }
    }

    internal IProcessRunner DockerRunnerForSession() => _docker;
    internal string DockerBinaryForSession() => _dockerBinary;
    internal AuditLog AuditForSession() => _audit;

    internal void ReleaseSlot()
    {
        Interlocked.Decrement(ref _currentInFlight);
        _concurrencyGate.Release();
    }

    private void UpdatePeak(int candidate)
    {
        while (true)
        {
            var current = Volatile.Read(ref _peakInFlight);
            if (candidate <= current) return;
            if (Interlocked.CompareExchange(ref _peakInFlight, candidate, current) == current) return;
        }
    }

    // --- docker run args --------------------------------------------------

    internal string BuildDockerRunArgs(SandboxSpec spec, string containerName, string? validatedRemoteHost)
    {
        // Build as a whitespace-joined string because the existing
        // IProcessRunner accepts a single `arguments` string. All user-supplied
        // values are passed through ShellQuote so there is no injection
        // surface; docker CLI parses these tokens.
        var sb = new StringBuilder();
        sb.Append("run -d");
        sb.Append(' ').Append("--name ").Append(ShellQuote(containerName));
        sb.Append(' ').Append("--label drederick.challenge_id=").Append(spec.ChallengeId);
        sb.Append(' ').Append("--label ").Append(ShellQuote($"drederick.challenge_name={spec.ChallengeName}"));
        sb.Append(' ').Append("--label ").Append(ShellQuote($"drederick.category={spec.Category}"));
        sb.Append(' ').Append("--workdir ").Append(WorkDirInContainer);
        sb.Append(' ').Append("--user 1000:1000");

        // Network isolation: default --network none; otherwise bridge with
        // an explicit --add-host mapping so the container can reach only the
        // validated remote host by hostname. iptables-level allowlisting is
        // intentionally NOT done here: if the operator needs it, they can
        // wrap the container in a custom user-defined bridge.
        if (validatedRemoteHost is null)
        {
            sb.Append(' ').Append("--network none");
        }
        else
        {
            sb.Append(' ').Append("--network bridge");
            sb.Append(' ').Append("--add-host ")
              .Append(ShellQuote($"ctf-target:{validatedRemoteHost}"));
        }

        // Resource caps.
        sb.Append(' ').Append("--memory ").Append(spec.MemoryBytesCap.ToString(CultureInfo.InvariantCulture));
        sb.Append(' ').Append("--cpu-shares ").Append(spec.CpuShares.ToString(CultureInfo.InvariantCulture));
        sb.Append(' ').Append("--pids-limit 512");

        // Security.
        sb.Append(' ').Append("--security-opt ").Append("no-new-privileges");
        sb.Append(' ').Append("--security-opt ").Append("seccomp=default");
        sb.Append(' ').Append("--cap-drop ALL");
        sb.Append(' ').Append("--cap-add NET_BIND_SERVICE");
        if (spec.Privileged)
        {
            sb.Append(' ').Append("--privileged");
        }

        // Read-only root filesystem with a writable workdir volume would be
        // ideal, but some CTF tools expect /tmp writable; leave rw.
        sb.Append(' ').Append("--init");
        sb.Append(' ').Append("--stop-timeout 10");

        // Entry: override ENTRYPOINT so the container stays alive for the
        // duration of the session. We drive work via `docker exec`.
        sb.Append(' ').Append("--entrypoint /bin/sh");
        sb.Append(' ').Append(ShellQuote(spec.ImageName));
        sb.Append(' ').Append("-c");
        sb.Append(' ').Append(ShellQuote("tail -f /dev/null"));

        return sb.ToString();
    }

    private async Task WaitForHealthyAsync(string containerId, int totalSeconds, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow.AddSeconds(totalSeconds);
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            var args = $"inspect --format={ShellQuote("{{.State.Health.Status}}")} {ShellQuote(containerId)}";
            int exit;
            string stdout;
            try
            {
                (exit, stdout, _) = await Task.Run(
                    () => _docker.Run(_dockerBinary, args, 10),
                    ct).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                continue;
            }
            if (exit != 0)
            {
                // Container likely gone; fail fast.
                throw new InvalidOperationException($"docker inspect failed for {containerId}");
            }
            var status = stdout.Trim();
            if (status.Length == 0
                || status.Equals("healthy", StringComparison.OrdinalIgnoreCase)
                || status.Equals("<nil>", StringComparison.OrdinalIgnoreCase)
                || status.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            if (status.Equals("unhealthy", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"sandbox {containerId} reported unhealthy");
            }
            await Task.Delay(TimeSpan.FromMilliseconds(500), ct).ConfigureAwait(false);
        }
        throw new TimeoutException(
            $"sandbox {containerId} did not report healthy within {totalSeconds}s");
    }

    internal async Task BestEffortRemoveAsync(string containerId)
    {
        try
        {
            var args = $"rm -f {ShellQuote(containerId)}";
            await Task.Run(() =>
            {
                try { _docker.Run(_dockerBinary, args, DockerCleanupTimeoutSeconds); }
                catch { }
            }).ConfigureAwait(false);
        }
        catch
        {
            // swallow — cleanup is best-effort.
        }
    }

    // --- scope check for ConnectionInfo -----------------------------------

    private static readonly Regex IpLikeRegex = new(
        @"(?<ip>(?:\d{1,3}\.){3}\d{1,3}|\[[0-9A-Fa-f:]+\]|[0-9A-Fa-f:]{2,39})",
        RegexOptions.Compiled);

    private string ExtractAndRequireInScopeHost(string connectionInfo)
    {
        // Try to find the first IP literal in the string. If nothing parses
        // as an IP, we refuse: scope is IP-based and we don't do DNS
        // resolution at this layer — the operator should pass an IP in
        // connection_info, or add the host via a custom bridge upstream.
        foreach (Match m in IpLikeRegex.Matches(connectionInfo))
        {
            var candidate = m.Groups["ip"].Value.Trim('[', ']');
            if (IPAddress.TryParse(candidate, out _))
            {
                _scope.Require(candidate);
                return candidate;
            }
        }
        throw new ScopeException(
            $"ConnectionInfo '{connectionInfo}' does not contain a parseable IP " +
            "address. Supply the target as an IP so the sandbox can scope-check it.");
    }

    // --- helpers ----------------------------------------------------------

    internal static string ShellQuote(string s)
    {
        // Quote for docker-CLI argument. The IProcessRunner parses
        // ProcessStartInfo.Arguments via the OS shell-free tokenizer on .NET,
        // which splits on whitespace and honors double quotes. We use a
        // minimal safe quoter: if the value contains whitespace, backslashes,
        // or doublequotes, wrap in double quotes and backslash-escape.
        if (s.Length == 0) return "\"\"";
        var needsQuote = false;
        foreach (var c in s)
        {
            if (char.IsWhiteSpace(c) || c == '"' || c == '\\' || c == '\'' || c == '$' || c == '`'
                || c == '*' || c == '?' || c == '&' || c == '|' || c == ';' || c == '<' || c == '>'
                || c == '(' || c == ')')
            {
                needsQuote = true;
                break;
            }
        }
        if (!needsQuote) return s;
        var sb = new StringBuilder(s.Length + 4);
        sb.Append('"');
        foreach (var c in s)
        {
            if (c == '"' || c == '\\') sb.Append('\\');
            sb.Append(c);
        }
        sb.Append('"');
        return sb.ToString();
    }

    internal static string Sha256Hex(string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s ?? string.Empty);
        return Sha256HexBytes(bytes);
    }

    internal static string Sha256HexBytes(byte[] bytes)
    {
        var hash = SHA256.HashData(bytes);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    internal static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max];

    internal static string SanitizeFilename(string name)
    {
        // Keep only safe characters; refuse path-traversal. Result lives in
        // /home/ctf/work/<name> inside the container.
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("attachment filename must be non-empty", nameof(name));
        var bare = Path.GetFileName(name);
        if (string.IsNullOrEmpty(bare) || bare == "." || bare == "..")
            throw new ArgumentException($"attachment filename '{name}' is not a plain file name.");
        foreach (var c in bare)
        {
            if (c == '/' || c == '\\' || c == '\0')
                throw new ArgumentException($"attachment filename '{name}' contains path separators.");
        }
        return bare;
    }
}
