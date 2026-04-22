using System.Threading;
using System.Threading.Tasks;

namespace Drederick.Jeopardy.Sandbox;

/// <summary>
/// Handle on a running sandbox container. All I/O against the container
/// flows through this interface so tests can substitute a canned driver
/// and production callers never bypass the audit log. Disposing the
/// session force-removes the container.
/// </summary>
public interface ISandboxSession : IAsyncDisposable
{
    /// <summary>Docker container id (short or long form; whatever the runtime returned).</summary>
    string ContainerId { get; }

    /// <summary>Workdir inside the container (always <c>/home/ctf/work</c>).</summary>
    string WorkDir { get; }

    /// <summary>
    /// Run a shell command inside the container via <c>docker exec … bash -c</c>.
    /// Stdout/stderr are truncated to 256 KiB in the result; the full-size
    /// SHA-256 is recorded in the audit log. If the command exceeds
    /// <paramref name="timeout"/> (or the spec default) the docker-exec
    /// process is killed and <see cref="SandboxExecResult.TimedOut"/> is
    /// true.
    /// </summary>
    Task<SandboxExecResult> ExecAsync(string shellCommand, TimeSpan? timeout, CancellationToken ct);

    /// <summary>Copy a file out of the container, refusing reads larger than <paramref name="maxBytes"/>.</summary>
    Task<byte[]> ReadFileAsync(string containerPath, long maxBytes, CancellationToken ct);

    /// <summary>Copy bytes into the container at the given path.</summary>
    Task WriteFileAsync(string containerPath, byte[] bytes, CancellationToken ct);

    /// <summary>
    /// Tar the workdir out of the container to <paramref name="hostOutputPath"/> on
    /// the host and return the final path.
    /// </summary>
    Task<string> SnapshotWorkDirAsync(string hostOutputPath, CancellationToken ct);
}
