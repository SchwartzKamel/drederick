using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Drederick.Jeopardy.Ops;

/// <summary>
/// CLI-side writer that appends <see cref="OperatorMessage"/> entries to a
/// JSONL inbox file consumed by a running <see cref="OperatorInbox"/>.
/// </summary>
/// <remarks>
/// <para><b>Future CLI wiring (jeopardy-cli todo).</b> The subcommand
/// <c>drederick ctf-msg</c> should construct an <see cref="OperatorMessage"/>
/// from its flags and invoke <see cref="SendAsync"/>. Expected surface:</para>
/// <code>
/// drederick ctf-msg --inbox &lt;path&gt; --kind hint --chal 42 --body "try ret2libc"
/// drederick ctf-msg --inbox &lt;path&gt; --kind shutdown
/// drederick ctf-msg --inbox &lt;path&gt; --kind focus --chal 42 --solver claude@c1 --body "aim at rop"
/// </code>
/// <para><c>--inbox</c> defaults to <c>~/.drederick/jeopardy-inbox.jsonl</c>.
/// <c>--kind</c> is required. <c>--chal</c> / <c>--solver</c> are optional
/// (null = broadcast). <c>--body</c> is required for <c>hint</c>/<c>focus</c>
/// and optional otherwise. Do NOT wire this subcommand from the
/// <c>jeopardy-ops</c> zone; that belongs to the future <c>jeopardy-cli</c>
/// todo that owns <c>Program.cs</c> / <c>CommandLineOptions.cs</c>.</para>
/// <para>Concurrency: multiple CLI invocations may call
/// <see cref="SendAsync"/> at the same time. The writer opens the file with
/// <see cref="FileShare.Read"/> and retries on sharing violations, guaranteeing
/// one writer at a time and therefore atomic whole-line appends.</para>
/// </remarks>
public static class OperatorSender
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
    };

    private const int MaxRetryAttempts = 50;
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(20);

    // Per-process serialization by path — prevents in-process write interleaving.
    // Cross-process contention is handled by FileShare.Read + IOException retry.
    private static readonly Dictionary<string, SemaphoreSlim> PathLocks = new(StringComparer.Ordinal);
    private static readonly Lock PathLocksGate = new();

    private static SemaphoreSlim GetPathLock(string path)
    {
        var key = Path.GetFullPath(path);
        lock (PathLocksGate)
        {
            if (!PathLocks.TryGetValue(key, out var sem))
            {
                sem = new SemaphoreSlim(1, 1);
                PathLocks[key] = sem;
            }
            return sem;
        }
    }

    /// <summary>
    /// Appends a single operator message as a JSONL line to
    /// <paramref name="inboxPath"/>. Creates the parent directory and the
    /// file if missing.
    /// </summary>
    public static async Task SendAsync(string inboxPath, OperatorMessage msg, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(inboxPath);
        ArgumentNullException.ThrowIfNull(msg);
        ct.ThrowIfCancellationRequested();

        var dir = Path.GetDirectoryName(inboxPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var json = JsonSerializer.Serialize(msg, JsonOpts);
        var bytes = Encoding.UTF8.GetBytes(json + "\n");

        var sem = GetPathLock(inboxPath);
        await sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    using var fs = new FileStream(
                        inboxPath,
                        FileMode.Append,
                        FileAccess.Write,
                        FileShare.Read,
                        bufferSize: 4096,
                        useAsync: false);
                    fs.Write(bytes, 0, bytes.Length);
                    fs.Flush();
                    return;
                }
                catch (IOException) when (attempt < MaxRetryAttempts)
                {
                    await Task.Delay(RetryDelay, ct).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            sem.Release();
        }
    }

    internal static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
