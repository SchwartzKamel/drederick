using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Jeopardy.Bus;

namespace Drederick.Jeopardy.Ops;

/// <summary>
/// Watches a local JSONL file for new operator messages and dispatches them
/// to the in-process <see cref="ISolverMessageBus"/>. The file path is local-
/// only — not a network resource, therefore not scope-gated. The message body
/// is never logged verbatim; audit records SHA-256 + length + kind only.
/// </summary>
public interface IOperatorInbox : IAsyncDisposable
{
    Task StartAsync(string inboxPath, CancellationToken ct);

    /// <summary>Fires for every NEW message appended after <see cref="StartAsync"/>.</summary>
    event Func<OperatorMessage, Task>? MessageReceived;

    /// <summary>Fires exactly for <c>kind=shutdown</c>/<c>stop</c> messages. Those do NOT fire <see cref="MessageReceived"/>.</summary>
    event Func<OperatorMessage, Task>? ShutdownRequested;
}

public sealed class OperatorInbox : IOperatorInbox
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    private readonly ISolverMessageBus _bus;
    private readonly AuditLog _audit;
    private readonly CancellationTokenSource _stopCts = new();
    private readonly SemaphoreSlim _dispatchGate = new(1, 1);
    private readonly StringBuilder _lineBuffer = new();
    private readonly object _wakeGate = new();
    private TaskCompletionSource _wakeTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private string? _inboxPath;
    private long _position;
    private Task? _loop;
    private FileSystemWatcher? _watcher;
    private int _disposed;

    public event Func<OperatorMessage, Task>? MessageReceived;
    public event Func<OperatorMessage, Task>? ShutdownRequested;

    public OperatorInbox(ISolverMessageBus bus, AuditLog audit)
    {
        ArgumentNullException.ThrowIfNull(bus);
        ArgumentNullException.ThrowIfNull(audit);
        _bus = bus;
        _audit = audit;
    }

    private void SignalWake()
    {
        lock (_wakeGate)
        {
            _wakeTcs.TrySetResult();
        }
    }

    private Task WakeTask
    {
        get { lock (_wakeGate) { return _wakeTcs.Task; } }
    }

    private void ResetWake()
    {
        lock (_wakeGate)
        {
            if (_wakeTcs.Task.IsCompleted)
            {
                _wakeTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }
    }

    public Task StartAsync(string inboxPath, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(inboxPath);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (_loop is not null)
        {
            throw new InvalidOperationException("OperatorInbox already started.");
        }

        _inboxPath = inboxPath;

        var dir = Path.GetDirectoryName(inboxPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        if (!File.Exists(inboxPath))
        {
            using var _ = new FileStream(inboxPath, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite);
        }

        _position = new FileInfo(inboxPath).Length;

        try
        {
            var watchDir = string.IsNullOrEmpty(dir) ? Directory.GetCurrentDirectory() : dir;
            _watcher = new FileSystemWatcher(watchDir, Path.GetFileName(inboxPath))
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                EnableRaisingEvents = true,
            };
            _watcher.Changed += (_, _) => SignalWake();
            _watcher.Created += (_, _) => SignalWake();
            _watcher.Renamed += (_, _) => SignalWake();
            _watcher.Error += (_, e) => _audit.Record("operator.msg.watcher_error", new Dictionary<string, object?>
            {
                ["error"] = e.GetException()?.Message,
            });
        }
        catch (Exception ex)
        {
            _audit.Record("operator.msg.watcher_error", new Dictionary<string, object?>
            {
                ["error"] = ex.Message,
            });
        }

        var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _stopCts.Token);
        _loop = Task.Run(() => RunLoopAsync(linked.Token), CancellationToken.None);

        _audit.Record("operator.inbox.start", new Dictionary<string, object?>
        {
            ["inbox_path"] = inboxPath,
            ["initial_position"] = _position,
        });

        return Task.CompletedTask;
    }

    private async Task RunLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await DrainAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _audit.Record("operator.msg.error", new Dictionary<string, object?>
                {
                    ["phase"] = "drain",
                    ["error"] = ex.Message,
                });
            }

            // Sleep up to PollInterval, but wake early if FSW signals.
            try
            {
                var delay = Task.Delay(PollInterval, ct);
                await Task.WhenAny(WakeTask, delay).ConfigureAwait(false);
                ResetWake();
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task DrainAsync(CancellationToken ct)
    {
        if (_inboxPath is null) return;
        if (!File.Exists(_inboxPath))
        {
            _position = 0;
            _lineBuffer.Clear();
            return;
        }

        long length;
        try
        {
            length = new FileInfo(_inboxPath).Length;
        }
        catch (IOException)
        {
            return;
        }

        if (length < _position)
        {
            _audit.Record("operator.inbox.truncated", new Dictionary<string, object?>
            {
                ["old_position"] = _position,
                ["new_length"] = length,
            });
            _position = 0;
            _lineBuffer.Clear();
        }

        if (length == _position)
        {
            return;
        }

        byte[] buf;
        try
        {
            await using var fs = new FileStream(
                _inboxPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 8192,
                useAsync: true);
            fs.Seek(_position, SeekOrigin.Begin);
            var toRead = (int)Math.Min(length - _position, 1 << 20);
            buf = new byte[toRead];
            int read = 0;
            while (read < toRead)
            {
                var n = await fs.ReadAsync(buf.AsMemory(read, toRead - read), ct).ConfigureAwait(false);
                if (n == 0) break;
                read += n;
            }
            _position += read;
            if (read < toRead) Array.Resize(ref buf, read);
        }
        catch (IOException ex)
        {
            _audit.Record("operator.msg.error", new Dictionary<string, object?>
            {
                ["phase"] = "read",
                ["error"] = ex.Message,
            });
            return;
        }

        var text = Encoding.UTF8.GetString(buf);
        _lineBuffer.Append(text);

        while (true)
        {
            var bufStr = _lineBuffer.ToString();
            var idx = bufStr.IndexOf('\n');
            if (idx < 0) break;
            var line = bufStr[..idx].TrimEnd('\r');
            _lineBuffer.Remove(0, idx + 1);
            if (string.IsNullOrWhiteSpace(line)) continue;
            await HandleLineAsync(line, ct).ConfigureAwait(false);
        }
    }

    private async Task HandleLineAsync(string line, CancellationToken ct)
    {
        OperatorMessage? msg;
        try
        {
            msg = JsonSerializer.Deserialize<OperatorMessage>(line, JsonOpts);
        }
        catch (JsonException ex)
        {
            _audit.Record("operator.msg.error", new Dictionary<string, object?>
            {
                ["phase"] = "parse",
                ["error"] = ex.Message,
                ["line_length"] = line.Length,
            });
            return;
        }

        if (msg is null || string.IsNullOrEmpty(msg.Kind))
        {
            _audit.Record("operator.msg.error", new Dictionary<string, object?>
            {
                ["phase"] = "validate",
                ["reason"] = "null_or_empty_kind",
            });
            return;
        }

        var bodyHash = OperatorSender.Sha256Hex(msg.Body ?? string.Empty);
        _audit.Record("operator.msg.received", new Dictionary<string, object?>
        {
            ["challenge_id"] = msg.ChallengeId,
            ["solver_id"] = msg.SolverId,
            ["kind"] = msg.Kind,
            ["body_sha256"] = bodyHash,
            ["body_length"] = (msg.Body ?? string.Empty).Length,
        });

        await _dispatchGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await DispatchAsync(msg, bodyHash, ct).ConfigureAwait(false);
        }
        finally
        {
            _dispatchGate.Release();
        }
    }

    private async Task DispatchAsync(OperatorMessage msg, string bodyHash, CancellationToken ct)
    {
        var kind = msg.Kind.Trim().ToLowerInvariant();

        if (kind is "shutdown" or "stop")
        {
            var handler = ShutdownRequested;
            if (handler is not null)
            {
                foreach (Func<OperatorMessage, Task> d in handler.GetInvocationList())
                {
                    try { await d(msg).ConfigureAwait(false); }
                    catch (Exception ex)
                    {
                        _audit.Record("operator.msg.error", new Dictionary<string, object?>
                        {
                            ["phase"] = "shutdown_handler",
                            ["error"] = ex.Message,
                        });
                    }
                }
            }
            _audit.Record("operator.msg.dispatched", new Dictionary<string, object?>
            {
                ["kind"] = kind,
                ["body_sha256"] = bodyHash,
                ["route"] = "shutdown",
            });
            return;
        }

        {
            var handler = MessageReceived;
            if (handler is not null)
            {
                foreach (Func<OperatorMessage, Task> d in handler.GetInvocationList())
                {
                    try { await d(msg).ConfigureAwait(false); }
                    catch (Exception ex)
                    {
                        _audit.Record("operator.msg.error", new Dictionary<string, object?>
                        {
                            ["phase"] = "handler",
                            ["error"] = ex.Message,
                        });
                    }
                }
            }
        }

        if (kind is "hint" or "focus" or "skip")
        {
            if (!string.IsNullOrEmpty(msg.ChallengeId))
            {
                var tags = new List<string> { $"op:{kind}" };
                if (!string.IsNullOrEmpty(msg.SolverId)) tags.Add($"solver:{msg.SolverId}");
                try
                {
                    var insight = new SolverInsight(
                        ChallengeId: msg.ChallengeId,
                        SolverId: "operator",
                        ModelId: "operator",
                        Kind: InsightKind.OperatorHint,
                        Summary: msg.Body ?? string.Empty,
                        DetailsSha256: null,
                        Tags: tags,
                        At: msg.At);
                    await _bus.PublishAsync(insight, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _audit.Record("operator.msg.error", new Dictionary<string, object?>
                    {
                        ["phase"] = "bus_push",
                        ["error"] = ex.Message,
                    });
                }
            }
        }

        _audit.Record("operator.msg.dispatched", new Dictionary<string, object?>
        {
            ["challenge_id"] = msg.ChallengeId,
            ["solver_id"] = msg.SolverId,
            ["kind"] = kind,
            ["body_sha256"] = bodyHash,
            ["route"] = kind is "hint" or "focus" or "skip" ? "bus" : "observer_only",
        });
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _stopCts.Cancel(); } catch (ObjectDisposedException) { }
        SignalWake();
        if (_watcher is not null)
        {
            try { _watcher.EnableRaisingEvents = false; } catch { }
            _watcher.Dispose();
            _watcher = null;
        }
        if (_loop is not null)
        {
            try { await _loop.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _audit.Record("operator.msg.error", new Dictionary<string, object?>
                {
                    ["phase"] = "dispose",
                    ["error"] = ex.Message,
                });
            }
        }
        await _dispatchGate.WaitAsync().ConfigureAwait(false);
        _dispatchGate.Release();
        _dispatchGate.Dispose();
        _stopCts.Dispose();
        _audit.Record("operator.inbox.stop", new Dictionary<string, object?>
        {
            ["inbox_path"] = _inboxPath,
        });
    }
}
