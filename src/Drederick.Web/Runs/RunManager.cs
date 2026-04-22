using System.Collections.Concurrent;
using Drederick.Host;

namespace Drederick.Web.Runs;

/// <summary>
/// Thin, testable wrapper around
/// <see cref="DrederickHost.RunAsync(Drederick.Scope.Scope, RunOptions, IProgress{ScanEvent}?, CancellationToken)"/>.
/// Tests inject a stub so endpoint tests don't spawn real scanners.
/// </summary>
public interface IRunExecutor
{
    Task<RunResult> RunAsync(
        Drederick.Scope.Scope scope,
        RunOptions options,
        IProgress<ScanEvent>? progress,
        CancellationToken ct);
}

/// <summary>Default executor: delegates to <see cref="DrederickHost"/>.</summary>
public sealed class DrederickHostRunExecutor : IRunExecutor
{
    private readonly DrederickHost _host;
    public DrederickHostRunExecutor(DrederickHost host) { _host = host; }

    public Task<RunResult> RunAsync(
        Drederick.Scope.Scope scope,
        RunOptions options,
        IProgress<ScanEvent>? progress,
        CancellationToken ct)
        => _host.RunAsync(scope, options, progress, ct);
}

/// <summary>
/// Set of high-blast-radius tool categories the server was started with. Fixed
/// at process start — endpoints cannot grant them at request time. Matches
/// the CLI's <c>--allow-exec-pocs</c> / <c>--allow-cred-attacks</c> /
/// <c>--allow-payloads</c> / <c>--allow-destructive</c> / <c>--allow-dos</c>
/// flag semantics. Populated from env vars at process start.
/// </summary>
public sealed class ServerCategoryGrants
{
    public IReadOnlySet<string> Granted { get; }

    public ServerCategoryGrants(IEnumerable<string> granted)
    {
        Granted = new HashSet<string>(granted, StringComparer.OrdinalIgnoreCase);
    }

    public static ServerCategoryGrants FromEnvironment()
    {
        var g = new List<string> { "recon" };
        static bool On(string name) =>
            Environment.GetEnvironmentVariable(name) is { Length: > 0 } v
            && (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
        if (On("DREDERICK_WEB_ALLOW_EXEC_POCS")) g.Add("exec-pocs");
        if (On("DREDERICK_WEB_ALLOW_CRED_ATTACKS")) g.Add("cred-attacks");
        if (On("DREDERICK_WEB_ALLOW_PAYLOADS")) g.Add("payloads");
        if (On("DREDERICK_WEB_ALLOW_DESTRUCTIVE")) g.Add("destructive");
        if (On("DREDERICK_WEB_ALLOW_DOS")) g.Add("dos");
        return new ServerCategoryGrants(g);
    }

    public bool IsGranted(string category) => Granted.Contains(category);
}

/// <summary>
/// Whitelist of directories under which a submitted <c>scope_path</c> is
/// allowed to resolve. Defaults to the process's current working directory.
/// Prevents <c>scope_path=../../../etc/passwd</c> style reads.
/// </summary>
public sealed class ScopePathPolicy
{
    public IReadOnlyList<string> AllowedRoots { get; }

    public ScopePathPolicy(IEnumerable<string> allowedRoots)
    {
        AllowedRoots = allowedRoots
            .Select(r => NormalizeDir(Path.GetFullPath(r)))
            .ToList();
    }

    public static ScopePathPolicy Default()
        => new(new[] { Directory.GetCurrentDirectory() });

    /// <summary>
    /// Returns the resolved absolute path if it is inside one of the allowed
    /// roots; otherwise returns null.
    /// </summary>
    public string? Resolve(string submittedPath)
    {
        if (string.IsNullOrWhiteSpace(submittedPath)) return null;
        string full;
        try { full = Path.GetFullPath(submittedPath); }
        catch { return null; }
        var cmp = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        foreach (var root in AllowedRoots)
        {
            if (full.StartsWith(root, cmp)) return full;
        }
        return null;
    }

    private static string NormalizeDir(string dir)
        => dir.EndsWith(Path.DirectorySeparatorChar) ? dir : dir + Path.DirectorySeparatorChar;
}

/// <summary>Internal mutable run record. The public API projects to <see cref="RunRecordDto"/>.</summary>
internal sealed class RunRecord
{
    public Guid RunId { get; }
    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset? FinishedAt { get; set; }
    public string Status { get; set; }
    public int TargetCount { get; }
    public int FindingCount { get; set; }
    public string? Error { get; set; }
    public CancellationTokenSource Cts { get; }
    public Task? Task { get; set; }

    private readonly List<ScanEvent> _events = new();
    private readonly object _eventsLock = new();

    public RunRecord(Guid id, DateTimeOffset startedAt, int targetCount)
    {
        RunId = id;
        StartedAt = startedAt;
        Status = "running";
        TargetCount = targetCount;
        Cts = new CancellationTokenSource();
    }

    public void AddEvent(ScanEvent e)
    {
        lock (_eventsLock) { _events.Add(e); }
    }

    public (List<ScanEvent> Events, bool Truncated) SnapshotEvents(
        DateTimeOffset? since, int maxBatch)
    {
        lock (_eventsLock)
        {
            IEnumerable<ScanEvent> q = _events;
            if (since.HasValue)
                q = q.Where(ev => ev.Timestamp > since.Value);
            var list = q.Take(maxBatch + 1).ToList();
            var truncated = list.Count > maxBatch;
            if (truncated) list = list.Take(maxBatch).ToList();
            return (list, truncated);
        }
    }

    public RunRecordDto ToDto() => new(
        RunId: RunId,
        StartedAt: StartedAt,
        FinishedAt: FinishedAt,
        Status: Status,
        TargetCount: TargetCount,
        FindingCount: FindingCount,
        Error: Error);
}

/// <summary>
/// In-process registry of active + recently-completed runs. Thread-safe.
/// Completed runs are retained for <see cref="RetentionWindow"/> then evicted
/// by a background timer so the dictionary cannot grow without bound.
/// Findings themselves persist in <c>findings.db</c> via the normal reporting
/// pipeline — this registry is only for UI-facing in-flight state.
/// </summary>
public sealed class RunManager : IDisposable
{
    public static readonly TimeSpan RetentionWindow = TimeSpan.FromHours(1);

    private readonly ConcurrentDictionary<Guid, RunRecord> _runs = new();
    private readonly IRunExecutor _executor;
    private readonly Timer _evictionTimer;
    private readonly TimeSpan _retention;

    public RunManager(IRunExecutor executor) : this(executor, RetentionWindow) { }

    internal RunManager(IRunExecutor executor, TimeSpan retention)
    {
        _executor = executor;
        _retention = retention;
        _evictionTimer = new Timer(
            _ => EvictExpired(),
            state: null,
            dueTime: TimeSpan.FromMinutes(5),
            period: TimeSpan.FromMinutes(5));
    }

    /// <summary>Start a run. Returns immediately with the new run id.</summary>
    public Guid StartRun(Drederick.Scope.Scope scope, RunOptions options)
    {
        var id = Guid.NewGuid();
        var record = new RunRecord(id, DateTimeOffset.UtcNow, options.Targets.Count);
        _runs[id] = record;

        var progress = new Progress<ScanEvent>(record.AddEvent);
        var ct = record.Cts.Token;

        record.Task = Task.Run(async () =>
        {
            try
            {
                var result = await _executor.RunAsync(scope, options, progress, ct)
                    .ConfigureAwait(false);
                record.FindingCount = result.HostCount;
                record.Status = "completed";
            }
            catch (OperationCanceledException)
            {
                record.Status = "cancelled";
            }
            catch (Exception ex)
            {
                record.Status = "failed";
                record.Error = ex.Message;
            }
            finally
            {
                record.FinishedAt = DateTimeOffset.UtcNow;
            }
        });

        return id;
    }

    public IReadOnlyList<RunRecordDto> List()
        => _runs.Values
            .OrderByDescending(r => r.StartedAt)
            .Select(r => r.ToDto())
            .ToList();

    public RunRecordDto? Get(Guid id)
        => _runs.TryGetValue(id, out var r) ? r.ToDto() : null;

    /// <summary>
    /// Cancel an in-flight run. Returns <c>null</c> if unknown, <c>true</c> if
    /// the CTS was triggered, <c>false</c> if the run was already finished.
    /// </summary>
    public bool? Cancel(Guid id)
    {
        if (!_runs.TryGetValue(id, out var r)) return null;
        if (r.FinishedAt.HasValue || r.Cts.IsCancellationRequested) return false;
        try { r.Cts.Cancel(); }
        catch (ObjectDisposedException) { return false; }
        return true;
    }

    public EventsBatchDto? Events(Guid id, DateTimeOffset? since, int maxBatch = 500)
    {
        if (!_runs.TryGetValue(id, out var r)) return null;
        var (events, truncated) = r.SnapshotEvents(since, maxBatch);
        var dtos = events.Select(e => new ScanEventDto(
            Kind: e.Kind.ToString(),
            Timestamp: e.Timestamp,
            Target: e.Target,
            Tool: e.Tool,
            Message: e.Message,
            ToolCallsTotal: e.ToolCallsTotal)).ToList();
        return new EventsBatchDto(id, since, dtos, truncated);
    }

    internal void EvictExpired()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _runs)
        {
            var r = kvp.Value;
            if (r.FinishedAt is { } fin && now - fin > _retention)
            {
                if (_runs.TryRemove(kvp.Key, out var removed))
                {
                    try { removed.Cts.Dispose(); } catch { }
                }
            }
        }
    }

    public void Dispose()
    {
        _evictionTimer.Dispose();
        foreach (var r in _runs.Values)
        {
            try { r.Cts.Dispose(); } catch { }
        }
    }
}
