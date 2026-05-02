using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;

namespace Drederick.Recon;

/// <summary>
/// Fast first-pass host-discovery sweep. Probes a small set of "known-noisy"
/// TCP ports per target in parallel; the first successful TCP connect marks
/// a host as alive. Designed for /N corp-style scopes (HTB Pro Labs,
/// OSCP-style ranges) where deep-scanning every host is wasteful — feed
/// alive hosts (and their <see cref="HostDiscoveryResult.RespondingPorts"/>
/// seeds) into downstream port scanners.
///
/// Scope-enforced: <see cref="Scope.Scope.Require"/> is the first statement
/// of every public method (per <c>@invariant-id:scope-in-every-tool</c>),
/// and is re-checked for every target before any socket is opened.
/// Bounded concurrency via <see cref="SemaphoreSlim"/> caps in-flight
/// connect attempts so a /16 sweep does not melt the workstation.
/// </summary>
public sealed class HostDiscoveryTool : IReconTool
{
    public string Name => "host-discovery";

    public string Description =>
        "Fast TCP-knock sweep across a /N scope. Probes a small set of " +
        "known-noisy TCP ports per target in parallel; first hit marks a " +
        "host as alive and seeds downstream port-scan with the responding " +
        "ports. Every target MUST be inside the authorized scope.";

    /// <summary>
    /// Default probe ports. Curated to maximise the chance of hitting at
    /// least one open port on a corp-style box: web (80/443), SSH (22),
    /// SMB (445), RDP (3389), WinRM (5985).
    /// </summary>
    public static readonly IReadOnlyList<int> DefaultProbePorts =
        new[] { 80, 443, 22, 445, 3389, 5985 };

    public const int DefaultConnectTimeoutMs = 1500;
    public const int DefaultMaxConcurrency = 256;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;

    public HostDiscoveryTool(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope;
        _audit = audit;
    }

    /// <summary>
    /// Sweep <paramref name="targets"/> and return one
    /// <see cref="HostDiscoveryResult"/> per target. Probes run in parallel
    /// across all targets and ports, capped by <paramref name="maxConcurrency"/>.
    /// First successful connect on any probe port marks the host alive;
    /// remaining probes against that same target are cancelled to free
    /// concurrency slots for the rest of the sweep.
    /// </summary>
    /// <param name="targets">Targets to probe. Each is validated against the
    /// authorized scope before any socket is opened; out-of-scope targets
    /// raise <see cref="Scope.ScopeException"/>.</param>
    /// <param name="ports">Probe ports. Defaults to
    /// <see cref="DefaultProbePorts"/>.</param>
    /// <param name="connectTimeoutMs">Per-probe TCP connect timeout. Default
    /// <see cref="DefaultConnectTimeoutMs"/>.</param>
    /// <param name="maxConcurrency">Hard cap on in-flight connect attempts
    /// across the whole sweep. Default <see cref="DefaultMaxConcurrency"/>.</param>
    /// <param name="ct">Caller cancellation token.</param>
    public Task<IReadOnlyList<HostDiscoveryResult>> SweepAsync(
        IEnumerable<string> targets,
        IReadOnlyList<int>? ports = null,
        int connectTimeoutMs = DefaultConnectTimeoutMs,
        int maxConcurrency = DefaultMaxConcurrency,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targets);

        var targetList = targets.ToList();

        // Scope check first — must reject before any side effect (audit or socket).
        foreach (var t in targetList)
        {
            _scope.Require(t);
        }

        return SweepInternalAsync(
            targetList,
            ports ?? DefaultProbePorts,
            connectTimeoutMs,
            maxConcurrency,
            inFlightObserver: null,
            ct);
    }

    /// <summary>
    /// Test hook: identical to <see cref="SweepAsync"/> but invokes
    /// <paramref name="inFlightObserver"/> immediately before and after each
    /// connect attempt so concurrency-cap regressions can be asserted. Not
    /// part of the public LLM-visible surface.
    /// </summary>
    internal Task<IReadOnlyList<HostDiscoveryResult>> SweepWithObserverAsync(
        IEnumerable<string> targets,
        IReadOnlyList<int>? ports,
        int connectTimeoutMs,
        int maxConcurrency,
        Action<int> inFlightObserver,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentNullException.ThrowIfNull(inFlightObserver);

        var targetList = targets.ToList();
        foreach (var t in targetList) _scope.Require(t);

        return SweepInternalAsync(
            targetList,
            ports ?? DefaultProbePorts,
            connectTimeoutMs,
            maxConcurrency,
            inFlightObserver,
            ct);
    }

    private async Task<IReadOnlyList<HostDiscoveryResult>> SweepInternalAsync(
        List<string> targetList,
        IReadOnlyList<int> ports,
        int connectTimeoutMs,
        int maxConcurrency,
        Action<int>? inFlightObserver,
        CancellationToken ct)
    {
        var portArr = ports.ToArray();
        var portsDigest = ComputePortsDigest(portArr);
        var cap = Math.Max(1, maxConcurrency);
        var timeout = Math.Max(1, connectTimeoutMs);

        _audit.Record("host-discovery.start", new Dictionary<string, object?>
        {
            ["target_count"] = targetList.Count,
            ["port_count"] = portArr.Length,
            ["ports_digest"] = portsDigest,
            ["concurrency_cap"] = cap,
            ["connect_timeout_ms"] = timeout,
        });

        using var sem = new SemaphoreSlim(cap, cap);
        var inFlight = 0;
        var results = new HostDiscoveryResult[targetList.Count];

        var sweepTasks = new Task[targetList.Count];
        for (var i = 0; i < targetList.Count; i++)
        {
            var idx = i;
            var target = targetList[idx];
            sweepTasks[idx] = Task.Run(async () =>
            {
                results[idx] = await ProbeOneTargetAsync(
                    target, portArr, timeout, sem, inFlightObserver,
                    () => Interlocked.Increment(ref inFlight),
                    () => Interlocked.Decrement(ref inFlight),
                    ct).ConfigureAwait(false);
            }, ct);
        }

        try
        {
            await Task.WhenAll(sweepTasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _audit.Record("host-discovery.cancel", new Dictionary<string, object?>
            {
                ["target_count"] = targetList.Count,
            });
            throw;
        }

        var aliveCount = results.Count(r => r is { Alive: true });
        _audit.Record("host-discovery.finish", new Dictionary<string, object?>
        {
            ["target_count"] = targetList.Count,
            ["alive_count"] = aliveCount,
            ["ports_digest"] = portsDigest,
        });

        return results;
    }

    private static async Task<HostDiscoveryResult> ProbeOneTargetAsync(
        string target,
        int[] ports,
        int timeoutMs,
        SemaphoreSlim sem,
        Action<int>? inFlightObserver,
        Func<int> incrementInFlight,
        Func<int> decrementInFlight,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var responding = new ConcurrentBag<int>();

        // Per-target token: when the first probe succeeds we cancel siblings
        // so the rest of the sweep gets its concurrency slots back fast.
        using var perTargetCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var probeTasks = new Task[ports.Length];
        for (var i = 0; i < ports.Length; i++)
        {
            var port = ports[i];
            probeTasks[i] = Task.Run(async () =>
            {
                try
                {
                    await sem.WaitAsync(perTargetCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                try
                {
                    if (perTargetCts.IsCancellationRequested) return;

                    var current = incrementInFlight();
                    inFlightObserver?.Invoke(current);
                    try
                    {
                        var ok = await TryConnectAsync(target, port, timeoutMs, perTargetCts.Token)
                            .ConfigureAwait(false);
                        if (ok)
                        {
                            responding.Add(port);
                            // Free remaining probes against this target.
                            try { perTargetCts.Cancel(); } catch { }
                        }
                    }
                    finally
                    {
                        var afterDec = decrementInFlight();
                        inFlightObserver?.Invoke(afterDec);
                    }
                }
                finally
                {
                    sem.Release();
                }
            }, perTargetCts.Token);
        }

        string? error = null;
        try
        {
            await Task.WhenAll(probeTasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            // Expected: per-target cancel after first successful probe.
        }
        catch (Exception ex)
        {
            error = ex.GetType().Name;
        }

        sw.Stop();

        return new HostDiscoveryResult
        {
            Target = target,
            Alive = !responding.IsEmpty,
            RespondingPorts = responding.OrderBy(p => p).ToList(),
            ProbeDurationMs = sw.ElapsedMilliseconds,
            Error = error,
        };
    }

    private static async Task<bool> TryConnectAsync(
        string host,
        int port,
        int timeoutMs,
        CancellationToken ct)
    {
        using var tcp = new TcpClient();
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connectCts.CancelAfter(timeoutMs);

        try
        {
            await tcp.ConnectAsync(host, port, connectCts.Token).ConfigureAwait(false);
            return tcp.Connected;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private static string ComputePortsDigest(int[] ports)
    {
        var text = string.Join(",", ports.OrderBy(p => p));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
