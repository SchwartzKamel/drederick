using System.Threading.Channels;
using Drederick.Recon;

namespace Drederick.Agent;

/// <summary>
/// A single follow-up probe work item. Carries enough identity metadata
/// (<see cref="Tool"/>, <see cref="Target"/>, <see cref="Port"/>) for audit and
/// diagnostics, plus an opaque executable closure <see cref="Run"/> because the
/// concrete recon tools have heterogeneous method signatures (nmap takes a
/// port spec, http takes a TLS flag, dns takes nothing) — forcing a uniform
/// ScanAsync on <see cref="IReconTool"/> would throw away useful parameters.
/// </summary>
public readonly record struct ScanJob(
    IReconTool Tool,
    string Target,
    int Port,
    Func<CancellationToken, Task> Run);

/// <summary>
/// Bounded per-host service-probe worker pool. Owns a single
/// <see cref="Channel{ScanJob}"/> (bounded, <see cref="BoundedChannelFullMode.Wait"/>
/// for true producer back-pressure) and a fixed set of worker tasks draining it.
///
/// Lifecycle: the caller passes a producer delegate to <see cref="RunAsync"/>.
/// Workers start; the producer enqueues jobs via <see cref="EnqueueAsync"/>;
/// when the producer returns the channel is completed and workers finish
/// draining the queue before <see cref="RunAsync"/> returns.
/// </summary>
public sealed class ServiceWorkerPool
{
    private readonly Channel<ScanJob> _channel;
    private readonly int _concurrency;

    public ServiceWorkerPool(int concurrency)
    {
        _concurrency = Math.Max(1, concurrency);
        _channel = Channel.CreateBounded<ScanJob>(new BoundedChannelOptions(_concurrency)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = false,
        });
    }

    public int Concurrency => _concurrency;

    /// <summary>Enqueue a job, waiting if the bounded channel is full.</summary>
    public ValueTask EnqueueAsync(ScanJob job, CancellationToken ct) =>
        _channel.Writer.WriteAsync(job, ct);

    /// <summary>
    /// Run the pool: spin up workers, invoke <paramref name="producer"/> (which
    /// should enqueue jobs), then drain the channel and wait for workers.
    /// </summary>
    public async Task RunAsync(
        Func<ServiceWorkerPool, Task> producer,
        Action<ScanJob, Exception>? onJobError,
        CancellationToken ct)
    {
        var workers = new Task[_concurrency];
        for (int i = 0; i < _concurrency; i++)
        {
            workers[i] = Task.Run(async () =>
            {
                await foreach (var job in _channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
                {
                    try
                    {
                        await job.Run(ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        onJobError?.Invoke(job, ex);
                    }
                }
            }, ct);
        }

        try
        {
            await producer(this).ConfigureAwait(false);
        }
        finally
        {
            _channel.Writer.TryComplete();
        }
        await Task.WhenAll(workers).ConfigureAwait(false);
    }
}

/// <summary>
/// Bounded host-level worker pool. Replaces the old per-host
/// <see cref="SemaphoreSlim"/> fan-out with an explicit
/// <see cref="Channel{String}"/> of host targets so we get true back-pressure
/// (producer waits when the channel is full) and a single cancellation path.
///
/// Each host consumer is handed a fresh <see cref="ServiceWorkerPool"/> so the
/// per-host scan routine can enqueue service probes that run bounded by
/// <see cref="ServiceConcurrency"/> — giving us two independent concurrency
/// knobs without one starving the other.
/// </summary>
public sealed class HostWorkerPool
{
    public const int MinConcurrency = 1;
    public const int MaxHostConcurrency = 32;
    public const int MaxServiceConcurrency = 64;

    public int HostConcurrency { get; }
    public int ServiceConcurrency { get; }

    public HostWorkerPool(int hostConcurrency, int serviceConcurrency)
    {
        HostConcurrency = Math.Clamp(hostConcurrency, MinConcurrency, MaxHostConcurrency);
        ServiceConcurrency = Math.Clamp(serviceConcurrency, MinConcurrency, MaxServiceConcurrency);
    }

    /// <summary>
    /// Drain <paramref name="targets"/> through <paramref name="perHost"/>,
    /// honouring <see cref="HostConcurrency"/>. Each invocation receives a
    /// fresh <see cref="ServiceWorkerPool"/> bounded by
    /// <see cref="ServiceConcurrency"/>; the pool is fully drained before the
    /// host is considered done.
    /// </summary>
    public async Task RunAsync(
        IEnumerable<string> targets,
        Func<string, ServiceWorkerPool, CancellationToken, Task> perHost,
        Action<string, Exception>? onHostError,
        CancellationToken ct)
    {
        var hostChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(HostConcurrency)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = true,
        });

        var producer = Task.Run(async () =>
        {
            try
            {
                foreach (var t in targets)
                {
                    await hostChannel.Writer.WriteAsync(t, ct).ConfigureAwait(false);
                }
            }
            finally
            {
                hostChannel.Writer.TryComplete();
            }
        }, ct);

        var workers = new Task[HostConcurrency];
        for (int i = 0; i < HostConcurrency; i++)
        {
            workers[i] = Task.Run(async () =>
            {
                await foreach (var host in hostChannel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
                {
                    var svcPool = new ServiceWorkerPool(ServiceConcurrency);
                    try
                    {
                        await svcPool.RunAsync(
                            pool => perHost(host, pool, ct),
                            onJobError: null,
                            ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        onHostError?.Invoke(host, ex);
                    }
                }
            }, ct);
        }

        await Task.WhenAll(workers.Append(producer)).ConfigureAwait(false);
    }
}
