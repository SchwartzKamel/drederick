using Drederick.Audit;

namespace Drederick.Ops.Tenable;

/// <summary>
/// Selection criteria for the "smart" pull. Exactly one of <see cref="ScanId"/>,
/// <see cref="ScanName"/>, or <see cref="Latest"/> must be set.
/// </summary>
public sealed class TenableScanSelector
{
    /// <summary>Pull the scan with this exact id.</summary>
    public int? ScanId { get; init; }

    /// <summary>Pull the most recently completed scan whose name matches (case-insensitive).</summary>
    public string? ScanName { get; init; }

    /// <summary>Pull the most recently completed scan, regardless of name.</summary>
    public bool Latest { get; init; }

    public bool Validate(out string error)
    {
        var count = (ScanId.HasValue ? 1 : 0) + (string.IsNullOrEmpty(ScanName) ? 0 : 1) + (Latest ? 1 : 0);
        if (count == 0) { error = "Provide one of --tenable-scan-id, --tenable-scan-name, or --tenable-latest."; return false; }
        if (count > 1) { error = "--tenable-scan-id, --tenable-scan-name, and --tenable-latest are mutually exclusive."; return false; }
        error = ""; return true;
    }
}

/// <summary>
/// Options controlling cache, polling, and export format for <see cref="TenableApiPuller"/>.
/// </summary>
public sealed class TenableApiPullOptions
{
    /// <summary>Export format requested from the API (<c>nessus</c> or <c>csv</c>).</summary>
    public string Format { get; init; } = "nessus";

    /// <summary>Directory under which exports are cached (default <c>&lt;out&gt;/tenable_cache</c>).</summary>
    public string CacheRoot { get; init; } = "tenable_cache";

    /// <summary>If true, ignore the cache and always re-export.</summary>
    public bool NoCache { get; init; }

    /// <summary>Maximum total time spent polling for export readiness.</summary>
    public TimeSpan PollTimeout { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Initial poll delay; the puller doubles this up to <see cref="MaxPollInterval"/>.</summary>
    public TimeSpan InitialPollInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Cap on the exponential-backoff poll interval.</summary>
    public TimeSpan MaxPollInterval { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// The result of a pull: where the bytes were written and which scan/file ids
/// produced them.
/// </summary>
public sealed class TenableApiPullResult
{
    public required int ScanId { get; init; }
    public required string ScanName { get; init; }
    public required long FileId { get; init; }
    public required string Format { get; init; }
    public required string CachedPath { get; init; }
    public required bool FromCache { get; init; }
    public required long LastModificationDate { get; init; }
}

/// <summary>
/// "Smart" Tenable.io pulling. Wraps <see cref="TenableApiClient"/> with:
///   * scan selection (latest / by name / by id),
///   * a deterministic on-disk cache so repeated runs do not re-export,
///   * exponential-backoff polling on <c>GET /export/.../status</c>,
///   * audit events on every meaningful step (<c>tenable.api.list</c>,
///     <c>tenable.api.select</c>, <c>tenable.api.export.request</c>,
///     <c>tenable.api.export.ready</c>, <c>tenable.api.cache.hit</c>,
///     <c>tenable.api.download</c>).
///
/// The caller hands the resulting cached file to
/// <c>TenableScanImporter.Parse</c>, reusing every test path validated for the
/// file-based ingest flow.
/// </summary>
public sealed class TenableApiPuller
{
    private readonly ITenableExportBackend _client;
    private readonly AuditLog _audit;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public TenableApiPuller(
        ITenableExportBackend client,
        AuditLog audit,
        Func<DateTimeOffset>? utcNow = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        _delay = delay ?? Task.Delay;
    }

    /// <summary>
    /// Resolve the scan, request (or reuse a cached) export, poll until ready, and
    /// download the bytes to <c>&lt;CacheRoot&gt;/&lt;scan_id&gt;-&lt;last_mod&gt;.&lt;ext&gt;</c>.
    /// </summary>
    public async Task<TenableApiPullResult> PullAsync(
        TenableScanSelector selector,
        TenableApiPullOptions options,
        CancellationToken ct = default)
    {
        if (!selector.Validate(out var error))
            throw new ArgumentException(error, nameof(selector));

        // 1. Find the scan we want.
        var scan = await SelectScanAsync(selector, ct);

        // 2. Compute the deterministic cache path (scan id + last_modification_date).
        var ext = options.Format.Equals("csv", StringComparison.OrdinalIgnoreCase) ? ".csv" : ".nessus";
        Directory.CreateDirectory(options.CacheRoot);
        var cachedPath = Path.Combine(
            options.CacheRoot,
            $"{scan.Id}-{scan.LastModificationDate}{ext}");

        // 3. Cache hit short-circuit.
        if (!options.NoCache && File.Exists(cachedPath))
        {
            _audit.Record("tenable.api.cache.hit", new Dictionary<string, object?>
            {
                ["scan_id"] = scan.Id,
                ["scan_name"] = scan.Name,
                ["path"] = cachedPath,
                ["last_modification_date"] = scan.LastModificationDate,
                ["key_digest"] = _client.AccessKeyDigest,
                ["backend"] = _client.BackendName,
            });
            return new TenableApiPullResult
            {
                ScanId = scan.Id,
                ScanName = scan.Name ?? "",
                FileId = -1,
                Format = options.Format,
                CachedPath = cachedPath,
                FromCache = true,
                LastModificationDate = scan.LastModificationDate,
            };
        }

        // 4. Request export, poll, download.
        var fileId = await _client.RequestExportAsync(scan.Id, options.Format, ct);
        _audit.Record("tenable.api.export.request", new Dictionary<string, object?>
        {
            ["scan_id"] = scan.Id,
            ["scan_name"] = scan.Name,
            ["file_id"] = fileId,
            ["format"] = options.Format,
            ["key_digest"] = _client.AccessKeyDigest,
            ["backend"] = _client.BackendName,
        });

        await PollUntilReadyAsync(scan.Id, fileId, options, ct);

        var bytes = await _client.DownloadExportAsync(scan.Id, fileId, ct);
        await File.WriteAllBytesAsync(cachedPath, bytes, ct);

        _audit.Record("tenable.api.download", new Dictionary<string, object?>
        {
            ["scan_id"] = scan.Id,
            ["scan_name"] = scan.Name,
            ["file_id"] = fileId,
            ["bytes"] = bytes.LongLength,
            ["path"] = cachedPath,
            ["key_digest"] = _client.AccessKeyDigest,
            ["backend"] = _client.BackendName,
        });

        return new TenableApiPullResult
        {
            ScanId = scan.Id,
            ScanName = scan.Name ?? "",
            FileId = fileId,
            Format = options.Format,
            CachedPath = cachedPath,
            FromCache = false,
            LastModificationDate = scan.LastModificationDate,
        };
    }

    private async Task<TenableScanSummary> SelectScanAsync(TenableScanSelector selector, CancellationToken ct)
    {
        var scans = await _client.ListScansAsync(ct);
        _audit.Record("tenable.api.list", new Dictionary<string, object?>
        {
            ["count"] = scans.Count,
            ["key_digest"] = _client.AccessKeyDigest,
            ["backend"] = _client.BackendName,
        });

        TenableScanSummary? chosen = null;

        if (selector.ScanId is int wantId)
        {
            chosen = scans.FirstOrDefault(s => s.Id == wantId)
                ?? throw new TenableApiException($"Tenable: scan id {wantId} not visible to this API key.");
        }
        else if (!string.IsNullOrEmpty(selector.ScanName))
        {
            chosen = scans
                .Where(s => string.Equals(s.Name, selector.ScanName, StringComparison.OrdinalIgnoreCase))
                .Where(s => IsCompleted(s.Status))
                .OrderByDescending(s => s.LastModificationDate)
                .FirstOrDefault()
                ?? throw new TenableApiException(
                    $"Tenable: no completed scan named '{selector.ScanName}' visible to this API key.");
        }
        else if (selector.Latest)
        {
            chosen = scans
                .Where(s => IsCompleted(s.Status))
                .OrderByDescending(s => s.LastModificationDate)
                .FirstOrDefault()
                ?? throw new TenableApiException(
                    "Tenable: no completed scans visible to this API key.");
        }

        // Validate() guarantees one branch above set chosen.
        var pick = chosen!;
        _audit.Record("tenable.api.select", new Dictionary<string, object?>
        {
            ["scan_id"] = pick.Id,
            ["scan_name"] = pick.Name,
            ["status"] = pick.Status,
            ["last_modification_date"] = pick.LastModificationDate,
            ["key_digest"] = _client.AccessKeyDigest,
            ["backend"] = _client.BackendName,
        });
        return pick;
    }

    private static bool IsCompleted(string? status) =>
        !string.IsNullOrEmpty(status) &&
        (status.Equals("completed", StringComparison.OrdinalIgnoreCase) ||
         status.Equals("imported", StringComparison.OrdinalIgnoreCase));

    private async Task PollUntilReadyAsync(int scanId, long fileId, TenableApiPullOptions options, CancellationToken ct)
    {
        var deadline = _utcNow() + options.PollTimeout;
        var interval = options.InitialPollInterval;
        var attempts = 0;
        while (true)
        {
            var status = await _client.GetExportStatusAsync(scanId, fileId, ct);
            attempts++;
            if (string.Equals(status, "ready", StringComparison.OrdinalIgnoreCase))
            {
                _audit.Record("tenable.api.export.ready", new Dictionary<string, object?>
                {
                    ["scan_id"] = scanId,
                    ["file_id"] = fileId,
                    ["attempts"] = attempts,
                    ["key_digest"] = _client.AccessKeyDigest,
                    ["backend"] = _client.BackendName,
                });
                return;
            }
            if (_utcNow() >= deadline)
            {
                throw new TenableApiException(
                    $"Tenable: export scan {scanId} file {fileId} not ready after {options.PollTimeout.TotalSeconds:0}s " +
                    $"(last status='{status}', {attempts} polls).");
            }
            await _delay(interval, ct);
            // Exponential backoff capped at MaxPollInterval.
            var next = TimeSpan.FromMilliseconds(Math.Min(
                interval.TotalMilliseconds * 2, options.MaxPollInterval.TotalMilliseconds));
            interval = next;
        }
    }
}
