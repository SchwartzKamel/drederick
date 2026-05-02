namespace Drederick.Ops.Tenable;

/// <summary>
/// Backend abstraction for "smart" Tenable export pulling. Every concrete
/// backend (Tenable.io, Nessus Professional, Tenable.sc / SecurityCenter)
/// reduces to four operations:
///
///   1. <see cref="ListScansAsync"/> — enumerate scans visible to the API key,
///   2. <see cref="RequestExportAsync"/> — kick off an export (or return a
///      synthetic file id when the backend's download is synchronous),
///   3. <see cref="GetExportStatusAsync"/> — poll for export readiness
///      (always <c>"ready"</c> when the backend's download is synchronous),
///   4. <see cref="DownloadExportAsync"/> — return the export bytes.
///
/// The shape mirrors Tenable.io's documented export workflow because that is
/// the most general of the three (Nessus Pro is byte-for-byte identical;
/// Tenable.sc collapses request+download into a single synchronous POST).
/// Keeping the interface uniform lets <see cref="TenableApiPuller"/> emit
/// the same audit events for every backend.
/// </summary>
public interface ITenableExportBackend : IDisposable
{
    /// <summary>SHA-256 prefix of the credential identifier, suitable for audit correlation.</summary>
    string AccessKeyDigest { get; }

    /// <summary>Human-readable backend name for audit (<c>tenable.io</c>, <c>nessus</c>, <c>tenable.sc</c>).</summary>
    string BackendName { get; }

    Task<IReadOnlyList<TenableScanSummary>> ListScansAsync(CancellationToken ct = default);

    Task<long> RequestExportAsync(int scanId, string format, CancellationToken ct = default);

    Task<string> GetExportStatusAsync(int scanId, long fileId, CancellationToken ct = default);

    Task<byte[]> DownloadExportAsync(int scanId, long fileId, CancellationToken ct = default);
}
