using System.Text.Json;
using Drederick.Recon;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;

namespace Drederick.Enrichment;

/// <summary>
/// Orchestrates CVE enrichment of a completed recon run:
/// 1. Ensure the NVD cache is populated (tolerates offline).
/// 2. For every nmap port with product/version, ask <see cref="CpeMatcher"/>.
/// 3. Write each match via <see cref="SqliteReport.UpsertCve"/> and record a
///    <c>kind = "cve"</c> finding linking the service to the CVE id.
///
/// Idempotent: re-running the same recon + feed yields the same rows.
/// </summary>
public sealed class CveAnnotator
{
    private readonly NvdCache _cache;

    public CveAnnotator(NvdCache? cache = null)
    {
        _cache = cache ?? new NvdCache();
    }

    /// <summary>Result summary, mostly for tests and log output.</summary>
    public sealed record AnnotationResult(int CveCount, int FindingCount, bool CacheLoaded);

    public async Task<AnnotationResult> AnnotateAsync(
        IEnumerable<HostFinding> findings,
        string outputDir,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(findings);
        if (string.IsNullOrWhiteSpace(outputDir)) throw new ArgumentException("outputDir required", nameof(outputDir));

        IReadOnlyList<NvdEntry> entries;
        try
        {
            entries = await _cache.LoadAsync(ct).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            // No cache and refresh failed — nothing to annotate with. Stay quiet.
            return new AnnotationResult(0, 0, false);
        }

        var matcher = new CpeMatcher(entries);
        var report = new SqliteReport(outputDir);
        var now = DateTimeOffset.UtcNow.ToString("o");

        int cveCount = 0;
        int findingCount = 0;

        using var conn = new SqliteConnection($"Data Source={report.DatabasePath}");
        conn.Open();

        foreach (var host in findings)
        {
            if (host is null || string.IsNullOrWhiteSpace(host.Target) || host.Nmap is null) continue;
            var hostId = LookupHostId(conn, host.Target);
            if (hostId is null) continue;

            foreach (var port in host.Nmap.OpenPorts)
            {
                if (string.IsNullOrWhiteSpace(port.Product)) continue;
                var serviceId = LookupServiceId(conn, hostId.Value, port.Port, port.Protocol ?? "tcp");

                var matches = matcher.Match(vendor: null, product: port.Product!, version: port.Version);
                foreach (var m in matches)
                {
                    report.UpsertCve(m.CveId, m.Cvss, m.Summary, m.Published);
                    cveCount++;

                    var payload = JsonSerializer.Serialize(new CveFindingPayload(
                        m.CveId, m.Cvss, port.Product, port.Version));
                    if (InsertCveFinding(conn, hostId.Value, serviceId, payload, now))
                    {
                        findingCount++;
                    }
                }
            }
        }

        return new AnnotationResult(cveCount, findingCount, true);
    }

    private sealed record CveFindingPayload(string cve_id, double? cvss, string? product, string? version);

    private static long? LookupHostId(SqliteConnection conn, string address)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id FROM hosts WHERE address = $a LIMIT 1;";
        cmd.Parameters.AddWithValue("$a", address);
        var r = cmd.ExecuteScalar();
        return r is null or DBNull ? null : Convert.ToInt64(r);
    }

    private static long? LookupServiceId(SqliteConnection conn, long hostId, int port, string proto)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id FROM services WHERE host_id=$h AND port=$p AND proto=$pr LIMIT 1;";
        cmd.Parameters.AddWithValue("$h", hostId);
        cmd.Parameters.AddWithValue("$p", port);
        cmd.Parameters.AddWithValue("$pr", proto);
        var r = cmd.ExecuteScalar();
        return r is null or DBNull ? null : Convert.ToInt64(r);
    }

    private static bool InsertCveFinding(SqliteConnection conn, long hostId, long? serviceId,
        string dataJson, string now)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO findings(host_id, service_id, kind, data_json, created_at)
VALUES($h, $s, 'cve', $d, $c)
ON CONFLICT(host_id, COALESCE(service_id, 0), kind, data_json) DO NOTHING;";
        cmd.Parameters.AddWithValue("$h", hostId);
        cmd.Parameters.AddWithValue("$s", (object?)serviceId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$d", dataJson);
        cmd.Parameters.AddWithValue("$c", now);
        return cmd.ExecuteNonQuery() > 0;
    }
}
