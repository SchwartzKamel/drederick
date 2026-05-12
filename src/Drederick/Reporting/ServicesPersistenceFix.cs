using Drederick.Recon;

namespace Drederick.Reporting;

// --- htb-findings-db-service-persistence ---
//
// GAP-040 (pterodactyl-R1 follow-up): the previous fix covered NativeScan
// fallback but missed the case where nmap returns zero ports and service
// discovery comes purely from HTTP banner / fingerprint stack / CMS
// fingerprint signals. <see cref="CveAnnotator"/> happily harvests product
// candidates from all of those signals and writes <c>findings(kind='cve')</c>
// rows, but <see cref="SqliteReport.WriteReport"/> never created the
// corresponding <c>services</c> rows — leaving the findings.db pterodactyl-R1
// audit shows: <c>cve.annotate cves=36 findings=36</c> yet
// <c>SELECT COUNT(*) FROM services WHERE host=…</c> returns 0.
//
// This helper enumerates (port, proto, service, product, version) tuples
// derived from the *non-nmap* signals attached to a <see cref="HostFinding"/>
// so <see cref="SqliteReport.WriteReport"/> can upsert them. Idempotent by
// (host_id, port, proto) thanks to the table's unique index.
/// <summary>
/// Harvests service tuples (port + proto + service/product/version) from
/// every recon signal on a <see cref="HostFinding"/> that carries a port
/// and is *not* already covered by <see cref="HostFinding.Nmap"/> or
/// <see cref="HostFinding.NativeScan"/>. Output is consumed by
/// <see cref="SqliteReport.WriteReport"/>.
/// </summary>
public static class ServicesPersistenceFix
{
    public readonly record struct ServiceTuple(
        int Port,
        string Protocol,
        string? Service,
        string? Product,
        string? Version);

    public static IEnumerable<ServiceTuple> HarvestNonNmapServiceTuples(HostFinding host)
    {
        ArgumentNullException.ThrowIfNull(host);

        // HTTP — every probed URL implies an open TCP port. Server header,
        // when present, yields product/version.
        foreach (var h in host.Http)
        {
            var port = PortFromUrl(h?.Url);
            if (port <= 0) continue;
            var scheme = SchemeFromUrl(h!.Url);
            var (product, version) = ParseServerBanner(h.Server);
            yield return new ServiceTuple(
                port,
                "tcp",
                scheme, // "http" / "https"
                product,
                version);
        }

        // Fingerprint stack — port-bound product candidates.
        foreach (var fp in host.Fingerprint)
        {
            if (fp is null || fp.Port is null || fp.Port.Value <= 0) continue;
            var top = fp.Candidates.Count > 0 ? fp.Candidates[0] : null;
            yield return new ServiceTuple(
                fp.Port.Value,
                "tcp",
                Service: null,
                Product: string.IsNullOrWhiteSpace(top?.Product) ? null : top!.Product,
                Version: string.IsNullOrWhiteSpace(top?.Version) ? null : top!.Version);
        }

        // CMS fingerprint — BaseUrl gives the port; highest-confidence match
        // gives the product/version.
        foreach (var cms in host.CmsFingerprint)
        {
            if (cms is null) continue;
            var port = PortFromUrl(cms.BaseUrl);
            if (port <= 0) port = SchemeFromUrl(cms.BaseUrl) == "https" ? 443 : 80;
            CmsMatch? best = null;
            foreach (var m in cms.Matches)
            {
                if (m is null || string.IsNullOrWhiteSpace(m.Name)) continue;
                if (best is null || m.Confidence > best.Confidence) best = m;
            }
            yield return new ServiceTuple(
                port,
                "tcp",
                Service: SchemeFromUrl(cms.BaseUrl),
                Product: best?.Name,
                Version: best?.Version);
        }

        // TLS — record the port (no product/version typically; the cipher
        // suite payload lives in `findings`).
        foreach (var t in host.Tls)
        {
            if (t is null || t.Port <= 0) continue;
            yield return new ServiceTuple(
                t.Port,
                "tcp",
                Service: "tls",
                Product: null,
                Version: null);
        }
    }

    internal static int PortFromUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return 0;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return 0;
        if (u.Port > 0) return u.Port;
        return u.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80;
    }

    internal static string? SchemeFromUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return null;
        return u.Scheme.ToLowerInvariant();
    }

    // Very small Server-header parser: takes "Apache/2.4.49 (Ubuntu)" →
    // ("Apache", "2.4.49"). Anything we can't parse cleanly returns
    // (null, null) so the existing COALESCE-on-upsert semantics preserve
    // whatever the previous row recorded.
    internal static (string? product, string? version) ParseServerBanner(string? server)
    {
        if (string.IsNullOrWhiteSpace(server)) return (null, null);
        var trimmed = server.Trim();
        var space = trimmed.IndexOf(' ');
        var head = space > 0 ? trimmed[..space] : trimmed;
        var slash = head.IndexOf('/');
        if (slash <= 0) return (head, null);
        var product = head[..slash];
        var version = head[(slash + 1)..];
        return (string.IsNullOrWhiteSpace(product) ? null : product,
                string.IsNullOrWhiteSpace(version) ? null : version);
    }
}
// --- end htb-findings-db-service-persistence ---
