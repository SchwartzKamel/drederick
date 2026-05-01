namespace Drederick.Enrichment.FingerprintStack;

/// <summary>
/// Pure-data bundle handed to every <see cref="Signals.IFingerprintSignal"/>.
/// All network I/O has already happened in <see cref="FingerprintStackTool"/>;
/// signals operate on this structure deterministically so they can be
/// fixture-tested without reaching the wire.
/// </summary>
public sealed class FingerprintInput
{
    public string Target { get; init; } = "";
    public int? Port { get; init; }

    /// <summary>Raw service banner (nmap product+version+extra, FTP/SSH banner, etc).</summary>
    public string? Banner { get; init; }

    public string? NmapProduct { get; init; }
    public string? NmapVersion { get; init; }

    public string? TlsSubject { get; init; }
    public string? TlsIssuer { get; init; }
    public IReadOnlyList<string> TlsSubjectAltNames { get; init; } = Array.Empty<string>();

    /// <summary>HTTP "Server" response header value, if known.</summary>
    public string? HttpServer { get; init; }

    /// <summary>Selected HTTP response headers (lower-cased keys preferred).</summary>
    public IReadOnlyDictionary<string, string> HttpHeaders { get; init; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>SHA-256 of /favicon.ico body in lowercase hex, or null if unavailable.</summary>
    public string? FaviconSha256 { get; init; }

    /// <summary>JA3 fingerprint hash, or null if unavailable.</summary>
    public string? Ja3 { get; init; }

    /// <summary>JA4 fingerprint hash, or null if unavailable.</summary>
    public string? Ja4 { get; init; }
}
