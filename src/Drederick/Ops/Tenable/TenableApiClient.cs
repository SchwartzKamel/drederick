using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Drederick.Ops.Tenable;

/// <summary>
/// Result of <see cref="TenableApiClient.ListScansAsync"/>.
/// </summary>
public sealed class TenableScanSummary
{
    [JsonPropertyName("id")] public int Id { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    /// <summary>Unix timestamp of the last scan completion (per Tenable.io schema).</summary>
    [JsonPropertyName("last_modification_date")] public long LastModificationDate { get; set; }
    [JsonPropertyName("creation_date")] public long CreationDate { get; set; }
    [JsonPropertyName("uuid")] public string? Uuid { get; set; }
}

/// <summary>
/// Status response from <c>GET /scans/{scan_id}/export/{file_id}/status</c>.
/// </summary>
public sealed class TenableExportStatus
{
    [JsonPropertyName("status")] public string? Status { get; set; }
}

/// <summary>
/// Thin wrapper over the Tenable.io REST API. Implements only the four endpoints
/// needed for ingestion: list scans, request export, poll status, download bytes.
///
/// The client uses Tenable's standard <c>X-ApiKeys: accessKey=…; secretKey=…</c>
/// authentication header. It does not log credentials; only an SHA-256 prefix of
/// the access key (first 12 hex chars) is exposed via <see cref="AccessKeyDigest"/>
/// for audit correlation.
///
/// Network policy: the Tenable.io endpoint is a metadata source (like NVD or
/// GHSA), not a scan target — every request is to the operator-configured
/// management plane URL (default <c>https://cloud.tenable.com</c>), never to
/// hosts in the engagement scope. This mirrors how
/// <c>Drederick.Enrichment.NvdCache</c> and <c>GhsaSource</c> reach external
/// services without participating in the per-target scope check.
/// </summary>
public sealed class TenableApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly string _baseUrl;

    /// <summary>SHA-256 prefix of the access key, suitable for audit correlation.</summary>
    public string AccessKeyDigest { get; }

    /// <summary>
    /// Construct a client with the given <paramref name="baseUrl"/> (e.g.
    /// <c>https://cloud.tenable.com</c>), <paramref name="accessKey"/> and
    /// <paramref name="secretKey"/>. Optionally accept an injected
    /// <paramref name="httpClient"/> for tests; if null, a fresh client with a
    /// 60-second timeout is constructed and owned by this instance.
    /// </summary>
    public TenableApiClient(string baseUrl, string accessKey, string secretKey, HttpClient? httpClient = null)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) throw new ArgumentException("baseUrl required", nameof(baseUrl));
        if (string.IsNullOrWhiteSpace(accessKey)) throw new ArgumentException("accessKey required", nameof(accessKey));
        if (string.IsNullOrWhiteSpace(secretKey)) throw new ArgumentException("secretKey required", nameof(secretKey));

        _baseUrl = baseUrl.TrimEnd('/');
        _ownsClient = httpClient is null;
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        // X-ApiKeys is Tenable's documented header. Format is "accessKey=AAAA;secretKey=BBBB".
        _http.DefaultRequestHeaders.Remove("X-ApiKeys");
        _http.DefaultRequestHeaders.TryAddWithoutValidation(
            "X-ApiKeys",
            $"accessKey={accessKey};secretKey={secretKey}");
        _http.DefaultRequestHeaders.UserAgent.Clear();
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("drederick", "1.0"));

        AccessKeyDigest = ComputeKeyDigest(accessKey);
    }

    private static string ComputeKeyDigest(string accessKey)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(accessKey));
        var sb = new StringBuilder();
        for (int i = 0; i < 6; i++) sb.Append(hash[i].ToString("x2"));
        return sb.ToString();
    }

    /// <summary>List all scans visible to the API key. Returns an empty list when the API returns no scans.</summary>
    public async Task<IReadOnlyList<TenableScanSummary>> ListScansAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{_baseUrl}/scans", ct);
        await EnsureSuccessAsync(resp, "list scans");
        var json = await resp.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("scans", out var scans) || scans.ValueKind != JsonValueKind.Array)
            return Array.Empty<TenableScanSummary>();
        var result = new List<TenableScanSummary>(scans.GetArrayLength());
        foreach (var s in scans.EnumerateArray())
        {
            var item = s.Deserialize<TenableScanSummary>();
            if (item is not null) result.Add(item);
        }
        return result;
    }

    /// <summary>
    /// Request an export of scan <paramref name="scanId"/> in <paramref name="format"/>
    /// (one of <c>nessus</c>, <c>csv</c>, <c>html</c>, <c>pdf</c>; <c>nessus</c> and
    /// <c>csv</c> are the formats <see cref="TenableScanImporter"/> can ingest).
    /// Returns the export <c>file</c> id used to poll for completion.
    /// </summary>
    public async Task<long> RequestExportAsync(int scanId, string format, CancellationToken ct = default)
    {
        var body = JsonSerializer.Serialize(new { format });
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        using var resp = await _http.PostAsync($"{_baseUrl}/scans/{scanId}/export", content, ct);
        await EnsureSuccessAsync(resp, $"request export scan {scanId}");
        var json = await resp.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("file", out var fileEl) &&
            (fileEl.ValueKind == JsonValueKind.Number || fileEl.ValueKind == JsonValueKind.String))
        {
            if (fileEl.ValueKind == JsonValueKind.Number) return fileEl.GetInt64();
            if (long.TryParse(fileEl.GetString(), out var asLong)) return asLong;
        }
        throw new TenableApiException(
            $"Tenable API: /scans/{scanId}/export response missing 'file' id. Body: {Truncate(json, 256)}");
    }

    /// <summary>Get the export status (<c>"loading"</c> or <c>"ready"</c>).</summary>
    public async Task<string> GetExportStatusAsync(int scanId, long fileId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{_baseUrl}/scans/{scanId}/export/{fileId}/status", ct);
        await EnsureSuccessAsync(resp, $"export status scan {scanId} file {fileId}");
        var json = await resp.Content.ReadAsStringAsync(ct);
        var status = JsonSerializer.Deserialize<TenableExportStatus>(json);
        return status?.Status ?? "";
    }

    /// <summary>Download the prepared export. Caller is responsible for writing the bytes to disk.</summary>
    public async Task<byte[]> DownloadExportAsync(int scanId, long fileId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync(
            $"{_baseUrl}/scans/{scanId}/export/{fileId}/download", ct);
        await EnsureSuccessAsync(resp, $"download export scan {scanId} file {fileId}");
        return await resp.Content.ReadAsByteArrayAsync(ct);
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage resp, string action)
    {
        if (resp.IsSuccessStatusCode) return;
        string body = "";
        try { body = await resp.Content.ReadAsStringAsync(); }
        catch { /* ignore */ }
        throw new TenableApiException(
            $"Tenable API: {action} returned HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}. " +
            $"Body: {Truncate(body, 512)}");
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s.Substring(0, max) + "…";

    public void Dispose()
    {
        if (_ownsClient) _http.Dispose();
    }
}

/// <summary>Thrown when the Tenable.io API returns an error or an unexpected response shape.</summary>
public sealed class TenableApiException : Exception
{
    public TenableApiException(string message) : base(message) { }
    public TenableApiException(string message, Exception inner) : base(message, inner) { }
}
