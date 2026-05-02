using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Drederick.Ops.Tenable;

/// <summary>
/// Tenable.sc (formerly SecurityCenter) REST client. Implements the same
/// <see cref="ITenableExportBackend"/> shape as <see cref="TenableApiClient"/>
/// so <see cref="TenableApiPuller"/> can drive it without knowing which backend
/// is in play.
///
/// Auth: Tenable.sc supports both username+password (POST /rest/token) and
/// API-key auth (X-ApiKey: accesskey=…; secretkey=…). This client supports
/// both. With user/pass we obtain a token + session cookie and post a
/// <c>X-SecurityCenter</c> token header on every subsequent request, then
/// <c>DELETE /rest/token</c> on dispose. With API keys we set the
/// <c>X-ApiKey</c> header and skip session management entirely.
///
/// Export workflow: SC's <c>POST /rest/scanResult/{id}/download</c> with body
/// <c>{"downloadType":"v2"}</c> returns a ZIP archive containing one or more
/// <c>.nessus</c> files. We collapse SC's synchronous download into the
/// io-shaped four-step contract by:
///   * <see cref="RequestExportAsync"/> returns the scan id as the synthetic file id,
///   * <see cref="GetExportStatusAsync"/> always returns <c>"ready"</c>,
///   * <see cref="DownloadExportAsync"/> issues the actual download POST,
///     unzips the response, and returns the bytes of the first
///     <c>.nessus</c> entry.
///
/// SC scan listing: <c>GET /rest/scanResult?fields=id,name,status,finishTime</c>.
/// We map SC's <c>finishTime</c> (string seconds-since-epoch) into
/// <see cref="TenableScanSummary.LastModificationDate"/> so the puller's
/// cache key (<c>scan_id-last_mod</c>) is stable and refreshes when SC
/// reruns the scan.
/// </summary>
public sealed class TenableScClient : ITenableExportBackend
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly string _baseUrl;
    private readonly string? _username;
    private readonly string? _password;
    private readonly string? _accessKey;
    private readonly string? _secretKey;
    private string? _token;       // populated by EnsureAuthAsync when using user/pass
    private bool _disposed;

    public string AccessKeyDigest { get; }
    public string BackendName => "tenable.sc";

    private TenableScClient(
        string baseUrl,
        string? username,
        string? password,
        string? accessKey,
        string? secretKey,
        HttpClient? httpClient,
        bool insecureTls)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) throw new ArgumentException("baseUrl required", nameof(baseUrl));
        _baseUrl = baseUrl.TrimEnd('/');
        _username = username;
        _password = password;
        _accessKey = accessKey;
        _secretKey = secretKey;

        _ownsClient = httpClient is null;
        if (httpClient is null)
        {
            var handler = new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() };
            if (insecureTls)
            {
                handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            }
            _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(120) };
        }
        else
        {
            _http = httpClient;
        }
        _http.DefaultRequestHeaders.UserAgent.Clear();
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("drederick", "1.0"));

        // For API-key auth, set the X-ApiKey header up front. SC documents
        // the header as "X-ApiKey: accesskey=AAAA; secretkey=BBBB".
        if (!string.IsNullOrEmpty(accessKey) && !string.IsNullOrEmpty(secretKey))
        {
            _http.DefaultRequestHeaders.Remove("X-ApiKey");
            _http.DefaultRequestHeaders.TryAddWithoutValidation(
                "X-ApiKey",
                $"accesskey={accessKey}; secretkey={secretKey}");
        }

        AccessKeyDigest = ComputeKeyDigest(
            !string.IsNullOrEmpty(accessKey) ? accessKey! :
            !string.IsNullOrEmpty(username) ? username! : "");
    }

    /// <summary>
    /// API-key auth (preferred for automation). Defaults to
    /// <paramref name="insecureTls"/>=<c>true</c> because Tenable.sc on-prem
    /// almost always ships with a self-signed cert; pass <c>false</c> to
    /// require a valid certificate chain. <strong>Insecure TLS disables
    /// certificate validation entirely</strong> — only enable it for
    /// operator-controlled SC instances on trusted networks.
    /// </summary>
    public static TenableScClient WithApiKey(
        string baseUrl, string accessKey, string secretKey,
        bool insecureTls = true, HttpClient? httpClient = null)
    {
        if (string.IsNullOrWhiteSpace(accessKey)) throw new ArgumentException("accessKey required", nameof(accessKey));
        if (string.IsNullOrWhiteSpace(secretKey)) throw new ArgumentException("secretKey required", nameof(secretKey));
        return new TenableScClient(baseUrl, null, null, accessKey, secretKey, httpClient, insecureTls);
    }

    /// <summary>
    /// Username + password auth (logs in lazily, logs out on dispose). Same
    /// insecure-TLS default as <see cref="WithApiKey"/> — see that method's
    /// remarks for the security caveat.
    /// </summary>
    public static TenableScClient WithUserPass(
        string baseUrl, string username, string password,
        bool insecureTls = true, HttpClient? httpClient = null)
    {
        if (string.IsNullOrWhiteSpace(username)) throw new ArgumentException("username required", nameof(username));
        if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("password required", nameof(password));
        return new TenableScClient(baseUrl, username, password, null, null, httpClient, insecureTls);
    }

    private static string ComputeKeyDigest(string secret)
    {
        if (string.IsNullOrEmpty(secret)) return "anon";
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(secret));
        var sb = new StringBuilder();
        for (int i = 0; i < 6; i++) sb.Append(hash[i].ToString("x2"));
        return sb.ToString();
    }

    /// <summary>
    /// Lazily POST /rest/token when using username/password. The cookie jar
    /// captures TNS_SESSIONID; the token is echoed via <c>X-SecurityCenter</c>
    /// on every subsequent request.
    /// </summary>
    private async Task EnsureAuthAsync(CancellationToken ct)
    {
        if (_token is not null) return;
        if (_username is null || _password is null) return; // API-key path

        var body = JsonSerializer.Serialize(new { username = _username, password = _password });
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        using var resp = await _http.PostAsync($"{_baseUrl}/rest/token", content, ct);
        await EnsureSuccessAsync(resp, "POST /rest/token");
        var json = await resp.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("response", out var r) &&
            r.TryGetProperty("token", out var tok))
        {
            _token = tok.ValueKind == JsonValueKind.Number
                ? tok.GetInt64().ToString(System.Globalization.CultureInfo.InvariantCulture)
                : tok.GetString();
        }
        if (string.IsNullOrEmpty(_token))
            throw new TenableApiException("Tenable.sc: /rest/token did not return a token field.");

        _http.DefaultRequestHeaders.Remove("X-SecurityCenter");
        _http.DefaultRequestHeaders.TryAddWithoutValidation("X-SecurityCenter", _token);
    }

    public async Task<IReadOnlyList<TenableScanSummary>> ListScansAsync(CancellationToken ct = default)
    {
        await EnsureAuthAsync(ct);
        // Ask only for the fields the puller needs.
        using var resp = await _http.GetAsync(
            $"{_baseUrl}/rest/scanResult?fields=id,name,status,finishTime,startTime,uuid", ct);
        await EnsureSuccessAsync(resp, "GET /rest/scanResult");
        var json = await resp.Content.ReadAsStringAsync(ct);
        return ParseScanResultList(json);
    }

    internal static IReadOnlyList<TenableScanSummary> ParseScanResultList(string json)
    {
        // SC returns { response: { usable: [...], manageable: [...] } }
        // for some installs and { response: [...] } for others. Handle both.
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("response", out var resp))
            return Array.Empty<TenableScanSummary>();

        IEnumerable<JsonElement> entries;
        if (resp.ValueKind == JsonValueKind.Array)
        {
            entries = resp.EnumerateArray();
        }
        else if (resp.ValueKind == JsonValueKind.Object)
        {
            // Prefer "usable" (scans the API user can read), fall back to "manageable".
            if (resp.TryGetProperty("usable", out var usable) && usable.ValueKind == JsonValueKind.Array)
                entries = usable.EnumerateArray().ToList();
            else if (resp.TryGetProperty("manageable", out var man) && man.ValueKind == JsonValueKind.Array)
                entries = man.EnumerateArray().ToList();
            else
                return Array.Empty<TenableScanSummary>();
        }
        else
        {
            return Array.Empty<TenableScanSummary>();
        }

        var result = new List<TenableScanSummary>();
        foreach (var s in entries)
        {
            var id = ReadInt(s, "id");
            if (id <= 0) continue;
            result.Add(new TenableScanSummary
            {
                Id = id,
                Name = ReadString(s, "name") ?? "",
                Status = ReadString(s, "status") ?? "",
                Uuid = ReadString(s, "uuid"),
                LastModificationDate = ReadEpoch(s, "finishTime"),
                CreationDate = ReadEpoch(s, "startTime"),
            });
        }
        return result;
    }

    private static int ReadInt(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var v)) return 0;
        return v.ValueKind switch
        {
            JsonValueKind.Number => v.GetInt32(),
            JsonValueKind.String when int.TryParse(v.GetString(), out var n) => n,
            _ => 0,
        };
    }

    private static string? ReadString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var v)) return null;
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.GetRawText(),
            _ => null,
        };
    }

    private static long ReadEpoch(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var v)) return 0;
        return v.ValueKind switch
        {
            JsonValueKind.Number => v.GetInt64(),
            JsonValueKind.String when long.TryParse(v.GetString(), out var n) => n,
            _ => 0,
        };
    }

    /// <summary>
    /// SC's download is synchronous; there is no separate "request export"
    /// step. We return the scan id itself as the synthetic file id so
    /// <see cref="DownloadExportAsync"/> can replay it.
    /// </summary>
    public async Task<long> RequestExportAsync(int scanId, string format, CancellationToken ct = default)
    {
        await EnsureAuthAsync(ct);
        // SC supports v2 (Nessus XML) and v1 (legacy). The puller asks for "nessus"; map both.
        if (!string.Equals(format, "nessus", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(format, "v2", StringComparison.OrdinalIgnoreCase))
        {
            throw new TenableApiException(
                $"Tenable.sc backend only supports format=nessus (downloadType=v2); got '{format}'.");
        }
        return scanId;
    }

    /// <summary>SC downloads are synchronous, so the export is always ready.</summary>
    public Task<string> GetExportStatusAsync(int scanId, long fileId, CancellationToken ct = default)
        => Task.FromResult("ready");

    public async Task<byte[]> DownloadExportAsync(int scanId, long fileId, CancellationToken ct = default)
    {
        await EnsureAuthAsync(ct);
        var body = JsonSerializer.Serialize(new { downloadType = "v2" });
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        using var resp = await _http.PostAsync($"{_baseUrl}/rest/scanResult/{scanId}/download", content, ct);
        await EnsureSuccessAsync(resp, $"POST /rest/scanResult/{scanId}/download");
        var raw = await resp.Content.ReadAsByteArrayAsync(ct);
        return UnzipFirstNessus(raw, scanId);
    }

    /// <summary>
    /// SC returns the export wrapped in a ZIP. Pull out the first
    /// <c>.nessus</c> entry and return its bytes. If the response is not a
    /// ZIP (some old SC builds return raw XML), pass it through.
    /// </summary>
    internal static byte[] UnzipFirstNessus(byte[] raw, int scanId)
    {
        if (raw.Length >= 4 && raw[0] == 0x50 && raw[1] == 0x4B &&
            // Local file header (PK\x03\x04) for zips with content,
            // or end-of-central-directory (PK\x05\x06) for empty zips.
            ((raw[2] == 0x03 && raw[3] == 0x04) || (raw[2] == 0x05 && raw[3] == 0x06)))
        {
            using var ms = new MemoryStream(raw);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
            var entry = zip.Entries
                .FirstOrDefault(e => e.FullName.EndsWith(".nessus", StringComparison.OrdinalIgnoreCase))
                ?? zip.Entries.FirstOrDefault();
            if (entry is null)
                throw new TenableApiException(
                    $"Tenable.sc: scan {scanId} download was an empty ZIP.");
            using var entryStream = entry.Open();
            using var outMs = new MemoryStream();
            entryStream.CopyTo(outMs);
            return outMs.ToArray();
        }
        return raw;
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage resp, string action)
    {
        if (resp.IsSuccessStatusCode) return;
        string body = "";
        try { body = await resp.Content.ReadAsStringAsync(); }
        catch
        {
            // Best-effort body capture; the HTTP status is the load-bearing diagnostic.
        }
        throw new TenableApiException(
            $"Tenable.sc: {action} returned HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}. " +
            $"Body: {Truncate(body, 512)}");
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s.Substring(0, max) + "…";

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // Best-effort logout when we obtained a session token.
        if (_token is not null)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Delete, $"{_baseUrl}/rest/token");
                _http.Send(req).Dispose();
            }
            catch
            {
                // Logout failure is not actionable; the session will expire on the server.
            }
        }
        if (_ownsClient) _http.Dispose();
    }
}
