namespace Drederick.Enrichment;

/// <summary>
/// Tiny abstraction over HTTP GET so tests can swap in a fake/offline fetcher.
/// Implementations should return the raw bytes of the response body, or throw
/// if the transfer fails. Returning null is reserved for "not found".
/// </summary>
public interface IHttpFetcher
{
    Task<byte[]?> FetchAsync(string url, CancellationToken ct);
}

internal sealed class HttpClientFetcher : IHttpFetcher, IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;

    public HttpClientFetcher(HttpClient? http = null)
    {
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        _ownsClient = http is null;
    }

    public async Task<byte[]?> FetchAsync(string url, CancellationToken ct)
    {
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_ownsClient) _http.Dispose();
    }
}
