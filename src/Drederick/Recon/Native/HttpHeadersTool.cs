// Original NSE script: http-headers.nse
// Source: https://nmap.org/nsedoc/scripts/http-headers.html
// Author: Ron Bowes, Andrew Orr
// License: NPSL
using System.Net;
using System.Net.Http;
using Drederick.Audit;

namespace Drederick.Recon.Native;

public sealed class HttpHeadersTool : IReconTool
{
    public string Name => "http-headers";
    public string Description =>
        "Native port of nmap's http-headers.nse: HEAD / (with GET fallback) and " +
        "report the full response header set. Target must be in scope.";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpMessageHandler? _handler;

    public HttpHeadersTool(Scope.Scope scope, AuditLog audit, HttpMessageHandler? handler = null)
    {
        _scope = scope;
        _audit = audit;
        _handler = handler;
    }

    public async Task<HttpHeadersResult> ProbeAsync(
        string target, int port = 80, bool tls = false, CancellationToken ct = default)
    {
        _scope.Require(target);
        var url = NativeHttpClientFactory.BuildUrl(target, port, tls);
        _audit.Record("http-headers.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["tls"] = tls,
            ["url"] = url,
        });

        var result = new HttpHeadersResult { Url = url, Method = "HEAD" };
        try
        {
            using var client = NativeHttpClientFactory.Build(_handler);
            HttpResponseMessage? response = null;
            try
            {
                response = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url), ct)
                    .ConfigureAwait(false);
                if (response.StatusCode is HttpStatusCode.MethodNotAllowed or HttpStatusCode.NotImplemented)
                {
                    response.Dispose();
                    response = null;
                    result.Method = "GET";
                }
            }
            catch
            {
                response?.Dispose();
                response = null;
                result.Method = "GET";
            }
            response ??= await client
                .GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            using (response)
            {
                result.Status = (int)response.StatusCode;
                CollectHeaders(response, result.Headers);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { result.Error = ex.Message; }

        _audit.Record("http-headers.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["status"] = result.Status,
            ["method"] = result.Method,
            ["header_count"] = result.Headers.Count,
            ["error"] = result.Error,
        });
        return result;
    }

    public static void CollectHeaders(HttpResponseMessage response, Dictionary<string, List<string>> bag)
    {
        foreach (var h in response.Headers)
            bag[h.Key] = h.Value.ToList();
        if (response.Content?.Headers is { } ch)
        {
            foreach (var h in ch)
                bag[h.Key] = h.Value.ToList();
        }
    }
}
