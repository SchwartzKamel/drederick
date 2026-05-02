// Original NSE script: http-methods.nse
// Source: https://nmap.org/nsedoc/scripts/http-methods.html
// Author: Bernd Stroessenreuther, Gyanendra Mishra
// License: NPSL
using System.Net.Http;
using Drederick.Audit;

namespace Drederick.Recon.Native;

public sealed class HttpMethodsTool : IReconTool
{
    public string Name => "http-methods";
    public string Description =>
        "Native port of nmap's http-methods.nse: send OPTIONS / and parse the " +
        "Allow and Public response headers, flagging risky methods. " +
        "Target must be in scope.";

    private static readonly HashSet<string> RiskyMethods = new(StringComparer.OrdinalIgnoreCase)
        { "PUT", "DELETE", "CONNECT", "TRACE", "PATCH" };

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpMessageHandler? _handler;

    public HttpMethodsTool(Scope.Scope scope, AuditLog audit, HttpMessageHandler? handler = null)
    {
        _scope = scope;
        _audit = audit;
        _handler = handler;
    }

    public async Task<HttpMethodsResult> ProbeAsync(
        string target, int port = 80, bool tls = false, CancellationToken ct = default)
    {
        _scope.Require(target);
        var url = NativeHttpClientFactory.BuildUrl(target, port, tls);
        _audit.Record("http-methods.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["tls"] = tls,
            ["url"] = url,
        });

        var result = new HttpMethodsResult { Url = url };
        try
        {
            using var client = NativeHttpClientFactory.Build(_handler);
            using var response = await client
                .SendAsync(new HttpRequestMessage(HttpMethod.Options, url), ct)
                .ConfigureAwait(false);
            result.Status = (int)response.StatusCode;
            if (response.Headers.TryGetValues("Allow", out var allow))
                result.Allow.AddRange(SplitMethods(string.Join(",", allow)));
            else if (response.Content?.Headers.TryGetValues("Allow", out var allowC) == true)
                result.Allow.AddRange(SplitMethods(string.Join(",", allowC)));
            if (response.Headers.TryGetValues("Public", out var pub))
                result.Public.AddRange(SplitMethods(string.Join(",", pub)));
            else if (response.Content?.Headers.TryGetValues("Public", out var pubC) == true)
                result.Public.AddRange(SplitMethods(string.Join(",", pubC)));
            foreach (var m in result.Allow.Concat(result.Public))
                if (RiskyMethods.Contains(m) && !result.RiskyMethods.Contains(m, StringComparer.OrdinalIgnoreCase))
                    result.RiskyMethods.Add(m.ToUpperInvariant());
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { result.Error = ex.Message; }

        _audit.Record("http-methods.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["status"] = result.Status,
            ["allow_count"] = result.Allow.Count,
            ["risky_count"] = result.RiskyMethods.Count,
            ["error"] = result.Error,
        });
        return result;
    }

    public static IEnumerable<string> SplitMethods(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) yield break;
        foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var m = part.ToUpperInvariant();
            if (m.Length > 0) yield return m;
        }
    }
}
