// Original NSE script: http-robots.txt.nse
// Source: https://nmap.org/nsedoc/scripts/http-robots.txt.html
// Author: Eddie Bell
// License: NPSL
using System.Net.Http;
using Drederick.Audit;

namespace Drederick.Recon.Native;

public sealed class HttpRobotsTool : IReconTool
{
    public string Name => "http-robots";
    public string Description =>
        "Native port of nmap's http-robots.txt.nse: fetch /robots.txt and parse " +
        "Disallow / Allow / Sitemap entries. Target must be in scope.";

    private const int MaxBodyBytes = 256 * 1024;
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpMessageHandler? _handler;

    public HttpRobotsTool(Scope.Scope scope, AuditLog audit, HttpMessageHandler? handler = null)
    {
        _scope = scope;
        _audit = audit;
        _handler = handler;
    }

    public async Task<HttpRobotsResult> ProbeAsync(
        string target, int port = 80, bool tls = false, CancellationToken ct = default)
    {
        _scope.Require(target);
        var url = NativeHttpClientFactory.BuildUrl(target, port, tls, "/robots.txt");
        _audit.Record("http-robots.start", new Dictionary<string, object?>
        {
            ["target"] = target, ["port"] = port, ["tls"] = tls, ["url"] = url,
        });

        var result = new HttpRobotsResult { Url = url };
        try
        {
            using var client = NativeHttpClientFactory.Build(_handler);
            using var response = await client.GetAsync(url, ct).ConfigureAwait(false);
            result.Status = (int)response.StatusCode;
            if (response.IsSuccessStatusCode)
            {
                var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                if (bytes.Length > MaxBodyBytes) bytes = bytes[..MaxBodyBytes];
                Parse(System.Text.Encoding.UTF8.GetString(bytes), result);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { result.Error = ex.Message; }

        _audit.Record("http-robots.finish", new Dictionary<string, object?>
        {
            ["target"] = target, ["port"] = port, ["status"] = result.Status,
            ["disallowed"] = result.Disallowed.Count,
            ["allowed"] = result.Allowed.Count,
            ["sitemaps"] = result.Sitemaps.Count,
            ["error"] = result.Error,
        });
        return result;
    }

    public static void Parse(string body, HttpRobotsResult result)
    {
        foreach (var rawLine in body.Split('\n'))
        {
            var line = rawLine;
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            if (line.Length == 0) continue;
            var colon = line.IndexOf(':');
            if (colon < 0) continue;
            var key = line[..colon].Trim();
            var val = line[(colon + 1)..].Trim();
            if (val.Length == 0) continue;
            if (key.Equals("Disallow", StringComparison.OrdinalIgnoreCase))
                result.Disallowed.Add(val);
            else if (key.Equals("Allow", StringComparison.OrdinalIgnoreCase))
                result.Allowed.Add(val);
            else if (key.Equals("Sitemap", StringComparison.OrdinalIgnoreCase))
                result.Sitemaps.Add(val);
        }
    }
}
