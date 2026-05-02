// Original NSE script: http-title.nse
// Source: https://nmap.org/nsedoc/scripts/http-title.html
// Author: Diman Todorov
// License: NPSL
using System.Net.Http;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Native;

public sealed partial class HttpTitleTool : IReconTool
{
    public string Name => "http-title";
    public string Description =>
        "Native port of nmap's http-title.nse: GET / and extract the page title. " +
        "Target must be inside the authorized scope.";

    [GeneratedRegex(@"<title[^>]*>(?<t>.*?)</title>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex TitleRegex();

    private const int MaxBodyBytes = 256 * 1024;
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpMessageHandler? _handler;

    public HttpTitleTool(Scope.Scope scope, AuditLog audit, HttpMessageHandler? handler = null)
    {
        _scope = scope;
        _audit = audit;
        _handler = handler;
    }

    public async Task<HttpTitleResult> ProbeAsync(
        string target, int port = 80, bool tls = false, CancellationToken ct = default)
    {
        _scope.Require(target);
        var url = NativeHttpClientFactory.BuildUrl(target, port, tls);
        _audit.Record("http-title.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["tls"] = tls,
            ["url"] = url,
        });

        var result = new HttpTitleResult { Url = url };
        try
        {
            using var client = NativeHttpClientFactory.Build(_handler);
            using var response = await client.GetAsync(url, ct).ConfigureAwait(false);
            result.Status = (int)response.StatusCode;
            var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            if (bytes.Length > MaxBodyBytes) bytes = bytes[..MaxBodyBytes];
            result.Title = ExtractTitle(System.Text.Encoding.UTF8.GetString(bytes));
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { result.Error = ex.Message; }

        _audit.Record("http-title.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["status"] = result.Status,
            ["has_title"] = result.Title is not null,
            ["error"] = result.Error,
        });
        return result;
    }

    public static string? ExtractTitle(string body)
    {
        var m = TitleRegex().Match(body);
        if (!m.Success) return null;
        var title = System.Net.WebUtility.HtmlDecode(m.Groups["t"].Value).Trim();
        return string.IsNullOrEmpty(title) ? null : title;
    }
}
