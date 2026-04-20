using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// HTTP fingerprinting probe. GETs "/" and reports status, title, server
/// header, and which common security headers are missing. Does not follow
/// redirects off the target host and does not submit credentials.
/// </summary>
public sealed partial class HttpProbeTool
{
    private static readonly string[] SecurityHeaders =
    [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ];

    [GeneratedRegex("<title[^>]*>(.*?)</title>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex TitleRegex();

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;

    public HttpProbeTool(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope;
        _audit = audit;
    }

    public async Task<HttpResult> ProbeAsync(
        string target,
        int port,
        bool useTls,
        CancellationToken ct = default)
    {
        _scope.Require(target);

        var scheme = useTls ? "https" : "http";
        var url = $"{scheme}://{target}:{port}/";
        _audit.Record("http.request", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["url"] = url,
        });

        // Lab targets frequently use self-signed certs. Accept them for
        // fingerprinting; never submit credentials or follow off-host redirects.
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("drederick/0.1 (+lab-recon)");

        var result = new HttpResult { Url = url };
        try
        {
            using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            result.Status = (int)resp.StatusCode;
            result.Server = resp.Headers.Server?.ToString();
            result.ContentType = resp.Content.Headers.ContentType?.ToString();

            var allHeaders = resp.Headers
                .Concat(resp.Content.Headers)
                .Select(h => h.Key.ToLowerInvariant())
                .ToHashSet();
            result.MissingSecurityHeaders = SecurityHeaders
                .Where(h => !allHeaders.Contains(h))
                .ToList();

            if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.MovedPermanently
                or HttpStatusCode.Found or HttpStatusCode.SeeOther
                or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
            {
                result.FinalUrl = resp.Headers.Location?.ToString();
            }

            if ((resp.Content.Headers.ContentType?.MediaType ?? "").Contains("html",
                    StringComparison.OrdinalIgnoreCase))
            {
                // Read at most 64KB for title extraction.
                var buf = new byte[65536];
                await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                int total = 0;
                while (total < buf.Length)
                {
                    var n = await stream.ReadAsync(buf.AsMemory(total, buf.Length - total), ct)
                        .ConfigureAwait(false);
                    if (n <= 0) break;
                    total += n;
                }
                var body = System.Text.Encoding.UTF8.GetString(buf, 0, total);
                var m = TitleRegex().Match(body);
                if (m.Success) result.Title = m.Groups[1].Value.Trim();
            }
        }
        catch (Exception ex)
        {
            _audit.Record("http.error", new Dictionary<string, object?>
            {
                ["target"] = target, ["url"] = url, ["error"] = ex.Message,
            });
            result.Error = ex.Message;
        }
        return result;
    }
}
