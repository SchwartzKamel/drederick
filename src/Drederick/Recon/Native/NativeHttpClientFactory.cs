// Shared HttpClient factory used by the four NSE-port HTTP tools
// (http-title, http-headers, http-robots, http-methods).
using System.Net.Http;
using System.Net.Security;

namespace Drederick.Recon.Native;

internal static class NativeHttpClientFactory
{
    public static HttpClient Build(HttpMessageHandler? handler, TimeSpan? timeout = null)
    {
        var client = handler is null
            ? new HttpClient(BuildDefaultHandler(), disposeHandler: true)
            : new HttpClient(handler, disposeHandler: false);
        client.Timeout = timeout ?? TimeSpan.FromSeconds(15);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Drederick/1.0 (+recon)");
        return client;
    }

    private static HttpMessageHandler BuildDefaultHandler() =>
        new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(8),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            },
        };

    public static string BuildUrl(string target, int port, bool tls, string path = "/")
    {
        var scheme = tls ? "https" : "http";
        var defaultPort = tls ? 443 : 80;
        var hostPort = port == defaultPort ? target : $"{target}:{port}";
        if (!path.StartsWith('/')) path = "/" + path;
        return $"{scheme}://{hostPort}{path}";
    }
}
