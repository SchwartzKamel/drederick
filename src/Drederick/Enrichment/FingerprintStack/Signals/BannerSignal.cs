using System.Text.RegularExpressions;

namespace Drederick.Enrichment.FingerprintStack.Signals;

/// <summary>
/// Extracts (vendor, product, version) candidates from raw service banners
/// and nmap product/version strings. Exact-match patterns score 0.9; a
/// generic "vendor product version" fallback scores 0.6 and only fires
/// when no exact pattern matched any source.
/// </summary>
public sealed partial class BannerSignal : IFingerprintSignal
{
    public string Name => "banner";

    private const double ExactWeight = 0.9;
    private const double GenericWeight = 0.6;

    private sealed record Pattern(Regex Re, string Vendor, string Product);

    private static readonly Pattern[] _patterns =
    {
        new(ApacheRe(),     "apache",       "http_server"),
        new(NginxRe(),      "nginx",        "nginx"),
        new(IisRe(),        "microsoft",    "iis"),
        new(OpenSshRe(),    "openbsd",      "openssh"),
        new(VsftpdRe(),     "vsftpd",       "vsftpd"),
        new(ProFtpdRe(),    "proftpd",      "proftpd"),
        new(PureFtpdRe(),   "pureftpd",     "pure-ftpd"),
        new(PostfixRe(),    "postfix",      "postfix"),
        new(EximRe(),       "exim",         "exim"),
        new(MariaDbRe(),    "mariadb",      "mariadb"),
        new(MysqlRe(),      "oracle",       "mysql"),
        new(PostgresRe(),   "postgresql",   "postgresql"),
        new(RedisRe(),      "redis",        "redis"),
        new(RabbitRe(),     "pivotal",      "rabbitmq"),
        new(JenkinsRe(),    "jenkins",      "jenkins"),
        new(TomcatRe(),     "apache",       "tomcat"),
        new(JettyRe(),      "eclipse",      "jetty"),
        new(LightTpdRe(),   "lighttpd",     "lighttpd"),
        new(NodeJsRe(),     "nodejs",       "node.js"),
    };

    private static readonly Regex GenericRe = new(
        @"^(?<vendor>[A-Za-z][\w\-]{1,40})[\s/](?<version>\d+(?:\.\d+){0,3})\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public IReadOnlyList<FingerprintSignalHit> Extract(FingerprintInput input)
    {
        var sources = new List<string>(4);
        if (!string.IsNullOrWhiteSpace(input.Banner)) sources.Add(input.Banner!);
        if (!string.IsNullOrWhiteSpace(input.NmapProduct))
        {
            var nm = input.NmapProduct!;
            if (!string.IsNullOrWhiteSpace(input.NmapVersion))
                nm += " " + input.NmapVersion;
            sources.Add(nm);
        }

        if (sources.Count == 0) return Array.Empty<FingerprintSignalHit>();

        var hits = new List<FingerprintSignalHit>();
        foreach (var src in sources)
        {
            foreach (var p in _patterns)
            {
                var m = p.Re.Match(src);
                if (m.Success)
                {
                    var version = m.Groups["version"].Success ? m.Groups["version"].Value : null;
                    hits.Add(new FingerprintSignalHit(Name, p.Vendor, p.Product, version, ExactWeight, src));
                }
            }
        }

        if (hits.Count == 0)
        {
            foreach (var src in sources)
            {
                var m = GenericRe.Match(src);
                if (m.Success)
                {
                    var vendor = m.Groups["vendor"].Value.ToLowerInvariant();
                    var version = m.Groups["version"].Value;
                    hits.Add(new FingerprintSignalHit(
                        Name, vendor, vendor, version, GenericWeight, src));
                }
            }
        }

        return hits;
    }

    [GeneratedRegex(@"Apache(?:[/\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex ApacheRe();

    [GeneratedRegex(@"nginx(?:[/\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex NginxRe();

    [GeneratedRegex(@"Microsoft-IIS(?:[/\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex IisRe();

    [GeneratedRegex(@"OpenSSH[_\s]+(?<version>\d+(?:\.\d+){0,3}(?:p\d+)?)", RegexOptions.IgnoreCase)]
    private static partial Regex OpenSshRe();

    [GeneratedRegex(@"vsftpd(?:[\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex VsftpdRe();

    [GeneratedRegex(@"ProFTPD(?:[\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex ProFtpdRe();

    [GeneratedRegex(@"Pure-FTPd(?:[\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex PureFtpdRe();

    [GeneratedRegex(@"Postfix(?:[\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex PostfixRe();

    [GeneratedRegex(@"Exim(?:[\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex EximRe();

    [GeneratedRegex(@"MariaDB(?:[\s\-]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex MariaDbRe();

    [GeneratedRegex(@"\bMySQL(?:[\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex MysqlRe();

    [GeneratedRegex(@"PostgreSQL(?:[\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex PostgresRe();

    [GeneratedRegex(@"Redis(?:[\s]+(?:server[\s]+v?)?(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex RedisRe();

    [GeneratedRegex(@"RabbitMQ(?:[\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex RabbitRe();

    [GeneratedRegex(@"Jenkins(?:[\s/]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex JenkinsRe();

    [GeneratedRegex(@"Apache[\s\-]?Tomcat(?:[/\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex TomcatRe();

    [GeneratedRegex(@"Jetty(?:[\s/\(]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex JettyRe();

    [GeneratedRegex(@"lighttpd(?:[/\s]+(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex LightTpdRe();

    [GeneratedRegex(@"Node\.js(?:[/\s]+v?(?<version>\d+(?:\.\d+){0,3}))?", RegexOptions.IgnoreCase)]
    private static partial Regex NodeJsRe();
}
