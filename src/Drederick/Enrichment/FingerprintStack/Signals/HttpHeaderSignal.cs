using System.Text.RegularExpressions;

namespace Drederick.Enrichment.FingerprintStack.Signals;

/// <summary>
/// Reads HTTP response headers (Server, X-Powered-By, X-AspNet-Version,
/// X-Generator, X-Drupal-Cache, X-Jenkins, X-Confluence-Version,
/// X-Jira-Version, X-GitLab-*) and emits weighted candidates. Server
/// header → 0.7, X-AspNet-Version → 0.6, other X-* hints → 0.5.
/// </summary>
public sealed partial class HttpHeaderSignal : IFingerprintSignal
{
    public string Name => "http-header";

    private const double ServerWeight = 0.7;
    private const double AspNetWeight = 0.6;
    private const double XHeaderWeight = 0.5;

    private static readonly Regex VersionRe = new(
        @"(?<version>\d+(?:\.\d+){0,3})",
        RegexOptions.Compiled);

    public IReadOnlyList<FingerprintSignalHit> Extract(FingerprintInput input)
    {
        var hits = new List<FingerprintSignalHit>();

        if (!string.IsNullOrWhiteSpace(input.HttpServer))
        {
            EmitFromTokenized(hits, "Server", input.HttpServer!, ServerWeight);
        }

        foreach (var (key, value) in input.HttpHeaders)
        {
            if (string.IsNullOrWhiteSpace(value)) continue;
            switch (key.ToLowerInvariant())
            {
                case "x-powered-by":
                    EmitFromTokenized(hits, key, value, XHeaderWeight);
                    break;
                case "x-aspnet-version":
                    var av = VersionRe.Match(value);
                    hits.Add(new FingerprintSignalHit(
                        Name, "microsoft", "asp.net",
                        av.Success ? av.Groups["version"].Value : null,
                        AspNetWeight, $"{key}: {value}"));
                    break;
                case "x-aspnetmvc-version":
                    var mv = VersionRe.Match(value);
                    hits.Add(new FingerprintSignalHit(
                        Name, "microsoft", "asp.net_mvc",
                        mv.Success ? mv.Groups["version"].Value : null,
                        AspNetWeight, $"{key}: {value}"));
                    break;
                case "x-generator":
                    EmitFromTokenized(hits, key, value, XHeaderWeight);
                    break;
                case "x-drupal-cache":
                    hits.Add(new FingerprintSignalHit(
                        Name, "drupal", "drupal", null, XHeaderWeight, $"{key}: {value}"));
                    break;
                case "x-jenkins":
                    hits.Add(new FingerprintSignalHit(
                        Name, "jenkins", "jenkins",
                        ExtractVersion(value), XHeaderWeight, $"{key}: {value}"));
                    break;
                case "x-confluence-version":
                    hits.Add(new FingerprintSignalHit(
                        Name, "atlassian", "confluence",
                        ExtractVersion(value), XHeaderWeight, $"{key}: {value}"));
                    break;
                case "x-jira-version":
                    hits.Add(new FingerprintSignalHit(
                        Name, "atlassian", "jira",
                        ExtractVersion(value), XHeaderWeight, $"{key}: {value}"));
                    break;
                case "x-gitlab-meta":
                case "x-gitlab-feature-category":
                    hits.Add(new FingerprintSignalHit(
                        Name, "gitlab", "gitlab", null, XHeaderWeight, $"{key}: {value}"));
                    break;
            }
        }

        return hits;
    }

    private static string? ExtractVersion(string s)
    {
        var m = VersionRe.Match(s);
        return m.Success ? m.Groups["version"].Value : null;
    }

    private static void EmitFromTokenized(
        List<FingerprintSignalHit> hits, string headerName, string value, double weight)
    {
        var src = $"{headerName}: {value}";
        foreach (Match m in TokenRe().Matches(value))
        {
            var product = m.Groups["product"].Value.ToLowerInvariant();
            if (product.Length < 2) continue;
            var version = m.Groups["version"].Success ? m.Groups["version"].Value : null;
            hits.Add(new FingerprintSignalHit(
                "http-header", product, product, version, weight, src));
        }
    }

    [GeneratedRegex(@"(?<product>[A-Za-z][\w\-\.]{1,40})(?:[/\s]+(?<version>\d+(?:\.\d+){0,3}))?")]
    private static partial Regex TokenRe();
}
