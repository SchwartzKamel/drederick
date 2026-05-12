using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Cms;

/// <summary>
/// GAP-034 (htb-cms-fingerprint-pack): programmatic detector for
/// WordPress. Combines meta-generator, wp-login/wp-admin/wp-content
/// path markers, X-Powered-By PHP header, and
/// <c>wordpress_logged_in_*</c> / <c>wp-settings-*</c> cookies. Two or
/// more signals trip the detector. Version is recovered from the
/// generator meta tag or the readme.html fixture when present.
/// </summary>
public static class WordPressSignature
{
    public const string EntryName = "WordPress";
    public const string Vendor = "wordpress";
    public const string Product = "wordpress";
    private const string CpeTemplate = "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*";

    private static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly Regex MetaGenerator = new(
        @"<meta[^>]+name=[""']generator[""'][^>]+content=[""']WordPress(?:\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?))?",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex WpLoginLink = new(
        @"/wp-login\.php",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex WpAdminLink = new(
        @"/wp-admin(?:/|"")",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex WpContentLink = new(
        @"/wp-content/",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex WpIncludesLink = new(
        @"/wp-includes/",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex ReadmeVersion = new(
        @"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    public static CmsFingerprint? Detect(
        string? html,
        IEnumerable<string>? cookieNames,
        string? headers,
        string? path = "/",
        AuditLog? audit = null,
        string? target = null)
    {
        html ??= string.Empty;
        headers ??= string.Empty;
        var cookies = (cookieNames ?? Array.Empty<string>())
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .Select(c => c.Trim())
            .ToList();

        int confidence = 0;
        var signals = new List<string>();
        string? version = null;

        try
        {
            var m = MetaGenerator.Match(html);
            if (m.Success)
            {
                confidence += 2; // strong, named generator
                signals.Add("meta:generator=WordPress");
                if (m.Groups.Count > 1 && m.Groups[1].Success && !string.IsNullOrEmpty(m.Groups[1].Value))
                    version = m.Groups[1].Value;
            }
        }
        catch (RegexMatchTimeoutException) { }

        if (SafeMatch(WpLoginLink, html)) { confidence++; signals.Add("html:/wp-login.php"); }
        if (SafeMatch(WpAdminLink, html)) { confidence++; signals.Add("html:/wp-admin"); }
        if (SafeMatch(WpContentLink, html)) { confidence++; signals.Add("html:/wp-content/"); }
        if (SafeMatch(WpIncludesLink, html)) { confidence++; signals.Add("html:/wp-includes/"); }

        if (cookies.Any(c => c.StartsWith("wordpress_logged_in", StringComparison.OrdinalIgnoreCase)))
        {
            confidence += 2; signals.Add("cookie:wordpress_logged_in");
        }
        if (cookies.Any(c => c.StartsWith("wp-settings", StringComparison.OrdinalIgnoreCase)))
        {
            confidence++; signals.Add("cookie:wp-settings");
        }
        if (cookies.Any(c => c.StartsWith("wordpress_test_cookie", StringComparison.OrdinalIgnoreCase)))
        {
            confidence++; signals.Add("cookie:wordpress_test_cookie");
        }

        if (version is null && SafeMatch(ReadmeVersion, html) && SafeMatch(WpIncludesLink, html))
        {
            try
            {
                var rm = ReadmeVersion.Match(html);
                if (rm.Success && rm.Groups.Count > 1) version = rm.Groups[1].Value;
            }
            catch (RegexMatchTimeoutException) { }
        }

        if (confidence < 2) return null;

        string cpe = CpeTemplate.Replace("{version}",
            string.IsNullOrWhiteSpace(version) ? "*" : version!,
            StringComparison.OrdinalIgnoreCase);

        var fp = new CmsFingerprint(Vendor, Product, version, cpe, confidence, signals);

        audit?.Record("cms.fingerprint", new Dictionary<string, object?>
        {
            ["product"] = Product,
            ["vendor"] = Vendor,
            ["name"] = "wordpress",
            ["target"] = target,
            ["version"] = version,
            ["cpe"] = cpe,
            ["confidence"] = confidence,
            ["signals"] = signals,
        });

        return fp;
    }

    private static bool SafeMatch(Regex rx, string input)
    {
        try { return rx.IsMatch(input); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    internal static CmsFingerprintEntry BuildEntry()
    {
        return new CmsFingerprintEntry
        {
            Name = EntryName,
            Description = "WordPress (GAP-034 programmatic backstop)",
            ConfidenceRequired = 2,
            CpeTemplate = CpeTemplate,
            Signals = new CmsSignals
            {
                Cookies = new List<string> { "wordpress_logged_in_*", "wp-settings-*", "wordpress_test_cookie" },
                MetaGenerator = new List<string> { "WordPress" },
                HtmlPatterns = new List<string>
                {
                    @"(?i)/wp-login\.php",
                    @"(?i)/wp-admin",
                    @"(?i)/wp-content/",
                    @"(?i)/wp-includes/",
                },
                HeaderPatterns = new List<string>
                {
                    @"(?i)X-Powered-By:.*PHP",
                },
                PathProbes = new List<CmsPathProbe>
                {
                    new()
                    {
                        Path = "/wp-login.php",
                        ExpectStatus = new List<int> { 200 },
                        ExpectBodyContains = new List<string> { "WordPress" },
                    },
                },
            },
            VersionExtract = new List<CmsVersionExtract>
            {
                new() { Regex = @"(?i)<meta[^>]+name=[""']generator[""'][^>]+content=[""']WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", Source = "html" },
                new() { Regex = @"(?i)Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", Source = "html" },
            },
        };
    }
}
