using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Cms;

/// <summary>
/// GAP-034 (htb-cms-fingerprint-pack): programmatic detector for Magento
/// (Adobe Commerce). Combines Mage.Cookies JS, /skin/frontend/,
/// /media/catalog/product/, /static/version*/ asset paths, and the
/// <c>frontend</c> / <c>X-Magento-Vary</c> cookies.
/// </summary>
public static class MagentoSignature
{
    public const string EntryName = "Magento";
    public const string Vendor = "magento";
    public const string Product = "magento";
    private const string CpeTemplate = "cpe:2.3:a:magento:magento:{version}:*:*:*:*:*:*:*";

    private static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly Regex MageCookiesJs = new(
        @"Mage\.Cookies|var\s+BASE_URL\s*=|Magento_PageCache",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex SkinFrontend = new(
        @"/skin/frontend/",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex MediaCatalog = new(
        @"/media/catalog/product/",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex StaticVersion = new(
        @"/static/version[0-9]+/|/static/frontend/",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex SetCookieFrontend = new(
        @"^Set-Cookie:[^\n]*\bfrontend\s*=",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant, RxTimeout);

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

        if (SafeMatch(MageCookiesJs, html)) { confidence += 2; signals.Add("html:Mage.Cookies/Magento_PageCache"); }
        if (SafeMatch(SkinFrontend, html)) { confidence++; signals.Add("html:/skin/frontend/"); }
        if (SafeMatch(MediaCatalog, html)) { confidence++; signals.Add("html:/media/catalog/product/"); }
        if (SafeMatch(StaticVersion, html)) { confidence++; signals.Add("html:/static/versionN/"); }

        if (cookies.Any(c => c.Equals("frontend", StringComparison.OrdinalIgnoreCase)))
        {
            confidence += 2; signals.Add("cookie:frontend");
        }
        if (cookies.Any(c => c.Equals("X-Magento-Vary", StringComparison.OrdinalIgnoreCase)
            || c.Equals("PHPSESSID", StringComparison.OrdinalIgnoreCase) && SafeMatch(MediaCatalog, html)))
        {
            confidence++; signals.Add("cookie:X-Magento-Vary/PHPSESSID");
        }
        if (SafeMatch(SetCookieFrontend, headers))
        {
            confidence++; signals.Add("header:Set-Cookie:frontend=");
        }

        if (confidence < 2) return null;

        string version = "*";
        string cpe = CpeTemplate.Replace("{version}", version, StringComparison.OrdinalIgnoreCase);

        var fp = new CmsFingerprint(Vendor, Product, null, cpe, confidence, signals);

        audit?.Record("cms.fingerprint", new Dictionary<string, object?>
        {
            ["product"] = Product,
            ["vendor"] = Vendor,
            ["name"] = "magento",
            ["target"] = target,
            ["version"] = null,
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
            Description = "Magento / Adobe Commerce (GAP-034 programmatic backstop)",
            ConfidenceRequired = 2,
            CpeTemplate = CpeTemplate,
            Signals = new CmsSignals
            {
                Cookies = new List<string> { "frontend", "X-Magento-Vary" },
                MetaGenerator = new List<string>(),
                HtmlPatterns = new List<string>
                {
                    @"(?i)Mage\.Cookies",
                    @"(?i)Magento_PageCache",
                    @"(?i)/skin/frontend/",
                    @"(?i)/media/catalog/product/",
                    @"(?i)/static/version[0-9]+/",
                },
                HeaderPatterns = new List<string>
                {
                    @"(?i)Set-Cookie:[^\n]*\bfrontend\s*=",
                    @"(?i)X-Magento-Vary",
                },
                PathProbes = new List<CmsPathProbe>
                {
                    new()
                    {
                        Path = "/static/version/",
                        ExpectStatus = new List<int> { 200, 301, 302, 404 },
                        ExpectBodyContains = new List<string>(),
                    },
                },
            },
            VersionExtract = new List<CmsVersionExtract>(),
        };
    }
}
