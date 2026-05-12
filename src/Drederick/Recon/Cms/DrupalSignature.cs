using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Cms;

/// <summary>
/// GAP-034 (htb-cms-fingerprint-pack): programmatic detector for Drupal.
/// Combines an X-Generator header, Drupal meta-generator,
/// /sites/default/files marker, drupalSettings JSON blob, and SESS/SSESS
/// cookie names.
/// </summary>
public static class DrupalSignature
{
    public const string EntryName = "Drupal";
    public const string Vendor = "drupal";
    public const string Product = "drupal";
    private const string CpeTemplate = "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*";

    private static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly Regex XGeneratorHeader = new(
        @"^X-Generator:[^\n]*Drupal(?:\s+([0-9]+(?:\.[0-9]+){0,2}))?",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex MetaGenerator = new(
        @"<meta[^>]+name=[""']generator[""'][^>]+content=[""']Drupal(?:\s+([0-9]+(?:\.[0-9]+){0,2}))?",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex SitesDefaultFiles = new(
        @"/sites/default/files",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex CoreChangelog = new(
        @"/core/CHANGELOG\.txt",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex DrupalSettingsJs = new(
        @"drupalSettings|Drupal\.behaviors",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex SessCookieName = new(
        @"^S?SESS[a-f0-9]{16,}$",
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
            var hm = XGeneratorHeader.Match(headers);
            if (hm.Success)
            {
                confidence += 2;
                signals.Add("header:X-Generator=Drupal");
                if (hm.Groups.Count > 1 && hm.Groups[1].Success && !string.IsNullOrEmpty(hm.Groups[1].Value))
                    version = hm.Groups[1].Value;
            }
        }
        catch (RegexMatchTimeoutException) { }

        try
        {
            var mg = MetaGenerator.Match(html);
            if (mg.Success)
            {
                confidence += 2;
                signals.Add("meta:generator=Drupal");
                if (version is null && mg.Groups.Count > 1 && mg.Groups[1].Success && !string.IsNullOrEmpty(mg.Groups[1].Value))
                    version = mg.Groups[1].Value;
            }
        }
        catch (RegexMatchTimeoutException) { }

        if (SafeMatch(SitesDefaultFiles, html)) { confidence++; signals.Add("html:/sites/default/files"); }
        if (SafeMatch(CoreChangelog, html)) { confidence++; signals.Add("html:/core/CHANGELOG.txt"); }
        if (SafeMatch(DrupalSettingsJs, html)) { confidence++; signals.Add("html:drupalSettings"); }

        if (cookies.Any(c => SafeMatch(SessCookieName, c)))
        {
            confidence++; signals.Add("cookie:SESS*");
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
            ["name"] = "drupal",
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
            Description = "Drupal (GAP-034 programmatic backstop)",
            ConfidenceRequired = 2,
            CpeTemplate = CpeTemplate,
            Signals = new CmsSignals
            {
                Cookies = new List<string> { "SESS*", "SSESS*" },
                MetaGenerator = new List<string> { "Drupal" },
                HtmlPatterns = new List<string>
                {
                    @"(?i)/sites/default/files",
                    @"(?i)/core/CHANGELOG\.txt",
                    @"(?i)drupalSettings",
                    @"(?i)Drupal\.behaviors",
                },
                HeaderPatterns = new List<string>
                {
                    @"(?i)X-Generator:.*Drupal",
                },
                PathProbes = new List<CmsPathProbe>
                {
                    new()
                    {
                        Path = "/core/CHANGELOG.txt",
                        ExpectStatus = new List<int> { 200 },
                        ExpectBodyContains = new List<string> { "Drupal" },
                    },
                },
            },
            VersionExtract = new List<CmsVersionExtract>
            {
                new() { Regex = @"(?i)<meta[^>]+name=[""']generator[""'][^>]+content=[""']Drupal\s+([0-9]+(?:\.[0-9]+){0,2})", Source = "html" },
                new() { Regex = @"(?i)X-Generator:[^\n]*Drupal\s+([0-9]+(?:\.[0-9]+){0,2})", Source = "header" },
            },
        };
    }
}
