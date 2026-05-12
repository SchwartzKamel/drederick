using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Cms;

/// <summary>
/// GAP-034 (htb-cms-fingerprint-pack): programmatic detector for SuiteCRM
/// (the SugarCRM open-source fork). Combines &lt;title&gt;SuiteCRM,
/// <c>index.php?module=Users&amp;action=Login</c>, /install.php marker,
/// SuiteP/Suite7/RacerX theme paths, and the SUGAR. JS namespace.
/// </summary>
public static class SuiteCrmSignature
{
    public const string EntryName = "SuiteCRM";
    public const string Vendor = "salesagility";
    public const string Product = "suitecrm";
    private const string CpeTemplate = "cpe:2.3:a:salesagility:suitecrm:{version}:*:*:*:*:*:*:*";

    private static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly Regex TitleSuiteCrm = new(
        @"<title>\s*SuiteCRM",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex LoginUrl = new(
        @"index\.php\?module=Users[^""'\s]*action=Login",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex InstallPhp = new(
        @"/install\.php",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex ThemePath = new(
        @"/cache/themes/(?:SuiteP|Suite7|RacerX)/|themes/(?:SuiteP|Suite7|RacerX)/",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex SugarNamespace = new(
        @"\bSUGAR\.[a-zA-Z_]+|\bSUGAR_URL\b|var\s+SUGAR\s*=",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex VersionMeta = new(
        @"SuiteCRM[^0-9]{0,10}([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
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

        if (SafeMatch(TitleSuiteCrm, html)) { confidence += 2; signals.Add("html:<title>SuiteCRM"); }
        if (SafeMatch(LoginUrl, html)) { confidence += 2; signals.Add("html:index.php?module=Users&action=Login"); }
        if (SafeMatch(InstallPhp, html)) { confidence++; signals.Add("html:/install.php"); }
        if (SafeMatch(ThemePath, html)) { confidence++; signals.Add("html:cache/themes/SuiteP|Suite7|RacerX"); }
        if (SafeMatch(SugarNamespace, html)) { confidence++; signals.Add("html:SUGAR namespace"); }

        if (cookies.Any(c => c.StartsWith("ck_login_id_", StringComparison.OrdinalIgnoreCase)
            || c.Equals("PHPSESSID", StringComparison.OrdinalIgnoreCase) && SafeMatch(LoginUrl, html)))
        {
            confidence++; signals.Add("cookie:PHPSESSID+suitecrm-marker");
        }

        try
        {
            var vm = VersionMeta.Match(html);
            if (vm.Success && vm.Groups.Count > 1) version = vm.Groups[1].Value;
        }
        catch (RegexMatchTimeoutException) { }

        if (confidence < 2) return null;

        string cpe = CpeTemplate.Replace("{version}",
            string.IsNullOrWhiteSpace(version) ? "*" : version!,
            StringComparison.OrdinalIgnoreCase);

        var fp = new CmsFingerprint(Vendor, Product, version, cpe, confidence, signals);

        audit?.Record("cms.fingerprint", new Dictionary<string, object?>
        {
            ["product"] = Product,
            ["vendor"] = Vendor,
            ["name"] = "suitecrm",
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
            Description = "SuiteCRM (GAP-034 programmatic backstop)",
            ConfidenceRequired = 2,
            CpeTemplate = CpeTemplate,
            Signals = new CmsSignals
            {
                Cookies = new List<string> { "ck_login_id_*" },
                MetaGenerator = new List<string>(),
                HtmlPatterns = new List<string>
                {
                    @"(?i)<title>\s*SuiteCRM",
                    @"(?i)index\.php\?module=Users[^""'\s]*action=Login",
                    @"(?i)/install\.php",
                    @"(?i)/cache/themes/(?:SuiteP|Suite7|RacerX)/",
                    @"(?i)\bSUGAR\.[a-zA-Z_]+",
                },
                HeaderPatterns = new List<string>(),
                PathProbes = new List<CmsPathProbe>
                {
                    new()
                    {
                        Path = "/index.php?module=Users&action=Login",
                        ExpectStatus = new List<int> { 200 },
                        ExpectBodyContains = new List<string> { "SuiteCRM" },
                    },
                },
            },
            VersionExtract = new List<CmsVersionExtract>
            {
                new() { Regex = @"(?i)SuiteCRM[^0-9]{0,10}([0-9]+\.[0-9]+(?:\.[0-9]+)?)", Source = "html" },
            },
        };
    }
}
