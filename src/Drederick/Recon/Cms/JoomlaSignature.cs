using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Cms;

/// <summary>
/// GAP-034 (htb-cms-fingerprint-pack): programmatic detector for Joomla!
/// Combines a Joomla! meta-generator, the /administrator/ path,
/// joomla.xml manifest, /media/system/js/ marker, and the MD5-shaped
/// session-cookie heuristic.
/// </summary>
public static class JoomlaSignature
{
    public const string EntryName = "Joomla";
    public const string Vendor = "joomla";
    public const string Product = "joomla!";
    private const string CpeTemplate = "cpe:2.3:a:joomla:joomla\\!:{version}:*:*:*:*:*:*:*";

    private static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly Regex MetaGenerator = new(
        @"<meta[^>]+name=[""']generator[""'][^>]+content=[""']Joomla!?(?:\s*[-!]\s*[^""']*?(?:\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?))?)?",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex AdministratorLink = new(
        @"/administrator(?:/|"")",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex MediaSystemJs = new(
        @"/media/system/js/",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex ComponentsLink = new(
        @"/components/com_",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex Md5CookieName = new(
        @"^[a-f0-9]{32}$",
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
                confidence += 2;
                signals.Add("meta:generator=Joomla");
                if (m.Groups.Count > 1 && m.Groups[1].Success && !string.IsNullOrEmpty(m.Groups[1].Value))
                    version = m.Groups[1].Value;
            }
        }
        catch (RegexMatchTimeoutException) { }

        if (SafeMatch(AdministratorLink, html)) { confidence++; signals.Add("html:/administrator/"); }
        if (SafeMatch(MediaSystemJs, html)) { confidence++; signals.Add("html:/media/system/js/"); }
        if (SafeMatch(ComponentsLink, html)) { confidence++; signals.Add("html:/components/com_*"); }

        // MD5-shaped session cookie + an administrator-path marker is a
        // canonical Joomla session-cookie signature.
        bool md5Cookie = cookies.Any(c => SafeMatch(Md5CookieName, c));
        if (md5Cookie && (SafeMatch(AdministratorLink, html) || SafeMatch(MediaSystemJs, html)))
        {
            confidence++; signals.Add("cookie:md5-session+admin-marker");
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
            ["name"] = "joomla",
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
            Description = "Joomla! (GAP-034 programmatic backstop)",
            ConfidenceRequired = 2,
            CpeTemplate = CpeTemplate,
            Signals = new CmsSignals
            {
                Cookies = new List<string>(),
                MetaGenerator = new List<string> { "Joomla" },
                HtmlPatterns = new List<string>
                {
                    @"(?i)/administrator/",
                    @"(?i)/media/system/js/",
                    @"(?i)/components/com_",
                },
                HeaderPatterns = new List<string>(),
                PathProbes = new List<CmsPathProbe>
                {
                    new()
                    {
                        Path = "/administrator/manifests/files/joomla.xml",
                        ExpectStatus = new List<int> { 200 },
                        ExpectBodyContains = new List<string> { "<extension" },
                    },
                    new()
                    {
                        Path = "/language/en-GB/en-GB.xml",
                        ExpectStatus = new List<int> { 200 },
                        ExpectBodyContains = new List<string> { "Joomla" },
                    },
                },
            },
            VersionExtract = new List<CmsVersionExtract>
            {
                new() { Regex = @"(?i)<meta[^>]+name=[""']generator[""'][^>]+content=[""']Joomla!?[^""']*?\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", Source = "html" },
                new() { Regex = @"(?i)<version>\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*</version>", Source = "html" },
            },
        };
    }
}
