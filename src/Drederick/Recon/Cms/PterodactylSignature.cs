using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Cms;

/// <summary>
/// GAP-052 (htb-pterodactyl-fingerprint): programmatic detector for the
/// Pterodactyl Panel — a Laravel-based game server management panel
/// commonly seen on HTB lab targets. The YAML corpus already carries a
/// loose <c>PterodactylPanel</c> entry; this class provides a tighter
/// in-code signature that also serves as the corpus fallback when the
/// embedded YAML is missing or partial (e.g. trimmed-resource builds).
///
/// Detection is multi-signal — none alone is sufficient on its own, but
/// any two from {title/HTML marker, manifest link, JS app version
/// reference, <c>pterodactyl_session</c> cookie, X-Powered-By Laravel
/// header alongside a Pterodactyl-shaped admin/server path marker} push
/// confidence past the threshold. Version is extracted from the admin
/// footer comment or a manifest <c>"version"</c> field where present.
///
/// Output shape is <see cref="CmsFingerprint"/> — a thin
/// vendor/product/version/cpe record — separate from
/// <see cref="CmsMatch"/> so this detector can be invoked outside the
/// full <see cref="CmsFingerprintTool"/> pipeline (unit tests, ad-hoc
/// LLM-driven probes, future post-ex web triage).
/// </summary>
public static class PterodactylSignature
{
    /// <summary>Stable corpus entry name — used by the YAML chain dedupe.</summary>
    public const string EntryName = "PterodactylPanel";

    public const string Vendor = "pterodactyl";
    public const string Product = "panel";

    private const string CpeTemplate = "cpe:2.3:a:pterodactyl:panel:{version}:*:*:*:*:*:*:*";

    private static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(250);

    // HTML markers — each contributes one confidence point.
    private static readonly Regex TitleMarker = new(
        @"<title>\s*Pterodactyl\s*(?:Panel)?\s*</title>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex PanelPhrase = new(
        @"Pterodactyl\s+Panel",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex ManifestLink = new(
        @"/assets/manifest\.json",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex AppVersionJs = new(
        @"(?:__pterodactyl_app_version|window\.PterodactylUser|window\.SiteConfiguration|/build/assets/app-)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    // Version extractors — first match wins.
    private static readonly Regex AdminFooterVersion = new(
        @"Pterodactyl\s+Panel\s+v?([0-9]+\.[0-9]+\.[0-9]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex ManifestVersionJson = new(
        @"""version""\s*:\s*""([0-9]+\.[0-9]+\.[0-9]+)""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    private static readonly Regex AppVersionMeta = new(
        @"__pterodactyl_app_version\s*=\s*['""]?([0-9]+\.[0-9]+\.[0-9]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RxTimeout);

    /// <summary>
    /// Examine a root fetch and emit a <see cref="CmsFingerprint"/> if the
    /// combined signal set crosses the confidence threshold (>= 2). Returns
    /// <c>null</c> when nothing matches or the only signal is the generic
    /// Laravel X-Powered-By header without any Pterodactyl-specific marker.
    /// </summary>
    /// <param name="html">Truncated HTML body of the root page.</param>
    /// <param name="cookieNames">Set-Cookie names parsed off the response.</param>
    /// <param name="headers">Flat <c>Header: value</c> string (lower or mixed case).</param>
    /// <param name="path">Request path that produced the response (for /admin or /server hits).</param>
    /// <param name="audit">Optional audit log — emits <c>cms.fingerprint</c> on match.</param>
    /// <param name="target">Target identifier recorded in the audit event.</param>
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

        if (SafeMatch(TitleMarker, html)) { confidence++; signals.Add("html:title=Pterodactyl"); }
        if (SafeMatch(PanelPhrase, html)) { confidence++; signals.Add("html:Pterodactyl Panel"); }
        if (SafeMatch(ManifestLink, html)) { confidence++; signals.Add("html:/assets/manifest.json"); }
        if (SafeMatch(AppVersionJs, html)) { confidence++; signals.Add("html:js-app-marker"); }

        foreach (var c in cookies)
        {
            if (c.Equals("pterodactyl_session", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 2; // strong, name-bound signal
                signals.Add("cookie:pterodactyl_session");
                break;
            }
        }
        if (cookies.Any(c => c.Equals("remember_web", StringComparison.OrdinalIgnoreCase)
            || c.StartsWith("remember_web_", StringComparison.OrdinalIgnoreCase)))
        {
            confidence++;
            signals.Add("cookie:remember_web");
        }
        if (cookies.Any(c => c.Equals("XSRF-TOKEN", StringComparison.OrdinalIgnoreCase))
            && cookies.Any(c => c.StartsWith("pterodactyl", StringComparison.OrdinalIgnoreCase)))
        {
            confidence++;
            signals.Add("cookie:XSRF+pterodactyl");
        }

        // Laravel header alone is too noisy — only count when paired with
        // an admin/server path or a Pterodactyl-named cookie.
        bool laravel = Regex.IsMatch(headers,
            @"^X-Powered-By:[^\n]*Laravel",
            RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant, RxTimeout);
        bool adminish = !string.IsNullOrEmpty(path)
            && (path!.StartsWith("/admin", StringComparison.OrdinalIgnoreCase)
                || path!.StartsWith("/server", StringComparison.OrdinalIgnoreCase));
        if (laravel && (adminish || cookies.Any(c => c.StartsWith("pterodactyl", StringComparison.OrdinalIgnoreCase))))
        {
            confidence++;
            signals.Add("header:laravel+pterodactyl-context");
        }

        if (confidence < 2) return null;

        string? version = ExtractVersion(html);
        string cpe = CpeTemplate.Replace("{version}",
            string.IsNullOrWhiteSpace(version) ? "*" : version!,
            StringComparison.OrdinalIgnoreCase);

        var fp = new CmsFingerprint(Vendor, Product, version, cpe, confidence, signals);

        audit?.Record("cms.fingerprint", new Dictionary<string, object?>
        {
            ["product"] = Product,
            ["vendor"] = Vendor,
            ["name"] = "pterodactyl",
            ["target"] = target,
            ["version"] = version,
            ["cpe"] = cpe,
            ["confidence"] = confidence,
            ["signals"] = signals,
        });

        return fp;
    }

    /// <summary>
    /// Convenience wrapper around <see cref="Detect"/> that takes raw
    /// Set-Cookie header values and parses cookie names off them.
    /// </summary>
    public static CmsFingerprint? DetectFromSetCookies(
        string? html,
        IEnumerable<string>? setCookieHeaders,
        string? headers = null,
        string? path = "/",
        AuditLog? audit = null,
        string? target = null)
    {
        var names = new List<string>();
        if (setCookieHeaders is not null)
        {
            foreach (var raw in setCookieHeaders)
            {
                if (string.IsNullOrEmpty(raw)) continue;
                var eq = raw.IndexOf('=');
                if (eq <= 0) continue;
                names.Add(raw[..eq].Trim());
            }
        }
        return Detect(html, names, headers, path, audit, target);
    }

    private static string? ExtractVersion(string body)
    {
        if (string.IsNullOrEmpty(body)) return null;
        try
        {
            var m = AdminFooterVersion.Match(body);
            if (m.Success && m.Groups.Count > 1) return m.Groups[1].Value;
            m = AppVersionMeta.Match(body);
            if (m.Success && m.Groups.Count > 1) return m.Groups[1].Value;
            m = ManifestVersionJson.Match(body);
            if (m.Success && m.Groups.Count > 1) return m.Groups[1].Value;
        }
        catch (RegexMatchTimeoutException) { /* adversarial body — skip */ }
        return null;
    }

    private static bool SafeMatch(Regex rx, string input)
    {
        try { return rx.IsMatch(input); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    /// <summary>
    /// Build a YAML-equivalent <see cref="CmsFingerprintEntry"/> for the
    /// <see cref="CmsFingerprintTool"/> corpus chain. Used as a backstop
    /// when the embedded YAML resource is absent or trimmed.
    /// </summary>
    internal static CmsFingerprintEntry BuildEntry()
    {
        return new CmsFingerprintEntry
        {
            Name = EntryName,
            Description = "Pterodactyl Panel — game-server management (GAP-052 programmatic backstop)",
            ConfidenceRequired = 2,
            CpeTemplate = CpeTemplate,
            Signals = new CmsSignals
            {
                Cookies = new List<string> { "pterodactyl_session", "remember_web_*" },
                MetaGenerator = new List<string> { "Pterodactyl" },
                HtmlPatterns = new List<string>
                {
                    @"(?i)<title>\s*Pterodactyl",
                    @"(?i)Pterodactyl\s+Panel",
                    @"(?i)/assets/manifest\.json",
                    @"(?i)__pterodactyl_app_version",
                    @"(?i)window\.PterodactylUser",
                },
                HeaderPatterns = new List<string>
                {
                    @"(?i)X-Powered-By:.*Laravel",
                },
                PathProbes = new List<CmsPathProbe>
                {
                    new()
                    {
                        Path = "/auth/login",
                        ExpectStatus = new List<int> { 200 },
                        ExpectBodyContains = new List<string> { "Pterodactyl" },
                    },
                },
            },
            VersionExtract = new List<CmsVersionExtract>
            {
                new() { Regex = @"(?i)Pterodactyl\s+Panel\s+v?([0-9]+\.[0-9]+\.[0-9]+)", Source = "html" },
                new() { Regex = @"(?i)__pterodactyl_app_version\s*=\s*['""]?([0-9]+\.[0-9]+\.[0-9]+)", Source = "html" },
                new() { Regex = @"(?i)""version""\s*:\s*""([0-9]+\.[0-9]+\.[0-9]+)""", Source = "html" },
            },
        };
    }
}

/// <summary>
/// GAP-052: flat fingerprint record emitted by per-CMS programmatic
/// signatures (currently <see cref="PterodactylSignature"/>). Parallel to
/// — but simpler than — <see cref="CmsMatch"/>, so per-product detectors
/// can be invoked outside the full corpus-driven <see cref="CmsFingerprintTool"/>
/// pipeline. Carries vendor/product/version/CPE in the shape consumed by
/// <see cref="Drederick.Enrichment.CuratedCveCorpus"/>.
/// </summary>
public sealed record CmsFingerprint(
    string Vendor,
    string Product,
    string? Version,
    string Cpe,
    int Confidence,
    IReadOnlyList<string> Signals);
