using System.Net;
using System.Text.RegularExpressions;

namespace Drederick.Recon;

/// <summary>
/// GAP-054: pure HTML parser for a phpinfo() page. Extracts the
/// foothold-relevant subset of directives needed to decide whether
/// arbitrary-write on the box leads directly to RCE (empty
/// disable_functions + empty open_basedir + file_uploads=On => yes)
/// and which OS account the FPM worker runs as.
/// <para>
/// No scope check: this class never touches the network and never
/// spawns a subprocess. The caller (e.g. <see cref="HttpProbeTool"/>)
/// has already gone through scope enforcement to fetch the body.
/// (@invariant-id:scope-in-every-tool — applies to network-touching
/// methods, not pure parsers.)
/// </para>
/// <para>
/// Parsing is deliberately tolerant: phpinfo() output varies subtly
/// across php versions, FPM pool layouts, and SAPIs. We prefer best-
/// effort extraction over strict validation; missing fields stay
/// empty rather than throwing.
/// </para>
/// </summary>
public static partial class PhpInfoParser
{
    [GeneratedRegex(@"<title[^>]*>\s*PHP\s+([0-9][0-9A-Za-z\.\-]*)\s*-\s*phpinfo\(\)\s*</title>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TitleVersionRegex();

    [GeneratedRegex(@"<h1[^>]*>\s*PHP\s+Version\s+([0-9][0-9A-Za-z\.\-]*)\s*</h1>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex H1VersionRegex();

    [GeneratedRegex(
        @"<tr>\s*<td\s+class=""e"">\s*Configure\s+Command\s*</td>\s*<td\s+class=""v"">(?<v>.*?)</td>\s*</tr>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex ConfigureCommandRegex();

    [GeneratedRegex(@"--with-fpm-user=([^\s'""<]+)",
        RegexOptions.CultureInvariant)]
    private static partial Regex FpmUserRegex();

    [GeneratedRegex(@"--with-fpm-group=([^\s'""<]+)",
        RegexOptions.CultureInvariant)]
    private static partial Regex FpmGroupRegex();

    /// <summary>Parse a phpinfo() HTML page. Returns a populated
    /// <see cref="PhpInfoFinding"/>; missing directives are emitted as
    /// empty strings rather than null. Multi-pool pages: the FIRST
    /// Configure Command row wins (callers wanting per-pool detail
    /// should split the body and call Parse per pool).</summary>
    public static PhpInfoFinding Parse(string html, string sourcePath = "")
    {
        ArgumentNullException.ThrowIfNull(html);

        var version = FirstGroup(TitleVersionRegex(), html)
                      ?? FirstGroup(H1VersionRegex(), html)
                      ?? "";

        string configCmd = "";
        var cm = ConfigureCommandRegex().Match(html);
        if (cm.Success)
        {
            configCmd = WebUtility.HtmlDecode(cm.Groups["v"].Value).Trim();
        }
        var fpmUser = FirstGroup(FpmUserRegex(), configCmd) ?? "";
        var fpmGroup = FirstGroup(FpmGroupRegex(), configCmd) ?? "";

        var disableFunctions = ExtractDirective(html, "disable_functions");
        var openBasedir = ExtractDirective(html, "open_basedir");
        var allowUrlFopen = ExtractDirective(html, "allow_url_fopen");
        var allowUrlInclude = ExtractDirective(html, "allow_url_include");
        var fileUploads = ExtractDirective(html, "file_uploads");
        var uploadMaxFilesize = ExtractDirective(html, "upload_max_filesize");
        var uploadTmpDir = ExtractDirective(html, "upload_tmp_dir");
        var userIniFilename = ExtractDirective(html, "user_ini.filename");
        var sessionSavePath = ExtractDirective(html, "session.save_path");
        var includePath = ExtractDirective(html, "include_path");

        bool fileUploadsOn = string.Equals(fileUploads, "On", StringComparison.OrdinalIgnoreCase);
        bool rceOnWriteLikely = disableFunctions.Length == 0
                                && openBasedir.Length == 0
                                && fileUploadsOn;
        bool userIniInjection = userIniFilename.Length > 0;

        return new PhpInfoFinding
        {
            PhpVersion = version,
            DisableFunctions = disableFunctions,
            OpenBasedir = openBasedir,
            AllowUrlFopen = allowUrlFopen,
            AllowUrlInclude = allowUrlInclude,
            FileUploads = fileUploads,
            UploadMaxFilesize = uploadMaxFilesize,
            UploadTmpDir = uploadTmpDir,
            UserIniFilename = userIniFilename,
            SessionSavePath = sessionSavePath,
            IncludePath = includePath,
            FpmUser = fpmUser,
            FpmGroup = fpmGroup,
            RceOnWriteLikely = rceOnWriteLikely,
            UserIniInjectionLikely = userIniInjection,
            SourcePath = sourcePath,
        };
    }

    /// <summary>
    /// Cheap HTML signature check used by HttpProbeTool to decide
    /// whether to invoke the parser. phpinfo() always emits
    /// <c>&lt;title&gt;PHP X.Y.Z - phpinfo()&lt;/title&gt;</c>.
    /// </summary>
    public static bool LooksLikePhpInfo(string? html)
    {
        if (string.IsNullOrEmpty(html)) return false;
        return TitleVersionRegex().IsMatch(html) || html.Contains("phpinfo()", StringComparison.Ordinal);
    }

    private static string ExtractDirective(string html, string name)
    {
        // <tr><td class="e">NAME</td><td class="v">LOCAL</td><td class="v">MASTER</td></tr>
        // Local value wins. <i>no value</i> normalises to empty.
        var pattern = @"<tr>\s*<td\s+class=""e"">\s*"
                      + Regex.Escape(name)
                      + @"\s*</td>\s*<td\s+class=""v"">(?<v>.*?)</td>";
        var m = Regex.Match(html, pattern,
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(2));
        if (!m.Success) return "";
        var raw = m.Groups["v"].Value.Trim();
        if (raw.Equals("<i>no value</i>", StringComparison.OrdinalIgnoreCase)) return "";
        // Strip any inner tags (e.g. <i>...</i>) but keep the text.
        var stripped = Regex.Replace(raw, @"<[^>]+>", "",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2)).Trim();
        return WebUtility.HtmlDecode(stripped);
    }

    private static string? FirstGroup(Regex rx, string input)
    {
        var m = rx.Match(input);
        return m.Success ? m.Groups[1].Value.Trim() : null;
    }
}
