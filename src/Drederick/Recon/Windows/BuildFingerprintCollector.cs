using System.Globalization;
using System.Text.RegularExpressions;
using Drederick.Exploit;

namespace Drederick.Recon.Windows;

/// <summary>
/// Slice-C Windows build fingerprint — aggregates already-collected recon
/// data into a high-signal shape consumable by
/// <see cref="Drederick.Enrichment.FingerprintMatcher.MatchWindowsBuild"/>.
///
/// Pure data carrier. <see cref="BuildFingerprintCollector"/> never touches
/// the network, never spawns subprocesses, never calls
/// <c>_scope.Require</c> — it is a passive join over fields that other
/// scope-validated tools have already produced.
/// </summary>
public sealed record WindowsBuildFingerprint(
    string? Product,
    string? CurrentBuild,
    string? Ubr,
    string? ReleaseId,
    string? FeaturePack,
    IReadOnlyList<string> InstalledKbs,
    IReadOnlyList<string> EnabledFeatures,
    string? SmbDialect,
    string? AdSchemaVersion,
    IReadOnlyDictionary<string, string> ServiceVersions)
{
    /// <summary>Empty fingerprint — no signal at all.</summary>
    public static WindowsBuildFingerprint Empty { get; } = new(
        Product: null,
        CurrentBuild: null,
        Ubr: null,
        ReleaseId: null,
        FeaturePack: null,
        InstalledKbs: Array.Empty<string>(),
        EnabledFeatures: Array.Empty<string>(),
        SmbDialect: null,
        AdSchemaVersion: null,
        ServiceVersions: new Dictionary<string, string>());

    /// <summary>Map the marketing <see cref="Product"/> string to the
    /// JSON corpus product tag set (Win10/Win11/WinSrv-2016/WinSrv-2019/
    /// WinSrv-2022). Returns an empty set on Unknown so the matcher's
    /// product filter falls through (prefer false positives).</summary>
    public IReadOnlyList<string> ProductTags()
    {
        var s = Product ?? string.Empty;
        if (string.IsNullOrWhiteSpace(s)) return Array.Empty<string>();
        var tags = new List<string>();
        if (s.Contains("Server 2022", StringComparison.OrdinalIgnoreCase)) tags.Add("WinSrv-2022");
        if (s.Contains("Server 2019", StringComparison.OrdinalIgnoreCase)) tags.Add("WinSrv-2019");
        if (s.Contains("Server 2016", StringComparison.OrdinalIgnoreCase)) tags.Add("WinSrv-2016");
        if (s.Contains("Windows 11", StringComparison.OrdinalIgnoreCase)) tags.Add("Win11");
        else if (s.Contains("Windows 10", StringComparison.OrdinalIgnoreCase)) tags.Add("Win10");
        if (s.Contains("Exchange", StringComparison.OrdinalIgnoreCase)) tags.Add("Exchange");
        return tags;
    }

    /// <summary>Numeric Update Build Revision suitable for ordered comparison
    /// against the corpus's <c>min_build_revision</c> threshold. Returns
    /// null when the UBR is missing or non-numeric.</summary>
    public int? UbrInt =>
        int.TryParse(Ubr, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

    /// <summary>Numeric CurrentBuild (e.g. 17763, 19041) suitable for
    /// comparison against the corpus's <c>min_build_revision</c> prefix.</summary>
    public int? CurrentBuildInt =>
        int.TryParse(CurrentBuild, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
}

/// <summary>
/// Passive aggregator over <see cref="HostFinding"/>. Reads existing recon
/// shapes — SMB negotiate output, nmap <c>smb-os-discovery</c> script lines,
/// LDAP rootDSE objectVersion, banner text — and assembles a
/// <see cref="WindowsBuildFingerprint"/>. No IO of its own.
/// </summary>
public sealed class BuildFingerprintCollector
{
    // smb-os-discovery emits lines like:
    //   "OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)"
    //   "OS CPE: cpe:/o:microsoft:windows_server_2019"
    //   "Computer name: DC01"
    //   "Domain name: example.local"
    private static readonly Regex OsLine = new(
        @"OS:\s*(?<os>[^\r\n(]+?)(?:\s+(?<build>\d{4,6})(?:\.(?<ubr>\d+))?)?(?:\s*\(|$)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // Get-HotFix / wmic qfe / systeminfo Hotfixes output: "KB5028171", "KB-5028171", "5028171".
    private static readonly Regex KbRegex = new(
        @"\bKB[\s\-]?(?<id>\d{6,8})\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // Patch-level hint in smb-os-discovery / smbv2-enabled output: e.g.
    //   "Windows Server 2019 (build 17763.4252)"
    //   "build 19041.3636"
    private static readonly Regex BuildUbrRegex = new(
        @"build\s+(?<build>\d{4,6})\.(?<ubr>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // SMB dialect from native SMB negotiate result e.g. "SMB 3.1.1".
    private static readonly Regex DialectRegex = new(
        @"(?:SMB[v\s]*|dialect[:\s]+)?(?<v>[23]\.[01](?:\.[01])?)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex SchemaVersionRegex = new(
        @"objectVersion[:\s=]+(?<v>\d{2,3})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>Build a fingerprint from already-collected recon. Pure
    /// aggregation. Returns <see cref="WindowsBuildFingerprint.Empty"/>
    /// when nothing Windows-shaped is present.</summary>
    public WindowsBuildFingerprint Build(HostFinding host)
    {
        ArgumentNullException.ThrowIfNull(host);

        string? product = null;
        string? currentBuild = null;
        string? ubr = null;
        string? smbDialect = null;
        string? schemaVersion = null;
        var kbs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var features = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var services = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // --- SMB negotiate / OS string ---
        foreach (var smb in host.Smb ?? new())
        {
            if (!string.IsNullOrWhiteSpace(smb.Os))
            {
                product ??= NormalizeProduct(smb.Os);
                var m = OsLine.Match("OS: " + smb.Os);
                if (m.Success)
                {
                    if (m.Groups["build"].Success && currentBuild is null)
                        currentBuild = m.Groups["build"].Value;
                    if (m.Groups["ubr"].Success && ubr is null)
                        ubr = m.Groups["ubr"].Value;
                }
                var ub = BuildUbrRegex.Match(smb.Os);
                if (ub.Success)
                {
                    currentBuild ??= ub.Groups["build"].Value;
                    ubr ??= ub.Groups["ubr"].Value;
                }
            }
            if (smb.Protocols is { Count: > 0 })
            {
                foreach (var proto in smb.Protocols)
                {
                    var d = DialectRegex.Match(proto ?? "");
                    if (d.Success)
                    {
                        smbDialect ??= d.Groups["v"].Value;
                    }
                    if ((proto ?? "").Contains("SMBv1", StringComparison.OrdinalIgnoreCase) ||
                        (proto ?? "").Contains("SMB 1", StringComparison.OrdinalIgnoreCase) ||
                        (proto ?? "").Equals("NT LM 0.12", StringComparison.OrdinalIgnoreCase))
                    {
                        features.Add("smbv1");
                    }
                }
            }
        }

        // --- nmap script output (smb-os-discovery, smb2-security-mode,
        //     smb-protocols, ms-sql-info, http-server-header, …) ---
        if (host.Nmap is not null)
        {
            foreach (var port in host.Nmap.OpenPorts)
            {
                foreach (var script in port.Scripts ?? new())
                {
                    var output = script.Output ?? string.Empty;
                    var id = script.Id ?? string.Empty;

                    if (id.Contains("smb-os-discovery", StringComparison.OrdinalIgnoreCase))
                    {
                        product ??= ExtractProductFromOsDiscovery(output);
                        var ub = BuildUbrRegex.Match(output);
                        if (ub.Success)
                        {
                            currentBuild ??= ub.Groups["build"].Value;
                            ubr ??= ub.Groups["ubr"].Value;
                        }
                        else
                        {
                            // Lines like: "OS: Windows Server 2019 Standard 17763"
                            var m = OsLine.Match(output);
                            if (m.Success && m.Groups["build"].Success)
                                currentBuild ??= m.Groups["build"].Value;
                        }
                    }
                    else if (id.Contains("smb-protocols", StringComparison.OrdinalIgnoreCase) ||
                             id.Contains("smb2-capabilities", StringComparison.OrdinalIgnoreCase))
                    {
                        var d = DialectRegex.Match(output);
                        if (d.Success) smbDialect ??= d.Groups["v"].Value;
                        if (output.Contains("NT LM 0.12", StringComparison.OrdinalIgnoreCase) ||
                            output.Contains("SMBv1", StringComparison.OrdinalIgnoreCase))
                        {
                            features.Add("smbv1");
                        }
                        if (output.Contains("SMBv3 compression", StringComparison.OrdinalIgnoreCase) ||
                            output.Contains("compression algorithm", StringComparison.OrdinalIgnoreCase))
                        {
                            features.Add("smbv3-compression");
                        }
                    }
                    else if (id.Contains("ldap-rootdse", StringComparison.OrdinalIgnoreCase) ||
                             id.Contains("ldap-search", StringComparison.OrdinalIgnoreCase))
                    {
                        var sv = SchemaVersionRegex.Match(output);
                        if (sv.Success) schemaVersion ??= sv.Groups["v"].Value;
                    }
                    else if (id.Contains("http-server-header", StringComparison.OrdinalIgnoreCase))
                    {
                        if (output.Contains("Microsoft-IIS", StringComparison.OrdinalIgnoreCase))
                        {
                            features.Add("iis");
                            var iis = Regex.Match(output, @"Microsoft-IIS/([0-9.]+)");
                            if (iis.Success) services["iis"] = iis.Groups[1].Value;
                        }
                    }

                    // Hotfix KBs sometimes surface in scripts that scrape
                    // version banners; harvest them everywhere.
                    foreach (Match kb in KbRegex.Matches(output))
                    {
                        kbs.Add("KB" + kb.Groups["id"].Value);
                    }
                }

                // Service product/version banner → service map.
                if (!string.IsNullOrWhiteSpace(port.Product) && !string.IsNullOrWhiteSpace(port.Version))
                {
                    var key = port.Service ?? port.Product;
                    if (!string.IsNullOrWhiteSpace(key) && !services.ContainsKey(key!))
                        services[key!] = port.Version!;
                }
                if ((port.Service ?? "").Equals("spoolss", StringComparison.OrdinalIgnoreCase) ||
                    port.Port == 1024)
                {
                    features.Add("spooler");
                }
            }
        }

        // --- LDAP rootDSE (AD schema version hint) ---
        foreach (var rd in host.LdapRootDse ?? new())
        {
            foreach (var nc in rd.NamingContexts ?? new())
            {
                if (nc.Contains("CN=Schema", StringComparison.OrdinalIgnoreCase))
                {
                    features.Add("domain-controller");
                }
            }
            // SupportedControls hints — 1.2.840.113556.1.4.1781 = forest fn
            if (rd.SupportedControls is { Count: > 0 }) features.Add("domain-controller");
        }

        // --- Findings dictionary (chain-template substitution surface)
        //     may carry pre-parsed KBs / build under "windows.*" keys.
        foreach (var kv in host.Findings ?? new())
        {
            if (kv.Key.Equals("windows.installed_kbs", StringComparison.OrdinalIgnoreCase))
            {
                foreach (Match m in KbRegex.Matches(kv.Value ?? ""))
                    kbs.Add("KB" + m.Groups["id"].Value);
            }
            else if (kv.Key.Equals("windows.current_build", StringComparison.OrdinalIgnoreCase))
            {
                currentBuild ??= kv.Value;
            }
            else if (kv.Key.Equals("windows.ubr", StringComparison.OrdinalIgnoreCase))
            {
                ubr ??= kv.Value;
            }
            else if (kv.Key.Equals("windows.release_id", StringComparison.OrdinalIgnoreCase))
            {
                // no-op handled below
            }
            else if (kv.Key.Equals("windows.product", StringComparison.OrdinalIgnoreCase) && product is null)
            {
                product = kv.Value;
            }
            else if (kv.Key.Equals("windows.ad_schema_version", StringComparison.OrdinalIgnoreCase))
            {
                schemaVersion ??= kv.Value;
            }
        }
        var releaseId = host.Findings?.TryGetValue("windows.release_id", out var rid) == true ? rid : null;
        var featurePack = host.Findings?.TryGetValue("windows.feature_pack", out var fp) == true ? fp : null;

        if (product is null && currentBuild is null && kbs.Count == 0 && smbDialect is null && schemaVersion is null)
        {
            return WindowsBuildFingerprint.Empty;
        }

        return new WindowsBuildFingerprint(
            Product: product,
            CurrentBuild: currentBuild,
            Ubr: ubr,
            ReleaseId: releaseId,
            FeaturePack: featurePack,
            InstalledKbs: kbs.OrderBy(k => k, StringComparer.OrdinalIgnoreCase).ToList(),
            EnabledFeatures: features.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList(),
            SmbDialect: smbDialect,
            AdSchemaVersion: schemaVersion,
            ServiceVersions: services);
    }

    private static string? NormalizeProduct(string raw)
    {
        var s = raw.Trim();
        if (s.Length == 0) return null;
        // strip trailing "(...)" build hint
        var idx = s.IndexOf('(');
        if (idx > 0) s = s[..idx].Trim();
        return s;
    }

    private static string? ExtractProductFromOsDiscovery(string output)
    {
        // First line shape: "OS: Windows Server 2019 Standard 17763 (...)"
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("OS:", StringComparison.OrdinalIgnoreCase))
            {
                var body = line[3..].Trim();
                return NormalizeProduct(StripBuildSuffix(body));
            }
        }
        return null;
    }

    private static string StripBuildSuffix(string s)
    {
        // remove trailing " 17763" build digits if present.
        var m = Regex.Match(s, @"\s+\d{4,6}(?:\.\d+)?\s*$");
        return m.Success ? s[..m.Index].Trim() : s;
    }
}
