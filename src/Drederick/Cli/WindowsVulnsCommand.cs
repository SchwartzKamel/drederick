using System.Text.Json;
using Drederick.Exploit;

namespace Drederick.Cli;

/// <summary>
/// `drederick windows-vulns` — Moriarty-style triage of the bundled
/// Windows MSRC corpus. Two read-only modes:
///
/// <list type="bullet">
///   <item><c>--list</c> prints every CVE / bulletin / title / severity in
///   the bundled <see cref="WindowsMsrcCorpus"/>. Operator-friendly
///   listing (mirrors Moriarty's <c>--list-vulns</c>). No scope, no
///   subprocess, no network.</item>
///   <item><c>--analyze --postex-json &lt;file&gt;</c> reads a captured
///   <see cref="PostExWindowsResult"/> JSON, builds a
///   <see cref="WindowsHostFingerprint"/>, runs <see cref="WindowsMsrcCorpus.Match"/>
///   and prints prioritised candidates. Offline triage workflow — same
///   shape as the Linux side already supports.</item>
/// </list>
///
/// Both modes are pure-data analysis: no network, no privileged
/// subprocesses, no scope dependency. The captured PostEx JSON has
/// already been scope-validated at capture time.
/// </summary>
public sealed class WindowsVulnsCommand
{
    private readonly TextWriter _out;
    private readonly TextWriter _err;

    public WindowsVulnsCommand(TextWriter? stdout = null, TextWriter? stderr = null)
    {
        _out = stdout ?? Console.Out;
        _err = stderr ?? Console.Error;
    }

    public Task<int> ExecuteAsync(CommandLineOptions opts)
    {
        if (opts.WindowsVulnsList)
        {
            return Task.FromResult(RunList(opts));
        }
        if (opts.WindowsVulnsAnalyze)
        {
            return Task.FromResult(RunAnalyze(opts));
        }
        _err.WriteLine("windows-vulns: nothing to do. Pass --list or --analyze --postex-json <file>.");
        return Task.FromResult(2);
    }

    private int RunList(CommandLineOptions opts)
    {
        var entries = WindowsMsrcCorpus.All
            .OrderByDescending(e => e.PublishedYear ?? "0000")
            .ThenBy(e => e.Cve, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (opts.WindowsVulnsJson)
        {
            var payload = entries.Select(e => new
            {
                cve = e.Cve,
                bulletin = e.Bulletin,
                title = e.Title,
                severity = e.Severity,
                exploit = e.Exploit,
                hint = e.Hint,
                requires_feature = e.RequiresFeature,
                year = e.PublishedYear,
                patch_kbs = e.PatchKbs,
                affected_products = e.AffectedProducts.Select(p => new
                {
                    family = p.Family.ToString(),
                    build_min = p.BuildMin,
                    build_max = p.BuildMax,
                    scope = p.Scope.ToString(),
                }),
            });
            _out.WriteLine(JsonSerializer.Serialize(payload,
                new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        _out.WriteLine($"Drederick Windows MSRC corpus — {WindowsMsrcCorpus.Count} entries");
        _out.WriteLine();
        _out.WriteLine($"{"CVE",-18}{"YEAR",-6}{"SEV",-8}{"FEATURE",-22}TITLE");
        _out.WriteLine(new string('-', 100));
        foreach (var e in entries)
        {
            var feat = e.RequiresFeature ?? "-";
            _out.WriteLine($"{e.Cve,-18}{e.PublishedYear ?? "-",-6}{e.Severity,-8}{feat,-22}{e.Title}");
        }
        return 0;
    }

    private int RunAnalyze(CommandLineOptions opts)
    {
        if (string.IsNullOrEmpty(opts.WindowsVulnsPostExJson))
        {
            _err.WriteLine("windows-vulns --analyze: --postex-json <path> is required.");
            return 2;
        }
        if (!File.Exists(opts.WindowsVulnsPostExJson))
        {
            _err.WriteLine($"windows-vulns --analyze: file not found: {opts.WindowsVulnsPostExJson}");
            return 2;
        }

        PostExWindowsResult? postex;
        try
        {
            using var stream = File.OpenRead(opts.WindowsVulnsPostExJson);
            postex = JsonSerializer.Deserialize<PostExWindowsResult>(stream,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
        }
        catch (JsonException ex)
        {
            _err.WriteLine($"windows-vulns --analyze: failed to parse JSON: {ex.Message}");
            return 2;
        }
        if (postex is null)
        {
            _err.WriteLine("windows-vulns --analyze: empty PostEx JSON.");
            return 2;
        }

        var fingerprint = BuildFingerprint(postex);
        var hits = WindowsMsrcCorpus.Match(fingerprint);

        if (opts.WindowsVulnsJson)
        {
            var payload = new
            {
                target = postex.Target,
                family = fingerprint.Family.ToString(),
                build = fingerprint.Build,
                installed_kb_count = fingerprint.InstalledKbs.Count,
                candidates = hits.Select(h => new
                {
                    cve = h.Cve,
                    severity = h.Severity,
                    exploit = h.Exploit,
                    hint = h.Hint,
                    missing_kb = h.MissingKb,
                }),
            };
            _out.WriteLine(JsonSerializer.Serialize(payload,
                new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        _out.WriteLine($"Target          : {postex.Target}");
        _out.WriteLine($"Family          : {fingerprint.Family}");
        _out.WriteLine($"Build           : {fingerprint.Build?.ToString() ?? "(unknown)"}");
        _out.WriteLine($"Installed KBs   : {fingerprint.InstalledKbs.Count}");
        _out.WriteLine($"Candidates      : {hits.Count}");
        _out.WriteLine();
        if (hits.Count == 0)
        {
            _out.WriteLine("No candidates surfaced. Either fully patched, or feature gates closed.");
            return 0;
        }
        _out.WriteLine($"{"CVE",-18}{"SEV",-8}{"MISSING-KB",-14}HINT");
        _out.WriteLine(new string('-', 100));
        foreach (var h in hits)
        {
            _out.WriteLine($"{h.Cve,-18}{h.Severity,-8}{h.MissingKb ?? "-",-14}{h.Hint}");
        }
        return 0;
    }

    /// <summary>Build a <see cref="WindowsHostFingerprint"/> from the
    /// fields available on a captured <see cref="PostExWindowsResult"/>.
    /// Slice-C feature probes are not yet wired, so feature flags default
    /// to null (soft pass) — we prefer false positives over false negatives.</summary>
    internal static WindowsHostFingerprint BuildFingerprint(PostExWindowsResult postex)
    {
        var family = WindowsHostFingerprint.DetectFamily(postex.HostInfo?.OsName);
        var build = PostExWindows.ParseOsBuildToInt(postex.HostInfo?.OsBuild);
        var kbs = postex.InstalledHotfixes?.KbIds ?? new List<string>();
        return new WindowsHostFingerprint
        {
            Family = family,
            Build = build,
            InstalledKbs = kbs,
            Features = new WindowsFeatureState(),
            Software = new WindowsInstalledSoftware(),
        };
    }
}
