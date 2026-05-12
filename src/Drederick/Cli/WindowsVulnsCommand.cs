using System.Text.Json;
using Drederick.Enrichment;
using Drederick.Exploit;
using Drederick.Recon;
using Drederick.Recon.Windows;

namespace Drederick.Cli;

/// <summary>
/// `drederick windows-vulns` — Moriarty-style triage of the bundled
/// Windows MSRC corpus. Two read-only modes:
///
/// <list type="bullet">
///   <item><c>--list</c> prints every CVE / bulletin / title / severity in
///   the bundled <see cref="WindowsMsrcCorpus"/>. Operator-friendly
///   listing analogous to Moriarty's vuln listing. No scope, no
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
        // --- htb-windows-vulns-feeder ---
        // Slice-C path: when --findings-json is supplied, run the
        // BuildFingerprintCollector over a captured HostFinding and feed
        // the build/UBR/KB fingerprint into FingerprintMatcher. Returns
        // suppression-aware high/medium/low-confidence candidates.
        if (!string.IsNullOrEmpty(opts.WindowsVulnsFindingsJson))
        {
            return RunAnalyzeFromFindings(opts);
        }
        // --- end htb-windows-vulns-feeder ---
        if (string.IsNullOrEmpty(opts.WindowsVulnsPostExJson))
        {
            _err.WriteLine("windows-vulns --analyze: --postex-json <path> or --findings-json <path> is required.");
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
        catch (UnauthorizedAccessException ex)
        {
            _err.WriteLine($"windows-vulns --analyze: permission denied reading {opts.WindowsVulnsPostExJson}: {ex.Message}");
            return 2;
        }
        catch (IOException ex)
        {
            _err.WriteLine($"windows-vulns --analyze: I/O error reading {opts.WindowsVulnsPostExJson}: {ex.Message}");
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

    // --- htb-windows-vulns-feeder ---
    /// <summary>Slice-C analyzer entry point: read a captured
    /// <see cref="HostFinding"/> JSON, build a
    /// <see cref="WindowsBuildFingerprint"/>, and emit suppression-aware
    /// candidates via <see cref="FingerprintMatcher.MatchWindowsBuild"/>.
    /// Pure data — the upstream recon already ran inside scope.</summary>
    private int RunAnalyzeFromFindings(CommandLineOptions opts)
    {
        var path = opts.WindowsVulnsFindingsJson!;
        if (!File.Exists(path))
        {
            _err.WriteLine($"windows-vulns --analyze: file not found: {path}");
            return 2;
        }

        HostFinding? host;
        try
        {
            using var stream = File.OpenRead(path);
            host = JsonSerializer.Deserialize<HostFinding>(stream);
        }
        catch (JsonException ex)
        {
            _err.WriteLine($"windows-vulns --analyze: failed to parse findings JSON: {ex.Message}");
            return 2;
        }
        catch (IOException ex)
        {
            _err.WriteLine($"windows-vulns --analyze: I/O error reading {path}: {ex.Message}");
            return 2;
        }
        if (host is null)
        {
            _err.WriteLine("windows-vulns --analyze: empty findings JSON.");
            return 2;
        }

        var collector = new BuildFingerprintCollector();
        var fp = collector.Build(host);
        var matcher = FingerprintMatcher.LoadEmbedded();
        var hits = matcher.MatchWindowsBuild(fp);

        if (!opts.WindowsVulnsVerbose)
        {
            hits = hits.Where(h => h.Confidence != FingerprintMatchConfidence.Low).ToList();
        }

        if (opts.WindowsVulnsJson)
        {
            var payload = new
            {
                target = host.Target,
                fingerprint_inputs = new
                {
                    product = fp.Product,
                    current_build = fp.CurrentBuild,
                    ubr = fp.Ubr,
                    release_id = fp.ReleaseId,
                    feature_pack = fp.FeaturePack,
                    smb_dialect = fp.SmbDialect,
                    ad_schema_version = fp.AdSchemaVersion,
                    installed_kbs = fp.InstalledKbs,
                    enabled_features = fp.EnabledFeatures,
                    service_versions = fp.ServiceVersions,
                },
                candidates = hits.Select(h => new
                {
                    cve = h.Cve,
                    title = h.Title,
                    severity = h.Severity,
                    confidence = h.Confidence.ToString().ToLowerInvariant(),
                    missing_kb = h.MissingKb,
                    feature_gate = h.FeatureGate,
                    reason = h.Reason,
                    source = h.Source,
                    references = h.References,
                }),
            };
            _out.WriteLine(JsonSerializer.Serialize(payload,
                new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        _out.WriteLine($"Target            : {host.Target}");
        _out.WriteLine($"Product           : {fp.Product ?? "(unknown)"}");
        _out.WriteLine($"Build             : {fp.CurrentBuild ?? "?"}.{fp.Ubr ?? "?"}");
        _out.WriteLine($"Installed KBs     : {fp.InstalledKbs.Count}");
        _out.WriteLine($"Enabled features  : {(fp.EnabledFeatures.Count == 0 ? "(none)" : string.Join(",", fp.EnabledFeatures))}");
        _out.WriteLine($"SMB dialect       : {fp.SmbDialect ?? "(unknown)"}");
        _out.WriteLine($"AD schema version : {fp.AdSchemaVersion ?? "(unknown)"}");
        _out.WriteLine();

        if (hits.Count == 0)
        {
            _out.WriteLine("No candidates surfaced. Either fully patched, or insufficient fingerprint data.");
            return 0;
        }

        foreach (var band in new[] {
            FingerprintMatchConfidence.High,
            FingerprintMatchConfidence.Medium,
            FingerprintMatchConfidence.Low })
        {
            var rows = hits.Where(h => h.Confidence == band).ToList();
            if (rows.Count == 0) continue;
            _out.WriteLine($"--- {band.ToString().ToUpperInvariant()} confidence ({rows.Count}) ---");
            _out.WriteLine($"{"CVE",-18}{"SEV",-8}{"MISSING-KB",-14}TITLE");
            foreach (var h in rows)
            {
                _out.WriteLine($"{h.Cve,-18}{h.Severity,-8}{h.MissingKb ?? "-",-14}{h.Title}");
            }
            _out.WriteLine();
        }
        return 0;
    }
    // --- end htb-windows-vulns-feeder ---
}
