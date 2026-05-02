using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Drederick.Doctor;

namespace Drederick.Enrichment;

/// <summary>
/// Discovers Metasploit modules that match a CVE id via two complementary
/// paths so the planner gets band-490 <c>msfrc</c> actions whether the box
/// has a live <c>msfconsole</c> CLI or just an installed module tree:
/// <list type="number">
///   <item><description><b>CLI search</b> — <c>msfconsole -q -x "search cve:&lt;cve&gt;; exit"</c>.
///   Authoritative when present, but slow (msfconsole spinup is multi-second)
///   and absent on minimal recon boxes.</description></item>
///   <item><description><b>Filesystem scan</b> — when a
///   <c>metasploit-framework/modules</c> tree is reachable on disk (Kali,
///   <c>/usr/share/metasploit-framework</c>, <c>~/.msf4/modules</c>, or
///   <c>$DREDERICK_MSF_MODULES</c>) <c>grep -rlF</c>'s <c>.rb</c> files for
///   the CVE id and copies every match verbatim into
///   <c>out/poc_cache/metasploit/&lt;safe-module-id&gt;/</c>. Records
///   SHA-256 via <see cref="Reporting.SqliteReport.UpsertPocSource"/> and
///   emits a <c>poc.fetch</c> audit event. Fast, offline, cache-priming —
///   GAP-031b's missing link.</description></item>
/// </list>
/// Results from both paths are unioned by module id; FS hits supply
/// <see cref="PocRef.LocalPath"/> so <c>ExploitationPlanner</c> emits
/// band-490 <c>msfrc</c> directly instead of falling back to band-250
/// <c>cve-lead</c>. <b>Invariant:</b> we never invoke modules; the cache
/// is read-only by this class. Verbatim copy — no rewriting, no
/// neutralisation.
/// </summary>
public sealed class MetasploitSource : IPocSource
{
    public const string SourceName = "metasploit";
    private const int CliTimeoutSeconds = 60;
    private const int GrepTimeoutSeconds = 30;
    private const long DefaultMaxArtifactBytes = 5L * 1024 * 1024;       // 5 MB
    private const long DefaultMaxTotalBytes = 2L * 1024 * 1024 * 1024;   // 2 GB

    // msfconsole search output rows look like:
    //     0  exploit/linux/ftp/vsftpd_234_backdoor  2011-07-03  excellent  No  ...
    // Grab the second whitespace-separated token (the module path).
    private static readonly Regex ModuleRowRegex = new(
        @"^\s*\d+\s+(?<mod>(?:exploit|auxiliary|post|payload|encoder|nop|evasion)/[A-Za-z0-9_./\-]+)\b",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private readonly IProcessRunner _runner;
    private readonly Func<string?> _modulesDirProbe;
    private readonly long _maxArtifactBytes;
    private readonly long _maxTotalBytes;

    // CVE-id whitelist regex — defends the grep argv from injection. Matches
    // exactly the canonical CVE-YYYY-NNNN[N…] shape we accept everywhere.
    private static readonly Regex CveShape = new(@"^CVE-\d{4}-\d{4,7}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public MetasploitSource(
        IProcessRunner? runner = null,
        Func<string?>? modulesDirProbe = null,
        long? maxArtifactBytes = null,
        long? maxTotalBytes = null)
    {
        _runner = runner ?? new DefaultProcessRunner();
        _modulesDirProbe = modulesDirProbe ?? DefaultModulesProbe;
        _maxArtifactBytes = maxArtifactBytes ?? DefaultMaxArtifactBytes;
        _maxTotalBytes = maxTotalBytes ?? DefaultMaxTotalBytes;
    }

    public string Name => SourceName;

    public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);
        ArgumentNullException.ThrowIfNull(ctx);

        // Reject anything that doesn't shape-match a CVE id. This keeps
        // unsanitized fragments out of the grep / msfconsole argv.
        if (!CveShape.IsMatch(cveId))
            return Task.FromResult<IReadOnlyList<PocRef>>(Array.Empty<PocRef>());

        var byModule = new Dictionary<string, PocRef>(StringComparer.Ordinal);

        // 1. msfconsole search — authoritative when present.
        foreach (var mod in QueryViaCli(cveId))
        {
            if (!byModule.ContainsKey(mod))
                byModule[mod] = new PocRef(Name, Url: null, ExternalId: mod);
        }

        // 2. Filesystem scan + cache. Default-on, gated by ctx.FetchPoc so
        //    --no-fetch-poc cleanly disables (the spec contract). When the
        //    FS hit lands we replace any CLI-only entry with one that carries
        //    LocalPath, so the planner's band-490 emit path fires.
        if (ctx.FetchPoc)
        {
            foreach (var hit in QueryViaFilesystem(cveId, ctx))
            {
                byModule[hit.ExternalId!] = hit;
            }
        }

        return Task.FromResult<IReadOnlyList<PocRef>>(byModule.Values.ToArray());
    }

    private IEnumerable<string> QueryViaCli(string cveId)
    {
        (int code, string stdout, string _) res;
        try
        {
            res = _runner.Run("msfconsole",
                $"-q -x \"search cve:{cveId}; exit\"",
                CliTimeoutSeconds);
        }
        catch (Win32Exception) { yield break; }
        catch (InvalidOperationException) { yield break; }
        catch (TimeoutException) { yield break; }

        if (res.code != 0 || string.IsNullOrWhiteSpace(res.stdout)) yield break;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in ModuleRowRegex.Matches(res.stdout))
        {
            var mod = m.Groups["mod"].Value;
            if (seen.Add(mod)) yield return mod;
        }
    }

    private IEnumerable<PocRef> QueryViaFilesystem(string cveId, PocQueryContext ctx)
    {
        var modulesRoot = _modulesDirProbe();
        if (string.IsNullOrWhiteSpace(modulesRoot) || !Directory.Exists(modulesRoot))
            yield break;

        // Only sweep module subtrees that can ship runnable exploit/auxiliary
        // logic. payload/encoder/nop/evasion bodies don't carry CVE refs.
        var subdirs = new[] { "exploits", "auxiliary", "post" }
            .Select(s => Path.Combine(modulesRoot, s))
            .Where(Directory.Exists)
            .ToArray();
        if (subdirs.Length == 0) yield break;

        // grep -rlnF for the bare CVE id ('CVE-YYYY-NNNN'). Modern MSF
        // modules cite the bare form even when also using ['CVE','YYYY-NNNN'].
        // We assemble the argv as a single shell command (NucleiSource does
        // the same) and quote every path so injection is impossible — the
        // CVE id is whitelisted by CveShape above.
        var argList = string.Join(' ', subdirs.Select(ShellArg));
        (int code, string stdout, string _) res;
        try
        {
            res = _runner.Run("grep",
                $"-rlnF -- {ShellArg(cveId)} {argList}",
                GrepTimeoutSeconds);
        }
        catch (Win32Exception) { yield break; }
        catch (InvalidOperationException) { yield break; }
        catch (TimeoutException) { yield break; }

        // grep exits 1 when no matches; that's not a failure.
        if (res.code != 0 && res.code != 1) yield break;

        long totalCached = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in res.stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var path = raw.Trim();
            if (path.Length == 0) continue;
            if (!path.EndsWith(".rb", StringComparison.OrdinalIgnoreCase)) continue;
            if (!File.Exists(path)) continue;

            var moduleId = ToModuleId(modulesRoot, path);
            if (string.IsNullOrEmpty(moduleId)) continue;
            if (!seen.Add(moduleId)) continue;

            PocRef? cached = TryCache(cveId, moduleId, path, ctx, ref totalCached);
            if (cached is null) continue;
            yield return cached;
        }
    }

    private PocRef? TryCache(string cveId, string moduleId, string sourcePath, PocQueryContext ctx, ref long totalCached)
    {
        try
        {
            var info = new FileInfo(sourcePath);
            if (!info.Exists) return null;
            if (info.Length > _maxArtifactBytes) return null;
            if (totalCached + info.Length > _maxTotalBytes) return null;

            var safeId = SafeId(moduleId);
            var dir = Path.Combine(ctx.CacheRoot, Name, safeId);
            Directory.CreateDirectory(dir);
            var dest = Path.Combine(dir, Path.GetFileName(sourcePath));

            // Verbatim copy — bytes flow through unchanged.
            var bytes = File.ReadAllBytes(sourcePath);
            File.WriteAllBytes(dest, bytes);
            totalCached += info.Length;

            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var fetchedAt = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            var sourceUrl = $"https://github.com/rapid7/metasploit-framework/blob/master/modules/{moduleId}.rb";

            ctx.Report.UpsertPocSource(
                source: Name,
                externalId: moduleId,
                sha256: sha,
                path: dest,
                fetchedAt: fetchedAt,
                sourceUrl: sourceUrl);

            ctx.Audit?.Record("poc.fetch", new Dictionary<string, object?>
            {
                ["source"] = Name,
                ["cve"] = cveId,
                ["external_id"] = moduleId,
                ["url"] = sourceUrl,
                ["local_path"] = dest,
                ["sha256"] = sha,
                ["bytes"] = info.Length,
            });

            return new PocRef(Name, Url: sourceUrl, ExternalId: moduleId, LocalPath: dest);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// Convert <c>/usr/share/metasploit-framework/modules/exploits/windows/http/foo.rb</c>
    /// → <c>exploit/windows/http/foo</c> (matches the canonical msf module
    /// path used by ExploitationPlanner.BuildMsfOptions).
    /// </summary>
    internal static string ToModuleId(string modulesRoot, string filePath)
    {
        var rooted = Path.GetFullPath(modulesRoot).TrimEnd(Path.DirectorySeparatorChar);
        var full = Path.GetFullPath(filePath);
        if (!full.StartsWith(rooted + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            return "";
        var rel = full.Substring(rooted.Length + 1);
        // Strip extension and normalize separators.
        rel = rel.Replace(Path.DirectorySeparatorChar, '/');
        if (rel.EndsWith(".rb", StringComparison.OrdinalIgnoreCase))
            rel = rel[..^3];
        // exploits/foo → exploit/foo (singular form is what msfconsole uses).
        if (rel.StartsWith("exploits/", StringComparison.Ordinal))
            rel = "exploit/" + rel.Substring("exploits/".Length);
        return rel;
    }

    private static string SafeId(string moduleId)
        => moduleId.Replace('/', '_').Replace('\\', '_');

    private static string? DefaultModulesProbe()
    {
        var env = Environment.GetEnvironmentVariable("DREDERICK_MSF_MODULES");
        if (!string.IsNullOrWhiteSpace(env) && Directory.Exists(env)) return env;

        var home = Environment.GetEnvironmentVariable("HOME")
                   ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var candidates = new List<string>
        {
            "/usr/share/metasploit-framework/modules",
            "/opt/metasploit-framework/modules",
            "/opt/metasploit-framework/embedded/framework/modules",
        };
        if (!string.IsNullOrWhiteSpace(home))
        {
            candidates.Add(Path.Combine(home, ".msf4", "modules"));
            candidates.Add(Path.Combine(home, "metasploit-framework", "modules"));
        }
        foreach (var c in candidates)
        {
            if (Directory.Exists(c)) return c;
        }
        return null;
    }

    private static string ShellArg(string s) => "'" + s.Replace("'", "'\\''") + "'";
}
