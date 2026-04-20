using System.ComponentModel;
using Drederick.Doctor;

namespace Drederick.Enrichment;

/// <summary>
/// Greps a local clone of <c>nuclei-templates</c> for the given CVE id and
/// records the resulting template paths. Looks for the templates directory
/// under a small list of conventional locations (overridable in tests). No
/// network, no execution — we read template paths off disk and stop.
/// </summary>
public sealed class NucleiSource : IPocSource
{
    public const string SourceName = "nuclei";
    private const int TimeoutSeconds = 30;

    private readonly IProcessRunner _runner;
    private readonly Func<string?> _templatesDirProbe;

    public NucleiSource(IProcessRunner? runner = null, Func<string?>? templatesDirProbe = null)
    {
        _runner = runner ?? new DefaultProcessRunner();
        _templatesDirProbe = templatesDirProbe ?? DefaultProbe;
    }

    public string Name => SourceName;

    public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);
        ArgumentNullException.ThrowIfNull(ctx);

        IReadOnlyList<PocRef> empty = Array.Empty<PocRef>();
        var dir = _templatesDirProbe();
        if (string.IsNullOrWhiteSpace(dir)) return Task.FromResult(empty);

        (int code, string stdout, string _) res;
        try
        {
            // grep -rln: recursive, filenames only, no line numbers. Fixed
            // string (-F) because CVE ids contain no regex metachars worth
            // interpreting and it avoids injecting a user-controlled pattern.
            res = _runner.Run("grep",
                $"-rlnF -- {ShellArg(cveId)} {ShellArg(dir)}",
                TimeoutSeconds);
        }
        catch (Win32Exception) { return Task.FromResult(empty); }
        catch (InvalidOperationException) { return Task.FromResult(empty); }
        catch (TimeoutException) { return Task.FromResult(empty); }

        // grep exits 1 when no matches; that's not a failure.
        if (res.code != 0 && res.code != 1) return Task.FromResult(empty);

        var refs = new List<PocRef>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in res.stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var path = line.Trim();
            if (path.Length == 0) continue;
            if (!seen.Add(path)) continue;
            var templateId = Path.GetFileNameWithoutExtension(path);
            refs.Add(new PocRef(Name, Url: null, ExternalId: templateId, LocalPath: path));
        }
        return Task.FromResult<IReadOnlyList<PocRef>>(refs);
    }

    private static string? DefaultProbe()
    {
        var home = Environment.GetEnvironmentVariable("HOME")
                   ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home)) return null;
        string[] candidates =
        {
            Path.Combine(home, "nuclei-templates"),
            Path.Combine(home, ".config", "nuclei", "templates"),
            Path.Combine(home, ".config", "nuclei-templates"),
        };
        foreach (var c in candidates)
        {
            if (Directory.Exists(c)) return c;
        }
        return null;
    }

    private static string ShellArg(string s) => "'" + s.Replace("'", "'\\''") + "'";
}
