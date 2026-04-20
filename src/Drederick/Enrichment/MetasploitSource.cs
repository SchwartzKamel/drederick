using System.ComponentModel;
using System.Text.RegularExpressions;
using Drederick.Doctor;

namespace Drederick.Enrichment;

/// <summary>
/// Enumerates Metasploit modules that match a CVE id via
/// <c>msfconsole -q -x "search cve:&lt;cve&gt;; exit"</c>. Gracefully no-ops
/// when <c>msfconsole</c> is not on PATH. Modules stay inside the Metasploit
/// tree — we record only the module name; nothing is cached to disk.
/// Invariant: we never invoke modules, only search for them.
/// </summary>
public sealed class MetasploitSource : IPocSource
{
    public const string SourceName = "metasploit";
    private const int TimeoutSeconds = 60;

    // msfconsole search output rows look like:
    //     0  exploit/linux/ftp/vsftpd_234_backdoor  2011-07-03  excellent  No  ...
    // Grab the second whitespace-separated token (the module path).
    private static readonly Regex ModuleRowRegex = new(
        @"^\s*\d+\s+(?<mod>(?:exploit|auxiliary|post|payload|encoder|nop|evasion)/[A-Za-z0-9_./\-]+)\b",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private readonly IProcessRunner _runner;

    public MetasploitSource(IProcessRunner? runner = null)
    {
        _runner = runner ?? new DefaultProcessRunner();
    }

    public string Name => SourceName;

    public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);
        ArgumentNullException.ThrowIfNull(ctx);

        IReadOnlyList<PocRef> empty = Array.Empty<PocRef>();

        (int code, string stdout, string _) res;
        try
        {
            res = _runner.Run("msfconsole",
                $"-q -x \"search cve:{cveId}; exit\"",
                TimeoutSeconds);
        }
        catch (Win32Exception) { return Task.FromResult(empty); }
        catch (InvalidOperationException) { return Task.FromResult(empty); }
        catch (TimeoutException) { return Task.FromResult(empty); }

        if (res.code != 0 || string.IsNullOrWhiteSpace(res.stdout)) return Task.FromResult(empty);

        var refs = new List<PocRef>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in ModuleRowRegex.Matches(res.stdout))
        {
            var mod = m.Groups["mod"].Value;
            if (!seen.Add(mod)) continue;
            refs.Add(new PocRef(Name, Url: null, ExternalId: mod));
        }
        return Task.FromResult<IReadOnlyList<PocRef>>(refs);
    }
}
