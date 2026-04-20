using System.Diagnostics;
using System.Xml.Linq;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Enumerates the TLS protocol versions and cipher suites offered on a single
/// port by delegating to nmap's <c>ssl-enum-ciphers</c> NSE script. The script
/// is a member of the <c>safe</c> category and performs handshake-only probes;
/// no brute force, no exploit attempts. Only the requested port is touched.
/// </summary>
public sealed class TlsCipherEnumTool : IReconTool
{
    public string Name => "tls-cipher-enum";

    public string Description =>
        "Enumerate TLS versions and cipher suites on a single port using nmap's " +
        "ssl-enum-ciphers NSE script (safe category). Target MUST be in scope.";

    /// <summary>Minimal result of a process invocation; injected for tests.</summary>
    public sealed record ProcessResult(int ExitCode, string Stdout, string Stderr);

    /// <summary>Process runner signature: run (path, args) and return exit+streams.</summary>
    public delegate Task<ProcessResult> ProcessRunner(
        string path,
        IReadOnlyList<string> args,
        CancellationToken ct);

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _nmapPath;
    private readonly ProcessRunner _runner;

    public TlsCipherEnumTool(
        Scope.Scope scope,
        AuditLog audit,
        string? nmapPath = null,
        ProcessRunner? runner = null)
    {
        _scope = scope;
        _audit = audit;
        _nmapPath = nmapPath ?? "nmap";
        _runner = runner ?? DefaultRunner;
    }

    public async Task<TlsCipherEnumResult> ProbeAsync(
        string target,
        int port = 443,
        CancellationToken ct = default)
    {
        _scope.Require(target);

        var args = new List<string>
        {
            "-Pn",
            "-p", port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--script", "ssl-enum-ciphers",
            "-oX", "-",
            target,
        };

        _audit.Record("tls-cipher-enum.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["argv"] = args,
        });

        var result = new TlsCipherEnumResult { Port = port };
        ProcessResult pr;
        try
        {
            pr = await _runner(_nmapPath, args, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            _audit.Record("tls-cipher-enum.finish", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["returncode"] = -1,
                ["error"] = ex.Message,
            });
            return result;
        }

        if (pr.ExitCode != 0)
        {
            result.Error = $"nmap exit={pr.ExitCode}: {Tail(pr.Stderr, 2000)}";
        }
        else
        {
            try { ParseXml(pr.Stdout, result); }
            catch (Exception ex) { result.Error = "xml-parse: " + ex.Message; }
        }

        _audit.Record("tls-cipher-enum.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["returncode"] = pr.ExitCode,
            ["versions"] = result.Versions.Keys.ToList(),
            ["error"] = result.Error,
        });
        return result;
    }

    private static void ParseXml(string xml, TlsCipherEnumResult result)
    {
        if (string.IsNullOrWhiteSpace(xml)) return;
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch (System.Xml.XmlException) { return; }

        var script = doc.Descendants("script")
            .FirstOrDefault(s => (string?)s.Attribute("id") == "ssl-enum-ciphers");
        if (script is null) return;

        string? leastStrength = script.Elements("elem")
            .FirstOrDefault(e => (string?)e.Attribute("key") == "least strength")?.Value;

        foreach (var verTable in script.Elements("table"))
        {
            var key = (string?)verTable.Attribute("key");
            if (string.IsNullOrEmpty(key)) continue;
            if (!key.StartsWith("TLSv", StringComparison.OrdinalIgnoreCase) &&
                !key.StartsWith("SSLv", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var version = new TlsCipherVersion { Grade = leastStrength };
            var ciphersTable = verTable.Elements("table")
                .FirstOrDefault(t => (string?)t.Attribute("key") == "ciphers");
            if (ciphersTable is not null)
            {
                foreach (var entry in ciphersTable.Elements("table"))
                {
                    var name = entry.Elements("elem")
                        .FirstOrDefault(e => (string?)e.Attribute("key") == "name")?.Value;
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        version.Ciphers.Add(name.Trim());
                    }
                }
            }
            result.Versions[key] = version;
        }
    }

    private static async Task<ProcessResult> DefaultRunner(
        string path,
        IReadOnlyList<string> args,
        CancellationToken ct)
    {
        var psi = new ProcessStartInfo(path)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        Process proc;
        try
        {
            proc = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null");
        }
        catch (Exception ex)
        {
            return new ProcessResult(-1, "", ex.Message);
        }

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        return new ProcessResult(proc.ExitCode, stdout, stderr);
    }

    private static string Tail(string s, int max) =>
        string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[^max..]);
}
