using System.Diagnostics;
using System.Xml.Linq;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// Wrapper around the <c>nmap</c> binary. Uses service/version detection and
/// the <c>safe</c> + <c>default</c> NSE categories only. Exploit, brute, and
/// vuln scripts are explicitly excluded; this tool performs discovery and
/// fingerprinting, not exploitation.
/// </summary>
public sealed class NmapTool
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _nmapPath;

    // -Pn           : targets often drop ICMP in HTB/CTF environments
    // -sV -sC       : service/version + default NSE scripts
    // --script      : restrict to safe+default categories only
    // --top-ports   : sensible default when the agent hasn't asked for -p-
    private static readonly string[] BaseArgs =
    [
        "-Pn", "-sV", "-sC",
        "-T4", "--min-rate", "1000",
        "--script", "safe,default",
        "-oX", "-",
    ];

    public NmapTool(Scope.Scope scope, AuditLog audit, string? nmapPath = null)
    {
        _scope = scope;
        _audit = audit;
        _nmapPath = nmapPath ?? "nmap";
    }

    public async Task<NmapResult> ScanAsync(
        string target,
        string? portSpec = null,
        CancellationToken ct = default)
    {
        _scope.Require(target);

        var args = new List<string>(BaseArgs);
        // Port spec: either user/agent-supplied (e.g. "1-65535", "80,443"), or top-1000 by default.
        if (!string.IsNullOrWhiteSpace(portSpec))
        {
            RejectUnsafePortSpec(portSpec);
            args.Add("-p");
            args.Add(portSpec);
        }
        else
        {
            args.Add("--top-ports");
            args.Add("1000");
        }
        args.Add(target);

        _audit.Record("nmap.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["argv"] = args,
        });

        var psi = new ProcessStartInfo(_nmapPath)
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
            _audit.Record("nmap.error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["error"] = ex.Message,
            });
            return new NmapResult { ReturnCode = -1, Stderr = ex.Message };
        }

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        _audit.Record("nmap.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["returncode"] = proc.ExitCode,
        });

        if (proc.ExitCode != 0)
        {
            return new NmapResult
            {
                ReturnCode = proc.ExitCode,
                Stderr = Tail(stderr, 2000),
            };
        }

        var result = new NmapResult { ReturnCode = 0 };
        try { result.OpenPorts.AddRange(ParseXml(stdout)); }
        catch (Exception ex) { result.Stderr = "xml-parse: " + ex.Message; }
        return result;
    }

    private static void RejectUnsafePortSpec(string portSpec)
    {
        // Allow digits, commas, dashes, and the special "-" (all ports) only.
        foreach (var ch in portSpec)
        {
            if (ch is not ((>= '0' and <= '9') or ',' or '-'))
                throw new ArgumentException(
                    $"Unsafe port spec '{portSpec}'. Only digits, commas, and dashes are allowed.");
        }
    }

    private static IEnumerable<NmapPort> ParseXml(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) yield break;
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch (System.Xml.XmlException) { yield break; }
        var host = doc.Root?.Element("host");
        if (host is null) yield break;
        foreach (var p in host.Elements("ports").Elements("port"))
        {
            var state = p.Element("state")?.Attribute("state")?.Value;
            if (state != "open") continue;
            var svc = p.Element("service");
            var port = new NmapPort
            {
                Port = int.TryParse(p.Attribute("portid")?.Value, out var n) ? n : 0,
                Protocol = p.Attribute("protocol")?.Value ?? "tcp",
                Service = svc?.Attribute("name")?.Value,
                Product = svc?.Attribute("product")?.Value,
                Version = svc?.Attribute("version")?.Value,
                Extra = svc?.Attribute("extrainfo")?.Value,
            };
            foreach (var s in p.Elements("script"))
            {
                port.Scripts.Add(new NmapScript
                {
                    Id = s.Attribute("id")?.Value ?? "",
                    Output = s.Attribute("output")?.Value ?? "",
                });
            }
            yield return port;
        }
    }

    private static string Tail(string s, int max) => s.Length <= max ? s : s[^max..];
}
