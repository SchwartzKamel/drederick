using System.Globalization;
using System.Xml.Linq;
using Drederick.Audit;
using Drederick.Doctor;

namespace Drederick.Recon;

/// <summary>
/// Read-only RPC portmapper enumeration. Queries the target's portmapper
/// with <c>rpcinfo -p</c> and cross-checks with nmap's <c>rpc-grind</c> NSE
/// script (member of the <c>safe</c> category). Never attempts NFS mounts,
/// YP/NIS dumps, SunRPC exploits, or nfsls-style probes.
/// </summary>
public sealed class RpcTool : IReconTool
{
    public string Name => "rpc";

    public string Description =>
        "Enumerate RPC programs registered with the portmapper on a single target. " +
        "Uses rpcinfo -p and nmap --script rpc-grind (safe NSE category). " +
        "Never mounts NFS, dumps YP/NIS, or runs SunRPC exploits.";

    // NSE script is a member of the `safe` category. Any attempt to widen
    // this list would also need to pass the NSE validator below.
    private const string RpcGrindScript = "rpc-grind";

    // Categories/keywords that must never appear on the nmap command line.
    private static readonly string[] ForbiddenNseTokens =
        ["vuln", "brute", "exploit", "intrusive", "dos", "malware"];

    // Wall-clock caps — rpcinfo/nmap should be short regardless of network weather.
    private const int RpcInfoTimeoutSeconds = 15;
    private const int NmapTimeoutSeconds = 60;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly IProcessRunner _runner;
    private readonly string _rpcinfoPath;
    private readonly string _nmapPath;

    public RpcTool(
        Scope.Scope scope,
        AuditLog audit,
        IProcessRunner? runner = null,
        string? rpcinfoPath = null,
        string? nmapPath = null)
    {
        _scope = scope;
        _audit = audit;
        _runner = runner ?? new DefaultProcessRunner();
        _rpcinfoPath = rpcinfoPath ?? "rpcinfo";
        _nmapPath = nmapPath ?? "nmap";
    }

    public Task<RpcResult> ProbeAsync(string target, int port = 111, CancellationToken ct = default)
    {
        _scope.Require(target);

        _audit.Record("rpc.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
        });

        var result = new RpcResult { Port = port };
        string? error = null;

        // 1. rpcinfo -p <target>
        ct.ThrowIfCancellationRequested();
        try
        {
            var (exit, stdout, stderr) = _runner.Run(_rpcinfoPath, $"-p {target}", RpcInfoTimeoutSeconds);
            if (exit == -1)
            {
                error = Append(error, $"rpcinfo: {FirstNonEmpty(stderr, stdout, "rpcinfo exited -1")}");
            }
            else if (exit != 0 && string.IsNullOrWhiteSpace(stdout))
            {
                error = Append(error, $"rpcinfo: {FirstNonEmpty(stderr, stdout, $"rpcinfo exit={exit}")}");
            }
            else
            {
                foreach (var prog in ParseRpcInfo(stdout))
                {
                    MergeProgram(result.Programs, prog);
                }
            }
        }
        catch (Exception ex)
        {
            error = Append(error, $"rpcinfo: {ex.Message}");
        }

        // 2. nmap -Pn -p 111 --script rpc-grind -oX - <target>
        ct.ThrowIfCancellationRequested();
        var nmapArgs = BuildNmapArguments(target, port);
        ValidateNmapArguments(nmapArgs);

        try
        {
            var (exit, stdout, stderr) = _runner.Run(_nmapPath, nmapArgs, NmapTimeoutSeconds);
            if (exit == -1)
            {
                error = Append(error, $"nmap: {FirstNonEmpty(stderr, stdout, "nmap exited -1")}");
            }
            else if (exit != 0 && string.IsNullOrWhiteSpace(stdout))
            {
                error = Append(error, $"nmap: {FirstNonEmpty(stderr, stdout, $"nmap exit={exit}")}");
            }
            else
            {
                foreach (var prog in ParseNmapRpcGrind(stdout))
                {
                    MergeProgram(result.Programs, prog);
                }
            }
        }
        catch (Exception ex)
        {
            error = Append(error, $"nmap: {ex.Message}");
        }

        if (!string.IsNullOrEmpty(error))
        {
            result.Error = Tail(error, 500);
        }

        _audit.Record("rpc.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["program_count"] = result.Programs.Count,
            ["error"] = result.Error,
        });

        return Task.FromResult(result);
    }

    internal static string BuildNmapArguments(string target, int port) =>
        string.Join(' ',
            "-Pn",
            "-p", port.ToString(CultureInfo.InvariantCulture),
            "--script", RpcGrindScript,
            "-oX", "-",
            target);

    // Belt-and-suspenders: guarantees that the --script value is exactly
    // rpc-grind and that no forbidden NSE category/keyword is present on the
    // command line. A bug that widened the script list would be caught here.
    internal static void ValidateNmapArguments(string arguments)
    {
        var tokens = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < tokens.Length; i++)
        {
            if (tokens[i] == "--script")
            {
                if (i + 1 >= tokens.Length || tokens[i + 1] != RpcGrindScript)
                {
                    throw new InvalidOperationException(
                        $"RpcTool: --script value must be exactly '{RpcGrindScript}'.");
                }
            }
        }

        var lower = arguments.ToLowerInvariant();
        foreach (var forbidden in ForbiddenNseTokens)
        {
            if (lower.Contains(forbidden, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"RpcTool: nmap arguments must not contain '{forbidden}'.");
            }
        }
    }

    internal static IEnumerable<RpcProgram> ParseRpcInfo(string stdout)
    {
        if (string.IsNullOrEmpty(stdout)) yield break;

        foreach (var raw in stdout.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            // Header line: "   program vers proto   port  service"
            if (line.StartsWith("program", StringComparison.OrdinalIgnoreCase)) continue;

            var cols = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length < 4) continue;
            if (!int.TryParse(cols[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var program)) continue;
            if (!int.TryParse(cols[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var version)) continue;
            var proto = cols[2];
            if (!int.TryParse(cols[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out var rport)) continue;
            string? name = cols.Length >= 5 ? cols[4] : null;

            yield return new RpcProgram
            {
                Program = program,
                Version = version,
                Protocol = proto,
                Port = rport,
                Name = name,
            };
        }
    }

    internal static IEnumerable<RpcProgram> ParseNmapRpcGrind(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) yield break;
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch (System.Xml.XmlException) { yield break; }

        foreach (var portEl in doc.Descendants("port"))
        {
            var protoAttr = (string?)portEl.Attribute("protocol") ?? "";
            var portIdAttr = (string?)portEl.Attribute("portid") ?? "";
            int.TryParse(portIdAttr, NumberStyles.Integer, CultureInfo.InvariantCulture, out var portNumber);

            foreach (var script in portEl.Elements("script"))
            {
                var id = (string?)script.Attribute("id");
                if (id != RpcGrindScript) continue;

                // rpc-grind emits one <table> per discovered program; each has
                // <elem key="program">, <elem key="version">, <elem key="name">.
                // Older versions embed everything in the script output string.
                var tables = script.Descendants("table").ToList();
                if (tables.Count > 0)
                {
                    foreach (var t in tables)
                    {
                        var prog = ReadElem(t, "program");
                        var ver = ReadElem(t, "version");
                        var name = ReadElem(t, "name");
                        var proto = ReadElem(t, "protocol") ?? protoAttr;
                        var rp = ReadElem(t, "port");

                        if (!int.TryParse(prog, NumberStyles.Integer, CultureInfo.InvariantCulture, out var programNum))
                            continue;
                        int version = 0;
                        int.TryParse(ver, NumberStyles.Integer, CultureInfo.InvariantCulture, out version);
                        int discoveredPort = portNumber;
                        if (!string.IsNullOrEmpty(rp))
                            int.TryParse(rp, NumberStyles.Integer, CultureInfo.InvariantCulture, out discoveredPort);

                        yield return new RpcProgram
                        {
                            Program = programNum,
                            Version = version,
                            Protocol = string.IsNullOrEmpty(proto) ? "" : proto,
                            Port = discoveredPort,
                            Name = string.IsNullOrEmpty(name) ? null : name,
                        };
                    }
                }
                else
                {
                    var output = (string?)script.Attribute("output") ?? "";
                    foreach (var prog in ParseRpcGrindOutput(output, protoAttr, portNumber))
                        yield return prog;
                }
            }
        }
    }

    private static string? ReadElem(XElement table, string key)
    {
        var e = table.Elements("elem").FirstOrDefault(x => (string?)x.Attribute("key") == key);
        return e?.Value;
    }

    // Fallback parser for the freetext form of rpc-grind output. Lines look
    // like: "100003 (nfs) v3" or "program: 100005 name: mountd version: 3".
    private static IEnumerable<RpcProgram> ParseRpcGrindOutput(string output, string proto, int port)
    {
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            var cols = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length < 2) continue;
            if (!int.TryParse(cols[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var program)) continue;
            string? name = null;
            int version = 0;
            foreach (var col in cols)
            {
                if (col.StartsWith('(') && col.EndsWith(')'))
                    name = col.Trim('(', ')');
                else if (col.StartsWith('v') && int.TryParse(col.AsSpan(1), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v))
                    version = v;
            }
            yield return new RpcProgram
            {
                Program = program,
                Version = version,
                Protocol = proto,
                Port = port,
                Name = name,
            };
        }
    }

    private static void MergeProgram(List<RpcProgram> programs, RpcProgram next)
    {
        foreach (var existing in programs)
        {
            if (existing.Program == next.Program
                && existing.Version == next.Version
                && string.Equals(existing.Protocol, next.Protocol, StringComparison.OrdinalIgnoreCase)
                && existing.Port == next.Port)
            {
                if (string.IsNullOrEmpty(existing.Name) && !string.IsNullOrEmpty(next.Name))
                    existing.Name = next.Name;
                return;
            }
        }
        programs.Add(next);
    }

    private static string Append(string? prev, string msg) =>
        string.IsNullOrEmpty(prev) ? msg : prev + "; " + msg;

    private static string FirstNonEmpty(params string?[] candidates)
    {
        foreach (var c in candidates)
            if (!string.IsNullOrWhiteSpace(c)) return c!.Trim();
        return string.Empty;
    }

    private static string Tail(string s, int max) => s.Length <= max ? s : s[^max..];
}
