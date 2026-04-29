using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Exploit;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// Stateful protocol fuzzer wrapping boofuzz (Python framework). Sends malformed
/// protocol messages to detect crashes, hangs, and memory-safety bugs in network
/// services. DESTRUCTIVE category — requires BOTH <c>--allow-destructive</c> AND
/// <c>--allow-dos</c> opt-in even in lab mode, as protocol fuzzing is functionally
/// a DoS attack that can crash services.
///
/// Supports:
///   • SMB (tcp/445): malformed SMB1/SMB2 negotiation packets
///   • SNMP (udp/161): malformed v1/v2c GetRequest PDUs
///   • FTP (tcp/21): malformed USER/PASS/SITE commands
///   • HTTP (tcp/port): malformed Request-Line, headers, body
///   • Generic (tcp/port): blind byte fuzzing
///
/// Safety posture:
///   • Scope-validated target first (<c>_scope.Require</c>).
///   • <see cref="RunPermissions.AllowDestructive"/> AND
///     <see cref="RunPermissions.AllowDos"/> must both be true — otherwise refuses.
///   • Generates a templated boofuzz Python script per run under
///     <c>out/&lt;host&gt;/fuzz/protocol/&lt;timestamp&gt;/fuzz.py</c>.
///   • Spawns python3 with bounded timeout, captures stdout/stderr (max 64 KB).
///   • Parses boofuzz log for crash/hang/anomaly markers and records to audit.
/// </summary>
public sealed class ProtocolFuzzTool : IFuzzTool
{
    public string Name => "protocol-fuzz";
    public string Description =>
        "Stateful network protocol fuzzer (boofuzz-backed). Mutates messages to trigger crashes/hangs. " +
        "DESTRUCTIVE — requires --allow-destructive AND --allow-dos (can crash services).";
    public FuzzCategory Category => FuzzCategory.Network;

    private const int MaxStdOutBytes = 64 * 1024;
    private const int MaxStdErrBytes = 64 * 1024;
    private static readonly Regex HostValidation = new(@"^[a-zA-Z0-9.\-_:]+$", RegexOptions.Compiled);

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly RunPermissions _permissions;
    private readonly string _python3Path;
    private readonly Doctor.IProcessRunner _runner;

    public ProtocolFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        RunPermissions permissions,
        string python3Path = "python3",
        Doctor.IProcessRunner? runner = null)
    {
        _scope = scope;
        _audit = audit;
        _permissions = permissions;
        _python3Path = python3Path;
        _runner = runner ?? new Doctor.DefaultProcessRunner();
    }

    public async Task<ProtocolFuzzResult> ProbeAsync(
        string targetHost,
        int targetPort,
        ProtocolFuzzOptions options,
        CancellationToken ct = default)
    {
        // Gate #1: Permissions check — BOTH AllowDestructive AND AllowDos required.
        if (!_permissions.AllowDestructive || !_permissions.AllowDos)
        {
            throw new InvalidOperationException(
                "protocol-fuzz requires --allow-destructive AND --allow-dos " +
                "(this tool sends malformed packets that can crash services)");
        }

        // Gate #2: Argument validation.
        if (!HostValidation.IsMatch(targetHost) || targetHost.Contains(".."))
        {
            throw new ArgumentException($"Invalid host: {targetHost} (contains shell metacharacters or path traversal).", nameof(targetHost));
        }
        if (targetPort is < 1 or > 65535)
        {
            throw new ArgumentException($"Port {targetPort} out of range 1..65535.", nameof(targetPort));
        }
        if (options.OutputDir is not null)
        {
            if (options.OutputDir.Contains(".."))
            {
                throw new ArgumentException("OutputDir contains path traversal (..).", nameof(options));
            }
            var parent = Path.GetDirectoryName(Path.GetFullPath(options.OutputDir));
            if (parent is null || !Directory.Exists(parent))
            {
                throw new ArgumentException($"Parent of OutputDir does not exist or is not writable: {parent}", nameof(options));
            }
        }

        // Gate #3: Scope check (first statement after permissions + validation).
        _scope.Require(targetHost);

        var startedAt = DateTimeOffset.UtcNow;
        var timestamp = startedAt.ToString("yyyyMMdd_HHmmss");
        var workDir = options.OutputDir ?? Path.Combine("out", SanitizeHost(targetHost), "fuzz", "protocol", timestamp);
        Directory.CreateDirectory(workDir);

        var scriptPath = Path.Combine(workDir, "fuzz.py");
        var scriptContent = GenerateBoofuzzScript(targetHost, targetPort, options);
        await File.WriteAllTextAsync(scriptPath, scriptContent, ct);

        var argv = $"\"{scriptPath}\"";
        var argvDigest = Sha256Hex(_python3Path + " " + argv);

        _audit.Record($"{Name}.start", new Dictionary<string, object?>
        {
            ["host"] = targetHost,
            ["port"] = targetPort,
            ["protocol"] = options.Protocol.ToString(),
            ["max_iterations"] = options.MaxIterations,
            ["script_path"] = scriptPath,
            ["argv_digest"] = argvDigest,
        });

        int exitCode;
        string stdout = string.Empty;
        string stderr = string.Empty;
        string? error = null;
        try
        {
            (exitCode, stdout, stderr) = _runner.Run(_python3Path, argv, options.TimeoutSec);
        }
        catch (Exception ex)
        {
            exitCode = -1;
            error = ex.Message;
        }

        var finishedAt = DateTimeOffset.UtcNow;
        var duration = finishedAt - startedAt;

        // Parse boofuzz log for crash markers.
        var (crashes, hangs, anomalyMarkers) = ParseBoofuzzLog(stdout + "\n" + stderr);

        // Extract iterations from output if available.
        var iterations = ExtractIterations(stdout + "\n" + stderr, options.MaxIterations);

        _audit.Record($"{Name}.finish", new Dictionary<string, object?>
        {
            ["iterations"] = iterations,
            ["crashes"] = crashes,
            ["hangs"] = hangs,
            ["anomaly_count"] = anomalyMarkers.Count,
            ["exit_code"] = exitCode,
            ["duration_ms"] = duration.TotalMilliseconds,
        });

        return new ProtocolFuzzResult
        {
            Target = $"{targetHost}:{targetPort}",
            ToolName = Name,
            StartedAt = startedAt,
            Duration = duration,
            Protocol = options.Protocol.ToString(),
            Iterations = iterations,
            Crashes = crashes,
            Hangs = hangs,
            AnomalyMarkers = anomalyMarkers,
            Error = error,
        };
    }

    internal static string GenerateBoofuzzScript(string host, int port, ProtocolFuzzOptions options)
    {
        // Escape host and port for Python string literals (they're already scope-validated).
        var escapedHost = EscapeForPython(host);
        var escapedPort = port.ToString();
        var maxIter = options.MaxIterations;

        return options.Protocol switch
        {
            ProtocolKind.Smb => GenerateSmbScript(escapedHost, escapedPort, maxIter),
            ProtocolKind.Snmp => GenerateSnmpScript(escapedHost, escapedPort, maxIter),
            ProtocolKind.Ftp => GenerateFtpScript(escapedHost, escapedPort, maxIter),
            ProtocolKind.Http => GenerateHttpScript(escapedHost, escapedPort, maxIter),
            ProtocolKind.Generic => GenerateGenericScript(escapedHost, escapedPort, maxIter),
            _ => throw new ArgumentException($"Unknown protocol: {options.Protocol}"),
        };
    }

    private static string GenerateSmbScript(string host, string port, int maxIter) => $$"""
#!/usr/bin/env python3
# Boofuzz SMB fuzzing harness
from boofuzz import *

def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("{{host}}", {{port}})),
        fuzz_loggers=[],
    )
    
    s_initialize("smb_negotiate")
    s_static(b"\x00\x00\x00")  # NetBIOS session header
    s_byte(0x85, fuzzable=False)  # NetBIOS session request
    s_string("FF SMB", fuzzable=True)  # SMB magic
    s_byte(0x72, fuzzable=True)  # Negotiate Protocol command
    s_dword(0, fuzzable=True)  # Status
    s_byte(0x18, fuzzable=True)  # Flags
    s_word(0, fuzzable=True)  # Flags2
    s_bytes(b"\x00" * 12, fuzzable=True)  # Reserved
    
    session.connect(s_get("smb_negotiate"))
    session.fuzz(max_depth={{maxIter}})

if __name__ == "__main__":
    main()
""";

    private static string GenerateSnmpScript(string host, string port, int maxIter) => $$"""
#!/usr/bin/env python3
# Boofuzz SNMP fuzzing harness
from boofuzz import *

def main():
    session = Session(
        target=Target(connection=UDPSocketConnection("{{host}}", {{port}})),
        fuzz_loggers=[],
    )
    
    s_initialize("snmp_get")
    s_byte(0x30, fuzzable=True)  # SEQUENCE
    s_byte(0x26, fuzzable=True)  # Length
    s_byte(0x02, fuzzable=False)  # INTEGER
    s_byte(0x01, fuzzable=False)  # Length
    s_byte(0x00, fuzzable=True)  # Version (SNMPv1)
    s_byte(0x04, fuzzable=False)  # OCTET STRING
    s_byte(0x06, fuzzable=True)  # Community length
    s_string("public", fuzzable=True)  # Community string
    s_byte(0xa0, fuzzable=True)  # GetRequest PDU
    s_bytes(b"\x00" * 16, fuzzable=True)  # Variable bindings
    
    session.connect(s_get("snmp_get"))
    session.fuzz(max_depth={{maxIter}})

if __name__ == "__main__":
    main()
""";

    private static string GenerateFtpScript(string host, string port, int maxIter) => $$"""
#!/usr/bin/env python3
# Boofuzz FTP fuzzing harness
from boofuzz import *

def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("{{host}}", {{port}})),
        fuzz_loggers=[],
    )
    
    s_initialize("ftp_user")
    s_string("USER ", fuzzable=False)
    s_string("anonymous", fuzzable=True)
    s_static("\r\n")
    
    s_initialize("ftp_pass")
    s_string("PASS ", fuzzable=False)
    s_string("guest@example.com", fuzzable=True)
    s_static("\r\n")
    
    s_initialize("ftp_site")
    s_string("SITE ", fuzzable=False)
    s_string("HELP", fuzzable=True)
    s_static("\r\n")
    
    session.connect(s_get("ftp_user"), s_get("ftp_pass"))
    session.connect(s_get("ftp_pass"), s_get("ftp_site"))
    session.fuzz(max_depth={{maxIter}})

if __name__ == "__main__":
    main()
""";

    private static string GenerateHttpScript(string host, string port, int maxIter) => $$"""
#!/usr/bin/env python3
# Boofuzz HTTP fuzzing harness
from boofuzz import *

def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("{{host}}", {{port}})),
        fuzz_loggers=[],
    )
    
    s_initialize("http_request")
    s_string("GET ", fuzzable=True)  # Method
    s_string("/index.html", fuzzable=True)  # Path
    s_string(" HTTP/1.1", fuzzable=True)  # Version
    s_static("\r\n")
    s_string("Host: ", fuzzable=False)
    s_string("{{host}}", fuzzable=True)
    s_static("\r\n")
    s_string("User-Agent: ", fuzzable=False)
    s_string("Boofuzz/1.0", fuzzable=True)
    s_static("\r\n")
    s_string("Content-Length: ", fuzzable=True)
    s_string("0", fuzzable=True)
    s_static("\r\n\r\n")
    
    session.connect(s_get("http_request"))
    session.fuzz(max_depth={{maxIter}})

if __name__ == "__main__":
    main()
""";

    private static string GenerateGenericScript(string host, string port, int maxIter) => $$"""
#!/usr/bin/env python3
# Boofuzz generic TCP fuzzing harness
from boofuzz import *

def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("{{host}}", {{port}})),
        fuzz_loggers=[],
    )
    
    s_initialize("generic_probe")
    s_bytes(b"\x00" * 32, fuzzable=True)  # Blind byte mutation
    s_string("ABCDEFGHIJKLMNOP", fuzzable=True)
    s_dword(0x41424344, fuzzable=True)
    s_word(0xAABB, fuzzable=True)
    
    session.connect(s_get("generic_probe"))
    session.fuzz(max_depth={{maxIter}})

if __name__ == "__main__":
    main()
""";

    internal static string EscapeForPython(string s)
    {
        // Escape backslashes and quotes for Python string literals.
        return s.Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("'", "\\'")
                .Replace("\n", "\\n")
                .Replace("\r", "\\r");
    }

    internal static (int Crashes, int Hangs, IReadOnlyList<string> AnomalyMarkers) ParseBoofuzzLog(string log)
    {
        var crashes = 0;
        var hangs = 0;
        var markers = new List<string>();

        foreach (var line in log.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var lower = line.ToLowerInvariant();
            if (lower.Contains("crash"))
            {
                crashes++;
                markers.Add(line.Trim());
            }
            if (lower.Contains("hang"))
            {
                hangs++;
                markers.Add(line.Trim());
            }
            if (lower.Contains("anomaly") || lower.Contains("connection refused"))
            {
                markers.Add(line.Trim());
            }
        }

        return (crashes, hangs, markers);
    }

    internal static int ExtractIterations(string log, int maxIterations)
    {
        // Try to extract iteration count from boofuzz output.
        // Boofuzz typically logs "Test Case: N / M" or similar.
        var match = Regex.Match(log, @"Test Case[:\s]+(\d+)", RegexOptions.IgnoreCase);
        if (match.Success && int.TryParse(match.Groups[1].Value, out var iter))
        {
            return iter;
        }
        return 0;
    }

    internal static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    internal static string SanitizeHost(string host)
    {
        // Replace non-alphanumeric with underscore for safe filesystem paths.
        return Regex.Replace(host, @"[^a-zA-Z0-9_\-.]", "_");
    }
}

/// <summary>
/// Configuration options for <see cref="ProtocolFuzzTool"/>.
/// </summary>
public sealed class ProtocolFuzzOptions
{
    /// <summary>Which protocol to fuzz (SMB, SNMP, FTP, HTTP, Generic).</summary>
    public ProtocolKind Protocol { get; set; }

    /// <summary>Maximum fuzzing iterations (boofuzz depth). Default 1000.</summary>
    public int MaxIterations { get; set; } = 1000;

    /// <summary>Timeout in seconds for the entire fuzz run. Default 600 (10 min).</summary>
    public int TimeoutSec { get; set; } = 600;

    /// <summary>Optional output directory. If null, defaults to out/&lt;host&gt;/fuzz/protocol/&lt;timestamp&gt;/.</summary>
    public string? OutputDir { get; set; }
}

/// <summary>
/// Protocol kinds supported by <see cref="ProtocolFuzzTool"/>.
/// </summary>
public enum ProtocolKind
{
    Smb,
    Snmp,
    Ftp,
    Http,
    Generic,
}
