using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Xml.Linq;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon;

/// <summary>
/// SSH fingerprinting probe. Performs a passive banner grab on the SSH port
/// and invokes <c>nmap --script ssh2-enum-algos</c> to enumerate supported
/// key-exchange, host-key, encryption, and MAC algorithms. Never attempts
/// authentication or key probing.
/// </summary>
public sealed class SshTool : IReconTool
{
    public string Name => "ssh";

    public string Description =>
        "Grab the SSH banner and enumerate kex/host-key/encryption/MAC algorithms " +
        "via nmap's ssh2-enum-algos NSE script. Non-authenticating and " +
        "non-exploitative; target MUST be in scope.";

    // Only safe+discovery NSE scripts are allowed for algo enumeration.
    private const string AllowedNseCategories = "safe,discovery";
    private const string AlgoEnumScript = "ssh2-enum-algos";

    private static readonly TimeSpan BannerTimeout = TimeSpan.FromSeconds(5);
    private const int MaxBannerBytes = 512;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _nmapPath;
    private readonly Func<string, int, CancellationToken, Task<Stream>> _tcpFactory;
    private readonly Func<string, IReadOnlyList<string>, CancellationToken, Task<ProcessRunResult>> _processRunner;

    public SshTool(
        Scope.Scope scope,
        AuditLog audit,
        string? nmapPath = null,
        Func<string, int, CancellationToken, Task<Stream>>? tcpFactory = null,
        Func<string, IReadOnlyList<string>, CancellationToken, Task<ProcessRunResult>>? processRunner = null)
    {
        _scope = scope;
        _audit = audit;
        _nmapPath = nmapPath ?? "nmap";
        _tcpFactory = tcpFactory ?? DefaultTcpFactoryAsync;
        _processRunner = processRunner ?? DefaultProcessRunnerAsync;
    }

    public async Task<SshResult> ProbeAsync(string target, int port = 22, CancellationToken ct = default)
    {
        _scope.Require(target);

        _audit.Record("ssh.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
        });

        var result = new SshResult { Port = port };

        // 1. Banner grab with 5s timeout. Failures are recorded but do not abort algo enum.
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(BannerTimeout);
            var stream = await _tcpFactory(target, port, cts.Token).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                var banner = await ReadBannerLineAsync(stream, cts.Token).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(banner))
                {
                    result.Banner = banner.TrimEnd('\r', '\n');
                }
            }
        }
        catch (Exception ex)
        {
            result.Error = $"banner: {ex.Message}";
            _audit.Record("ssh.banner_error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["error"] = ex.Message,
            });
        }

        // 2. Algo enumeration via nmap ssh2-enum-algos. safe,discovery only.
        var args = new List<string>
        {
            "-Pn",
            "-p", port.ToString(CultureInfo.InvariantCulture),
            "--script", AlgoEnumScript,
            "-oX", "-",
            target,
        };

        try
        {
            var pr = await _processRunner(_nmapPath, args, ct).ConfigureAwait(false);
            if (pr.ExitCode == 0 && !string.IsNullOrWhiteSpace(pr.Stdout))
            {
                try { ParseAlgoXml(pr.Stdout, result); }
                catch (Exception ex) { AppendError(result, $"xml-parse: {ex.Message}"); }
            }
            else
            {
                var msg = !string.IsNullOrWhiteSpace(pr.Stderr)
                    ? Tail(pr.Stderr, 500)
                    : $"nmap exit {pr.ExitCode}";
                AppendError(result, $"algo-enum: {msg}");
            }
        }
        catch (Exception ex)
        {
            AppendError(result, $"algo-enum: {ex.Message}");
        }

        _audit.Record("ssh.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["banner"] = result.Banner,
            ["kex_count"] = result.KexAlgorithms.Count,
            ["error"] = result.Error,
        });
        return result;
    }

    /// <summary>
    /// Public for tests. The allowed NSE categories for the ssh algo enum. Kept
    /// deliberately narrow so this tool can never pull in exploit/intrusive/brute/vuln scripts.
    /// </summary>
    public string NseCategories => AllowedNseCategories;

    internal static async Task<string?> ReadBannerLineAsync(Stream stream, CancellationToken ct)
    {
        var buf = new byte[MaxBannerBytes];
        int total = 0;
        while (total < buf.Length)
        {
            var n = await stream.ReadAsync(buf.AsMemory(total, 1), ct).ConfigureAwait(false);
            if (n <= 0) break;
            total += n;
            if (buf[total - 1] == (byte)'\n') break;
        }
        if (total == 0) return null;
        return System.Text.Encoding.ASCII.GetString(buf, 0, total);
    }

    internal static void ParseAlgoXml(string xml, SshResult result)
    {
        if (string.IsNullOrWhiteSpace(xml)) return;
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch (System.Xml.XmlException) { return; }

        var script = doc.Descendants("script")
            .FirstOrDefault(s => (string?)s.Attribute("id") == AlgoEnumScript);
        if (script is null) return;

        foreach (var table in script.Elements("table"))
        {
            var key = (string?)table.Attribute("key");
            if (string.IsNullOrEmpty(key)) continue;
            var values = table.Elements("elem").Select(e => e.Value).ToList();
            switch (key)
            {
                case "kex_algorithms":
                    result.KexAlgorithms = values;
                    break;
                case "server_host_key_algorithms":
                case "host_key_algorithms":
                    result.HostKeyAlgorithms = values;
                    break;
                case "encryption_algorithms":
                    result.EncryptionAlgorithms = values;
                    break;
                case "mac_algorithms":
                    result.MacAlgorithms = values;
                    break;
            }
        }
    }

    private static void AppendError(SshResult result, string msg)
    {
        result.Error = string.IsNullOrEmpty(result.Error) ? msg : result.Error + "; " + msg;
    }

    private static string Tail(string s, int max) => s.Length <= max ? s : s[^max..];

    private static async Task<Stream> DefaultTcpFactoryAsync(string host, int port, CancellationToken ct)
    {
        var client = new TcpClient();
        try
        {
            await client.ConnectAsync(host, port, ct).ConfigureAwait(false);
        }
        catch
        {
            client.Dispose();
            throw;
        }
        return new OwningTcpStream(client);
    }

    private static async Task<ProcessRunResult> DefaultProcessRunnerAsync(
        string binary, IReadOnlyList<string> args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(binary)
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
            return new ProcessRunResult(-1, "", ex.Message);
        }

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        return new ProcessRunResult(proc.ExitCode, stdout, stderr);
    }

    private sealed class OwningTcpStream : Stream
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _inner;

        public OwningTcpStream(TcpClient client)
        {
            _client = client;
            _inner = client.GetStream();
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => _inner.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
            => _inner.ReadAsync(buffer, ct);
        public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
                _client.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}

/// <summary>
/// Injection point for running an external process (e.g. nmap) when probing
/// SSH. Tests supply a fake runner; production uses the default that actually
/// forks the <c>nmap</c> binary.
/// </summary>
public readonly record struct ProcessRunResult(int ExitCode, string Stdout, string Stderr);
