using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon;

/// <summary>
/// Minimal, read-only FTP probe: grab banner, test anonymous login, capture a
/// bounded root listing if anonymous is allowed. Never writes (STOR/DELE/MKD/
/// RMD), never brute forces (only the single anonymous credential), and never
/// recurses. The connection is scope-checked before any byte is read or
/// written.
///
/// For testability the TCP connection is injected as a factory. The default
/// factory uses <see cref="TcpClient"/>; tests pass an in-memory stream.
/// </summary>
public sealed partial class FtpTool : IReconTool
{
    public string Name => "ftp";

    public string Description =>
        "Probe an FTP service on a given port: read the banner, test whether " +
        "anonymous login is allowed, and if so record the root directory " +
        "listing. Read-only — no writes, no credential brute force.";

    private const int MaxListingLines = 200;
    private const int MaxListingBytes = 64 * 1024;
    private const int MaxBannerBytes = 8 * 1024;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TotalTimeout = TimeSpan.FromSeconds(10);

    [GeneratedRegex(@"^(\d{3})([ -])(.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ResponseLineRegex();

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, int, CancellationToken, Task<Stream>> _connect;

    public FtpTool(
        Scope.Scope scope,
        AuditLog audit,
        Func<string, int, CancellationToken, Task<Stream>>? connectFactory = null)
    {
        _scope = scope;
        _audit = audit;
        _connect = connectFactory ?? DefaultConnectAsync;
    }

    private static async Task<Stream> DefaultConnectAsync(string host, int port, CancellationToken ct)
    {
        var client = new TcpClient();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(ConnectTimeout);
        await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
        return client.GetStream();
    }

    public async Task<FtpResult> ProbeAsync(string target, int port = 21, CancellationToken ct = default)
    {
        _scope.Require(target);

        _audit.Record("ftp.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
        });

        var result = new FtpResult { Port = port };
        using var totalCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        totalCts.CancelAfter(TotalTimeout);

        Stream? stream = null;
        try
        {
            try
            {
                stream = await _connect(target, port, totalCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (totalCts.IsCancellationRequested && !ct.IsCancellationRequested)
            {
                result.Error = "connect timeout";
                RecordFinish(target, port, result);
                return result;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                RecordFinish(target, port, result);
                return result;
            }

            var reader = new LineReader(stream, MaxListingBytes + MaxBannerBytes);

            var banner = await ReadResponseAsync(reader, totalCts.Token).ConfigureAwait(false);
            result.Banner = banner.Text;
            if (banner.Code != 220)
            {
                await TryQuitAsync(stream, totalCts.Token).ConfigureAwait(false);
                RecordFinish(target, port, result);
                return result;
            }

            await WriteLineAsync(stream, "USER anonymous", totalCts.Token).ConfigureAwait(false);
            var userResp = await ReadResponseAsync(reader, totalCts.Token).ConfigureAwait(false);
            int lastCode = userResp.Code;

            if (userResp.Code == 331)
            {
                await WriteLineAsync(stream, "PASS anonymous@drederick.invalid", totalCts.Token).ConfigureAwait(false);
                var passResp = await ReadResponseAsync(reader, totalCts.Token).ConfigureAwait(false);
                lastCode = passResp.Code;
            }

            if (lastCode == 230)
            {
                result.AnonymousAllowed = true;
                await WriteLineAsync(stream, "LIST", totalCts.Token).ConfigureAwait(false);
                await ReadListingAsync(reader, result.RootListing, totalCts.Token).ConfigureAwait(false);
            }

            await TryQuitAsync(stream, totalCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (totalCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            result.Error = "ftp probe timeout";
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }
        finally
        {
            if (stream is not null)
            {
                try { await stream.DisposeAsync().ConfigureAwait(false); } catch { /* best-effort close */ }
            }
        }

        RecordFinish(target, port, result);
        return result;
    }

    private void RecordFinish(string target, int port, FtpResult result)
    {
        _audit.Record("ftp.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["anonymous_allowed"] = result.AnonymousAllowed,
            ["listing_lines"] = result.RootListing.Count,
            ["error"] = result.Error,
        });
    }

    private static async Task WriteLineAsync(Stream s, string line, CancellationToken ct)
    {
        var bytes = Encoding.ASCII.GetBytes(line + "\r\n");
        await s.WriteAsync(bytes.AsMemory(), ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task TryQuitAsync(Stream s, CancellationToken ct)
    {
        try { await WriteLineAsync(s, "QUIT", ct).ConfigureAwait(false); }
        catch { /* best-effort close */ }
    }

    private readonly record struct FtpResponse(int Code, string Text);

    private static async Task<FtpResponse> ReadResponseAsync(LineReader reader, CancellationToken ct)
    {
        var first = await reader.ReadLineAsync(ct).ConfigureAwait(false);
        if (first is null) return new FtpResponse(0, "");
        var m = ResponseLineRegex().Match(first);
        if (!m.Success) return new FtpResponse(0, first);

        var code = int.Parse(m.Groups[1].Value);
        var sep = m.Groups[2].Value;
        var sb = new StringBuilder();
        sb.Append(m.Groups[3].Value);

        if (sep == "-")
        {
            // Multi-line response: read until a line with the same 3-digit code
            // followed by a space.
            var terminator = m.Groups[1].Value + " ";
            while (true)
            {
                var next = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (next is null) break;
                sb.Append('\n').Append(next);
                if (next.StartsWith(terminator, StringComparison.Ordinal)) break;
            }
        }
        return new FtpResponse(code, sb.ToString());
    }

    private static async Task ReadListingAsync(LineReader reader, List<string> listing, CancellationToken ct)
    {
        int bytesAccum = 0;
        bool capped = false;
        while (true)
        {
            var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (line is null) break;

            var m = ResponseLineRegex().Match(line);
            if (m.Success)
            {
                var code = int.Parse(m.Groups[1].Value);
                if (code >= 100 && code <= 199)
                {
                    // Preliminary ("150 Opening data connection"); keep reading.
                    continue;
                }
                // Final response terminates the listing whether success or error.
                return;
            }

            if (capped) continue;
            if (listing.Count >= MaxListingLines)
            {
                capped = true;
                continue;
            }
            if (bytesAccum + line.Length > MaxListingBytes)
            {
                capped = true;
                continue;
            }
            listing.Add(line);
            bytesAccum += line.Length;
        }
    }

    /// <summary>
    /// Minimal CRLF-terminated line reader with a hard byte budget to prevent
    /// a hostile server from causing unbounded memory growth.
    /// </summary>
    private sealed class LineReader
    {
        private readonly Stream _stream;
        private readonly byte[] _buf = new byte[4096];
        private int _bufLen;
        private int _bufPos;
        private readonly int _maxTotalBytes;
        private int _totalBytes;

        public LineReader(Stream stream, int maxTotalBytes)
        {
            _stream = stream;
            _maxTotalBytes = maxTotalBytes;
        }

        public async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            var sb = new StringBuilder();
            while (true)
            {
                if (_bufPos >= _bufLen)
                {
                    _bufLen = await _stream.ReadAsync(_buf.AsMemory(), ct).ConfigureAwait(false);
                    _bufPos = 0;
                    if (_bufLen == 0)
                    {
                        return sb.Length == 0 ? null : sb.ToString();
                    }
                }
                byte b = _buf[_bufPos++];
                if (b == (byte)'\n')
                {
                    var s = sb.ToString();
                    if (s.Length > 0 && s[^1] == '\r') s = s[..^1];
                    return s;
                }
                sb.Append((char)b);
                _totalBytes++;
                if (_totalBytes > _maxTotalBytes)
                {
                    // Stop growing; treat remaining bytes on this line as
                    // boundary and return what we have.
                    return sb.ToString();
                }
            }
        }
    }
}
