// Original NSE script: ftp-anon.nse
// Source: https://nmap.org/nsedoc/scripts/ftp-anon.html
// Author: Eddie Bell
// License: NPSL
//
// Native C# port: connect, read banner, attempt anonymous login
// (USER anonymous / PASS IEUser@), and on success issue PASV + LIST
// against the data channel. Re-validates the PASV-returned host
// through scope before opening the data connection.
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Native;

public sealed partial class FtpAnonTool : IReconTool
{
    public string Name => "ftp-anon";
    public string Description =>
        "Native port of nmap's ftp-anon.nse: test anonymous FTP login and " +
        "(if accepted) capture the root directory listing. Target must be in scope.";

    private const int MaxListingLines = 200;
    private const int MaxListingBytes = 64 * 1024;
    private const int MaxBannerBytes = 8 * 1024;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TotalTimeout = TimeSpan.FromSeconds(15);

    [GeneratedRegex(@"^(\d{3})([ -])(.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ResponseLineRegex();

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, int, CancellationToken, Task<Stream>> _connect;

    public FtpAnonTool(
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

    public async Task<FtpAnonResult> ProbeAsync(string target, int port = 21, CancellationToken ct = default)
    {
        _scope.Require(target);
        _audit.Record("ftp-anon.start", new Dictionary<string, object?>
        {
            ["target"] = target, ["port"] = port,
        });

        var result = new FtpAnonResult { Port = port };
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(TotalTimeout);
        try
        {
            await using var control = await _connect(target, port, linked.Token).ConfigureAwait(false);
            using var reader = new StreamReader(control, Encoding.ASCII, false, 1024, leaveOpen: true);
            using var writer = new StreamWriter(control, new ASCIIEncoding()) { NewLine = "\r\n", AutoFlush = true };

            var banner = await ReadResponseAsync(reader, MaxBannerBytes, linked.Token).ConfigureAwait(false);
            result.Banner = banner.Text;

            await writer.WriteLineAsync("USER anonymous").ConfigureAwait(false);
            var userResp = await ReadResponseAsync(reader, MaxBannerBytes, linked.Token).ConfigureAwait(false);

            await writer.WriteLineAsync("PASS IEUser@").ConfigureAwait(false);
            var passResp = await ReadResponseAsync(reader, MaxBannerBytes, linked.Token).ConfigureAwait(false);
            result.LoginResponse = passResp.Text;
            result.AnonymousAllowed = passResp.Code is >= 200 and < 300;

            if (result.AnonymousAllowed)
            {
                await writer.WriteLineAsync("PASV").ConfigureAwait(false);
                var pasvResp = await ReadResponseAsync(reader, MaxBannerBytes, linked.Token).ConfigureAwait(false);
                if (pasvResp.Code == 227 && ParsePasv(pasvResp.Text, out var dataHost, out var dataPort))
                {
                    _scope.Require(dataHost);
                    await using var data = await _connect(dataHost, dataPort, linked.Token).ConfigureAwait(false);
                    await writer.WriteLineAsync("LIST").ConfigureAwait(false);
                    var listResp = await ReadResponseAsync(reader, MaxBannerBytes, linked.Token).ConfigureAwait(false);
                    if (listResp.Code is >= 100 and < 300)
                    {
                        await ReadListingAsync(data, result.RootListing, linked.Token).ConfigureAwait(false);
                        await ReadResponseAsync(reader, MaxBannerBytes, linked.Token).ConfigureAwait(false);
                    }
                }
                try { await writer.WriteLineAsync("QUIT").ConfigureAwait(false); } catch { }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            result.Error = "timeout";
        }
        catch (OperationCanceledException) { throw; }
        catch (Drederick.Scope.ScopeException) { throw; }
        catch (Exception ex) { result.Error = ex.Message; }

        _audit.Record("ftp-anon.finish", new Dictionary<string, object?>
        {
            ["target"] = target, ["port"] = port,
            ["anonymous_allowed"] = result.AnonymousAllowed,
            ["listing_count"] = result.RootListing.Count,
            ["error"] = result.Error,
        });
        return result;
    }

    private sealed record Response(int Code, string Text);

    private static async Task<Response> ReadResponseAsync(StreamReader reader, int maxBytes, CancellationToken ct)
    {
        var sb = new StringBuilder();
        int code = 0;
        int read = 0;
        while (true)
        {
            var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (line is null) break;
            read += line.Length + 2;
            if (read > maxBytes) break;
            sb.AppendLine(line);
            if (TryParseCode(line, out var c, out var multi))
            {
                code = c;
                if (!multi) break;
            }
        }
        return new Response(code, sb.ToString().TrimEnd());
    }

    public static int ParseCode(string line) =>
        TryParseCode(line, out var c, out _) ? c : 0;

    private static bool TryParseCode(string line, out int code, out bool multi)
    {
        code = 0; multi = false;
        var m = ResponseLineRegex().Match(line);
        if (!m.Success) return false;
        if (!int.TryParse(m.Groups[1].Value, out code)) return false;
        multi = m.Groups[2].Value == "-";
        return true;
    }

    private static async Task ReadListingAsync(Stream data, List<string> listing, CancellationToken ct)
    {
        using var reader = new StreamReader(data, Encoding.ASCII);
        int total = 0;
        while (listing.Count < MaxListingLines)
        {
            var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (line is null) break;
            total += line.Length + 2;
            if (total > MaxListingBytes) break;
            listing.Add(line);
        }
    }

    /// <summary>Parse a 227 PASV response into (host, port). Returns false on malformed input.</summary>
    public static bool ParsePasv(string text, out string host, out int port)
    {
        host = ""; port = 0;
        var m = Regex.Match(text, @"\((\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})\)",
            RegexOptions.CultureInvariant);
        if (!m.Success) return false;
        var p = new int[6];
        for (int i = 0; i < 6; i++) p[i] = int.Parse(m.Groups[i + 1].Value);
        if (p.Any(x => x < 0 || x > 255)) return false;
        host = $"{p[0]}.{p[1]}.{p[2]}.{p[3]}";
        port = (p[4] << 8) | p[5];
        return true;
    }
}
