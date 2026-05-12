using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon;

/// <summary>
/// SMTP enumeration tool (GAP-011). Banner grab, EHLO capability listing,
/// STARTTLS negotiation, and unauthenticated user enumeration via
/// VRFY / EXPN / RCPT TO against a small built-in or operator-supplied
/// wordlist. Read-only and credential-free; we do not brute-force AUTH.
///
/// Scope is enforced as the first statement of the public entry point and
/// again before any RCPT TO domain that came off the wire is reused.
/// Subprocess-style argv shape (host:port) is validated up front.
/// </summary>
public sealed partial class SmtpEnumTool : IReconTool
{
    public string Name => "smtp-enum";

    public string Description =>
        "Enumerate SMTP: banner, EHLO capabilities (PIPELINING, SIZE, STARTTLS, AUTH …), " +
        "optional STARTTLS upgrade, and unauthenticated user discovery via " +
        "VRFY/EXPN/RCPT TO against a small admin wordlist. No credential brute-force.";

    private const int MaxBannerBytes = 8 * 1024;
    private const int MaxLineBytes = 16 * 1024;
    private const int MaxTotalBytes = 256 * 1024;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TotalTimeout = TimeSpan.FromSeconds(30);

    [GeneratedRegex(@"^[\w.\-]+(:\d+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex TargetShapeRegex();

    [GeneratedRegex(@"^(?<code>\d{3})(?<sep>[ -])(?<text>.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex SmtpReplyLineRegex();

    /// <summary>Default 20-name admin wordlist embedded so the tool works without
    /// a wordlist file. Intentionally short to keep one full pass under the
    /// default rate limit.</summary>
    public static readonly IReadOnlyList<string> DefaultUserList = new[]
    {
        "admin", "root", "postmaster", "webmaster", "www-data",
        "mail", "support", "info", "noreply", "backup",
        "oracle", "mysql", "postgres", "nobody", "daemon",
        "sync", "sys", "bin", "games", "news",
    };

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, int, CancellationToken, Task<Stream>> _connect;
    private readonly Func<Stream, string, CancellationToken, Task<Stream>> _startTls;

    public SmtpEnumTool(
        Scope.Scope scope,
        AuditLog audit,
        Func<string, int, CancellationToken, Task<Stream>>? connectFactory = null,
        Func<Stream, string, CancellationToken, Task<Stream>>? startTlsFactory = null)
    {
        _scope = scope;
        _audit = audit;
        _connect = connectFactory ?? DefaultConnectAsync;
        _startTls = startTlsFactory ?? DefaultStartTlsAsync;
    }

    private static async Task<Stream> DefaultConnectAsync(string host, int port, CancellationToken ct)
    {
        var client = new TcpClient();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(ConnectTimeout);
        await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
        return client.GetStream();
    }

    private static async Task<Stream> DefaultStartTlsAsync(Stream inner, string targetHost, CancellationToken ct)
    {
        // Lab-grade defaults: SMTP servers on offensive targets routinely
        // present self-signed certs. We do not pin issuers — the channel is
        // used only for enumeration, not for trust.
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = targetHost,
        }, ct).ConfigureAwait(false);
        return ssl;
    }

    public async Task<SmtpEnumResult> EnumerateAsync(
        string target,
        int port = 25,
        string? wordlistPath = null,
        int probesPerSecond = 20,
        CancellationToken ct = default)
    {
        _scope.Require(target);

        // Argv-shape validation: target must be `host` or `host:port` only.
        // Strip an inline :port (we honour `port` arg) before the regex
        // check so callers can pass either shape.
        var bareHost = target.Contains(':') ? target[..target.IndexOf(':')] : target;
        if (!TargetShapeRegex().IsMatch(target) || Scope.ArgvValidator.ContainsShellMetachars(target))
        {
            throw new ArgumentException(
                $"Invalid SMTP target '{target}': expected host or host:port.", nameof(target));
        }
        if (port < 1 || port > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        if (probesPerSecond < 1) probesPerSecond = 1;
        if (probesPerSecond > 1000) probesPerSecond = 1000;

        var users = LoadWordlist(wordlistPath);

        _audit.Record("smtp-enum.start", new Dictionary<string, object?>
        {
            ["target"] = bareHost,
            ["port"] = port,
            ["wordlist_size"] = users.Count,
            ["wordlist_source"] = wordlistPath is null ? "builtin" : "file",
            ["probes_per_second"] = probesPerSecond,
        });

        var result = new SmtpEnumResult { Port = port };
        using var totalCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        totalCts.CancelAfter(TotalTimeout);

        Stream? stream = null;
        try
        {
            try
            {
                stream = await _connect(bareHost, port, totalCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (totalCts.IsCancellationRequested && !ct.IsCancellationRequested)
            {
                result.Error = "connect timeout";
                RecordFinish(bareHost, port, result);
                return result;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                RecordFinish(bareHost, port, result);
                return result;
            }

            var reader = new SmtpReader(stream, MaxTotalBytes);

            // Banner.
            var banner = await ReadReplyAsync(reader, totalCts.Token).ConfigureAwait(false);
            result.Banner = banner.Text;
            if (banner.Code != 220 || string.IsNullOrEmpty(banner.Text))
            {
                // Either no banner or hard reject — record what we have and bail.
                if (string.IsNullOrEmpty(banner.Text)) result.Banner = null;
                await TryQuitAsync(stream, totalCts.Token).ConfigureAwait(false);
                RecordFinish(bareHost, port, result);
                return result;
            }

            // EHLO.
            var caps = await SendEhloAsync(stream, reader, totalCts.Token).ConfigureAwait(false);
            ApplyCapabilities(result, caps);

            // Opportunistic STARTTLS.
            if (result.StartTlsSupported)
            {
                await WriteLineAsync(stream, "STARTTLS", totalCts.Token).ConfigureAwait(false);
                var startTlsReply = await ReadReplyAsync(reader, totalCts.Token).ConfigureAwait(false);
                if (startTlsReply.Code == 220)
                {
                    try
                    {
                        stream = await _startTls(stream, bareHost, totalCts.Token).ConfigureAwait(false);
                        reader = new SmtpReader(stream, MaxTotalBytes);
                        result.StartTlsNegotiated = true;
                        // Re-EHLO over the encrypted channel.
                        var caps2 = await SendEhloAsync(stream, reader, totalCts.Token).ConfigureAwait(false);
                        ApplyCapabilities(result, caps2);
                    }
                    catch (Exception ex)
                    {
                        result.Error = $"starttls: {ex.Message}";
                        // Connection state is now unusable; bail cleanly.
                        RecordFinish(bareHost, port, result);
                        return result;
                    }
                }
            }

            // User enumeration: VRFY → EXPN → RCPT TO. First mode that
            // returns at least one positive hit wins.
            var rcptDomain = PickRcptDomain(result.Banner, bareHost);
            // If the banner reported a hostname we now want to use inside RCPT
            // TO, re-check scope on it; do NOT relay through third-party
            // domains. We accept the bare IP fallback when scope rejects.
            try { _scope.Require(rcptDomain); }
            catch (Scope.ScopeException)
            {
                rcptDomain = bareHost;
            }

            var sw = Stopwatch.StartNew();
            int probes = 0;
            var minInterval = TimeSpan.FromSeconds(1.0 / probesPerSecond);

            foreach (var mode in new[] { "VRFY", "EXPN", "RCPT" })
            {
                var hits = new List<string>();
                foreach (var u in users)
                {
                    if (totalCts.IsCancellationRequested) break;

                    // Rate-limit: keep an average ≤ probesPerSecond.
                    var expected = TimeSpan.FromTicks(minInterval.Ticks * probes);
                    var elapsed = sw.Elapsed;
                    if (elapsed < expected)
                    {
                        try { await Task.Delay(expected - elapsed, totalCts.Token).ConfigureAwait(false); }
                        catch (OperationCanceledException) { break; }
                    }
                    probes++;

                    bool? hit = mode switch
                    {
                        "VRFY" => await TryVrfyAsync(stream, reader, u, totalCts.Token).ConfigureAwait(false),
                        "EXPN" => await TryExpnAsync(stream, reader, u, totalCts.Token).ConfigureAwait(false),
                        "RCPT" => await TryRcptAsync(stream, reader, u, rcptDomain, totalCts.Token).ConfigureAwait(false),
                        _ => null,
                    };
                    if (hit == true) hits.Add(u);
                    if (hit is null)
                    {
                        // Mode unsupported by this server (502 etc.); abandon
                        // and try the next mode.
                        break;
                    }
                }
                if (hits.Count > 0)
                {
                    result.EnumMode = mode;
                    result.DiscoveredUsers = hits;
                    break;
                }
            }

            await TryQuitAsync(stream, totalCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (totalCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            result.Error ??= "smtp-enum timeout";
        }
        catch (Exception ex)
        {
            result.Error ??= ex.Message;
        }
        finally
        {
            if (stream is not null)
            {
                try { await stream.DisposeAsync().ConfigureAwait(false); } catch { /* best-effort */ }
            }
        }

        RecordFinish(bareHost, port, result);
        return result;
    }

    private void RecordFinish(string target, int port, SmtpEnumResult result)
    {
        _audit.Record("smtp-enum.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["banner_len"] = result.Banner?.Length ?? 0,
            ["capabilities"] = result.EhloCapabilities.Count,
            ["starttls_supported"] = result.StartTlsSupported,
            ["starttls_negotiated"] = result.StartTlsNegotiated,
            ["enum_mode"] = result.EnumMode,
            ["users_found"] = result.DiscoveredUsers.Count,
            ["error"] = result.Error,
        });
    }

    private static IReadOnlyList<string> LoadWordlist(string? path)
    {
        if (string.IsNullOrEmpty(path)) return DefaultUserList;
        try
        {
            var list = File.ReadLines(path)
                .Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.StartsWith('#') && l.Length <= 64)
                .Take(10_000)
                .ToList();
            return list.Count > 0 ? list : DefaultUserList;
        }
        catch
        {
            return DefaultUserList;
        }
    }

    private static string PickRcptDomain(string? banner, string fallbackHost)
    {
        if (string.IsNullOrEmpty(banner)) return fallbackHost;
        // SMTP banners look like "220 mail.lab.local ESMTP …". Pull the
        // second whitespace-delimited token if it looks like a hostname.
        var parts = banner.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parts.Length; i++)
        {
            var p = parts[i];
            if (p.Length == 0) continue;
            // Skip codes / numeric tokens.
            if (int.TryParse(p, out _)) continue;
            if (p.Contains('.') && Regex.IsMatch(p, @"^[A-Za-z0-9\.\-]+$"))
            {
                return p;
            }
        }
        return fallbackHost;
    }

    private static async Task<List<string>> SendEhloAsync(Stream s, SmtpReader r, CancellationToken ct)
    {
        await WriteLineAsync(s, "EHLO drederick.local", ct).ConfigureAwait(false);
        var reply = await ReadReplyAsync(r, ct).ConfigureAwait(false);
        // 250 multi-line: first line is server identity, subsequent are caps.
        if (reply.Code != 250) return new List<string>();
        var lines = reply.Text.Split('\n');
        // Drop the first line (server identity); the rest are capability tokens.
        return lines.Length <= 1
            ? new List<string>()
            : lines.Skip(1).Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
    }

    private static void ApplyCapabilities(SmtpEnumResult result, List<string> caps)
    {
        if (caps.Count == 0) return;
        // Preserve order, deduplicate.
        foreach (var c in caps)
        {
            if (!result.EhloCapabilities.Contains(c, StringComparer.OrdinalIgnoreCase))
                result.EhloCapabilities.Add(c);
        }
        foreach (var c in caps)
        {
            if (c.Equals("STARTTLS", StringComparison.OrdinalIgnoreCase))
                result.StartTlsSupported = true;
            if (c.StartsWith("AUTH ", StringComparison.OrdinalIgnoreCase) ||
                c.Equals("AUTH", StringComparison.OrdinalIgnoreCase))
            {
                var methods = c.Length > 4
                    ? c[5..].Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    : Array.Empty<string>();
                foreach (var m in methods)
                {
                    if (!result.AuthMethods.Contains(m, StringComparer.OrdinalIgnoreCase))
                        result.AuthMethods.Add(m.ToUpperInvariant());
                }
            }
        }
    }

    private static async Task<bool?> TryVrfyAsync(Stream s, SmtpReader r, string user, CancellationToken ct)
    {
        await WriteLineAsync(s, $"VRFY {user}", ct).ConfigureAwait(false);
        var reply = await ReadReplyAsync(r, ct).ConfigureAwait(false);
        return InterpretEnumReply(reply.Code);
    }

    private static async Task<bool?> TryExpnAsync(Stream s, SmtpReader r, string user, CancellationToken ct)
    {
        await WriteLineAsync(s, $"EXPN {user}", ct).ConfigureAwait(false);
        var reply = await ReadReplyAsync(r, ct).ConfigureAwait(false);
        return InterpretEnumReply(reply.Code);
    }

    private static async Task<bool?> TryRcptAsync(Stream s, SmtpReader r, string user, string domain, CancellationToken ct)
    {
        await WriteLineAsync(s, "MAIL FROM:<probe@drederick.local>", ct).ConfigureAwait(false);
        var mailReply = await ReadReplyAsync(r, ct).ConfigureAwait(false);
        if (mailReply.Code is not (250 or 251)) return null;

        await WriteLineAsync(s, $"RCPT TO:<{user}@{domain}>", ct).ConfigureAwait(false);
        var rcptReply = await ReadReplyAsync(r, ct).ConfigureAwait(false);

        await WriteLineAsync(s, "RSET", ct).ConfigureAwait(false);
        _ = await ReadReplyAsync(r, ct).ConfigureAwait(false);

        return InterpretEnumReply(rcptReply.Code);
    }

    /// <summary>250/251/252 = positive, 550/551/553 = negative, 5xx
    /// unsupported (e.g. 502 "VRFY disabled") → null so caller falls back
    /// to the next mode.</summary>
    private static bool? InterpretEnumReply(int code) => code switch
    {
        250 or 251 or 252 => true,
        450 or 451 or 452 => false,
        550 or 551 or 553 => false,
        502 or 503 or 504 => null,
        _ => false,
    };

    private readonly record struct SmtpReply(int Code, string Text);

    private static async Task<SmtpReply> ReadReplyAsync(SmtpReader reader, CancellationToken ct)
    {
        var first = await reader.ReadLineAsync(ct).ConfigureAwait(false);
        if (first is null) return new SmtpReply(0, "");
        var m = SmtpReplyLineRegex().Match(first);
        if (!m.Success) return new SmtpReply(0, first);

        int code = int.Parse(m.Groups["code"].Value);
        string sep = m.Groups["sep"].Value;
        var sb = new StringBuilder();
        sb.Append(m.Groups["text"].Value);

        while (sep == "-")
        {
            var next = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (next is null) break;
            var mm = SmtpReplyLineRegex().Match(next);
            if (!mm.Success)
            {
                sb.Append('\n').Append(next);
                break;
            }
            sep = mm.Groups["sep"].Value;
            sb.Append('\n').Append(mm.Groups["text"].Value);
        }
        return new SmtpReply(code, sb.ToString());
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
        catch { /* best-effort */ }
    }

    /// <summary>CRLF line reader with a hard byte budget.</summary>
    private sealed class SmtpReader
    {
        private readonly Stream _stream;
        private readonly byte[] _buf = new byte[4096];
        private int _bufLen;
        private int _bufPos;
        private readonly int _maxTotalBytes;
        private int _totalBytes;

        public SmtpReader(Stream stream, int maxTotalBytes)
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
                if (_totalBytes > _maxTotalBytes || sb.Length > MaxLineBytes)
                {
                    return sb.ToString();
                }
            }
        }
    }
}
