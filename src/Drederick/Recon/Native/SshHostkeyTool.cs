// Original NSE script: ssh-hostkey.nse
// Source: https://nmap.org/nsedoc/scripts/ssh-hostkey.html
// Author: Sven Klemm
// License: NPSL
//
// Native C# port: read the SSH banner (RFC 4253 §4.2), then read one
// binary packet, decode it as SSH_MSG_KEXINIT (msg code 20) and
// extract the algorithm name-lists. Connection is injectable as a
// Stream factory so tests can replay a recorded handshake without
// touching the network.
using System.Net.Sockets;
using System.Text;
using Drederick.Audit;

namespace Drederick.Recon.Native;

public sealed class SshHostkeyTool : IReconTool
{
    public string Name => "ssh-hostkey";
    public string Description =>
        "Native port of nmap's ssh-hostkey.nse: read the SSH banner and KEXINIT " +
        "packet, then enumerate host-key / kex / cipher / MAC algorithms. " +
        "Target must be in scope.";

    private const int MaxPacketBytes = 64 * 1024;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TotalTimeout = TimeSpan.FromSeconds(10);

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, int, CancellationToken, Task<Stream>> _connect;

    public SshHostkeyTool(
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

    public async Task<SshHostkeyResult> ProbeAsync(string target, int port = 22, CancellationToken ct = default)
    {
        _scope.Require(target);
        _audit.Record("ssh-hostkey.start", new Dictionary<string, object?>
        {
            ["target"] = target, ["port"] = port,
        });

        var result = new SshHostkeyResult { Port = port };
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(TotalTimeout);
        try
        {
            await using var stream = await _connect(target, port, linked.Token).ConfigureAwait(false);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("SSH-2.0-Drederick\r\n"), linked.Token).ConfigureAwait(false);
            await stream.FlushAsync(linked.Token).ConfigureAwait(false);
            result.Banner = await ReadBannerAsync(stream, linked.Token).ConfigureAwait(false);
            var packet = await ReadPacketAsync(stream, linked.Token).ConfigureAwait(false);
            if (packet is not null)
                ParseKexInit(packet, result);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            result.Error = "timeout";
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { result.Error = ex.Message; }

        _audit.Record("ssh-hostkey.finish", new Dictionary<string, object?>
        {
            ["target"] = target, ["port"] = port,
            ["banner"] = result.Banner,
            ["host_key_algorithms"] = result.HostKeyAlgorithms.Count,
            ["error"] = result.Error,
        });
        return result;
    }

    internal static async Task<string?> ReadBannerAsync(Stream s, CancellationToken ct)
    {
        var buf = new byte[1024];
        var sb = new StringBuilder();
        while (true)
        {
            var n = await s.ReadAsync(buf.AsMemory(0, 1), ct).ConfigureAwait(false);
            if (n <= 0) break;
            sb.Append((char)buf[0]);
            if (sb.Length >= 2 && sb[^2] == '\r' && sb[^1] == '\n')
                return sb.ToString(0, sb.Length - 2);
            if (sb.Length > 8192) break;
        }
        return sb.Length == 0 ? null : sb.ToString();
    }

    internal static async Task<byte[]?> ReadPacketAsync(Stream s, CancellationToken ct)
    {
        var lenBuf = new byte[4];
        if (!await ReadExactlyAsync(s, lenBuf, ct).ConfigureAwait(false)) return null;
        int len = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
        if (len <= 0 || len > MaxPacketBytes) return null;
        var pkt = new byte[len];
        if (!await ReadExactlyAsync(s, pkt, ct).ConfigureAwait(false)) return null;
        return pkt;
    }

    private static async Task<bool> ReadExactlyAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        var off = 0;
        while (off < buf.Length)
        {
            var n = await s.ReadAsync(buf.AsMemory(off, buf.Length - off), ct).ConfigureAwait(false);
            if (n <= 0) return false;
            off += n;
        }
        return true;
    }

    /// <summary>
    /// Parse a binary KEXINIT payload (the bytes after the 4-byte length
    /// prefix). Layout per RFC 4253 §7.1:
    ///   pad_length(1) || msg_code(1)=20 || cookie(16) ||
    ///   10 name-lists, each = uint32 length || ASCII bytes.
    /// </summary>
    public static void ParseKexInit(byte[] packet, SshHostkeyResult result)
    {
        if (packet.Length < 1 + 1 + 16) return;
        int pos = 0;
        int padLen = packet[pos++];
        var msgCode = packet[pos++];
        if (msgCode != 20) return;
        pos += 16; // cookie
        var lists = new List<string>(10);
        for (int i = 0; i < 10 && pos + 4 <= packet.Length - padLen; i++)
        {
            int n = (packet[pos] << 24) | (packet[pos + 1] << 16) | (packet[pos + 2] << 8) | packet[pos + 3];
            pos += 4;
            if (n < 0 || pos + n > packet.Length) return;
            var s = Encoding.ASCII.GetString(packet, pos, n);
            pos += n;
            lists.Add(s);
        }
        if (lists.Count < 10) return;
        result.KexAlgorithms.AddRange(SplitNameList(lists[0]));
        result.HostKeyAlgorithms.AddRange(SplitNameList(lists[1]));
        result.EncryptionAlgorithms.AddRange(SplitNameList(lists[2]));
        // skip lists[3] (encryption_algorithms_server_to_client) -- merged into above? keep first
        result.MacAlgorithms.AddRange(SplitNameList(lists[4]));
    }

    private static IEnumerable<string> SplitNameList(string list) =>
        string.IsNullOrEmpty(list)
            ? Array.Empty<string>()
            : list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
