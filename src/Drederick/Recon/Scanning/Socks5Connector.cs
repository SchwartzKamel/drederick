using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Drederick.Recon.Scanning;

/// <summary>
/// Minimal SOCKS5 client (RFC 1928) — CONNECT method only, no auth or
/// USERNAME/PASSWORD auth. Used by <see cref="NativeScannerTool"/> when a
/// <see cref="Drederick.Recon.ProxyContext"/> is configured. Scope re-validation is the
/// caller's responsibility — this helper only relays the bytes.
/// </summary>
internal static class Socks5Connector
{
    public static async Task<Socket> ConnectAsync(
        Recon.ProxyContext proxy,
        string dstHost,
        int dstPort,
        int timeoutMs,
        bool resolveAtProxy,
        CancellationToken ct)
    {
        var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            await sock.ConnectAsync(proxy.Host, proxy.Port, cts.Token).ConfigureAwait(false);

            // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
            await sock.SendAsync(new byte[] { 0x05, 0x01, 0x00 }, SocketFlags.None, cts.Token)
                .ConfigureAwait(false);

            var greet = new byte[2];
            await ReadExactAsync(sock, greet, cts.Token).ConfigureAwait(false);
            if (greet[0] != 0x05 || greet[1] != 0x00)
                throw new IOException(
                    $"SOCKS5 greeting refused (ver={greet[0]:x2}, method={greet[1]:x2}); only no-auth supported.");

            // CONNECT request: VER=5, CMD=CONNECT(1), RSV=0, ATYP+ADDR+PORT
            var req = new List<byte> { 0x05, 0x01, 0x00 };
            if (!resolveAtProxy && IPAddress.TryParse(dstHost, out var ip))
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    req.Add(0x01);
                    req.AddRange(ip.GetAddressBytes());
                }
                else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    req.Add(0x04);
                    req.AddRange(ip.GetAddressBytes());
                }
                else
                {
                    throw new IOException($"SOCKS5 unsupported address family {ip.AddressFamily}.");
                }
            }
            else
            {
                var hostBytes = Encoding.ASCII.GetBytes(dstHost);
                if (hostBytes.Length > 255)
                    throw new ArgumentException("SOCKS5 hostname too long (>255 bytes).");
                req.Add(0x03);
                req.Add((byte)hostBytes.Length);
                req.AddRange(hostBytes);
            }
            var portBe = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(portBe, (ushort)dstPort);
            req.AddRange(portBe);

            await sock.SendAsync(req.ToArray(), SocketFlags.None, cts.Token).ConfigureAwait(false);

            var head = new byte[4];
            await ReadExactAsync(sock, head, cts.Token).ConfigureAwait(false);
            if (head[0] != 0x05)
                throw new IOException($"SOCKS5 reply has wrong version {head[0]:x2}.");
            if (head[1] != 0x00)
                throw new IOException($"SOCKS5 CONNECT failed (rep={head[1]:x2}).");
            int bndLen = head[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => await ReadByte(sock, cts.Token).ConfigureAwait(false),
                _ => throw new IOException($"SOCKS5 reply has unknown ATYP {head[3]:x2}."),
            };
            var bnd = new byte[bndLen + 2];
            await ReadExactAsync(sock, bnd, cts.Token).ConfigureAwait(false);
            return sock;
        }
        catch
        {
            try { sock.Dispose(); } catch { /* best-effort */ }
            throw;
        }
    }

    private static async Task ReadExactAsync(Socket s, byte[] buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            var n = await s.ReceiveAsync(buf.AsMemory(read, buf.Length - read), SocketFlags.None, ct)
                .ConfigureAwait(false);
            if (n <= 0) throw new IOException("SOCKS5 stream closed mid-reply.");
            read += n;
        }
    }

    private static async Task<int> ReadByte(Socket s, CancellationToken ct)
    {
        var b = new byte[1];
        await ReadExactAsync(s, b, ct).ConfigureAwait(false);
        return b[0];
    }
}
