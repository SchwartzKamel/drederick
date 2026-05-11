using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Drederick.Audit;

namespace Drederick.Recon.Scanning;

/// <summary>
/// Raw-socket TCP SYN ("half-open") scanner. Requires CAP_NET_RAW on Linux
/// (or root); on platforms where a raw socket cannot be opened
/// <see cref="IsAvailable"/> returns false and the caller should fall back
/// to a connect-scan.
///
/// Scope-enforced: <see cref="Scope.Scope.Require"/> is the first statement
/// in every public network-touching method, and is re-checked per packet.
///
/// SYN-scan is faster and stealthier than full connect-scan because we
/// never complete the three-way handshake — on receiving SYN+ACK we record
/// the port as open and let the kernel's RST take care of teardown.
/// </summary>
public sealed class SynScanner
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Drederick.Recon.ProxyContext? _proxy;

    public SynScanner(Scope.Scope scope, AuditLog audit, Drederick.Recon.ProxyContext? proxy = null)
    {
        _scope = scope;
        _audit = audit;
        _proxy = proxy;
    }

    /// <summary>GAP-049: true when raw-socket SYN scanning is incompatible with
    /// the active configuration. Raw sockets cannot be tunnelled through a
    /// SOCKS/HTTP proxy; callers must fall back to <see cref="NativeScannerTool"/>.</summary>
    public bool ProxyForcesFallback => _proxy is not null;

    /// <summary>
    /// Probe whether a raw TCP socket can be opened in this process.
    /// Never throws; returns false on missing CAP_NET_RAW, sandboxed
    /// runtimes, or platforms that don't expose IPPROTO_TCP raw sockets.
    /// </summary>
    public static bool IsAvailable()
    {
        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Send a SYN to each port in <paramref name="ports"/> and return the
    /// list of ports for which a SYN+ACK was observed before
    /// <paramref name="timeoutMs"/> elapsed.
    /// </summary>
    public async Task<IReadOnlyList<int>> ScanAsync(
        string target,
        IReadOnlyList<int> ports,
        int timeoutMs = 1500,
        CancellationToken ct = default)
    {
        _scope.Require(target);
        if (_proxy is not null)
        {
            _audit.Record("scanner.syn.proxy.fallback", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["proxy_endpoint"] = $"{_proxy.Host}:{_proxy.Port}",
                ["reason"] = "SYN scan refused under --proxy: raw sockets cannot be tunnelled through SOCKS/HTTP.",
            });
            return Array.Empty<int>();
        }
        if (ports.Count == 0)
        {
            return Array.Empty<int>();
        }

        var dst = ResolveIPv4(target)
            ?? throw new InvalidOperationException($"Cannot resolve {target} to an IPv4 address for SYN-scan.");

        // Per-packet scope re-validation per AGENTS.md @invariant-id:scope-in-every-tool.
        _scope.Require(dst.ToString());

        _audit.Record("scanner.syn.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["resolved"] = dst.ToString(),
            ["port_count"] = ports.Count,
        });

        var open = new List<int>();
        try
        {
            using var send = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
            send.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);

            using var recv = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
            recv.Bind(new IPEndPoint(IPAddress.Any, 0));
            recv.ReceiveTimeout = Math.Max(50, Math.Min(timeoutMs, 5000));

            var src = LocalIPv4For(dst);
            ushort srcPort = (ushort)(33000 + (Random.Shared.Next() & 0x1FFF));
            uint seq = (uint)Random.Shared.Next();

            foreach (var port in ports)
            {
                ct.ThrowIfCancellationRequested();
                _scope.Require(dst.ToString());
                var pkt = BuildSynPacket(src, dst, srcPort, (ushort)port, seq);
                await send.SendToAsync(pkt, SocketFlags.None,
                    new IPEndPoint(dst, port), ct).ConfigureAwait(false);
            }

            var deadline = Environment.TickCount64 + timeoutMs;
            var buf = new byte[2048];
            while (Environment.TickCount64 < deadline)
            {
                ct.ThrowIfCancellationRequested();
                int n;
                try
                {
                    n = recv.Available > 0 ? recv.Receive(buf) : 0;
                }
                catch (SocketException) { break; }
                if (n <= 0) { await Task.Delay(20, ct).ConfigureAwait(false); continue; }
                if (TryParseSynAck(buf.AsSpan(0, n), srcPort, out var srcOfReply))
                {
                    if (!open.Contains(srcOfReply)) open.Add(srcOfReply);
                }
            }
        }
        finally
        {
            _audit.Record("scanner.syn.finish", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["open_count"] = open.Count,
            });
        }

        open.Sort();
        return open;
    }

    // ---- packet building ----

    internal static byte[] BuildSynPacket(IPAddress src, IPAddress dst, ushort srcPort, ushort dstPort, uint seq)
    {
        var pkt = new byte[40]; // 20 IP + 20 TCP

        // IP header
        pkt[0] = 0x45;                                  // ver=4, ihl=5
        pkt[1] = 0;                                     // tos
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(2, 2), 40); // total length
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(4, 2), (ushort)Random.Shared.Next(0, ushort.MaxValue)); // id
        pkt[6] = 0x40;                                  // flags=DF
        pkt[7] = 0;                                     // frag
        pkt[8] = 64;                                    // ttl
        pkt[9] = 6;                                     // protocol = TCP
        // checksum (10..12) zero for now
        src.GetAddressBytes().CopyTo(pkt, 12);
        dst.GetAddressBytes().CopyTo(pkt, 16);
        var ipChk = OnesComplementChecksum(pkt.AsSpan(0, 20));
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(10, 2), ipChk);

        // TCP header
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(20, 2), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(22, 2), dstPort);
        BinaryPrimitives.WriteUInt32BigEndian(pkt.AsSpan(24, 4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(pkt.AsSpan(28, 4), 0); // ack
        pkt[32] = 0x50;     // data offset = 5 (20 bytes), reserved
        pkt[33] = 0x02;     // flags = SYN
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(34, 2), 0xFAF0); // window
        // checksum (36..38) zero
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(38, 2), 0); // urg

        // TCP checksum over pseudo-header + TCP segment
        Span<byte> pseudo = stackalloc byte[12 + 20];
        src.GetAddressBytes().CopyTo(pseudo[..4]);
        dst.GetAddressBytes().CopyTo(pseudo.Slice(4, 4));
        pseudo[8] = 0;
        pseudo[9] = 6;
        BinaryPrimitives.WriteUInt16BigEndian(pseudo.Slice(10, 2), 20);
        pkt.AsSpan(20, 20).CopyTo(pseudo[12..]);
        var tcpChk = OnesComplementChecksum(pseudo);
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(36, 2), tcpChk);

        return pkt;
    }

    /// <summary>RFC 1071 one's-complement checksum.</summary>
    internal static ushort OnesComplementChecksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        int i = 0;
        while (i + 1 < data.Length)
        {
            sum += (uint)((data[i] << 8) | data[i + 1]);
            i += 2;
        }
        if (i < data.Length)
        {
            sum += (uint)(data[i] << 8);
        }
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (ushort)(~sum & 0xFFFF);
    }

    /// <summary>
    /// Try to parse a raw IPv4 datagram as a TCP SYN+ACK reply addressed
    /// to <paramref name="ourSrcPort"/>. Returns the original destination
    /// port (i.e. the remote port that's open) on success.
    /// </summary>
    internal static bool TryParseSynAck(ReadOnlySpan<byte> datagram, ushort ourSrcPort, out int remotePort)
    {
        remotePort = 0;
        if (datagram.Length < 40) return false;
        var ihl = (datagram[0] & 0x0F) * 4;
        if (ihl < 20 || datagram.Length < ihl + 20) return false;
        if (datagram[9] != 6) return false; // not TCP
        var tcp = datagram[ihl..];
        var srcPort = BinaryPrimitives.ReadUInt16BigEndian(tcp[..2]);
        var dstPort = BinaryPrimitives.ReadUInt16BigEndian(tcp.Slice(2, 2));
        if (dstPort != ourSrcPort) return false;
        var flags = tcp[13];
        const byte SYN = 0x02, ACK = 0x10;
        if ((flags & (SYN | ACK)) != (SYN | ACK)) return false;
        remotePort = srcPort;
        return true;
    }

    // ---- helpers ----

    private static IPAddress? ResolveIPv4(string target)
    {
        if (IPAddress.TryParse(target, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
        {
            return ip;
        }
        try
        {
            var entry = Dns.GetHostAddresses(target);
            return Array.Find(entry, a => a.AddressFamily == AddressFamily.InterNetwork);
        }
        catch
        {
            return null;
        }
    }

    private static IPAddress LocalIPv4For(IPAddress dst)
    {
        try
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.Connect(new IPEndPoint(dst, 65530));
            if (probe.LocalEndPoint is IPEndPoint ep)
            {
                return ep.Address;
            }
        }
        catch
        {
        }
        return IPAddress.Loopback;
    }
}
