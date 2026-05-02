using System.Net;
using Drederick.Audit;
using Drederick.Recon.Scanning;
using Xunit;

namespace Drederick.Tests.Recon.Scanning;

public class SynScannerTests
{
    private static Scope.Scope MakeScope(params string[] entries)
    {
        var path = Path.Combine(Path.GetTempPath(), $"syn-scope-{Guid.NewGuid():N}.txt");
        File.WriteAllLines(path, entries);
        try
        {
            return Scope.ScopeLoader.LoadFile(path, allowBroad: false, labMode: true);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    private static AuditLog MakeAudit()
    {
        var path = Path.Combine(Path.GetTempPath(), $"syn-audit-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    [Fact]
    public void IsAvailable_DoesNotThrow_AndReturnsBool()
    {
        var ok = SynScanner.IsAvailable();
        Assert.True(ok || !ok); // contract: never throws, returns bool
    }

    [Fact]
    public async Task ScanAsync_ScopeRejectsOutOfScopeTarget()
    {
        var scope = MakeScope("10.10.10.10/32");
        var scanner = new SynScanner(scope, MakeAudit());
        await Assert.ThrowsAsync<Scope.ScopeException>(async () =>
            await scanner.ScanAsync("8.8.8.8", new[] { 80 }));
    }

    [Fact]
    public void OnesComplementChecksum_AllZeros_IsAllOnes()
    {
        var data = new byte[20];
        var chk = SynScanner.OnesComplementChecksum(data);
        Assert.Equal((ushort)0xFFFF, chk);
    }

    [Fact]
    public void OnesComplementChecksum_AllOnes_IsZero()
    {
        var data = Enumerable.Repeat((byte)0xFF, 20).ToArray();
        var chk = SynScanner.OnesComplementChecksum(data);
        Assert.Equal((ushort)0x0000, chk);
    }

    [Fact]
    public void BuildSynPacket_LengthIs40Bytes()
    {
        var pkt = SynScanner.BuildSynPacket(
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("10.0.0.2"),
            srcPort: 40000, dstPort: 22, seq: 0xDEADBEEF);
        Assert.Equal(40, pkt.Length);
    }

    [Fact]
    public void BuildSynPacket_HeaderFieldsAreCorrect()
    {
        var pkt = SynScanner.BuildSynPacket(
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("10.0.0.2"),
            srcPort: 40000, dstPort: 22, seq: 0xDEADBEEF);

        Assert.Equal(0x45, pkt[0]);             // IPv4, IHL=5
        Assert.Equal(6, pkt[9]);                // protocol = TCP
        Assert.Equal(0x50, pkt[32]);            // data offset = 5
        Assert.Equal(0x02, pkt[33]);            // SYN flag
    }

    [Fact]
    public void BuildSynPacket_IPChecksum_IsSelfConsistent()
    {
        var pkt = SynScanner.BuildSynPacket(
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("10.0.0.2"),
            srcPort: 40000, dstPort: 22, seq: 1);
        // Re-running the checksum over the IP header (with chk in place) sums to 0.
        var verify = SynScanner.OnesComplementChecksum(pkt.AsSpan(0, 20));
        Assert.Equal((ushort)0, verify);
    }

    [Fact]
    public void TryParseSynAck_RecognizesValidSynAckToOurSrcPort()
    {
        // Build a fake reply: dst=us, src=remote, flags=SYN+ACK
        var pkt = new byte[40];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP
        // tcp header at offset 20
        pkt[20] = 0x00; pkt[21] = 22;       // remote src port = 22
        pkt[22] = 0x9C; pkt[23] = 0x40;     // dst port = 40000 (our src)
        pkt[33] = 0x12;                     // SYN+ACK

        Assert.True(SynScanner.TryParseSynAck(pkt, ourSrcPort: 40000, out var port));
        Assert.Equal(22, port);
    }

    [Fact]
    public void TryParseSynAck_RejectsRstAck()
    {
        var pkt = new byte[40];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[20] = 0x00; pkt[21] = 80;
        pkt[22] = 0x9C; pkt[23] = 0x40;
        pkt[33] = 0x14;                     // RST+ACK
        Assert.False(SynScanner.TryParseSynAck(pkt, 40000, out _));
    }

    [Fact]
    public void TryParseSynAck_RejectsWrongDstPort()
    {
        var pkt = new byte[40];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[20] = 0x00; pkt[21] = 22;
        pkt[22] = 0x00; pkt[23] = 0x50;     // dst = 80, not ours
        pkt[33] = 0x12;
        Assert.False(SynScanner.TryParseSynAck(pkt, 40000, out _));
    }
}
