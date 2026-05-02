using System.Text;
using Drederick.Recon;
using Drederick.Recon.Native;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Native;

public class SshHostkeyToolTests
{
    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new SshHostkeyTool(NativeTestHelpers.SmallScope(), audit,
            (_, _, _) => Task.FromResult<Stream>(new MemoryStream()));
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("172.16.0.1"));
    }

    [Fact]
    public void ParseKexInit_Extracts_HostKey_And_Kex_Algorithms()
    {
        // Build a minimal KEXINIT payload (no length prefix, no padding):
        //   pad_len(1) || msg_code 20 || cookie(16) || 10 name-lists
        var lists = new[]
        {
            "curve25519-sha256,diffie-hellman-group14-sha1",
            "ssh-ed25519,ssh-rsa",
            "aes128-ctr,aes256-ctr",
            "aes128-ctr,aes256-ctr",
            "hmac-sha2-256,hmac-sha1",
            "hmac-sha2-256,hmac-sha1",
            "none",
            "none",
            "",
            "",
        };
        var ms = new MemoryStream();
        ms.WriteByte(0); // pad_len
        ms.WriteByte(20); // SSH_MSG_KEXINIT
        ms.Write(new byte[16], 0, 16); // cookie
        foreach (var l in lists)
        {
            var b = Encoding.ASCII.GetBytes(l);
            ms.Write(new[] { (byte)((b.Length >> 24) & 0xff), (byte)((b.Length >> 16) & 0xff),
                              (byte)((b.Length >> 8) & 0xff), (byte)(b.Length & 0xff) }, 0, 4);
            ms.Write(b, 0, b.Length);
        }
        ms.WriteByte(0); // boolean first_kex_packet_follows
        ms.Write(new byte[4], 0, 4); // reserved uint32

        var result = new SshHostkeyResult { Port = 22 };
        SshHostkeyTool.ParseKexInit(ms.ToArray(), result);
        Assert.Contains("curve25519-sha256", result.KexAlgorithms);
        Assert.Contains("ssh-ed25519", result.HostKeyAlgorithms);
        Assert.Contains("ssh-rsa", result.HostKeyAlgorithms);
        Assert.Contains("aes128-ctr", result.EncryptionAlgorithms);
        Assert.Contains("hmac-sha2-256", result.MacAlgorithms);
    }

    [Fact]
    public void ParseKexInit_Ignores_NonKexInit_PacketCode()
    {
        var buf = new byte[20];
        buf[1] = 1; // not 20
        var r = new SshHostkeyResult();
        SshHostkeyTool.ParseKexInit(buf, r);
        Assert.Empty(r.HostKeyAlgorithms);
    }
}
