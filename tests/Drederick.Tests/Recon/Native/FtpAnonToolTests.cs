using System.Text;
using Drederick.Recon;
using Drederick.Recon.Native;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Native;

public class FtpAnonToolTests
{
    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new FtpAnonTool(NativeTestHelpers.SmallScope(), audit,
            (_, _, _) => Task.FromResult<Stream>(new MemoryStream()));
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("172.16.0.1"));
    }

    [Fact]
    public void ParsePasv_Decodes_Standard_Response()
    {
        Assert.True(FtpAnonTool.ParsePasv(
            "227 Entering Passive Mode (10,10,10,5,200,21)", out var host, out var port));
        Assert.Equal("10.10.10.5", host);
        Assert.Equal((200 << 8) | 21, port);
    }

    [Fact]
    public void ParsePasv_Rejects_Garbage()
    {
        Assert.False(FtpAnonTool.ParsePasv("227 Bad", out _, out _));
        Assert.False(FtpAnonTool.ParsePasv("(1,2,3,4,5)", out _, out _));
    }

    [Fact]
    public void ParseCode_Reads_3_Digit_Status()
    {
        Assert.Equal(220, FtpAnonTool.ParseCode("220 Welcome"));
        Assert.Equal(331, FtpAnonTool.ParseCode("331-User OK"));
        Assert.Equal(0, FtpAnonTool.ParseCode("garbage"));
    }

    [Fact]
    public async Task Anonymous_Allowed_Records_Banner_And_LoginResponse()
    {
        var script = Encoding.ASCII.GetBytes(
            "220 Welcome to FakeFTP\r\n" +
            "331 User name okay, need password\r\n" +
            "230 Login successful\r\n" +
            "227 Entering Passive Mode (10,10,10,5,0,80)\r\n" +
            "150 Opening data connection\r\n" +
            "226 Transfer complete\r\n" +
            "221 Goodbye\r\n");
        var control = new ScriptedStream(script);
        var dataScript = Encoding.ASCII.GetBytes("drwxr-xr-x 2 root root  4096 Jan  1 00:00 pub\r\n");
        var data = new ScriptedStream(dataScript);
        int call = 0;
        Func<string, int, CancellationToken, Task<Stream>> factory = (_, _, _) =>
            Task.FromResult<Stream>(call++ == 0 ? control : data);

        using var audit = NativeTestHelpers.NewAudit();
        var tool = new FtpAnonTool(NativeTestHelpers.SmallScope(), audit, factory);
        var r = await tool.ProbeAsync("10.10.10.5", 21);

        Assert.Contains("Welcome to FakeFTP", r.Banner);
        Assert.True(r.AnonymousAllowed);
        Assert.Contains("Login successful", r.LoginResponse);
    }
}
