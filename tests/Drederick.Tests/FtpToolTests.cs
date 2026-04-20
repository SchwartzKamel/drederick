using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class FtpToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-ftp-{Guid.NewGuid():N}.jsonl"));

    /// <summary>Stream that serves pre-seeded server bytes on Read and
    /// captures client Writes for later inspection.</summary>
    private sealed class ScriptedStream : Stream
    {
        private readonly MemoryStream _serverToClient;
        private readonly MemoryStream _clientToServer = new();

        public ScriptedStream(byte[] serverBytes) => _serverToClient = new MemoryStream(serverBytes);

        public byte[] WrittenBytes => _clientToServer.ToArray();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _serverToClient.Length;
        public override long Position { get => _serverToClient.Position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => _serverToClient.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
            => _serverToClient.ReadAsync(buffer, ct);
        public override void Write(byte[] buffer, int offset, int count) => _clientToServer.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
            => _clientToServer.WriteAsync(buffer, ct);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private static Func<string, int, CancellationToken, Task<Stream>> Factory(ScriptedStream s, Action? onCall = null)
        => (_, _, _) => { onCall?.Invoke(); return Task.FromResult<Stream>(s); };

    [Fact]
    public async Task OutOfScope_Throws_ScopeException_And_Does_Not_Connect()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var called = false;
        var tool = new FtpTool(scope, audit,
            (_, _, _) => { called = true; return Task.FromResult<Stream>(new MemoryStream()); });

        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("192.168.1.1"));
        Assert.False(called);
    }

    [Fact]
    public async Task Anonymous_Accepted_Parses_Banner_And_Listing()
    {
        var script = Encoding.ASCII.GetBytes(
            "220 Welcome to FakeFTP\r\n" +
            "331 User anonymous okay, need password\r\n" +
            "230 Login successful\r\n" +
            "150 Opening data connection\r\n" +
            "drwxr-xr-x 2 root root  4096 Jan  1 00:00 pub\r\n" +
            "-rw-r--r-- 1 root root    42 Jan  1 00:00 readme.txt\r\n" +
            "226 Transfer complete\r\n" +
            "221 Goodbye\r\n");
        var stream = new ScriptedStream(script);
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new FtpTool(scope, audit, Factory(stream));

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.Equal(21, result.Port);
        Assert.Contains("Welcome to FakeFTP", result.Banner);
        Assert.True(result.AnonymousAllowed);
        Assert.Equal(2, result.RootListing.Count);
        Assert.Contains("pub", result.RootListing[0]);
        Assert.Contains("readme.txt", result.RootListing[1]);
        Assert.Null(result.Error);

        var sent = Encoding.ASCII.GetString(stream.WrittenBytes);
        Assert.Contains("USER anonymous\r\n", sent);
        Assert.Contains("PASS anonymous@drederick.invalid\r\n", sent);
        Assert.Contains("LIST\r\n", sent);
        Assert.Contains("QUIT\r\n", sent);
    }

    [Fact]
    public async Task Anonymous_Rejected_Reports_False_With_No_Error()
    {
        var script = Encoding.ASCII.GetBytes(
            "220 Secured FTP\r\n" +
            "530 Anonymous login not permitted\r\n" +
            "221 Goodbye\r\n");
        var stream = new ScriptedStream(script);
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new FtpTool(scope, audit, Factory(stream));

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.False(result.AnonymousAllowed);
        Assert.Empty(result.RootListing);
        Assert.Contains("Secured FTP", result.Banner);
        Assert.Null(result.Error);

        var sent = Encoding.ASCII.GetString(stream.WrittenBytes);
        Assert.Contains("USER anonymous\r\n", sent);
        Assert.DoesNotContain("LIST\r\n", sent);
    }

    [Fact]
    public async Task Connection_Refused_Sets_Error_Without_Throwing()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new FtpTool(scope, audit,
            (_, _, _) => throw new System.Net.Sockets.SocketException(111) /* ECONNREFUSED */);

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.False(result.AnonymousAllowed);
        Assert.False(string.IsNullOrEmpty(result.Error));
        Assert.Null(result.Banner);
        Assert.Empty(result.RootListing);
    }

    [Fact]
    public async Task Listing_Size_Cap_Is_Honored()
    {
        var sb = new StringBuilder();
        sb.Append("220 Cap Test FTP\r\n");
        sb.Append("331 need pass\r\n");
        sb.Append("230 ok\r\n");
        sb.Append("150 opening\r\n");
        for (int i = 0; i < 500; i++)
        {
            sb.Append("-rw-r--r-- 1 a a 0 Jan 1 00:00 file").Append(i).Append(".txt\r\n");
        }
        sb.Append("226 done\r\n");

        var stream = new ScriptedStream(Encoding.ASCII.GetBytes(sb.ToString()));
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new FtpTool(scope, audit, Factory(stream));

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.True(result.AnonymousAllowed);
        Assert.Equal(200, result.RootListing.Count);
    }
}
