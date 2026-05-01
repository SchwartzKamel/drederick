using System.Net;
using System.Net.Sockets;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

public class NativeScannerToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-nativescan-{Guid.NewGuid():N}.jsonl"));

    // ------------------------------------------------------------------ //
    // 1. Out-of-scope target throws ScopeException before any TCP connect.
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NativeScannerTool(scope, audit);

        await Assert.ThrowsAsync<ScopeException>(
            () => tool.ScanAsync("192.168.1.99", [80]));
    }

    // ------------------------------------------------------------------ //
    // 2. Port that fails to connect → not in OpenPorts, no exception.
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task ClosedPort_NotInOpenPorts_NoException()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new NativeScannerTool(scope, audit);

        // Acquire a free port then immediately stop the listener so nothing
        // is listening on it when we scan.
        int port;
        using (var tmp = new TcpListener(IPAddress.Loopback, 0))
        {
            tmp.Start();
            port = ((IPEndPoint)tmp.LocalEndpoint).Port;
        }

        var result = await tool.ScanAsync("127.0.0.1", [port], concurrency: 1, timeoutMs: 500);

        Assert.NotNull(result.NativeScan);
        Assert.Equal("nativescan", result.NativeScan.Source);
        Assert.Empty(result.NativeScan.OpenPorts);
    }

    // ------------------------------------------------------------------ //
    // 3. Banner "SSH-2.0-OpenSSH_8.9\r\n" → service=ssh.
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task SshBanner_DetectsProtocol_Ssh()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new NativeScannerTool(scope, audit);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            var stream = client.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_8.9\r\n"));
            // Hold the connection open long enough for the client to read the banner.
            await Task.Delay(1000);
        });

        try
        {
            var result = await tool.ScanAsync(
                "127.0.0.1", [port], concurrency: 1, timeoutMs: 3000);

            var openPort = Assert.Single(result.NativeScan!.OpenPorts);
            Assert.Equal(port, openPort.Port);
            Assert.Equal("ssh", openPort.Service);
        }
        finally
        {
            listener.Stop();
            await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    // ------------------------------------------------------------------ //
    // 4. Server that responds "+PONG\r\n" → service=redis.
    // ------------------------------------------------------------------ //

    [Fact]
    public async Task RedisPong_DetectsProtocol_Redis()
    {
        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new NativeScannerTool(scope, audit);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            var stream = client.GetStream();
            // Drain any probe bytes the client may have sent (port != 6379 here
            // so the tool won't send PING, but we drain anyway for robustness).
            var discard = new byte[16];
            _ = await stream.ReadAsync(discard.AsMemory()).AsTask().WaitAsync(
                TimeSpan.FromMilliseconds(200)).ContinueWith(_ => 0);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("+PONG\r\n"));
            await Task.Delay(1000);
        });

        try
        {
            var result = await tool.ScanAsync(
                "127.0.0.1", [port], concurrency: 1, timeoutMs: 3000);

            var openPort = Assert.Single(result.NativeScan!.OpenPorts);
            Assert.Equal(port, openPort.Port);
            Assert.Equal("redis", openPort.Service);
        }
        finally
        {
            listener.Stop();
            await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }
}
