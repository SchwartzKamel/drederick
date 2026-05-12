using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

/// <summary>
/// Tests for <see cref="SmtpEnumTool"/> (GAP-011). Uses an in-process
/// <see cref="TcpListener"/> on 127.0.0.1:0 that replays a recorded
/// transcript so the tool exercises real socket I/O without depending on
/// any external SMTP server.
/// </summary>
public class SmtpEnumToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-smtpenum-{Guid.NewGuid():N}.jsonl"));

    /// <summary>Tiny scripted SMTP server. The script is a list of
    /// <see cref="Step"/>s; on each <c>Recv</c> the server reads a line and
    /// asserts it matches; on each <c>Send</c> it writes the supplied bytes.
    /// </summary>
    private sealed class FakeSmtpServer : IAsyncDisposable
    {
        public enum Op { Send, Recv, RecvAny, Close }
        public sealed record Step(Op Op, string Payload = "");

        private readonly TcpListener _listener;
        private readonly List<Step> _script;
        private readonly Task _serverTask;
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
        public List<string> ReceivedLines { get; } = new();

        public FakeSmtpServer(IEnumerable<Step> script)
        {
            _script = script.ToList();
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            _serverTask = Task.Run(RunAsync);
        }

        private async Task RunAsync()
        {
            try
            {
                using var client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                using var stream = client.GetStream();
                var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                var writer = new StreamWriter(stream, new ASCIIEncoding()) { AutoFlush = true, NewLine = "\r\n" };
                foreach (var step in _script)
                {
                    if (step.Op == Op.Send)
                    {
                        await writer.WriteAsync(step.Payload).ConfigureAwait(false);
                        await writer.FlushAsync().ConfigureAwait(false);
                    }
                    else if (step.Op == Op.Recv)
                    {
                        var line = await reader.ReadLineAsync().ConfigureAwait(false);
                        if (line is null) return;
                        ReceivedLines.Add(line);
                        // soft-match: starts-with is enough; the rest is data.
                        if (!line.StartsWith(step.Payload, StringComparison.Ordinal))
                        {
                            // Diverged — record and stop so test fails on
                            // expected later traffic.
                            return;
                        }
                    }
                    else if (step.Op == Op.RecvAny)
                    {
                        var line = await reader.ReadLineAsync().ConfigureAwait(false);
                        if (line is null) return;
                        ReceivedLines.Add(line);
                    }
                    else if (step.Op == Op.Close)
                    {
                        return;
                    }
                }
            }
            catch { /* swallow — tests assert on result, not server liveness */ }
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            try { await _serverTask.ConfigureAwait(false); } catch { /* ignore */ }
        }
    }

    private static Func<string, int, CancellationToken, Task<Stream>> TcpFactory()
        => async (host, port, ct) =>
        {
            var c = new TcpClient();
            await c.ConnectAsync(host, port, ct).ConfigureAwait(false);
            return c.GetStream();
        };

    // STARTTLS test override: do not actually negotiate TLS, just keep
    // talking on the same stream so the scripted server can keep replaying.
    private static Func<Stream, string, CancellationToken, Task<Stream>> NoopStartTls()
        => (s, _, _) => Task.FromResult(s);

    private static IEnumerable<FakeSmtpServer.Step> BasicEhloScript() => new[]
    {
        new FakeSmtpServer.Step(FakeSmtpServer.Op.Send,
            "220 mail.lab.local ESMTP Postfix\r\n"),
        new FakeSmtpServer.Step(FakeSmtpServer.Op.Recv, "EHLO"),
        new FakeSmtpServer.Step(FakeSmtpServer.Op.Send,
            "250-mail.lab.local\r\n" +
            "250-PIPELINING\r\n" +
            "250-SIZE 10485760\r\n" +
            "250-VRFY\r\n" +
            "250-AUTH PLAIN LOGIN\r\n" +
            "250 HELP\r\n"),
    };

    [Fact]
    public async Task Banner_And_EhloCapabilities_Parsed()
    {
        var script = BasicEhloScript().Concat(new[]
        {
            // All VRFYs reject so no enumeration mode succeeds; we are only
            // checking the banner / capability shape here.
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Recv, "VRFY"),
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Send, "550 unknown\r\n"),
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Close),
        });
        await using var server = new FakeSmtpServer(script);

        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new SmtpEnumTool(scope, audit, TcpFactory(), NoopStartTls());

        var r = await tool.EnumerateAsync("127.0.0.1", server.Port, probesPerSecond: 1000);

        Assert.Equal(server.Port, r.Port);
        Assert.Contains("mail.lab.local", r.Banner);
        Assert.Contains("PIPELINING", r.EhloCapabilities, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("SIZE 10485760", r.EhloCapabilities, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("VRFY", r.EhloCapabilities, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("AUTH PLAIN LOGIN", r.EhloCapabilities, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("PLAIN", r.AuthMethods);
        Assert.Contains("LOGIN", r.AuthMethods);
        Assert.False(r.StartTlsSupported);
        Assert.Empty(r.DiscoveredUsers);
    }

    [Fact]
    public async Task VrfyEnum_DiscoversValidUsers()
    {
        // Custom wordlist of two: admin (negative), root (positive).
        var wlPath = Path.Combine(Path.GetTempPath(), $"smtp-wl-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(wlPath, "admin\nroot\n");
        try
        {
            var script = BasicEhloScript().Concat(new[]
            {
                new FakeSmtpServer.Step(FakeSmtpServer.Op.Recv, "VRFY admin"),
                new FakeSmtpServer.Step(FakeSmtpServer.Op.Send,
                    "550 5.1.1 <admin>: Recipient address rejected: User unknown\r\n"),
                new FakeSmtpServer.Step(FakeSmtpServer.Op.Recv, "VRFY root"),
                new FakeSmtpServer.Step(FakeSmtpServer.Op.Send, "252 2.0.0 root\r\n"),
                new FakeSmtpServer.Step(FakeSmtpServer.Op.RecvAny),
                new FakeSmtpServer.Step(FakeSmtpServer.Op.Send, "221 2.0.0 Bye\r\n"),
            });
            await using var server = new FakeSmtpServer(script);

            var scope = ScopeLoader.Parse("127.0.0.1");
            using var audit = NewAudit();
            var tool = new SmtpEnumTool(scope, audit, TcpFactory(), NoopStartTls());

            var r = await tool.EnumerateAsync("127.0.0.1", server.Port, wordlistPath: wlPath,
                probesPerSecond: 1000);

            Assert.Equal("VRFY", r.EnumMode);
            Assert.Single(r.DiscoveredUsers);
            Assert.Contains("root", r.DiscoveredUsers);
            Assert.DoesNotContain("admin", r.DiscoveredUsers);
        }
        finally
        {
            try { File.Delete(wlPath); } catch { }
        }
    }

    [Fact]
    public async Task StartTls_Negotiated_WhenAdvertised()
    {
        var script = new[]
        {
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Send, "220 mail.lab.local ESMTP\r\n"),
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Recv, "EHLO"),
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Send,
                "250-mail.lab.local\r\n" +
                "250-STARTTLS\r\n" +
                "250 HELP\r\n"),
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Recv, "STARTTLS"),
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Send, "220 ready\r\n"),
            // After (no-op) TLS upgrade in tests, tool sends a second EHLO.
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Recv, "EHLO"),
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Send,
                "250-mail.lab.local\r\n" +
                "250-AUTH PLAIN LOGIN\r\n" +
                "250 HELP\r\n"),
            // Tool now runs VRFY enumeration over the upgraded channel —
            // reject everything so it exits cleanly.
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Recv, "VRFY"),
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Send, "550 unknown\r\n"),
            new FakeSmtpServer.Step(FakeSmtpServer.Op.Close),
        };
        await using var server = new FakeSmtpServer(script);

        var scope = ScopeLoader.Parse("127.0.0.1");
        using var audit = NewAudit();
        var tool = new SmtpEnumTool(scope, audit, TcpFactory(), NoopStartTls());

        var r = await tool.EnumerateAsync("127.0.0.1", server.Port, probesPerSecond: 1000);

        Assert.True(r.StartTlsSupported);
        Assert.True(r.StartTlsNegotiated);
        Assert.Contains("PLAIN", r.AuthMethods);
    }

    [Fact]
    public async Task RejectsOutOfScopeTarget()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var connected = false;
        var tool = new SmtpEnumTool(scope, audit,
            (_, _, _) => { connected = true; return Task.FromResult<Stream>(new MemoryStream()); },
            NoopStartTls());

        await Assert.ThrowsAsync<ScopeException>(
            () => tool.EnumerateAsync("192.168.1.1"));
        Assert.False(connected);
    }

    [Fact]
    public async Task ArgvInjection_Rejected()
    {
        // `evil.com; rm` is not a parseable IP, so Scope.Require rejects it
        // first. Defense-in-depth: even if scope let it through, the argv-
        // shape regex would refuse the shell metachars. Either rejection
        // type satisfies the security contract.
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var connected = false;
        var tool = new SmtpEnumTool(scope, audit,
            (_, _, _) => { connected = true; return Task.FromResult<Stream>(new MemoryStream()); },
            NoopStartTls());

        await Assert.ThrowsAnyAsync<Exception>(
            () => tool.EnumerateAsync("evil.com; rm"));
        Assert.False(connected);
    }

    [Fact]
    public async Task RateLimit_Honored()
    {
        // 5 probes at 10/s should take ≥ ~400ms (4 inter-probe gaps × 100ms).
        // Use a 250ms threshold to keep the test cheap and stable.
        var wlPath = Path.Combine(Path.GetTempPath(), $"smtp-wl-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(wlPath, "u1\nu2\nu3\nu4\nu5\n");
        try
        {
            var steps = new List<FakeSmtpServer.Step>(BasicEhloScript());
            for (int i = 0; i < 5; i++)
            {
                steps.Add(new FakeSmtpServer.Step(FakeSmtpServer.Op.Recv, $"VRFY u{i + 1}"));
                steps.Add(new FakeSmtpServer.Step(FakeSmtpServer.Op.Send, "550 unknown\r\n"));
            }
            // After all VRFYs fail, tool falls back to EXPN — answer 502 to
            // abandon, then RCPT — answer 502 again so it gives up quickly.
            for (int j = 0; j < 2; j++)
            {
                for (int i = 0; i < 5; i++)
                {
                    steps.Add(new FakeSmtpServer.Step(FakeSmtpServer.Op.RecvAny));
                    steps.Add(new FakeSmtpServer.Step(FakeSmtpServer.Op.Send, "502 unsupported\r\n"));
                }
            }
            steps.Add(new FakeSmtpServer.Step(FakeSmtpServer.Op.Close));

            await using var server = new FakeSmtpServer(steps);
            var scope = ScopeLoader.Parse("127.0.0.1");
            using var audit = NewAudit();
            var tool = new SmtpEnumTool(scope, audit, TcpFactory(), NoopStartTls());

            var sw = Stopwatch.StartNew();
            await tool.EnumerateAsync("127.0.0.1", server.Port, wordlistPath: wlPath,
                probesPerSecond: 10);
            sw.Stop();

            Assert.True(sw.ElapsedMilliseconds >= 250,
                $"expected ≥250ms with rps=10 over 5 probes; got {sw.ElapsedMilliseconds}ms");
        }
        finally
        {
            try { File.Delete(wlPath); } catch { }
        }
    }

    [Fact]
    public async Task EmptyBanner_FallsBackGracefully()
    {
        // Server accepts connection and immediately closes.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                // Close without sending anything.
            }
            catch { }
        });

        try
        {
            var scope = ScopeLoader.Parse("127.0.0.1");
            using var audit = NewAudit();
            var tool = new SmtpEnumTool(scope, audit, TcpFactory(), NoopStartTls());

            var r = await tool.EnumerateAsync("127.0.0.1", port, probesPerSecond: 1000);

            Assert.Null(r.Banner);
            Assert.Empty(r.EhloCapabilities);
            Assert.Empty(r.DiscoveredUsers);
            // Tool must not crash, may or may not set an error string.
        }
        finally
        {
            listener.Stop();
            try { await serverTask; } catch { }
        }
    }
}
