using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Drederick.Host;
using Drederick.Web.Hubs;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Drederick.Web.Tests;

/// <summary>
/// End-to-end SignalR tests for <see cref="EventsHub"/> + <see cref="ScanEventBridge"/>.
/// Covers loopback connect, non-loopback bearer (via access_token query),
/// fan-out ordering, multi-client delivery, sensitive-field redaction, and
/// plaintext-token audit safety.
///
/// All tests use <see cref="DrederickWebFactory"/>'s in-memory test server;
/// the SignalR client is wired to the factory's test handler so no real
/// network socket is opened.
/// </summary>
public sealed class EventsHubTests
{
    private const string CanaryToken = "CANARY-SECRET-hub-abc123-XYZ789-drederick";
    private static readonly TimeSpan ReceiveTimeout = TimeSpan.FromSeconds(5);

    private static WebAppSettings NonLoopback(string? token) => new()
    {
        BindHost = "0.0.0.0",
        BindPort = 0,
        RequireBearer = true,
        Token = token,
        OutputDir = "out",
    };

    private static HubConnection BuildConnection(
        DrederickWebFactory factory,
        string? accessToken = null)
    {
        var hubUrl = new Uri(factory.Server.BaseAddress, "/hubs/events");
        return new HubConnectionBuilder()
            .WithUrl(hubUrl, HttpTransportType.LongPolling, opts =>
            {
                // Route the SignalR transport through the WebApplicationFactory's
                // in-memory test handler so the hub is exercised without a
                // real network socket.
                opts.HttpMessageHandlerFactory = _ => factory.Server.CreateHandler();
                opts.AccessTokenProvider = accessToken is null
                    ? null
                    : () => Task.FromResult<string?>(accessToken);
                // WebSockets don't go through the test server; restrict to
                // long-polling for test determinism.
                opts.Transports = HttpTransportType.LongPolling;
            })
            .Build();
    }

    private static ScanEvent MakeEvent(int ordinal = 0) => new(
        Kind: ScanEventKind.Info,
        Timestamp: DateTimeOffset.UtcNow,
        Target: "10.0.0.1",
        Tool: "test",
        Message: $"event-{ordinal}",
        ToolCallsTotal: ordinal);

    [Fact]
    public async Task Hub_Connect_OnLoopback_NoAuth()
    {
        using var factory = new DrederickWebFactory();
        var bridge = factory.Services.GetRequiredService<ScanEventBridge>();

        await using var conn = BuildConnection(factory);
        var received = new TaskCompletionSource<ScanEventPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.On<ScanEventPayload>(ScanEventBridge.ClientMethod, p => received.TrySetResult(p));

        await conn.StartAsync();
        await conn.InvokeAsync(nameof(EventsHub.JoinScope), ScanEventBridge.DefaultGroup);

        await bridge.PublishAsync(MakeEvent(1));

        var payload = await received.Task.WaitAsync(ReceiveTimeout);
        Assert.Equal("Info", payload.Kind);
        Assert.Equal("event-1", payload.Message);
    }

    [Fact]
    public async Task Hub_NonLoopback_RequiresBearer()
    {
        using var factory = new DrederickWebFactory(NonLoopback(CanaryToken));

        // No access_token → negotiate rejected with 401.
        await using (var anon = BuildConnection(factory))
        {
            var ex = await Assert.ThrowsAnyAsync<Exception>(() => anon.StartAsync());
            Assert.Contains("401", ex.ToString(), StringComparison.Ordinal);
        }

        // Correct access_token → accepted.
        var bridge = factory.Services.GetRequiredService<ScanEventBridge>();
        await using var auth = BuildConnection(factory, accessToken: CanaryToken);
        var received = new TaskCompletionSource<ScanEventPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        auth.On<ScanEventPayload>(ScanEventBridge.ClientMethod, p => received.TrySetResult(p));
        await auth.StartAsync();
        await auth.InvokeAsync(nameof(EventsHub.JoinScope), ScanEventBridge.DefaultGroup);
        await bridge.PublishAsync(MakeEvent(42));
        var payload = await received.Task.WaitAsync(ReceiveTimeout);
        Assert.Equal("event-42", payload.Message);
    }

    [Fact]
    public async Task Hub_ScanEventFanOut()
    {
        using var factory = new DrederickWebFactory();
        var bridge = factory.Services.GetRequiredService<ScanEventBridge>();

        await using var conn = BuildConnection(factory);
        var received = new List<ScanEventPayload>();
        var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.On<ScanEventPayload>(ScanEventBridge.ClientMethod, p =>
        {
            lock (received)
            {
                received.Add(p);
                if (received.Count == 10) done.TrySetResult(true);
            }
        });

        await conn.StartAsync();
        await conn.InvokeAsync(nameof(EventsHub.JoinScope), ScanEventBridge.DefaultGroup);

        for (int i = 0; i < 10; i++)
        {
            await bridge.PublishAsync(MakeEvent(i));
        }

        await done.Task.WaitAsync(ReceiveTimeout);
        Assert.Equal(10, received.Count);
        for (int i = 0; i < 10; i++)
        {
            Assert.Equal($"event-{i}", received[i].Message);
        }
    }

    [Fact]
    public async Task Hub_MultipleClients_AllReceive()
    {
        using var factory = new DrederickWebFactory();
        var bridge = factory.Services.GetRequiredService<ScanEventBridge>();

        await using var a = BuildConnection(factory);
        await using var b = BuildConnection(factory);
        var gotA = new TaskCompletionSource<ScanEventPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gotB = new TaskCompletionSource<ScanEventPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        a.On<ScanEventPayload>(ScanEventBridge.ClientMethod, p => gotA.TrySetResult(p));
        b.On<ScanEventPayload>(ScanEventBridge.ClientMethod, p => gotB.TrySetResult(p));

        await a.StartAsync();
        await b.StartAsync();
        await a.InvokeAsync(nameof(EventsHub.JoinScope), ScanEventBridge.DefaultGroup);
        await b.InvokeAsync(nameof(EventsHub.JoinScope), ScanEventBridge.DefaultGroup);

        await bridge.PublishAsync(MakeEvent(99));

        var pa = await gotA.Task.WaitAsync(ReceiveTimeout);
        var pb = await gotB.Task.WaitAsync(ReceiveTimeout);
        Assert.Equal("event-99", pa.Message);
        Assert.Equal("event-99", pb.Message);
    }

    [Fact]
    public async Task Hub_RedactsSensitiveFields()
    {
        const string canary = "PLAINTEXT-PASSWORD-CANARY-donotleak";
        using var factory = new DrederickWebFactory();
        var bridge = factory.Services.GetRequiredService<ScanEventBridge>();

        await using var conn = BuildConnection(factory);
        var received = new TaskCompletionSource<ScanEventPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        conn.On<ScanEventPayload>(ScanEventBridge.ClientMethod, p => received.TrySetResult(p));

        await conn.StartAsync();
        await conn.InvokeAsync(nameof(EventsHub.JoinScope), ScanEventBridge.DefaultGroup);

        var details = new Dictionary<string, object?>
        {
            ["password"] = canary,
            ["api_key"] = "another-secret",
            ["target"] = "10.0.0.1", // safe — unchanged
        };
        await bridge.PublishAsync(MakeEvent(7), details);

        var payload = await received.Task.WaitAsync(ReceiveTimeout);
        Assert.NotNull(payload.Details);

        // The plaintext canary must never appear anywhere in the payload.
        var serialized = System.Text.Json.JsonSerializer.Serialize(payload);
        Assert.DoesNotContain(canary, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("another-secret", serialized, StringComparison.Ordinal);

        // The SHA-256 of the canary must appear (under the "password" key).
        var expected = "sha256:" + Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(canary)));
        Assert.Contains(expected, serialized, StringComparison.Ordinal);

        // The non-sensitive field survives unchanged.
        Assert.Contains("10.0.0.1", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Hub_AuditLog_Connect_NoPlaintextToken()
    {
        using var factory = new DrederickWebFactory(NonLoopback(CanaryToken));

        await using var conn = BuildConnection(factory, accessToken: CanaryToken);
        await conn.StartAsync();
        await conn.StopAsync();

        // Allow the audit-log writer to flush.
        await Task.Delay(100);

        var audit = File.ReadAllText(factory.AuditLogPath);
        Assert.DoesNotContain(CanaryToken, audit, StringComparison.Ordinal);
        Assert.Contains("web.hub.connect", audit, StringComparison.Ordinal);
    }
}
