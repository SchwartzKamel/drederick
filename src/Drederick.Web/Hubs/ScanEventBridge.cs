using System.Security.Cryptography;
using System.Text;
using Drederick.Host;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Hosting;

namespace Drederick.Web.Hubs;

/// <summary>
/// Hosted service that forwards <see cref="ScanEvent"/>s to SignalR clients
/// connected to <see cref="EventsHub"/>. There is no event stream on
/// <see cref="DrederickHost"/> itself — it surfaces progress via
/// <see cref="IProgress{T}"/> — so this class implements
/// <see cref="IProgress{ScanEvent}"/> and can be passed into
/// <see cref="DrederickHost.RunAsync(Drederick.Scope.Scope, RunOptions, IProgress{ScanEvent}?, CancellationToken)"/>
/// as the progress sink. Callers may also call <see cref="PublishAsync"/>
/// directly to broadcast a richer payload (with a details dictionary that
/// is redacted before send).
///
/// <para>
/// Invariants:
/// <list type="bullet">
///   <item><description><c>@invariant-id:no-plaintext-secrets</c> —
///     before broadcast, <see cref="Redact"/> replaces any value whose
///     key name contains a sensitive substring (password, secret, token,
///     key, credential, flag) with a SHA-256 digest. The plaintext never
///     leaves the server.</description></item>
///   <item><description>The bridge is a broadcast-only fan-out: it reads
///     from an in-process progress sink and writes to
///     <see cref="IHubContext{THub}"/>. It never touches a target, never
///     spawns a subprocess, and holds no scope state.</description></item>
/// </list>
/// </para>
/// </summary>
public sealed class ScanEventBridge : IHostedService, IProgress<ScanEvent>
{
    // Phase 1: all events land in the "recon" group. Phase-2 routers will
    // select a group based on ScanEvent.Kind / Tool.
    internal const string DefaultGroup = "recon";

    // SignalR client method name — browser clients subscribe to this.
    internal const string ClientMethod = "scanEvent";

    private static readonly string[] SensitiveSubstrings = new[]
    {
        "password", "secret", "token", "credential", "flag", "apikey",
    };

    private readonly IHubContext<EventsHub> _hub;

    public ScanEventBridge(IHubContext<EventsHub> hub)
    {
        _hub = hub;
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// IProgress sink. Fire-and-forget: the SignalR send is scheduled on the
    /// thread pool so the producer isn't blocked if a slow client backs up
    /// the hub.
    /// </summary>
    public void Report(ScanEvent value)
    {
        _ = PublishAsync(value);
    }

    /// <summary>
    /// Broadcast a <see cref="ScanEvent"/> (plus optional details) to all
    /// clients in the default group. Details are redacted in place before
    /// send.
    /// </summary>
    public Task PublishAsync(ScanEvent scanEvent, IDictionary<string, object?>? details = null, CancellationToken ct = default)
    {
        var payload = new ScanEventPayload(
            Kind: scanEvent.Kind.ToString(),
            Timestamp: scanEvent.Timestamp,
            Target: scanEvent.Target,
            Tool: scanEvent.Tool,
            Message: scanEvent.Message,
            ToolCallsTotal: scanEvent.ToolCallsTotal,
            Details: Redact(details));

        return _hub.Clients.Group(DefaultGroup)
            .SendAsync(ClientMethod, payload, ct);
    }

    internal static Dictionary<string, object?>? Redact(IDictionary<string, object?>? details)
    {
        if (details is null || details.Count == 0) return null;
        var result = new Dictionary<string, object?>(details.Count, StringComparer.Ordinal);
        foreach (var kv in details)
        {
            if (IsSensitiveKey(kv.Key) && kv.Value is not null)
            {
                result[kv.Key] = "sha256:" + Sha256Hex(kv.Value.ToString() ?? string.Empty);
            }
            else
            {
                result[kv.Key] = kv.Value;
            }
        }
        return result;
    }

    internal static bool IsSensitiveKey(string key)
    {
        if (string.IsNullOrEmpty(key)) return false;
        var lowered = key.ToLowerInvariant();
        foreach (var needle in SensitiveSubstrings)
        {
            if (lowered.Contains(needle, StringComparison.Ordinal)) return true;
        }
        // "key" as a standalone word or a conventional suffix ("api_key",
        // "host_key"). Guarded so benign identifiers like "keyword" or
        // "monkey" don't false-positive.
        if (lowered == "key" || lowered.EndsWith("_key", StringComparison.Ordinal))
        {
            return true;
        }
        return false;
    }

    private static string Sha256Hex(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexStringLower(hash);
    }
}

/// <summary>
/// Wire shape sent to SignalR clients. Kept distinct from
/// <see cref="ScanEvent"/> so (a) the enum is serialised as a string, and
/// (b) the redacted <see cref="Details"/> dictionary can travel with the
/// event.
/// </summary>
public sealed record ScanEventPayload(
    string Kind,
    DateTimeOffset Timestamp,
    string? Target,
    string? Tool,
    string? Message,
    int? ToolCallsTotal,
    Dictionary<string, object?>? Details);
