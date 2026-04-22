using Drederick.Audit;
using Microsoft.AspNetCore.SignalR;

namespace Drederick.Web.Hubs;

/// <summary>
/// Read-only SignalR hub that fans <see cref="Drederick.Host.ScanEvent"/>s to
/// connected browser clients. Clients can opt into named event streams via
/// <see cref="JoinScope(string)"/> — the server adds the connection to a
/// SignalR group of that name. There are no state-mutating, client-invokable
/// methods: the hub is strictly a broadcast surface.
///
/// <para>
/// Invariants:
/// <list type="bullet">
///   <item><description><c>@invariant-id:audit-everything</c> — connects and
///     disconnects are recorded to <see cref="AuditLog"/> as
///     <c>web.hub.connect</c> / <c>web.hub.disconnect</c> with the
///     connection id and remote endpoint. The bearer token never reaches
///     the audit record.</description></item>
///   <item><description>Auth is enforced upstream by
///     <see cref="Auth.BearerTokenAuth"/>; WebSocket upgrades carry the
///     token via the <c>access_token</c> query param (SignalR convention)
///     because browsers cannot set arbitrary headers on a WebSocket
///     handshake.</description></item>
/// </list>
/// </para>
/// </summary>
public sealed class EventsHub : Hub
{
    private readonly AuditLog? _audit;

    public EventsHub(AuditLog? audit = null)
    {
        _audit = audit;
    }

    /// <summary>
    /// Opts the current connection into the named event stream. Group names
    /// are normalised (trim + lower-case) and bounded in length to prevent
    /// groups being used as an unbounded server-side key namespace.
    /// </summary>
    public Task JoinScope(string scopeName)
    {
        var group = NormalizeGroup(scopeName);
        if (group is null) return Task.CompletedTask;
        return Groups.AddToGroupAsync(Context.ConnectionId, group);
    }

    public override Task OnConnectedAsync()
    {
        var http = Context.GetHttpContext();
        _audit?.Record("web.hub.connect", new Dictionary<string, object?>
        {
            ["conn"] = Context.ConnectionId,
            ["remote"] = http?.Connection.RemoteIpAddress?.ToString(),
            ["path"] = http?.Request.Path.Value,
        });
        return base.OnConnectedAsync();
    }

    public override Task OnDisconnectedAsync(Exception? exception)
    {
        _audit?.Record("web.hub.disconnect", new Dictionary<string, object?>
        {
            ["conn"] = Context.ConnectionId,
            ["error"] = exception?.Message,
        });
        return base.OnDisconnectedAsync(exception);
    }

    internal static string? NormalizeGroup(string? scopeName)
    {
        if (string.IsNullOrWhiteSpace(scopeName)) return null;
        var trimmed = scopeName.Trim().ToLowerInvariant();
        if (trimmed.Length > 64) trimmed = trimmed[..64];
        return trimmed;
    }
}
