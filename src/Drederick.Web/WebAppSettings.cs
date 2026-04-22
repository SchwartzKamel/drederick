namespace Drederick.Web;

/// <summary>
/// Immutable per-process configuration for the Drederick REST/SignalR host.
/// Populated by <see cref="Cli.WebRunner"/> (CLI path) or by the test-host
/// factory (test path) before the app is built, then consumed by
/// <see cref="Auth.BearerTokenAuth"/> and the health/openapi endpoints.
///
/// <para>
/// <c>RequireBearer</c> is the enforcement bit. <see cref="Cli.WebRunner"/>
/// sets it to <c>true</c> whenever the resolved bind host is not a loopback
/// address, and to <c>false</c> for loopback binds (sandbox-dev UX). Tests
/// flip it independently of <see cref="BindHost"/> so they can cover the
/// non-loopback code path without actually binding a public interface.
/// </para>
/// </summary>
public sealed class WebAppSettings
{
    public string BindHost { get; init; } = "127.0.0.1";
    public int BindPort { get; init; } = 7070;

    /// <summary>
    /// When true, every HTTP request must carry a matching
    /// <c>Authorization: Bearer &lt;token&gt;</c> header. When false, requests
    /// are accepted without an Authorization header (loopback sandbox UX).
    /// Regardless of this flag, if an Authorization header IS supplied it
    /// must validate — operators cannot downgrade their own auth by
    /// accident.
    /// </summary>
    public bool RequireBearer { get; init; }

    /// <summary>
    /// Bearer token bytes (UTF-8). Null only when <see cref="RequireBearer"/>
    /// is false and no token was supplied. Never logged in plaintext; only
    /// SHA-256 goes to the audit log.
    /// </summary>
    public string? Token { get; init; }

    /// <summary>
    /// Output directory for the audit log and any per-run artefacts this
    /// process emits. Defaults to <c>out/</c>.
    /// </summary>
    public string OutputDir { get; init; } = "out";
}
