using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Microsoft.AspNetCore.Http;

namespace Drederick.Web.Auth;

/// <summary>
/// Minimal bearer-token middleware. Constant-time token comparison via
/// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
/// Loopback-only binds bypass the check (<see cref="WebAppSettings.RequireBearer"/>
/// is false); non-loopback binds require a valid bearer on every request.
///
/// <para>
/// Invariants:
/// <list type="bullet">
///   <item><description><c>@invariant-id:audit-everything</c> — every
///     request is recorded to <see cref="AuditLog"/> as
///     <c>web.request</c> with method, path, remote endpoint, and auth
///     status.</description></item>
///   <item><description><c>@invariant-id:no-plaintext-secrets</c> —
///     the plaintext token never reaches the audit log; only a SHA-256
///     digest of the token material does, and only on server start.
///     </description></item>
/// </list>
/// </para>
/// </summary>
public sealed class BearerTokenAuth
{
    private readonly RequestDelegate _next;
    private readonly WebAppSettings _settings;
    private readonly AuditLog? _audit;
    private readonly byte[]? _expectedTokenBytes;

    public BearerTokenAuth(RequestDelegate next, WebAppSettings settings, AuditLog? audit = null)
    {
        _next = next;
        _settings = settings;
        _audit = audit;
        _expectedTokenBytes = settings.Token is null
            ? null
            : Encoding.UTF8.GetBytes(settings.Token);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var authStatus = EvaluateAuth(context, out var rejectionReason);
        _audit?.Record("web.request", new Dictionary<string, object?>
        {
            ["method"] = context.Request.Method,
            ["path"] = context.Request.Path.Value,
            ["remote"] = context.Connection.RemoteIpAddress?.ToString(),
            ["auth"] = authStatus,
        });

        if (authStatus == "denied")
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = "Bearer";
            await context.Response.WriteAsync(
                $"401 Unauthorized: {rejectionReason}").ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    private string EvaluateAuth(HttpContext context, out string? reason)
    {
        reason = null;
        var header = context.Request.Headers.Authorization.ToString();
        var hasHeader = !string.IsNullOrEmpty(header);

        if (!_settings.RequireBearer && !hasHeader)
        {
            return "loopback_bypass";
        }

        if (_settings.RequireBearer && !hasHeader)
        {
            reason = "missing Authorization: Bearer <token>";
            return "denied";
        }

        // Either RequireBearer is true, or an Authorization header was supplied
        // on a loopback bind. Validate in both cases so operators cannot
        // partially authenticate.
        const string prefix = "Bearer ";
        if (!header.StartsWith(prefix, StringComparison.Ordinal))
        {
            reason = "Authorization header is not of scheme Bearer";
            return "denied";
        }

        if (_expectedTokenBytes is null)
        {
            reason = "server has no token configured";
            return "denied";
        }

        var supplied = header[prefix.Length..].Trim();
        var suppliedBytes = Encoding.UTF8.GetBytes(supplied);
        if (!CryptographicOperations.FixedTimeEquals(suppliedBytes, _expectedTokenBytes))
        {
            reason = "bearer token mismatch";
            return "denied";
        }

        return "ok";
    }

    /// <summary>
    /// SHA-256 of the given token bytes, lowercase hex. Used for audit-safe
    /// token correlation on <c>web.server.start</c>.
    /// </summary>
    public static string TokenDigest(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexStringLower(hash);
    }
}
