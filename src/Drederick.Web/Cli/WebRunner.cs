using Drederick.Audit;
using Drederick.Web.Auth;
using Drederick.Web.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Drederick.Web.Cli;

/// <summary>
/// Entry point for the Drederick REST/SignalR host. The main drederick CLI
/// dispatches <c>drederick web</c> either in-process (future) or via
/// subprocess (today — same pattern as <c>drederick serve</c> launching
/// datasette), but in both paths the app is built here so behaviour is
/// identical.
///
/// <para>
/// Invariant posture:
/// <list type="bullet">
///   <item><description><c>@invariant-id:scope-is-authorization</c> — the
///     web server itself does not touch any targets; it is a UI layer.
///     Every downstream API call will go through the scope-enforced
///     toolbox / <see cref="Drederick.Host.DrederickHost"/> surface.
///     Phase-2 endpoint authors must preserve this.</description></item>
///   <item><description><c>@invariant-id:audit-everything</c> —
///     <see cref="BearerTokenAuth"/> records every request to
///     <c>audit.jsonl</c> with target, path, and auth status.
///     </description></item>
///   <item><description><c>@invariant-id:no-plaintext-secrets</c> — the
///     bearer token never reaches the audit log in plaintext; only a
///     SHA-256 digest on <c>web.server.start</c>.</description></item>
/// </list>
/// </para>
/// </summary>
public static class WebRunner
{
    /// <summary>
    /// Configure services and the HTTP pipeline on a pre-constructed
    /// <see cref="WebApplicationBuilder"/>. Extracted so <c>Program.cs</c>
    /// (standalone path) and any future in-process dispatcher share the
    /// exact same wiring. The returned <see cref="WebApplication"/> is
    /// built but not yet running — the caller picks between
    /// <see cref="WebApplication.Run()"/> (CLI) and
    /// <c>WebApplicationFactory&lt;Program&gt;</c> (tests).
    /// </summary>
    public static WebApplication ConfigureAndBuild(
        WebApplicationBuilder builder,
        WebAppSettings settings,
        AuditLog audit)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(audit);

        Directory.CreateDirectory(settings.OutputDir);

        builder.Services.AddSingleton(settings);
        builder.Services.AddSingleton(audit);
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddOpenApi();

        var app = builder.Build();

        var runtimeSettings = app.Services.GetRequiredService<WebAppSettings>();
        var runtimeAudit = app.Services.GetRequiredService<AuditLog>();

        runtimeAudit.Record("web.server.start", new Dictionary<string, object?>
        {
            ["bind_host"] = runtimeSettings.BindHost,
            ["bind_port"] = runtimeSettings.BindPort,
            ["require_bearer"] = runtimeSettings.RequireBearer,
            ["token_sha256"] = runtimeSettings.Token is null
                ? null
                : BearerTokenAuth.TokenDigest(runtimeSettings.Token),
        });

        app.UseMiddleware<BearerTokenAuth>();
        app.MapHealthEndpoints();
        app.MapOpenApi();
        app.UseDefaultFiles();
        app.UseStaticFiles();

        // MapFallbackToFile is registered unconditionally — if index.html
        // doesn't exist at request time, the file-serving middleware emits
        // 404, which is the correct behaviour for a scaffold with an empty
        // wwwroot. Registering it unconditionally also keeps the endpoint
        // surface stable for phase-2 SPA work.
        app.MapFallbackToFile("index.html");

        var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
        lifetime.ApplicationStopping.Register(() =>
        {
            try { runtimeAudit.Record("web.server.stop"); }
            catch { /* never throw from shutdown */ }
        });

        return app;
    }
}
