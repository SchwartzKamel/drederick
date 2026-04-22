using Drederick.Audit;
using Drederick.Host;
using Drederick.Web;
using Drederick.Web.Cli;
using Drederick.Web.Endpoints;
using Drederick.Web.Hubs;
using Drederick.Web.Jeopardy;
using Drederick.Web.Runs;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

// Parse CLI args (minimal parser — the full drederick CLI lives in the main
// project). Tests invoke Program via WebApplicationFactory<Program> with no
// args and override the DI registrations through ConfigureTestServices.
var webArgs = WebRunnerArgs.Parse(args);
var settings = WebRunnerArgs.ResolveSettings(webArgs);

Directory.CreateDirectory(settings.OutputDir);
var audit = new AuditLog(Path.Combine(settings.OutputDir, "audit.jsonl"));

var builder = WebApplication.CreateBuilder(args);

// --- signalr-hub-wiring ---
// SignalR hub + bridge for real-time ScanEvent fan-out to browser clients.
// The bridge is registered as both a concrete singleton (so callers with a
// DrederickHost reference can inject it as an IProgress<ScanEvent> sink) and
// as a hosted service (so its lifetime matches the application).
builder.Services.AddSignalR();
builder.Services.AddSingleton<ScanEventBridge>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ScanEventBridge>());

// --- runs-service-wiring ---
// REST endpoints under /api/runs/ start/stop recon runs via DrederickHost,
// tracking active + recently-completed runs in an in-process RunManager.
// IRunExecutor is the seam tests override with a stub; ScopePathPolicy
// enforces path-traversal guards on the submitted scope_path; and
// ServerCategoryGrants fixes the set of high-blast-radius categories at
// process start (mirrors CLI --allow-exec-pocs / --allow-cred-attacks / ...).
builder.Services.AddSingleton<DrederickHost>();
builder.Services.AddSingleton<IRunExecutor, DrederickHostRunExecutor>();
builder.Services.AddSingleton<RunManager>();
builder.Services.AddSingleton(ScopePathPolicy.Default());
builder.Services.AddSingleton(ServerCategoryGrants.FromEnvironment());

// --- findings-service-wiring ---
// Read-only REST access to findings.db for the operator UI. The query
// facade opens a fresh read-only SqliteConnection per call so it's safe
// to share across concurrent requests. WebAppSettings comes from DI so
// test overrides (DrederickWebFactory) flow through the same path as the
// CLI.
builder.Services.AddSingleton<Drederick.Web.Data.FindingsQueries>(sp =>
    new Drederick.Web.Data.FindingsQueries(
        sp.GetRequiredService<Drederick.Web.WebAppSettings>()));

// --- jeopardy-service-wiring ---
// REST endpoints under /api/jeopardy/ drive the Jeopardy CTF solver swarm
// via CtfCoordinator. The coordinator factory is the seam tests override
// with a stub so WebApplicationFactory<Program> never spins up real HTTP /
// Docker / LLM clients. The manager is a singleton: sessions live for the
// lifetime of the process, capped at a modest retention count.
builder.Services.AddSingleton<IJeopardyCoordinatorFactory, DefaultJeopardyCoordinatorFactory>();
builder.Services.AddSingleton<JeopardySessionManager>();

var app = WebRunner.ConfigureAndBuild(builder, settings, audit);

// --- runs-endpoint-map ---
app.MapRunsEndpoints();

// --- jeopardy-endpoint-map ---
// Registered before MapFallbackToFile (which is registered inside
// ConfigureAndBuild with lowest priority), so /api/jeopardy/* matches
// before the SPA fallback.
app.MapJeopardyEndpoints();

// --- findings-endpoint-map ---
// Mapped after ConfigureAndBuild so the /api/findings group precedes the
// SPA fallback route (MapFallbackToFile registers with lowest priority),
// while still sitting alongside other /api/* routes.
app.MapFindingsEndpoints();

// --- signalr-hub-map ---
// Registered after WebRunner.ConfigureAndBuild has wired the fallback SPA
// route. Endpoint routing resolves explicit endpoint patterns (hub) before
// MapFallbackToFile (which registers with lowest priority), so the hub
// still matches first.
app.MapHub<EventsHub>("/hubs/events");

if (!string.IsNullOrEmpty(settings.BindHost) && settings.BindPort > 0
    && app.Urls.Count == 0)
{
    app.Urls.Add($"http://{settings.BindHost}:{settings.BindPort}");
}

app.Run();

// Expose Program to the WebApplicationFactory<T> in Drederick.Web.Tests.
public partial class Program { }
