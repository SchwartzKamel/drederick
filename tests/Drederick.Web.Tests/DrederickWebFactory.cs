using Drederick.Audit;
using Drederick.Web;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Drederick.Web.Tests;

/// <summary>
/// Test harness around <see cref="WebApplicationFactory{TEntryPoint}"/> that
/// lets each test case configure the <see cref="WebAppSettings"/> instance
/// (loopback / non-loopback, token / no token) and capture the backing
/// <see cref="AuditLog"/> for canary-pattern assertions. Each factory owns
/// its own temp output directory so audit.jsonl contents are test-local.
/// </summary>
internal class DrederickWebFactory : WebApplicationFactory<Program>
{
    public string OutputDir { get; }
    public WebAppSettings Settings { get; set; }

    public DrederickWebFactory(WebAppSettings? seed = null)
    {
        OutputDir = Path.Combine(
            Path.GetTempPath(),
            "drederick-web-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(OutputDir);
        Settings = seed ?? new WebAppSettings
        {
            BindHost = "127.0.0.1",
            BindPort = 0,
            RequireBearer = false,
            Token = null,
            OutputDir = OutputDir,
        };
        // Force OutputDir on the injected settings so tests that supply only
        // RequireBearer/Token still get a test-local audit path.
        Settings = new WebAppSettings
        {
            BindHost = Settings.BindHost,
            BindPort = Settings.BindPort,
            RequireBearer = Settings.RequireBearer,
            Token = Settings.Token,
            OutputDir = OutputDir,
        };
    }

    public string AuditLogPath => Path.Combine(OutputDir, "audit.jsonl");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Replace the CLI-path registrations with the test-owned ones.
            var existingSettings = services
                .Where(d => d.ServiceType == typeof(WebAppSettings)).ToList();
            foreach (var d in existingSettings) services.Remove(d);
            services.AddSingleton(Settings);

            // AuditLog: replace with one writing into the per-test output dir.
            var existingAudit = services
                .Where(d => d.ServiceType == typeof(AuditLog)).ToList();
            foreach (var d in existingAudit) services.Remove(d);
            var audit = new AuditLog(AuditLogPath);
            services.AddSingleton(audit);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;
        try
        {
            if (Directory.Exists(OutputDir))
                Directory.Delete(OutputDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup — temp dir will be reclaimed by the OS.
        }
    }
}
