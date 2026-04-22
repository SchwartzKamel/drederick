using Drederick.Audit;
using Drederick.Web;
using Drederick.Web.Cli;
using Microsoft.AspNetCore.Builder;

// Parse CLI args (minimal parser — the full drederick CLI lives in the main
// project). Tests invoke Program via WebApplicationFactory<Program> with no
// args and override the DI registrations through ConfigureTestServices.
var webArgs = WebRunnerArgs.Parse(args);
var settings = WebRunnerArgs.ResolveSettings(webArgs);

Directory.CreateDirectory(settings.OutputDir);
var audit = new AuditLog(Path.Combine(settings.OutputDir, "audit.jsonl"));

var builder = WebApplication.CreateBuilder(args);
var app = WebRunner.ConfigureAndBuild(builder, settings, audit);

if (!string.IsNullOrEmpty(settings.BindHost) && settings.BindPort > 0
    && app.Urls.Count == 0)
{
    app.Urls.Add($"http://{settings.BindHost}:{settings.BindPort}");
}

app.Run();

// Expose Program to the WebApplicationFactory<T> in Drederick.Web.Tests.
public partial class Program { }
