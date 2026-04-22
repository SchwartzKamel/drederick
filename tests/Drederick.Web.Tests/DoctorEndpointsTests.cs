using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Drederick.Doctor;
using Drederick.Web;
using Drederick.Web.Endpoints;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Drederick.Web.Tests;

public sealed class DoctorEndpointsTests
{
    // Canned checks so tests don't require docker/impacket/etc. on CI.
    private sealed class FakeCheck : IDoctorCheck
    {
        public string Id { get; }
        public string Category { get; }
        private readonly DoctorCheckResult _result;
        public FakeCheck(string id, string category, DoctorCheckResult result)
        {
            Id = id; Category = category; _result = result;
        }
        public Task<DoctorCheckResult> RunAsync(
            bool install, bool assumeYes, TextReader stdin,
            TextWriter stdout, CancellationToken ct)
            => Task.FromResult(_result);
    }

    private static DoctorEndpoints.IWebDoctorCheckRegistry BuildRegistry()
    {
        var checks = new IDoctorCheck[]
        {
            new FakeCheck("jeopardy.docker.installed", "jeopardy",
                new DoctorCheckResult("jeopardy.docker.installed",
                    DoctorCheckStatus.Pass, "docker present")),
            new FakeCheck("jeopardy.disk.free", "jeopardy",
                new DoctorCheckResult("jeopardy.disk.free",
                    DoctorCheckStatus.Warn, "low on disk")),
            new FakeCheck("jeopardy.ctfd.configured", "jeopardy",
                new DoctorCheckResult("jeopardy.ctfd.configured",
                    DoctorCheckStatus.Fail, "CTFD_URL not set",
                    FixCommand: "export CTFD_URL=https://…")),
            new FakeCheck("jeopardy.nmap.installed", "jeopardy",
                new DoctorCheckResult("jeopardy.nmap.installed",
                    DoctorCheckStatus.Fail, "nmap not found on PATH")),
        };
        return new DoctorEndpoints.StaticRegistry(checks);
    }

    private static DrederickWebFactory FactoryWithRegistry()
    {
        var f = new DrederickWebFactory();
        f.ClientOptions.HandleCookies = false;
        var registry = BuildRegistry();
        f.WithWebHostBuilder(b => { }); // no-op; override via test factory subclass pattern
        return new CustomFactory(registry);
    }

    private sealed class CustomFactory : DrederickWebFactory
    {
        private readonly DoctorEndpoints.IWebDoctorCheckRegistry _registry;
        public CustomFactory(DoctorEndpoints.IWebDoctorCheckRegistry r) { _registry = r; }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services =>
            {
                var existing = services
                    .Where(d => d.ServiceType == typeof(DoctorEndpoints.IWebDoctorCheckRegistry))
                    .ToList();
                foreach (var d in existing) services.Remove(d);
                services.AddSingleton(_registry);
            });
        }
    }

    [Fact]
    public async Task Checks_ReturnsAllChecks_WithStatuses()
    {
        using var factory = FactoryWithRegistry();
        using var client = factory.CreateClient();

        var resp = await client.GetAsync("/api/doctor/checks");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();

        var checks = body.GetProperty("checks").EnumerateArray().ToList();
        Assert.Equal(4, checks.Count);

        var summary = body.GetProperty("summary");
        Assert.Equal(1, summary.GetProperty("ok").GetInt32());
        Assert.Equal(1, summary.GetProperty("warn").GetInt32());
        Assert.Equal(1, summary.GetProperty("fail").GetInt32());
        Assert.Equal(1, summary.GetProperty("missing").GetInt32());

        var statuses = checks.Select(c => c.GetProperty("status").GetString()).ToHashSet();
        Assert.Contains("ok", statuses);
        Assert.Contains("warn", statuses);
        Assert.Contains("fail", statuses);
        Assert.Contains("missing", statuses);
    }

    [Fact]
    public async Task Checks_Single_ById()
    {
        using var factory = FactoryWithRegistry();
        using var client = factory.CreateClient();

        var resp = await client.GetAsync("/api/doctor/checks/jeopardy.docker.installed");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("jeopardy.docker.installed", body.GetProperty("id").GetString());
        Assert.Equal("ok", body.GetProperty("status").GetString());

        var miss = await client.GetAsync("/api/doctor/checks/does.not.exist");
        Assert.Equal(HttpStatusCode.NotFound, miss.StatusCode);
    }

    [Fact]
    public void Doctor_NeverInstalls_FromWeb()
    {
        // Static assertion: the endpoint type exposes no install surface.
        // Anything HTTP-verby other than GET should not exist for /api/doctor/.
        var methods = typeof(DoctorEndpoints)
            .GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
        foreach (var m in methods)
        {
            var name = m.Name.ToLowerInvariant();
            Assert.DoesNotContain("install", name);
            Assert.DoesNotContain("apt", name);
            Assert.DoesNotContain("pipx", name);
            Assert.DoesNotContain("sudo", name);
        }

        // And: a check that throws must not crash the pipeline.
        var throwingRegistry = new DoctorEndpoints.StaticRegistry(
            new IDoctorCheck[] { new ThrowingCheck() });
        using var factory = new CustomFactory(throwingRegistry);
        using var client = factory.CreateClient();

        var resp = client.GetAsync("/api/doctor/checks").GetAwaiter().GetResult();
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    private sealed class ThrowingCheck : IDoctorCheck
    {
        public string Id => "boom";
        public string Category => "test";
        public Task<DoctorCheckResult> RunAsync(
            bool install, bool assumeYes, TextReader stdin,
            TextWriter stdout, CancellationToken ct)
            => throw new InvalidOperationException("kaboom");
    }

    [Fact]
    public async Task Loopback_NoAuth_Required()
    {
        using var factory = FactoryWithRegistry();
        // Default factory has RequireBearer=false (loopback).
        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/api/doctor/checks");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}
