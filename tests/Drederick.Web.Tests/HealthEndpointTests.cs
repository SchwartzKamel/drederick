using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace Drederick.Web.Tests;

public sealed class HealthEndpointTests
{
    [Fact]
    public async Task HealthEndpoint_ReturnsOk()
    {
        using var factory = new DrederickWebFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("ok", body.GetProperty("status").GetString());
        Assert.True(body.TryGetProperty("version", out _));
        Assert.True(body.TryGetProperty("started_at", out _));
    }

    [Fact]
    public async Task Loopback_NoAuthRequired()
    {
        // Default factory: RequireBearer=false → no Authorization header
        // should return 200.
        using var factory = new DrederickWebFactory(new WebAppSettings
        {
            BindHost = "127.0.0.1",
            BindPort = 0,
            RequireBearer = false,
            Token = null,
            OutputDir = "out",
        });
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task OpenAPI_SpecAvailable()
    {
        using var factory = new DrederickWebFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();
        // Spec must reference our /api/health path.
        Assert.Contains("/api/health", body, StringComparison.Ordinal);
        // And must look like an OpenAPI document (has openapi version key).
        Assert.Contains("\"openapi\"", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StaticFallback_IndexHtml()
    {
        // Fallback check: GET to any non-API route should be served by
        // MapFallbackToFile("index.html") when an index.html is present in
        // wwwroot. The SPA agent's build output populates wwwroot; the
        // scaffold itself ships an empty wwwroot with only .gitkeep. This
        // test works in both scenarios:
        //   - SPA populated:  returns 200 with text/html body
        //   - scaffold only:  returns 404 (fallback registered, file absent)
        // Either way, the route must NOT 500 or reach the API pipeline.
        using var factory = new DrederickWebFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/some/spa/route");
        Assert.True(
            response.StatusCode == HttpStatusCode.OK
            || response.StatusCode == HttpStatusCode.NotFound,
            $"Expected 200 or 404 from SPA fallback, got {(int)response.StatusCode}.");

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync();
            // When a real index.html is served, it must look like HTML.
            Assert.Contains("<html", body, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith(
                "text/html",
                response.Content.Headers.ContentType?.MediaType ?? "",
                StringComparison.OrdinalIgnoreCase);
        }
    }
}
