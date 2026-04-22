using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace Drederick.Web.Tests;

public sealed class ScopeEndpointsTests
{
    private static string WriteScopeFile(string content, string? prefix = null)
    {
        var cwd = Directory.GetCurrentDirectory();
        // Keep scope files inside cwd so the in-cwd path policy accepts them.
        var dir = Path.Combine(cwd, ".test-scopes-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, (prefix ?? "scope") + ".txt");
        File.WriteAllText(path, content);
        return path;
    }

    private static string Relative(string abs)
    {
        var cwd = Directory.GetCurrentDirectory();
        return Path.GetRelativePath(cwd, abs);
    }

    [Fact]
    public async Task Scope_Load_ValidFile_ReturnsEntries()
    {
        var path = WriteScopeFile("10.10.10.0/24\n192.168.1.5\n");
        try
        {
            using var factory = new DrederickWebFactory();
            using var client = factory.CreateClient();

            var resp = await client.GetAsync($"/api/scope?path={Uri.EscapeDataString(Relative(path))}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = await resp.Content.ReadFromJsonAsync<JsonElement>();

            var entries = body.GetProperty("entries").EnumerateArray().ToList();
            Assert.Equal(2, entries.Count);
            Assert.Equal("v4", entries[0].GetProperty("family").GetString());
            Assert.Equal("lab", body.GetProperty("mode").GetString());
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Fact]
    public async Task Scope_Load_WildcardFile_ReportsWarnings()
    {
        // A /0 is refused outright — not a "warning" case, but a too-broad
        // /4 IPv4 prefix triggers the lab-cap refusal, which we surface as
        // a warning and a view-only retry.
        var path = WriteScopeFile("10.0.0.0/4\n");
        try
        {
            using var factory = new DrederickWebFactory();
            using var client = factory.CreateClient();

            var resp = await client.GetAsync($"/api/scope?path={Uri.EscapeDataString(Relative(path))}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
            var warnings = body.GetProperty("warnings").EnumerateArray().ToList();
            Assert.NotEmpty(warnings);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Fact]
    public async Task Scope_PathTraversal_Rejected()
    {
        using var factory = new DrederickWebFactory();
        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/api/scope?path=../../etc/passwd");
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Validate_InScopeTarget_Accepted()
    {
        var path = WriteScopeFile("10.10.10.0/24\n");
        try
        {
            using var factory = new DrederickWebFactory();
            using var client = factory.CreateClient();

            var resp = await client.PostAsJsonAsync("/api/scope/validate", new
            {
                path = Relative(path),
                proposed_targets = new[] { "10.10.10.5", "10.10.10.200" },
            });
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(2, body.GetProperty("accepted").GetArrayLength());
            Assert.Equal(0, body.GetProperty("rejected").GetArrayLength());
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Fact]
    public async Task Validate_OutOfScopeTarget_Rejected()
    {
        var path = WriteScopeFile("10.10.10.0/24\n");
        try
        {
            using var factory = new DrederickWebFactory();
            using var client = factory.CreateClient();

            var resp = await client.PostAsJsonAsync("/api/scope/validate", new
            {
                path = Relative(path),
                proposed_targets = new[] { "8.8.8.8", "10.10.10.5" },
            });
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(1, body.GetProperty("accepted").GetArrayLength());
            var rejected = body.GetProperty("rejected").EnumerateArray().ToList();
            Assert.Single(rejected);
            Assert.Equal("8.8.8.8", rejected[0].GetProperty("target").GetString());
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Fact]
    public async Task ScopeFile_NeverWrittenFrom_WebUI()
    {
        var path = WriteScopeFile("10.10.10.0/24\n");
        try
        {
            var originalMtime = File.GetLastWriteTimeUtc(path);
            var originalContent = File.ReadAllText(path);

            using var factory = new DrederickWebFactory();
            using var client = factory.CreateClient();

            await client.GetAsync($"/api/scope?path={Uri.EscapeDataString(Relative(path))}");
            await client.PostAsJsonAsync("/api/scope/validate", new
            {
                path = Relative(path),
                proposed_targets = new[] { "10.10.10.5", "8.8.8.8" },
            });

            Assert.Equal(originalMtime, File.GetLastWriteTimeUtc(path));
            Assert.Equal(originalContent, File.ReadAllText(path));

            // And: no PUT/POST/DELETE/PATCH verb on /api/scope itself mutates.
            var putResp = await client.PutAsync(
                $"/api/scope?path={Uri.EscapeDataString(Relative(path))}",
                new StringContent("10.0.0.0/8"));
            Assert.True(
                putResp.StatusCode == HttpStatusCode.NotFound
                || putResp.StatusCode == HttpStatusCode.MethodNotAllowed,
                $"expected 404/405 for PUT to /api/scope, got {(int)putResp.StatusCode}");

            var delResp = await client.DeleteAsync(
                $"/api/scope?path={Uri.EscapeDataString(Relative(path))}");
            Assert.True(
                delResp.StatusCode == HttpStatusCode.NotFound
                || delResp.StatusCode == HttpStatusCode.MethodNotAllowed,
                $"expected 404/405 for DELETE to /api/scope, got {(int)delResp.StatusCode}");

            // Final mtime check after attempted mutation verbs.
            Assert.Equal(originalMtime, File.GetLastWriteTimeUtc(path));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }
}
