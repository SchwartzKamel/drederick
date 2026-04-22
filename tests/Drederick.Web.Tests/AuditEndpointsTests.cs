using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace Drederick.Web.Tests;

public sealed class AuditEndpointsTests
{
    private static void SeedAuditFile(string path, IEnumerable<string> lines)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.AppendAllLines(path, lines);
    }

    private static string JsonLine(string eventType, DateTimeOffset ts, object? extra = null)
    {
        var dict = new Dictionary<string, object?>
        {
            ["ts"] = ts.ToString("o"),
            ["pid"] = 1234,
            ["event"] = eventType,
        };
        if (extra is not null)
        {
            foreach (var p in extra.GetType().GetProperties())
            {
                dict[p.Name] = p.GetValue(extra);
            }
        }
        return JsonSerializer.Serialize(dict);
    }

    [Fact]
    public async Task Tail_ReturnsRecentEntries()
    {
        using var factory = new DrederickWebFactory();
        var now = DateTimeOffset.UtcNow;
        SeedAuditFile(factory.AuditLogPath, new[]
        {
            JsonLine("scope.check", now.AddMinutes(-5)),
            JsonLine("web.runs.start", now.AddMinutes(-2)),
            JsonLine("web.runs.finish", now.AddMinutes(-1)),
        });

        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/api/audit/tail");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        // Seeded 3 plus whatever the factory startup emitted.
        Assert.True(body.GetProperty("count").GetInt32() >= 3);
    }

    [Fact]
    public async Task Tail_SinceFilter_Respected()
    {
        using var factory = new DrederickWebFactory();
        var now = DateTimeOffset.UtcNow;
        SeedAuditFile(factory.AuditLogPath, new[]
        {
            JsonLine("scope.check", now.AddHours(-2)),
            JsonLine("web.runs.start", now.AddMinutes(-1)),
        });

        using var client = factory.CreateClient();
        var since = now.AddMinutes(-30).ToString("o");
        var resp = await client.GetAsync($"/api/audit/tail?since={Uri.EscapeDataString(since)}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        foreach (var entry in body.GetProperty("entries").EnumerateArray())
        {
            if (entry.TryGetProperty("ts", out var tsEl) && tsEl.ValueKind == JsonValueKind.String)
            {
                var ts = DateTimeOffset.Parse(tsEl.GetString()!);
                Assert.True(ts >= now.AddMinutes(-30), $"entry ts {ts} before since");
            }
        }
    }

    [Fact]
    public async Task Tail_CategoryFilter_Respected()
    {
        using var factory = new DrederickWebFactory();
        var now = DateTimeOffset.UtcNow;
        SeedAuditFile(factory.AuditLogPath, new[]
        {
            JsonLine("scope.check", now.AddMinutes(-5)),
            JsonLine("web.runs.start", now.AddMinutes(-4)),
            JsonLine("web.runs.finish", now.AddMinutes(-3)),
            JsonLine("jeopardy.docker.probe", now.AddMinutes(-2)),
        });

        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/api/audit/tail?category=web.runs");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        foreach (var entry in body.GetProperty("entries").EnumerateArray())
        {
            var ev = entry.GetProperty("event").GetString()!;
            Assert.StartsWith("web.runs", ev);
        }
    }

    [Fact]
    public async Task Tail_LimitClamp_1000()
    {
        using var factory = new DrederickWebFactory();
        var now = DateTimeOffset.UtcNow;
        var lines = new List<string>();
        for (int i = 0; i < 1500; i++)
        {
            lines.Add(JsonLine("bulk.event", now.AddSeconds(-1500 + i)));
        }
        SeedAuditFile(factory.AuditLogPath, lines);

        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/api/audit/tail?limit=5000&category=bulk");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var count = body.GetProperty("count").GetInt32();
        Assert.True(count <= 1000, $"limit clamp failed: got {count} entries");
        Assert.Equal(1000, count);
    }

    [Fact]
    public async Task NoPlaintextInResponse_CanaryTest()
    {
        using var factory = new DrederickWebFactory();
        var now = DateTimeOffset.UtcNow;
        // Entry 1: well-formed, uses a digest (safe).
        // Entry 2: has a plaintext canary in an unexpected field — must be
        // redacted in the response.
        SeedAuditFile(factory.AuditLogPath, new[]
        {
            JsonLine("cred.attempt", now.AddMinutes(-2), new
            {
                target = "10.10.10.5",
                username = "admin",
                secret_sha256 = "deadbeefcafebabe",
            }),
            JsonLine("broken.producer", now.AddMinutes(-1), new
            {
                note = "DREDERICK_TEST_PLAINTEXT_CANARY must never leak",
            }),
        });

        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/api/audit/tail?category=broken");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var text = await resp.Content.ReadAsStringAsync();

        // The canary must never appear in the response body. The endpoint
        // should emit a redacted stand-in instead.
        Assert.DoesNotContain("DREDERICK_TEST_PLAINTEXT_CANARY", text);
        var body = JsonDocument.Parse(text).RootElement;
        Assert.True(body.GetProperty("redacted").GetInt32() >= 1);
    }

    [Fact]
    public async Task Categories_Endpoint_ReturnsPrefixes()
    {
        using var factory = new DrederickWebFactory();
        var now = DateTimeOffset.UtcNow;
        SeedAuditFile(factory.AuditLogPath, new[]
        {
            JsonLine("scope.check", now),
            JsonLine("web.runs.start", now),
            JsonLine("jeopardy.docker.probe", now),
        });
        using var client = factory.CreateClient();
        var resp = await client.GetAsync("/api/audit/categories");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var prefixes = body.GetProperty("prefixes").EnumerateArray()
            .Select(e => e.GetString()).ToHashSet();
        Assert.Contains("scope", prefixes);
        Assert.Contains("web", prefixes);
        Assert.Contains("jeopardy", prefixes);
    }
}
