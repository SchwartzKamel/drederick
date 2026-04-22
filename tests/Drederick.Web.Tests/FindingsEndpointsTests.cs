using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Drederick.Web.Tests.TestFixtures;
using Xunit;

namespace Drederick.Web.Tests;

/// <summary>
/// Integration tests for the read-only <c>/api/findings/*</c> endpoints.
/// Each test spins up a <see cref="DrederickWebFactory"/>, seeds a
/// canned findings.db via <see cref="SeedFindingsDb"/> into the factory's
/// per-test OutputDir, and exercises the HTTP surface end-to-end.
/// </summary>
public sealed class FindingsEndpointsTests
{
    private static DrederickWebFactory SeededFactory()
    {
        var f = new DrederickWebFactory();
        SeedFindingsDb.CreateAndSeed(Path.Combine(f.OutputDir, "findings.db"));
        return f;
    }

    [Fact]
    public async Task Hosts_List_ReturnsSeededRows()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/hosts");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(3, body.GetProperty("total").GetInt32());
        var items = body.GetProperty("items");
        Assert.Equal(3, items.GetArrayLength());
        Assert.Contains("10.0.0.1", items.EnumerateArray()
            .Select(x => x.GetProperty("address").GetString()));
        // services_count present on each host.
        Assert.True(items[0].TryGetProperty("services_count", out _));
    }

    [Fact]
    public async Task Hosts_Pagination_LimitOffset_Respected()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/hosts?limit=2&offset=1");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(3, body.GetProperty("total").GetInt32());
        Assert.Equal(2, body.GetProperty("limit").GetInt32());
        Assert.Equal(1, body.GetProperty("offset").GetInt32());
        Assert.Equal(2, body.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task Services_List_FilteredByHost()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/services?host_id=1");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(4, body.GetProperty("total").GetInt32());
        foreach (var s in body.GetProperty("items").EnumerateArray())
        {
            Assert.Equal(1, s.GetProperty("host_id").GetInt64());
            Assert.True(s.TryGetProperty("protocol", out _));
            Assert.True(s.TryGetProperty("service_name", out _));
        }
    }

    [Fact]
    public async Task Cves_List_FilteredBySeverity()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/cves?severity=critical");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(5, body.GetProperty("total").GetInt32());
        foreach (var cve in body.GetProperty("items").EnumerateArray())
        {
            Assert.Equal("critical", cve.GetProperty("severity").GetString());
            Assert.True(cve.GetProperty("cvss").GetDouble() >= 9.0);
        }
    }

    [Fact]
    public async Task ExploitRuns_List_ContainsNoStdoutStderrContent()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/exploit-runs");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(5, body.GetProperty("total").GetInt32());

        foreach (var r in body.GetProperty("items").EnumerateArray())
        {
            Assert.True(r.TryGetProperty("stdout_sha256", out _));
            Assert.True(r.TryGetProperty("stdout_bytes", out _));
            Assert.True(r.TryGetProperty("stderr_sha256", out _));
            Assert.False(r.TryGetProperty("stdout", out _),
                "exploit-runs response must not project raw stdout content.");
            Assert.False(r.TryGetProperty("stderr", out _),
                "exploit-runs response must not project raw stderr content.");
        }
    }

    [Fact]
    public async Task Loot_List_NeverReturnsPlaintextValue()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/loot");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var raw = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain(SeedFindingsDb.LootCanary, raw);

        var body = JsonDocument.Parse(raw).RootElement;
        Assert.Equal(4, body.GetProperty("total").GetInt32());
        foreach (var l in body.GetProperty("items").EnumerateArray())
        {
            Assert.True(l.TryGetProperty("value_sha256", out _));
            Assert.False(l.TryGetProperty("value", out _),
                "loot response must never expose a plaintext value column.");
            Assert.False(l.TryGetProperty("metadata", out _),
                "loot response must redact tool-controlled metadata.");
        }
    }

    [Fact]
    public async Task Summary_ReturnsAllCategoryCounts()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/summary");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(3, body.GetProperty("hosts").GetInt32());
        Assert.Equal(10, body.GetProperty("services").GetInt32());
        Assert.Equal(20, body.GetProperty("cves").GetInt32());

        var sev = body.GetProperty("cves_by_severity");
        Assert.Equal(5, sev.GetProperty("critical").GetInt32());
        Assert.Equal(5, sev.GetProperty("high").GetInt32());
        Assert.Equal(5, sev.GetProperty("medium").GetInt32());
        Assert.Equal(5, sev.GetProperty("low").GetInt32());

        Assert.Equal(5, body.GetProperty("exploit_runs").GetInt32());
        var cats = body.GetProperty("exploit_runs_by_category");
        Assert.True(cats.TryGetProperty("exploit", out _));
        Assert.True(cats.TryGetProperty("cred", out _));
        Assert.True(cats.TryGetProperty("payload", out _));

        Assert.Equal(1, body.GetProperty("sessions_open").GetInt32());
        Assert.Equal(1, body.GetProperty("sessions_closed").GetInt32());

        Assert.Equal(4, body.GetProperty("loot").GetInt32());
    }

    [Fact]
    public async Task NoDatabase_ReturnsNoDatabaseStatus()
    {
        // Factory without seeding — OutputDir exists but no findings.db.
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/summary");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("no_database", body.GetProperty("status").GetString());

        // Every endpoint must honour the same contract.
        foreach (var path in new[]
        {
            "/api/findings/hosts",
            "/api/findings/services",
            "/api/findings/cves",
            "/api/findings/poc-refs",
            "/api/findings/exploit-runs",
            "/api/findings/sessions",
            "/api/findings/loot",
        })
        {
            var r = await c.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            var b = await r.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("no_database", b.GetProperty("status").GetString());
        }
    }

    [Fact]
    public async Task Loopback_NoAuthRequired_ForFindingsRoutes()
    {
        // Default factory binds loopback with RequireBearer=false; every
        // /api/findings route must answer without an Authorization header.
        using var f = SeededFactory();
        using var c = f.CreateClient();

        foreach (var path in new[]
        {
            "/api/findings/hosts",
            "/api/findings/services",
            "/api/findings/cves",
            "/api/findings/summary",
        })
        {
            var r = await c.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        }
    }

    [Fact]
    public async Task SqlInjection_ParameterizedBinding()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        // A classic injection payload in the substring-search param. If
        // binding were string-concatenated, this would return all rows;
        // with parametrized @q binding it's a literal with zero matches.
        var resp = await c.GetAsync(
            "/api/findings/hosts?q_param=" + Uri.EscapeDataString("' OR 1=1--"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(0, body.GetProperty("total").GetInt32());
        Assert.Equal(0, body.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task ReadOnly_WriteVerbsAreRejected()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Delete, HttpMethod.Patch })
        {
            var req = new HttpRequestMessage(method, "/api/findings/hosts");
            var r = await c.SendAsync(req);
            // Write verbs never match a GET route — ASP.NET returns 404
            // or 405 depending on routing; both are acceptable, the key
            // invariant is "not 2xx".
            Assert.False((int)r.StatusCode is >= 200 and < 300,
                $"{method} {r.RequestMessage?.RequestUri} must not succeed; got {(int)r.StatusCode}.");
        }
    }

    [Fact]
    public async Task Loot_CanaryNotPresentInSummaryEither()
    {
        // Defence in depth: summary computes counts; no row content leaves
        // the server. This is a belt-and-braces check for the canary.
        using var f = SeededFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/summary");
        var raw = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain(SeedFindingsDb.LootCanary, raw);
    }

    [Fact]
    public async Task Cves_Detail_IncludesPocRefs()
    {
        using var f = SeededFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/findings/cves/CVE-2024-1000");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("CVE-2024-1000", body.GetProperty("cve_id").GetString());
        Assert.Equal("critical", body.GetProperty("severity").GetString());
        var pocs = body.GetProperty("poc_refs");
        Assert.Equal(2, pocs.GetArrayLength());
    }
}
