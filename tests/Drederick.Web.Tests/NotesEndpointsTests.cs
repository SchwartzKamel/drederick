using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Drederick.Web.Auth;
using Xunit;

namespace Drederick.Web.Tests;

/// <summary>
/// Integration tests for <c>/api/notes</c>. Each test spins up a
/// <see cref="DrederickWebFactory"/> with its own temp OutputDir; notes
/// land in <c>findings.db</c> under that dir and are torn down when the
/// factory disposes.
/// </summary>
public sealed class NotesEndpointsTests
{
    private const string CanaryToken = "CANARY-NOTES-abc123-xyz789-drederick";

    [Fact]
    public async Task Create_Then_List_RoundTrip()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        var created = await c.PostAsJsonAsync("/api/notes", new
        {
            host = "10.0.0.1",
            tag = "intel",
            body = "I learned the opponent guards low.",
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>();
        var id = createdBody.GetProperty("id").GetInt64();
        Assert.Equal("10.0.0.1", createdBody.GetProperty("host").GetString());
        Assert.Equal("intel", createdBody.GetProperty("tag").GetString());
        Assert.Equal("I learned the opponent guards low.", createdBody.GetProperty("body").GetString());

        var listResp = await c.GetAsync("/api/notes");
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);
        var listBody = await listResp.Content.ReadFromJsonAsync<JsonElement>();
        var notes = listBody.GetProperty("notes");
        Assert.Equal(1, notes.GetArrayLength());
        Assert.Equal(id, notes[0].GetProperty("id").GetInt64());
    }

    [Fact]
    public async Task Get_ReturnsNote()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        var created = await c.PostAsJsonAsync("/api/notes", new { body = "first jotting" });
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetInt64();

        var resp = await c.GetAsync($"/api/notes/{id}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("first jotting", body.GetProperty("body").GetString());
    }

    [Fact]
    public async Task Get_UnknownId_Returns404()
    {
        using var f = new DrederickWebFactory();
        // Seed at least one note so the DB exists.
        using var c = f.CreateClient();
        await c.PostAsJsonAsync("/api/notes", new { body = "seed" });

        var resp = await c.GetAsync("/api/notes/99999");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Delete_RemovesNote()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        var created = await c.PostAsJsonAsync("/api/notes", new { body = "throwaway" });
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetInt64();

        var del = await c.DeleteAsync($"/api/notes/{id}");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        var after = await c.GetAsync($"/api/notes/{id}");
        Assert.Equal(HttpStatusCode.NotFound, after.StatusCode);
    }

    [Fact]
    public async Task Delete_UnknownId_Returns404()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();
        // Bootstrap DB.
        await c.PostAsJsonAsync("/api/notes", new { body = "seed" });

        var resp = await c.DeleteAsync("/api/notes/99999");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task List_NoDatabase_ReturnsNoDatabaseStatus()
    {
        // Fresh factory: OutputDir exists but no findings.db.
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/notes");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("no_database", body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Get_NoDatabase_ReturnsNoDatabaseStatus()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        var resp = await c.GetAsync("/api/notes/1");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("no_database", body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task List_FilteredByHost()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        await c.PostAsJsonAsync("/api/notes", new { host = "10.0.0.1", body = "a" });
        await c.PostAsJsonAsync("/api/notes", new { host = "10.0.0.2", body = "b" });

        var resp = await c.GetAsync("/api/notes?host=10.0.0.1");
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var notes = body.GetProperty("notes");
        Assert.Equal(1, notes.GetArrayLength());
        Assert.Equal("10.0.0.1", notes[0].GetProperty("host").GetString());
    }

    [Fact]
    public async Task List_FilteredByTag()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        await c.PostAsJsonAsync("/api/notes", new { tag = "intel", body = "a" });
        await c.PostAsJsonAsync("/api/notes", new { tag = "loot", body = "b" });

        var resp = await c.GetAsync("/api/notes?tag=intel");
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var notes = body.GetProperty("notes");
        Assert.Equal(1, notes.GetArrayLength());
        Assert.Equal("intel", notes[0].GetProperty("tag").GetString());
    }

    [Fact]
    public async Task Create_EmptyBody_Returns400()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        var resp = await c.PostAsJsonAsync("/api/notes", new { host = "x", tag = "y", body = "" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task NonLoopback_RequiresBearer_OnAllRoutes()
    {
        var settings = new WebAppSettings
        {
            BindHost = "0.0.0.0",
            BindPort = 0,
            RequireBearer = true,
            Token = CanaryToken,
            OutputDir = "out",
        };
        using var f = new DrederickWebFactory(settings);
        using var c = f.CreateClient();

        // No auth header → 401 on every verb.
        var list = await c.GetAsync("/api/notes");
        Assert.Equal(HttpStatusCode.Unauthorized, list.StatusCode);

        var get = await c.GetAsync("/api/notes/1");
        Assert.Equal(HttpStatusCode.Unauthorized, get.StatusCode);

        var post = await c.PostAsJsonAsync("/api/notes", new { body = "x" });
        Assert.Equal(HttpStatusCode.Unauthorized, post.StatusCode);

        var del = new HttpRequestMessage(HttpMethod.Delete, "/api/notes/1");
        var delResp = await c.SendAsync(del);
        Assert.Equal(HttpStatusCode.Unauthorized, delResp.StatusCode);

        // With bearer → works (list returns no_database stub since empty).
        using var okReq = new HttpRequestMessage(HttpMethod.Get, "/api/notes");
        okReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", CanaryToken);
        var ok = await c.SendAsync(okReq);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Fact]
    public async Task Create_AuditRecord_HasIdHostTagLength_AndNoBody()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        const string canary = "SUPER-SECRET-NOTE-BODY-XYZZY";
        var resp = await c.PostAsJsonAsync("/api/notes", new
        {
            host = "10.9.9.9",
            tag = "private",
            body = canary,
        });
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        // Flush window.
        await Task.Delay(50);
        var auditContents = await File.ReadAllTextAsync(f.AuditLogPath);

        // Body canary must NOT appear in audit in any form.
        Assert.DoesNotContain(canary, auditContents, StringComparison.Ordinal);

        // notes.create event must be present with the metadata fields.
        Assert.Contains("\"notes.create\"", auditContents, StringComparison.Ordinal);
        Assert.Contains("\"host\":\"10.9.9.9\"", auditContents, StringComparison.Ordinal);
        Assert.Contains("\"tag\":\"private\"", auditContents, StringComparison.Ordinal);
        Assert.Contains($"\"length\":{canary.Length}", auditContents, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Delete_AuditRecord_HasIdHostTagLength()
    {
        using var f = new DrederickWebFactory();
        using var c = f.CreateClient();

        var created = await c.PostAsJsonAsync("/api/notes", new
        {
            host = "10.8.8.8",
            tag = "sweep",
            body = "remove-me",
        });
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetInt64();

        var del = await c.DeleteAsync($"/api/notes/{id}");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        await Task.Delay(50);
        var auditContents = await File.ReadAllTextAsync(f.AuditLogPath);

        Assert.Contains("\"notes.delete\"", auditContents, StringComparison.Ordinal);
        Assert.Contains($"\"id\":{id}", auditContents, StringComparison.Ordinal);
        Assert.Contains("\"host\":\"10.8.8.8\"", auditContents, StringComparison.Ordinal);
        Assert.DoesNotContain("remove-me", auditContents, StringComparison.Ordinal);
    }
}
