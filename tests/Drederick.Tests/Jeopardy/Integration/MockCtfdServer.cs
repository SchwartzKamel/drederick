using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Drederick.Tests.Jeopardy.Integration;

/// <summary>
/// Minimal in-process CTFd v3 HTTP server for end-to-end integration tests.
///
/// <para>Implements just enough of the API surface that <see cref="Drederick.Jeopardy.Ctfd.CtfdClient"/>
/// exercises during a full solve run:</para>
/// <list type="bullet">
///   <item><c>GET /api/v1/challenges</c> — summary list</item>
///   <item><c>GET /api/v1/challenges/{id}</c> — detail</item>
///   <item><c>POST /api/v1/challenges/attempt</c> — flag submission with configurable correct map</item>
///   <item><c>GET /api/v1/users/me/solves</c> — already-solved list</item>
///   <item><c>GET /api/v1/scoreboard</c> — empty scoreboard</item>
/// </list>
///
/// <para>Binds on <c>127.0.0.1</c> at a port grabbed from the OS; surfaced
/// as <see cref="BaseUrl"/>. Any non-empty <c>Authorization: Token …</c>
/// header is accepted — no realism is required for tests. Every submission
/// is recorded in <see cref="Submissions"/> (both correct and incorrect).</para>
///
/// <para>Dispose to shut the listener down cleanly.</para>
/// </summary>
internal sealed class MockCtfdServer : IDisposable
{
    private readonly HttpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;
    private readonly ConcurrentDictionary<int, Entry> _challenges = new();
    private readonly ConcurrentDictionary<int, byte> _solved = new();
    private int _missingAuthCount;
    private int _badAuthCount;

    public Uri BaseUrl { get; }

    /// <summary>Every submission that reached the server, in order.</summary>
    public List<SubmissionRecord> Submissions { get; } = new();

    /// <summary>How often an endpoint returned 401 because no Authorization header was sent.</summary>
    public int MissingAuthCount => Volatile.Read(ref _missingAuthCount);
    /// <summary>How often an endpoint returned 401 because of a malformed Authorization header.</summary>
    public int BadAuthCount => Volatile.Read(ref _badAuthCount);

    public MockCtfdServer()
    {
        var port = FindFreePort();
        BaseUrl = new Uri($"http://127.0.0.1:{port}/");
        _listener = new HttpListener();
        _listener.Prefixes.Add(BaseUrl.ToString());
        _listener.Start();
        _loop = Task.Run(AcceptLoopAsync);
    }

    public MockCtfdServer WithChallenge(int id, string name, string category, int value, string correctFlag,
        string? description = null, string? connectionInfo = null, IReadOnlyList<string>? tags = null)
    {
        _challenges[id] = new Entry(id, name, category, value,
            description ?? "Description for " + name,
            connectionInfo, tags ?? Array.Empty<string>(), correctFlag);
        return this;
    }

    public MockCtfdServer MarkSolved(int id)
    {
        _solved[id] = 1;
        return this;
    }

    private static int FindFreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested && _listener.IsListening)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException) { return; }
            catch (HttpListenerException) { return; }

            _ = Task.Run(() => HandleAsync(ctx));
        }
    }

    private async Task HandleAsync(HttpListenerContext ctx)
    {
        try
        {
            if (!CheckAuth(ctx))
            {
                await Respond(ctx, 401, "{\"success\":false,\"message\":\"auth\"}").ConfigureAwait(false);
                return;
            }

            var path = ctx.Request.Url!.AbsolutePath;
            var method = ctx.Request.HttpMethod;

            if (method == "GET" && path == "/api/v1/challenges")
            {
                await HandleListAsync(ctx).ConfigureAwait(false);
                return;
            }
            if (method == "GET" && path.StartsWith("/api/v1/challenges/", StringComparison.Ordinal))
            {
                var tail = path.Substring("/api/v1/challenges/".Length);
                if (int.TryParse(tail, out var id))
                {
                    await HandleGetAsync(ctx, id).ConfigureAwait(false);
                    return;
                }
            }
            if (method == "POST" && path == "/api/v1/challenges/attempt")
            {
                await HandleSubmitAsync(ctx).ConfigureAwait(false);
                return;
            }
            if (method == "GET" && path == "/api/v1/users/me/solves")
            {
                await HandleSolvesAsync(ctx).ConfigureAwait(false);
                return;
            }
            if (method == "GET" && path == "/api/v1/scoreboard")
            {
                await Respond(ctx, 200, "{\"success\":true,\"data\":[]}").ConfigureAwait(false);
                return;
            }

            await Respond(ctx, 404, "{\"success\":false,\"message\":\"not_found\"}").ConfigureAwait(false);
        }
        catch
        {
            try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
        }
    }

    private bool CheckAuth(HttpListenerContext ctx)
    {
        var auth = ctx.Request.Headers["Authorization"];
        if (string.IsNullOrEmpty(auth))
        {
            Interlocked.Increment(ref _missingAuthCount);
            return false;
        }
        if (!auth.StartsWith("Token ", StringComparison.Ordinal) || auth.Length <= "Token ".Length)
        {
            Interlocked.Increment(ref _badAuthCount);
            return false;
        }
        return true;
    }

    private async Task HandleListAsync(HttpListenerContext ctx)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteBoolean("success", true);
            w.WriteStartArray("data");
            foreach (var e in _challenges.Values)
            {
                w.WriteStartObject();
                w.WriteNumber("id", e.Id);
                w.WriteString("name", e.Name);
                w.WriteString("category", e.Category);
                w.WriteNumber("value", e.Value);
                w.WriteBoolean("solved_by_me", _solved.ContainsKey(e.Id));
                w.WriteStartArray("tags");
                foreach (var t in e.Tags) w.WriteStringValue(t);
                w.WriteEndArray();
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        await Respond(ctx, 200, Encoding.UTF8.GetString(ms.ToArray())).ConfigureAwait(false);
    }

    private async Task HandleGetAsync(HttpListenerContext ctx, int id)
    {
        if (!_challenges.TryGetValue(id, out var e))
        {
            await Respond(ctx, 404, "{\"success\":false,\"message\":\"no_such_challenge\"}").ConfigureAwait(false);
            return;
        }

        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteBoolean("success", true);
            w.WriteStartObject("data");
            w.WriteNumber("id", e.Id);
            w.WriteString("name", e.Name);
            w.WriteString("category", e.Category);
            w.WriteNumber("value", e.Value);
            w.WriteString("description", e.Description);
            if (e.ConnectionInfo is not null) w.WriteString("connection_info", e.ConnectionInfo);
            w.WriteBoolean("solved_by_me", _solved.ContainsKey(e.Id));
            w.WriteStartArray("files");
            w.WriteEndArray();
            w.WriteStartArray("tags");
            foreach (var t in e.Tags) w.WriteStringValue(t);
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteEndObject();
        }
        await Respond(ctx, 200, Encoding.UTF8.GetString(ms.ToArray())).ConfigureAwait(false);
    }

    private async Task HandleSubmitAsync(HttpListenerContext ctx)
    {
        string body;
        using (var sr = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding ?? Encoding.UTF8))
        {
            body = await sr.ReadToEndAsync().ConfigureAwait(false);
        }

        int challengeId;
        string submission;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            challengeId = root.GetProperty("challenge_id").GetInt32();
            submission = root.GetProperty("submission").GetString() ?? string.Empty;
        }
        catch (Exception)
        {
            await Respond(ctx, 400, "{\"success\":false,\"message\":\"bad_json\"}").ConfigureAwait(false);
            return;
        }

        string status;
        if (_solved.ContainsKey(challengeId))
        {
            status = "already_solved";
        }
        else if (_challenges.TryGetValue(challengeId, out var e)
            && string.Equals(e.CorrectFlag, submission.Trim(), StringComparison.Ordinal))
        {
            status = "correct";
            _solved[challengeId] = 1;
        }
        else
        {
            status = "incorrect";
        }

        lock (Submissions)
        {
            Submissions.Add(new SubmissionRecord(challengeId, submission, status, DateTimeOffset.UtcNow));
        }

        var resp = $"{{\"success\":true,\"data\":{{\"status\":\"{status}\",\"message\":\"{status}\"}}}}";
        await Respond(ctx, 200, resp).ConfigureAwait(false);
    }

    private async Task HandleSolvesAsync(HttpListenerContext ctx)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteBoolean("success", true);
            w.WriteStartArray("data");
            foreach (var id in _solved.Keys)
            {
                w.WriteStartObject();
                w.WriteNumber("challenge_id", id);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        await Respond(ctx, 200, Encoding.UTF8.GetString(ms.ToArray())).ConfigureAwait(false);
    }

    private static async Task Respond(HttpListenerContext ctx, int status, string body)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
        ctx.Response.Close();
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _listener.Stop(); } catch { }
        try { _listener.Close(); } catch { }
        try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cts.Dispose();
    }

    internal sealed record Entry(
        int Id, string Name, string Category, int Value,
        string Description, string? ConnectionInfo,
        IReadOnlyList<string> Tags, string CorrectFlag);

    public sealed record SubmissionRecord(int ChallengeId, string Submission, string Status, DateTimeOffset At);
}
