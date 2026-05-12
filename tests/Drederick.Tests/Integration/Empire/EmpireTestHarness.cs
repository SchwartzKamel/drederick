using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.Memory;
using Drederick.PostEx;
using Drederick.Scope;

namespace Drederick.Tests.Integration.Empire;

/// <summary>
/// DI harness for the Empire end-to-end integration tests. Wires
/// AutopilotRunner + EmpireStagerGenerator + a FakeExploitRunner (with a
/// payload-gated delivery path) + EmpirePostExDispatcher
/// (FixtureEmpireTaskClient) + EmpireCredentialBridge (StubHttpHandler-
/// backed cred client) against a shared <see cref="AuditLog"/>,
/// <see cref="CredentialStore"/>, and <see cref="KnowledgeBase"/>. No real
/// network, no real processes, no real Empire server. Every entry point
/// still runs through the genuine scope and opt-in gates so the
/// integration tests exercise the real invariants, not test-only shims.
/// </summary>
internal sealed class EmpireTestHarness : IDisposable
{
    public string AuditPath { get; }
    public AuditLog Audit { get; }
    public Scope.Scope Scope { get; }
    public RunPermissions Permissions { get; private set; }
    public CredentialStore Credentials { get; }
    public KnowledgeBase Kb { get; }
    public string OutputRoot { get; }
    public EmpireOptions EmpireOptions { get; }

    public FakeEmpireServer EmpireServer { get; }
    public FakeEmpireRestClient EmpireRest { get; }
    public FakeSessionManager Sessions { get; }
    public FakeExploitRunner Exploit { get; }
    public FixtureEmpireTaskClient TaskClient { get; }

    public EmpireStagerGenerator StagerGenerator { get; }
    public EmpirePostExDispatcher Dispatcher { get; }
    public EmpireCredentialClient CredClient { get; }
    public EmpireCredentialBridge CredBridge { get; }
    public AutopilotRunner Autopilot { get; }

    public StubHandler StagerHandler { get; }
    public StubHandler CredHandler { get; }

    /// <summary>Synthetic opt-in gate: stand-in for a future
    /// <c>--empire-autopilot</c> CLI flag. The integration tests gate
    /// the whole pipeline through it so we can prove the missing-flag
    /// refusal surfaces correctly without editing CLI-owned files.</summary>
    public bool EmpireAutopilotEnabled { get; set; }

    private readonly HttpClient _stagerHttp;
    private readonly HttpClient _credHttp;
    private bool _disposed;

    public EmpireTestHarness(string scopeSpec, RunPermissions perms, bool empireAutopilotEnabled = true)
    {
        Scope = ScopeLoader.Parse(scopeSpec);
        Permissions = perms ?? throw new ArgumentNullException(nameof(perms));
        EmpireAutopilotEnabled = empireAutopilotEnabled;

        AuditPath = Path.Combine(AppContext.BaseDirectory,
            $"empire-it-{Guid.NewGuid():N}.jsonl");
        Audit = new AuditLog(AuditPath);

        Credentials = new CredentialStore(Audit);
        Kb = new KnowledgeBase();
        OutputRoot = Path.Combine(AppContext.BaseDirectory,
            $"empire-it-out-{Guid.NewGuid():N}");
        Directory.CreateDirectory(OutputRoot);

        EmpireOptions = new EmpireOptions
        {
            Host = "127.0.0.1",
            Port = 1337,
            Scheme = "http",
            Username = "empireadmin",
            Password = "harness-password",
            ApiToken = "HARNESS-TOKEN",
            InstallPath = "/opt/Empire",
        };

        StagerHandler = new StubHandler();
        _stagerHttp = new HttpClient(StagerHandler);
        EmpireRest = new FakeEmpireRestClient(EmpireOptions, Audit, _stagerHttp);
        StagerGenerator = new EmpireStagerGenerator(Scope, Audit, EmpireOptions, EmpireRest.Inner, _stagerHttp);

        CredHandler = new StubHandler();
        _credHttp = new HttpClient(CredHandler);
        CredClient = new EmpireCredentialClient(EmpireOptions, Audit, "HARNESS-TOKEN", _credHttp);
        CredBridge = new EmpireCredentialBridge(Scope, CredClient, Credentials, Audit, autoSubscribe: false);

        TaskClient = new FixtureEmpireTaskClient();
        Dispatcher = new EmpirePostExDispatcher(Scope, Audit, Permissions, TaskClient, Credentials, Kb);

        EmpireServer = new FakeEmpireServer();
        Sessions = new FakeSessionManager(Scope, Audit);
        Exploit = new FakeExploitRunner(Scope, Audit);

        var planner = new ExploitationPlanner(Audit, OutputRoot);
        var flagExtractor = new FlagExtractor(Audit);
        Autopilot = new AutopilotRunner(
            Scope, Audit, Permissions, planner, Credentials, flagExtractor, OutputRoot,
            nuclei: null, spray: null, msf: null, maxIterations: 1);
    }

    public void RegisterStagerResponse(string responseJson)
    {
        StagerHandler.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseJson, Encoding.UTF8, "application/json"),
        });
    }

    public void RegisterEmptyCredList()
    {
        CredHandler.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("[]", Encoding.UTF8, "application/json"),
        });
    }

    public void RegisterCredCreate(int id)
    {
        var body = $"{{\"id\":{id},\"credtype\":\"plaintext\",\"username\":\"x\",\"password\":\"x\"}}";
        CredHandler.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });
    }

    public Scenario LoadScenario(string fixtureName)
    {
        var path = ResolveFixture(fixtureName);
        return Scenario.Parse(File.ReadAllText(path));
    }

    public static string ResolveFixture(string name)
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null &&
            !Directory.Exists(Path.Combine(dir, "tests", "fixtures", "empire", "integration")))
        {
            dir = Path.GetDirectoryName(dir);
        }
        if (dir is null)
        {
            throw new InvalidOperationException(
                "tests/fixtures/empire/integration not found from " + AppContext.BaseDirectory);
        }
        return Path.Combine(dir, "tests", "fixtures", "empire", "integration", name);
    }

    /// <summary>Read the full audit log JSONL. Disposes the writer first so all rows are flushed.</summary>
    public string ReadAuditLogFlushed()
    {
        Audit.Dispose();
        return File.ReadAllText(AuditPath);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { CredBridge.Dispose(); } catch { }
        try { CredClient.Dispose(); } catch { }
        try { EmpireRest.Dispose(); } catch { }
        try { _stagerHttp.Dispose(); } catch { }
        try { _credHttp.Dispose(); } catch { }
        try { Audit.Dispose(); } catch { }
        try { if (File.Exists(AuditPath)) File.Delete(AuditPath); } catch { }
        try { if (Directory.Exists(OutputRoot)) Directory.Delete(OutputRoot, recursive: true); } catch { }
    }
}

/// <summary>Stub HttpMessageHandler that replays a queue of canned responses.</summary>
internal sealed class StubHandler : HttpMessageHandler
{
    public Queue<HttpResponseMessage> Responses { get; } = new();
    public List<HttpRequestMessage> Requests { get; } = new();
    public List<string> RequestBodies { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        if (request.Content != null)
        {
            try { RequestBodies.Add(await request.Content.ReadAsStringAsync(cancellationToken)); }
            catch { RequestBodies.Add(string.Empty); }
        }
        else
        {
            RequestBodies.Add(string.Empty);
        }
        if (Responses.Count == 0)
        {
            return new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("{\"error\":\"no canned response\"}",
                    Encoding.UTF8, "application/json"),
            };
        }
        return Responses.Dequeue();
    }
}

/// <summary>Marker / state-recording wrapper around the real EmpireRestClient.
/// The real client is constructed with a stub-handler-backed HttpClient so
/// every request flows through; this wrapper exposes it under the name
/// the task description asks for.</summary>
internal sealed class FakeEmpireRestClient : IDisposable
{
    public EmpireRestClient Inner { get; }
    public FakeEmpireRestClient(EmpireOptions opts, AuditLog audit, HttpClient http)
    {
        Inner = new EmpireRestClient(opts, audit, http);
    }
    public void Dispose() => Inner.Dispose();
}

/// <summary>In-memory registry of registered Empire agents. Stand-in for
/// the real Empire server's <c>/api/v2/agents</c> surface.</summary>
internal sealed class FakeEmpireServer
{
    private readonly ConcurrentDictionary<string, EmpireSession> _agents = new(StringComparer.Ordinal);

    public IReadOnlyCollection<EmpireSession> Agents => _agents.Values.ToArray();

    public EmpireSession Checkin(string agentId, string host, string user, string listener)
    {
        var session = new EmpireSession(agentId, host, user, listener, DateTimeOffset.UtcNow);
        _agents[agentId] = session;
        return session;
    }

    public bool Disconnect(string agentId) => _agents.TryRemove(agentId, out _);
}

/// <summary>Simulated SessionManager. Records register/close to audit and
/// re-validates the host against scope at registration time so the scope
/// invariant is exercised even though no real
/// <see cref="SessionManager"/> is wired (it depends on real PostExLinux /
/// PostExWindows tools that would require subprocess infra).</summary>
internal sealed class FakeSessionManager
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly ConcurrentDictionary<string, EmpireSession> _live = new(StringComparer.Ordinal);

    public FakeSessionManager(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope;
        _audit = audit;
    }

    public IReadOnlyCollection<EmpireSession> Live => _live.Values.ToArray();

    public EmpireSession Register(EmpireSession session)
    {
        _scope.Require(session.Host);
        _live[session.AgentId] = session;
        _audit.Record("empire.session.registered", new Dictionary<string, object?>
        {
            ["agent_id"] = session.AgentId,
            ["host"] = session.Host,
            ["listener"] = session.Listener,
        });
        return session;
    }

    public bool Close(string agentId)
    {
        if (!_live.TryRemove(agentId, out var session)) return false;
        _audit.Record("empire.session.closed", new Dictionary<string, object?>
        {
            ["agent_id"] = agentId,
            ["host"] = session.Host,
        });
        return true;
    }
}

/// <summary>Canned in-process replacement for <see cref="ExploitRunner"/>'s
/// stager-delivery path. Mirrors the real <c>empire.delivery.prepare</c> /
/// <c>empire.delivery.dispatch</c> audit shape and re-checks scope + the
/// <c>AllowPayloads</c> gate exactly the way the production runner does.</summary>
internal sealed class FakeExploitRunner
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;

    public List<string> DeliveredTo { get; } = new();
    public bool DeliveryShouldFail { get; set; }

    public FakeExploitRunner(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope;
        _audit = audit;
    }

    /// <summary>Mirrors <see cref="ExploitRunner.DeliverEmpireArtifactAsync"/>.</summary>
    public Task<(bool success, string? error)> DeliverEmpireArtifactAsync(
        string target, EmpireDeliveryArtifact artifact, RunPermissions permissions,
        CancellationToken ct = default)
    {
        // @invariant-id:scope-in-every-tool — first statement.
        _scope.Require(target);
        ArgumentNullException.ThrowIfNull(artifact);
        ArgumentNullException.ThrowIfNull(permissions);

        if (!permissions.AllowPayloads)
        {
            _audit.Record("empire.delivery.refused", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["reason"] = "permission_refused",
                ["required_flag"] = "--allow-payloads",
            });
            throw new PermissionRefusedException(
                $"empire.delivery: category Payloads not permitted this run (pass --allow-payloads to opt in).",
                ExploitCategory.Payloads);
        }

        _audit.Record("empire.delivery.prepare", artifact.ToAuditFields(target));

        if (DeliveryShouldFail)
        {
            _audit.Record("empire.delivery.dispatch", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["kind"] = artifact.Kind.ToString().ToLowerInvariant(),
                ["listener"] = artifact.ListenerName,
                ["payload_sha256"] = artifact.PayloadSha256,
                ["payload_length"] = artifact.PayloadLength,
                ["success"] = false,
                ["error"] = "fake-delivery-failure",
            });
            return Task.FromResult<(bool, string?)>((false, "fake-delivery-failure"));
        }

        DeliveredTo.Add(target);
        _audit.Record("empire.delivery.dispatch", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["kind"] = artifact.Kind.ToString().ToLowerInvariant(),
            ["listener"] = artifact.ListenerName,
            ["payload_sha256"] = artifact.PayloadSha256,
            ["payload_length"] = artifact.PayloadLength,
            ["success"] = true,
            ["error"] = (string?)null,
        });
        return Task.FromResult<(bool, string?)>((true, null));
    }
}

/// <summary>Raised by the harness when <see cref="EmpireTestHarness.EmpireAutopilotEnabled"/>
/// is false but the test attempts to drive the full Empire flow. Stand-in
/// for a not-yet-existing <c>--empire-autopilot</c> CLI flag refusal
/// path; lets the gate be asserted without editing CLI-owned files.</summary>
internal sealed class EmpireAutopilotDisabledException : Exception
{
    public EmpireAutopilotDisabledException()
        : base("Empire autopilot disabled: pass --empire-autopilot to opt in.") { }
}

/// <summary>Parsed scenario fixture. Output fields contain <c>${CANARY}</c>
/// placeholders; tests substitute the per-test canary via
/// <see cref="ApplyCanary"/>.</summary>
internal sealed record Scenario(
    string Name,
    string Target,
    string Platform,
    string AgentId,
    string AgentUser,
    string Listener,
    string StagerResponseJson,
    string? MimikatzOutput,
    string? SshKeysOutput,
    string? PortscanOutput,
    IReadOnlyList<string> ExtraTargets)
{
    public static Scenario Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        var extras = new List<string>();
        if (r.TryGetProperty("extra_targets", out var et) && et.ValueKind == JsonValueKind.Array)
        {
            foreach (var e in et.EnumerateArray()) extras.Add(e.GetString() ?? "");
        }
        string? mim = r.TryGetProperty("mimikatz_output", out var m) ? m.GetString() : null;
        string? ssh = r.TryGetProperty("ssh_keys_output", out var s) ? s.GetString() : null;
        string? ps  = r.TryGetProperty("portscan_output", out var p) ? p.GetString() : null;
        var stager = r.GetProperty("stager_response").GetRawText();
        return new Scenario(
            r.GetProperty("name").GetString() ?? "",
            r.GetProperty("target").GetString() ?? "",
            r.GetProperty("platform").GetString() ?? "",
            r.GetProperty("agent_id").GetString() ?? "",
            r.GetProperty("agent_user").GetString() ?? "",
            r.GetProperty("listener").GetString() ?? "",
            stager, mim, ssh, ps, extras);
    }

    public Scenario ApplyCanary(string canary) => this with
    {
        MimikatzOutput = MimikatzOutput?.Replace("${CANARY}", canary),
        SshKeysOutput = SshKeysOutput?.Replace("${CANARY}", canary),
        PortscanOutput = PortscanOutput?.Replace("${CANARY}", canary),
    };
}
