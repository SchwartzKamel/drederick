using System.Net.Http;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Exploit;
using Drederick.Scope;
using Microsoft.Extensions.AI;
using Xunit;

namespace Drederick.Tests.Autopilot;

/// <summary>
/// Tests the production <see cref="CveLeadLlmAuthorChatClient"/> adapter
/// that wires a real <see cref="IChatClient"/> behind the bridge's
/// <see cref="CveLeadLlmAuthorFunc"/> contract. Closes the
/// "no training wheels" gap exposed at commit 10dfa86 (bridge shipped
/// with <c>llm: null</c>; fallback always emitted no_llm_key).
/// </summary>
public sealed class CveLeadLlmAuthorChatClientTests : IDisposable
{
    private readonly string _outDir;
    private readonly string _auditPath;

    public CveLeadLlmAuthorChatClientTests()
    {
        _outDir = Path.Combine(Path.GetTempPath(), $"drederick-cve-llm-cc-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_outDir);
        _auditPath = Path.Combine(_outDir, "audit.jsonl");
    }

    public void Dispose()
    {
        try { Directory.Delete(_outDir, recursive: true); } catch { }
    }

    private const string InScope = "10.129.10.5";

    private static CveLeadPromptContext Ctx() =>
        new(CveId: "CVE-2026-99999",
            Target: InScope,
            Port: 80,
            Service: "http",
            Url: $"http://{InScope}/",
            Reason: "matched on nginx 1.18 (lab corpus)",
            BannerHint: null);

    /// <summary>
    /// Capture-everything shell runner stand-in. Records call count;
    /// returns canned ExecShellResult.
    /// </summary>
    private sealed class FakeShellRunner : ICveLeadShellRunner
    {
        public int CallCount;
        public string? LastCommand;
        public ExecShellResult Result { get; init; } = new()
        {
            ArgvDigest = "deadbeef",
            ArgvCount = 3,
            Binary = "curl",
            ExitCode = 0,
            StdoutTruncated = "",
            StderrTruncated = "",
        };
        public bool ThrowBudget;

        public Task<ExecShellResult> RunAsync(string command, string? workingDirHint, CancellationToken ct)
        {
            Interlocked.Increment(ref CallCount);
            LastCommand = command;
            if (ThrowBudget)
                throw new CveLeadShellBudgetExceededException("test budget");
            return Task.FromResult(Result);
        }
    }

    /// <summary>
    /// Programmable IChatClient: returns scripted ChatResponses in order.
    /// Each script entry is either a function-call directive (call exec_shell)
    /// or a text response. Throws when a script entry of type Throw is hit.
    /// </summary>
    private sealed class ScriptedChatClient : IChatClient
    {
        private readonly Queue<ScriptStep> _script;
        public int Calls;
        public ScriptedChatClient(IEnumerable<ScriptStep> script) { _script = new(script); }

        public Task<ChatResponse> GetResponseAsync(
            IEnumerable<ChatMessage> messages, ChatOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref Calls);
            if (_script.Count == 0)
            {
                // Default: fall through with an empty assistant message so the
                // FunctionInvokingChatClient stops cleanly.
                return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "")));
            }
            var step = _script.Dequeue();
            return step switch
            {
                ScriptStep.Throw th => throw th.Exception,
                ScriptStep.Cancel => Cancel(cancellationToken),
                ScriptStep.Text t => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, t.Body))),
                ScriptStep.Tool tc => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant,
                    new List<AIContent>
                    {
                        new FunctionCallContent(tc.CallId, tc.Name,
                            new Dictionary<string, object?>
                            {
                                ["command"] = tc.Command,
                                ["working_dir_hint"] = (string?)null,
                            }),
                    }))),
                _ => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, ""))),
            };

            static Task<ChatResponse> Cancel(CancellationToken ct)
            {
                throw new OperationCanceledException(ct);
            }
        }

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages, ChatOptions? options = null,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;
        public void Dispose() { }
    }

    private abstract record ScriptStep
    {
        public sealed record Text(string Body) : ScriptStep;
        public sealed record Tool(string Name, string Command, string CallId = "call_1") : ScriptStep;
        public sealed record Throw(Exception Exception) : ScriptStep;
        public sealed record Cancel : ScriptStep;
    }

    // 1. No env / no chat client at all → adapter is never built; bridge
    //    handles no_llm_key on its own. We assert the adapter REJECTS a
    //    null chat client (defense-in-depth: callers should guard but the
    //    constructor enforces).
    [Fact]
    public void Constructor_NullChatClient_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => new CveLeadLlmAuthorChatClient(null!, "model"));
    }

    [Fact]
    public void Constructor_BlankModel_Throws()
    {
        var fake = new ScriptedChatClient([]);
        Assert.Throws<ArgumentException>(
            () => new CveLeadLlmAuthorChatClient(fake, ""));
    }

    // 2. LLM returns plain text "skip" → adapter returns Skip.
    [Fact]
    public async Task Skip_TextResponse_ReturnsSkip()
    {
        var fake = new ScriptedChatClient(
            [new ScriptStep.Text("skip — no probe known for this CVE")]);
        var adapter = new CveLeadLlmAuthorChatClient(fake, "test-model");
        var shell = new FakeShellRunner();

        var decision = await adapter.AuthorAsync(Ctx(), shell, default);

        Assert.IsType<CveLeadLlmDecision.Skip>(decision);
        Assert.Equal(0, shell.CallCount);
        var skip = (CveLeadLlmDecision.Skip)decision;
        Assert.StartsWith("skip", skip.Reason, StringComparison.OrdinalIgnoreCase);
    }

    // 3. LLM calls exec_shell once → adapter returns ShellAuthored with
    //    the captured ExecShellResult.
    [Fact]
    public async Task ToolCall_Once_ReturnsShellAuthored()
    {
        var fake = new ScriptedChatClient(
        [
            new ScriptStep.Tool("exec_shell", "curl -s http://10.129.10.5/"),
            // Wrap-up after FunctionInvokingChatClient injects the tool result.
            new ScriptStep.Text("ran probe"),
        ]);
        var adapter = new CveLeadLlmAuthorChatClient(fake, "test-model");
        var shell = new FakeShellRunner();

        var decision = await adapter.AuthorAsync(Ctx(), shell, default);

        var sa = Assert.IsType<CveLeadLlmDecision.ShellAuthored>(decision);
        Assert.Equal(1, shell.CallCount);
        Assert.Equal("deadbeef", sa.Result.ArgvDigest);
        Assert.Contains("curl", shell.LastCommand);
    }

    // 4. LLM tries to call exec_shell twice → adapter caps at one and
    //    returns ShellAuthored for the first call's result. The second
    //    call short-circuits with budget_exceeded back to the model.
    [Fact]
    public async Task ToolCall_Twice_FirstResultPreserved_BudgetEnforced()
    {
        var fake = new ScriptedChatClient(
        [
            new ScriptStep.Tool("exec_shell", "curl -s http://10.129.10.5/", CallId: "call_a"),
            new ScriptStep.Tool("exec_shell", "curl -s http://10.129.10.5/again", CallId: "call_b"),
            new ScriptStep.Text("done"),
        ]);
        var adapter = new CveLeadLlmAuthorChatClient(fake, "test-model");
        var shell = new FakeShellRunner();

        var decision = await adapter.AuthorAsync(Ctx(), shell, default);

        // The first tool call captured a result — that wins. We do NOT
        // collapse to Error just because the model later misbehaved.
        var sa = Assert.IsType<CveLeadLlmDecision.ShellAuthored>(decision);
        Assert.Equal("deadbeef", sa.Result.ArgvDigest);
        // Second call must NOT have invoked the underlying shell runner.
        Assert.Equal(1, shell.CallCount);
    }

    // 5. LLM throws (network exception) → adapter classifies network and
    //    returns Error.
    [Fact]
    public async Task NetworkException_ReturnsErrorWithNetworkKind()
    {
        var fake = new ScriptedChatClient(
            [new ScriptStep.Throw(new HttpRequestException("connection reset"))]);
        var adapter = new CveLeadLlmAuthorChatClient(fake, "test-model");
        var shell = new FakeShellRunner();

        var decision = await adapter.AuthorAsync(Ctx(), shell, default);

        var err = Assert.IsType<CveLeadLlmDecision.Error>(decision);
        Assert.Contains("network", err.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, shell.CallCount);
    }

    // 6. Cancellation token cancels mid-call → adapter returns
    //    Error("cancelled"). No exception propagates.
    [Fact]
    public async Task Cancellation_ReturnsErrorCancelled_NoExceptionLeaks()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var fake = new ScriptedChatClient([new ScriptStep.Cancel()]);
        var adapter = new CveLeadLlmAuthorChatClient(fake, "test-model");
        var shell = new FakeShellRunner();

        var decision = await adapter.AuthorAsync(Ctx(), shell, cts.Token);

        var err = Assert.IsType<CveLeadLlmDecision.Error>(decision);
        Assert.Equal("cancelled", err.Message);
    }

    // 7. Auth-style 401 message buckets as auth.
    [Fact]
    public async Task UnauthorizedException_ReturnsErrorWithAuthKind()
    {
        var fake = new ScriptedChatClient(
            [new ScriptStep.Throw(new InvalidOperationException("HTTP 401 Unauthorized: bad token"))]);
        var adapter = new CveLeadLlmAuthorChatClient(fake, "test-model");
        var shell = new FakeShellRunner();

        var decision = await adapter.AuthorAsync(Ctx(), shell, default);

        var err = Assert.IsType<CveLeadLlmDecision.Error>(decision);
        Assert.Contains("auth", err.Message, StringComparison.OrdinalIgnoreCase);
    }

    // 8. Plaintext canary in LLM response — adapter MUST NOT log raw text
    //    anywhere it owns. The adapter has no audit dependency; verify by
    //    asserting that no audit log is written by the adapter (the file
    //    we provide stays empty).
    [Fact]
    public async Task PlaintextCanary_AdapterNeverLogsRawResponseText()
    {
        const string canary = "PLAINTEXT_CANARY_HUNTER2";
        var fake = new ScriptedChatClient(
            [new ScriptStep.Text($"skip {canary} — model reasoning")]);
        var adapter = new CveLeadLlmAuthorChatClient(fake, "test-model");
        var shell = new FakeShellRunner();

        // Pre-touch the audit path; adapter must NOT write to it.
        File.WriteAllText(_auditPath, "");
        using (var audit = new AuditLog(_auditPath))
        {
            // adapter has no audit dependency — just sanity that the file
            // exists and the lifetime is bounded.
        }

        var decision = await adapter.AuthorAsync(Ctx(), shell, default);

        // The Skip reason is bounded (single line, ≤200 chars) but we
        // accept that the canary may appear in the bounded reason itself
        // — the bridge owns that audit decision. The contract here is
        // "adapter writes no logs of its own."
        var auditText = File.ReadAllText(_auditPath);
        Assert.DoesNotContain(canary, auditText);
        Assert.IsType<CveLeadLlmDecision.Skip>(decision);
    }

    // 9. AsFunc() wires the adapter into the bridge contract.
    [Fact]
    public void AsFunc_ReturnsDelegateMatchingFuncSignature()
    {
        var fake = new ScriptedChatClient([]);
        var adapter = new CveLeadLlmAuthorChatClient(fake, "test-model");
        CveLeadLlmAuthorFunc f = adapter.AsFunc();
        Assert.NotNull(f);
    }

    // 10. End-to-end through the bridge: real CveLeadLlmAuthor + adapter
    //     + scripted IChatClient + canned shell runner. Proves the wiring
    //     produces the correct audit chain when the LLM authors a shell.
    [Fact]
    public async Task EndToEndThroughBridge_LlmAuthors_FullAuditChain()
    {
        var fake = new ScriptedChatClient(
        [
            new ScriptStep.Tool("exec_shell", "curl -s http://10.129.10.5/"),
            new ScriptStep.Text("ran"),
        ]);
        var adapter = new CveLeadLlmAuthorChatClient(fake, "test-model");

        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecShell: true, allowCveLeadLlmAuthor: true);
        var scope = ScopeLoader.Parse("10.129.0.0/16");
        var execShell = new LlmExecShellTool(scope, audit, perms, _outDir,
            spawn: (binary, argv, workDir, timeout, ct) =>
                Task.FromResult(new ExecShellSpawnResult(0, [], [], TimedOut: false)));

        var bridge = new CveLeadLlmAuthor(scope, audit, perms, execShell, adapter.AsFunc());

        var action = new ExploitAction
        {
            Tool = "cve-lead",
            Target = InScope,
            Port = 80,
            Protocol = "http",
            Url = $"http://{InScope}/",
            Reason = "matched CVE-2026-99999",
            CveId = "CVE-2026-99999",
            Priority = 250,
            Category = "execpocs",
        };

        var result = await bridge.TryAuthorAsync(action,
            new System.Collections.Concurrent.ConcurrentDictionary<string, byte>());

        Assert.Equal(CveLeadLlmAuthorOutcome.ShellAuthored, result.Outcome);
        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("\"cve.lead.llm_author.start\"", auditText);
        Assert.Contains("\"cve.lead.llm_author.shell_authored\"", auditText);
        Assert.Contains("\"outcome\":\"shell_authored\"", auditText);
    }
}
