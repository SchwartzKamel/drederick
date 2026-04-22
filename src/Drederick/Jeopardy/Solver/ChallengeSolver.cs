using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Jeopardy.Budget;
using Drederick.Jeopardy.Bus;
using Drederick.Jeopardy.Ctfd;
using Drederick.Jeopardy.Detection;
using Drederick.Jeopardy.Llm;
using Drederick.Jeopardy.Prompts;
using Drederick.Jeopardy.Sandbox;
using Drederick.Jeopardy.Submit;
using Microsoft.Extensions.AI;

namespace Drederick.Jeopardy.Solver;

/// <summary>
/// Single-model Jeopardy CTF solver. Drives one LLM + one Docker sandbox in
/// an iterative tool-using loop until the flag is found, another solver in
/// the swarm wins, a loop is detected, the wall-clock / budget / max-turns
/// runs out, or the model gives up.
///
/// <para>Hard invariants enforced here:</para>
/// <list type="bullet">
///   <item>Budget is checked <b>first</b> every turn via
///     <see cref="ICostTracker.AssertWithinBudget"/>.</item>
///   <item>Peer wins short-circuit the loop via
///     <see cref="IFlagSubmitCoordinator.IsSolved"/>.</item>
///   <item>Every chat + tool call is fingerprinted and observed by the
///     <see cref="ILoopDetector"/>.</item>
///   <item>Tool arguments are audited as SHA-256 only; plaintext flags
///     never reach the audit log — submission goes through
///     <see cref="IFlagSubmitCoordinator"/> which hashes internally.</item>
///   <item>The sandbox is disposed in a <c>finally</c> block so the
///     container cannot outlive the solver even on exception.</item>
/// </list>
/// </summary>
public sealed class ChallengeSolver : IChallengeSolver
{
    private const int SandboxReadCapBytes = 1 * 1024 * 1024;
    private const int SandboxWriteCapBytes = 10 * 1024 * 1024;
    private const int ToolStdoutBudgetBytes = 16 * 1024;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly ICopilotLlmClient _llm;
    private readonly SandboxManager _sandboxes;
    private readonly IFlagSubmitCoordinator _flagSubmit;
    private readonly ISolverMessageBus _bus;
    private readonly ICostTracker _costs;
    private readonly ILoopDetector _loopDetector;
    private readonly AuditLog _audit;

    public ChallengeSolver(
        ICopilotLlmClient llm,
        SandboxManager sandboxes,
        IFlagSubmitCoordinator flagSubmit,
        ISolverMessageBus bus,
        ICostTracker costs,
        ILoopDetector loopDetector,
        AuditLog audit)
    {
        _llm = llm ?? throw new ArgumentNullException(nameof(llm));
        _sandboxes = sandboxes ?? throw new ArgumentNullException(nameof(sandboxes));
        _flagSubmit = flagSubmit ?? throw new ArgumentNullException(nameof(flagSubmit));
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _costs = costs ?? throw new ArgumentNullException(nameof(costs));
        _loopDetector = loopDetector ?? throw new ArgumentNullException(nameof(loopDetector));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    public async Task<SolverRunResult> SolveAsync(CtfdChallenge chal, SolverConfig cfg, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(chal);
        ArgumentNullException.ThrowIfNull(cfg);
        ArgumentException.ThrowIfNullOrWhiteSpace(cfg.ModelId);

        var solverId = $"{cfg.ModelId}@chal{chal.Id}";
        var chalIdStr = chal.Id.ToString(CultureInfo.InvariantCulture);
        var wallClock = cfg.WallClock ?? TimeSpan.FromMinutes(20);

        using var wallCts = new CancellationTokenSource(wallClock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, wallCts.Token);

        _audit.Record("solver.start", new Dictionary<string, object?>
        {
            ["solver_id"] = solverId,
            ["model"] = cfg.ModelId,
            ["challenge_id"] = chal.Id,
            ["challenge"] = chal.Name,
            ["category"] = chal.Category,
            ["max_turns"] = cfg.MaxTurns,
            ["wall_clock_seconds"] = (int)wallClock.TotalSeconds,
            ["per_challenge_budget_usd"] = cfg.PerChallengeBudgetUsd?.ToString("F6", CultureInfo.InvariantCulture),
        });

        var started = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();
        var state = new SolverState(solverId, cfg.ModelId, chal.Id, chalIdStr);

        LoopReport? pendingLoop = null;
        Action<LoopReport> onLoop = r =>
        {
            if (string.Equals(r.SolverId, solverId, StringComparison.Ordinal)
                && string.Equals(r.ChallengeId, chalIdStr, StringComparison.Ordinal)
                && Volatile.Read(ref pendingLoop) is null)
            {
                Interlocked.CompareExchange(ref pendingLoop, r, null);
            }
        };
        _loopDetector.LoopDetected += onLoop;

        ISandboxSession? session = null;
        try
        {
            var spec = SandboxSpec.ForChallenge(
                challengeId: chal.Id,
                challengeName: chal.Name,
                category: chal.Category,
                attachments: null,
                connectionInfo: chal.ConnectionInfo);

            session = await _sandboxes.StartAsync(spec, linked.Token).ConfigureAwait(false);

            var chalContext = new ChallengeContext(
                Id: chal.Id,
                Name: chal.Name,
                Category: chal.Category,
                Points: chal.Value,
                DescriptionPlaintext: chal.Description ?? string.Empty,
                AttachmentFileNames: chal.Files?.Select(f => f.Name).ToArray() ?? Array.Empty<string>(),
                ConnectionInfo: chal.ConnectionInfo,
                Tags: chal.Tags ?? Array.Empty<string>());

            var prompts = PromptLibrary.Build(chalContext, solverId, cfg.ModelId);

            var messages = new List<CopilotChatMessage>
            {
                new("system", prompts.System),
                new("user", prompts.InitialUser),
            };

            // Pre-fetch peer insights and inject BEFORE the first LLM call so
            // the swarm's shared knowledge compounds from turn 1.
            var peerSummary = BuildPeerInsightSummary(chalIdStr, solverId);
            if (peerSummary is not null)
            {
                messages.Add(new CopilotChatMessage("user", peerSummary));
            }

            var tools = BuildAiTools();

            while (state.Turns < cfg.MaxTurns)
            {
                linked.Token.ThrowIfCancellationRequested();

                // 1. Budget check FIRST.
                try
                {
                    _costs.AssertWithinBudget(chalIdStr);
                }
                catch (BudgetExceededException ex)
                {
                    return Finalize(state, SolverOutcome.BudgetExceeded, null, null,
                        $"budget:{ex.Scope}:{ex.Cap:F6}", sw, started, session, cfg);
                }

                if (cfg.PerChallengeBudgetUsd is decimal localCap
                    && _costs.UsdForChallenge(chalIdStr) >= localCap)
                {
                    _audit.Record("cost.budget_exceeded", new Dictionary<string, object?>
                    {
                        ["scope"] = $"challenge:{chalIdStr}",
                        ["cap_usd"] = localCap.ToString("F6", CultureInfo.InvariantCulture),
                        ["actual_usd"] = _costs.UsdForChallenge(chalIdStr).ToString("F6", CultureInfo.InvariantCulture),
                        ["solver_id"] = solverId,
                    });
                    return Finalize(state, SolverOutcome.BudgetExceeded, null, null,
                        $"budget:local_challenge_cap:{localCap:F6}", sw, started, session, cfg);
                }

                // 2. Peer win? Fast-exit.
                if (_flagSubmit.IsSolved(chal.Id))
                {
                    return Finalize(state, SolverOutcome.GaveUp, null, null,
                        "peer_won", sw, started, session, cfg);
                }

                // 3. Existing loop? (event handler catches Observe-triggered
                //    detections; also re-check in case a latent buffer trips.)
                var prior = Volatile.Read(ref pendingLoop) ?? _loopDetector.CheckForLoop(solverId, chalIdStr);
                if (prior is not null)
                {
                    await PublishLoopHintAsync(prior, linked.Token).ConfigureAwait(false);
                    return Finalize(state, SolverOutcome.LoopDetected, null, prior.LoopKind,
                        "loop_" + prior.LoopKind, sw, started, session, cfg);
                }

                state.Turns++;

                // 4. LLM call with a single-shot retry on 429/5xx.
                CopilotChatResponse response;
                try
                {
                    response = await ChatWithRetryAsync(cfg.ModelId, messages, tools, linked.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (wallCts.IsCancellationRequested && !ct.IsCancellationRequested)
                {
                    return Finalize(state, SolverOutcome.Timeout, null, null,
                        "wall_clock", sw, started, session, cfg);
                }
                catch (CopilotLlmException ex)
                {
                    _audit.Record("solver.llm_error", new Dictionary<string, object?>
                    {
                        ["solver_id"] = solverId,
                        ["turn"] = state.Turns,
                        ["status"] = ex.StatusCode.HasValue ? (int)ex.StatusCode.Value : (int?)null,
                    });
                    return Finalize(state, SolverOutcome.Error, null, null,
                        "llm:" + (ex.StatusCode?.ToString() ?? "transport"), sw, started, session, cfg);
                }

                _costs.Record(response.ModelId, response.PromptTokens, response.CompletionTokens,
                    chalIdStr, solverId);

                var chatFingerprint = ComputeChatFingerprint(response);
                _loopDetector.Observe(new SolverAction(
                    solverId, chalIdStr, "chat", chatFingerprint, DateTimeOffset.UtcNow));

                _audit.Record("solver.turn", new Dictionary<string, object?>
                {
                    ["solver_id"] = solverId,
                    ["challenge_id"] = chal.Id,
                    ["turn"] = state.Turns,
                    ["tool_calls_count"] = response.ToolCalls.Count,
                    ["prompt_tokens"] = response.PromptTokens,
                    ["completion_tokens"] = response.CompletionTokens,
                    ["content_sha256"] = Sha256Hex(response.Content ?? string.Empty),
                });

                // 5. Dispatch tool calls (if any).
                if (response.ToolCalls.Count > 0)
                {
                    // Append a stub assistant message so the chat history
                    // reflects that the model invoked tools. We never feed the
                    // model's reasoning back to the audit as plaintext.
                    var assistantStub = "[assistant requested " + response.ToolCalls.Count + " tool(s)]"
                        + (string.IsNullOrEmpty(response.Content) ? string.Empty : "\n" + response.Content);
                    messages.Add(new CopilotChatMessage("assistant", assistantStub));

                    var dispatchOutcome = await DispatchToolCallsAsync(
                        response.ToolCalls,
                        cfg.MaxParallelToolCalls,
                        session!,
                        state,
                        chal,
                        cfg,
                        messages,
                        linked.Token).ConfigureAwait(false);

                    if (dispatchOutcome is not null)
                    {
                        return Finalize(state,
                            dispatchOutcome.Value.Outcome,
                            dispatchOutcome.Value.FlagSha256,
                            null,
                            dispatchOutcome.Value.Reason,
                            sw, started, session, cfg);
                    }

                    state.ConsecutiveEmptyResponses = 0;
                }
                else
                {
                    // Free-text only. Append it to the history so the model
                    // has continuity, but never auto-submit a flag glimpsed
                    // in content — only the submit_flag tool triggers.
                    messages.Add(new CopilotChatMessage("assistant", response.Content ?? string.Empty));

                    var trimmed = (response.Content ?? string.Empty).Trim();
                    if (trimmed.Length < 8)
                    {
                        state.ConsecutiveEmptyResponses++;
                        if (state.ConsecutiveEmptyResponses >= 2)
                        {
                            return Finalize(state, SolverOutcome.OutOfDepth, null, null,
                                "short_response_twice", sw, started, session, cfg);
                        }
                    }
                    else
                    {
                        state.ConsecutiveEmptyResponses = 0;
                    }

                    if (MentionsPossibleFlag(trimmed))
                    {
                        messages.Add(new CopilotChatMessage("user",
                            "You appear to have a candidate flag in your last message. " +
                            "Do NOT write it in free-text. Call the submit_flag tool with the " +
                            "flag argument so it can be validated."));
                    }
                    else
                    {
                        messages.Add(new CopilotChatMessage("user",
                            "Continue. Use a tool — sandbox_exec, sandbox_read_file, " +
                            "sandbox_write_file, publish_insight, get_insights, submit_flag, " +
                            "or give_up."));
                    }
                }

                // 6. Re-check loop detector after this turn's observations.
                var post = Volatile.Read(ref pendingLoop) ?? _loopDetector.CheckForLoop(solverId, chalIdStr);
                if (post is not null)
                {
                    await PublishLoopHintAsync(post, linked.Token).ConfigureAwait(false);
                    return Finalize(state, SolverOutcome.LoopDetected, null, post.LoopKind,
                        "loop_" + post.LoopKind, sw, started, session, cfg);
                }
            }

            // Ran out of turns without a terminal outcome.
            return Finalize(state, SolverOutcome.GaveUp, null, null,
                "max_turns", sw, started, session, cfg);
        }
        catch (OperationCanceledException) when (wallCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return Finalize(state, SolverOutcome.Timeout, null, null,
                "wall_clock", sw, started, session, cfg);
        }
        catch (OperationCanceledException)
        {
            return Finalize(state, SolverOutcome.Error, null, null,
                "cancelled", sw, started, session, cfg);
        }
        catch (Exception ex)
        {
            _audit.Record("solver.exception", new Dictionary<string, object?>
            {
                ["solver_id"] = solverId,
                ["error"] = ex.GetType().Name,
            });
            return Finalize(state, SolverOutcome.Error, null, null,
                ex.GetType().Name, sw, started, session, cfg);
        }
        finally
        {
            _loopDetector.LoopDetected -= onLoop;
            if (session is not null)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); }
                catch { /* swallowed — cleanup is best-effort */ }
            }
        }
    }

    // ------------------------------------------------------------------
    // Tool dispatch
    // ------------------------------------------------------------------

    /// <summary>Outcome emitted by tool dispatch that terminates the solver loop.</summary>
    private readonly record struct DispatchTerminal(SolverOutcome Outcome, string? FlagSha256, string? Reason);

    private async Task<DispatchTerminal?> DispatchToolCallsAsync(
        IReadOnlyList<CopilotToolCall> calls,
        int maxParallel,
        ISandboxSession session,
        SolverState state,
        CtfdChallenge chal,
        SolverConfig cfg,
        List<CopilotChatMessage> messages,
        CancellationToken ct)
    {
        maxParallel = Math.Max(1, maxParallel);
        using var gate = new SemaphoreSlim(maxParallel, maxParallel);

        var results = new (CopilotToolCall Call, ToolCallResult Result)[calls.Count];
        var tasks = new Task[calls.Count];

        for (int i = 0; i < calls.Count; i++)
        {
            var idx = i;
            var call = calls[i];
            tasks[i] = Task.Run(async () =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    var r = await InvokeToolAsync(call, session, state, chal, cfg, ct)
                        .ConfigureAwait(false);
                    results[idx] = (call, r);
                }
                finally
                {
                    gate.Release();
                }
            }, ct);
        }

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }

        // Feed results back to the model in-order as user messages so the
        // chat history is deterministic regardless of parallel completion.
        DispatchTerminal? terminal = null;
        foreach (var (call, result) in results)
        {
            messages.Add(new CopilotChatMessage("user",
                $"[tool:{call.Name}] {result.ContentJson}"));

            if (result.Terminal is DispatchTerminal t && terminal is null)
            {
                terminal = t;
            }
        }
        return terminal;
    }

    private readonly record struct ToolCallResult(string ContentJson, DispatchTerminal? Terminal);

    private async Task<ToolCallResult> InvokeToolAsync(
        CopilotToolCall call,
        ISandboxSession session,
        SolverState state,
        CtfdChallenge chal,
        SolverConfig cfg,
        CancellationToken ct)
    {
        var argsDigest = Sha256Hex(call.ArgumentsJson ?? string.Empty);
        var callFingerprint = Sha256Hex((call.Name ?? "?") + "\x1f" + argsDigest);

        _loopDetector.Observe(new SolverAction(
            state.SolverId, state.ChallengeIdStr, "tool_call", callFingerprint, DateTimeOffset.UtcNow));

        _audit.Record($"solver.tool.{call.Name}.start", new Dictionary<string, object?>
        {
            ["solver_id"] = state.SolverId,
            ["challenge_id"] = state.ChallengeId,
            ["turn"] = state.Turns,
            ["args_sha256"] = argsDigest,
            ["call_id"] = call.Id,
        });

        JsonElement args;
        try
        {
            args = string.IsNullOrWhiteSpace(call.ArgumentsJson)
                ? JsonDocument.Parse("{}").RootElement
                : JsonDocument.Parse(call.ArgumentsJson).RootElement;
        }
        catch (JsonException)
        {
            return AuditAndReturn(call, argsDigest,
                new ToolCallResult("{\"error\":\"invalid_arguments_json\"}", null));
        }

        var sw = Stopwatch.StartNew();
        try
        {
            ToolCallResult result = call.Name switch
            {
                "sandbox_exec" => await DoSandboxExecAsync(session, args, ct).ConfigureAwait(false),
                "sandbox_read_file" => await DoSandboxReadAsync(session, args, ct).ConfigureAwait(false),
                "sandbox_write_file" => await DoSandboxWriteAsync(session, args, ct).ConfigureAwait(false),
                "submit_flag" => await DoSubmitFlagAsync(args, state, chal, ct).ConfigureAwait(false),
                "publish_insight" => await DoPublishInsightAsync(args, state, cfg, ct).ConfigureAwait(false),
                "get_insights" => DoGetInsights(state),
                "give_up" => DoGiveUp(args),
                _ => new ToolCallResult(
                    JsonSerializer.Serialize(new { error = "unknown_tool", name = call.Name }, Json),
                    null),
            };

            sw.Stop();
            _audit.Record($"solver.tool.{call.Name}.finish", new Dictionary<string, object?>
            {
                ["solver_id"] = state.SolverId,
                ["challenge_id"] = state.ChallengeId,
                ["turn"] = state.Turns,
                ["args_sha256"] = argsDigest,
                ["call_id"] = call.Id,
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
                ["terminal"] = result.Terminal?.Outcome.ToString(),
            });
            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            sw.Stop();
            _audit.Record($"solver.tool.{call.Name}.finish", new Dictionary<string, object?>
            {
                ["solver_id"] = state.SolverId,
                ["challenge_id"] = state.ChallengeId,
                ["turn"] = state.Turns,
                ["args_sha256"] = argsDigest,
                ["call_id"] = call.Id,
                ["elapsed_ms"] = sw.ElapsedMilliseconds,
                ["error"] = ex.GetType().Name,
            });
            var payload = JsonSerializer.Serialize(new
            {
                error = "tool_exception",
                type = ex.GetType().Name,
                message = ex.Message,
            }, Json);
            return new ToolCallResult(payload, null);
        }
    }

    private ToolCallResult AuditAndReturn(CopilotToolCall call, string argsDigest, ToolCallResult result)
    {
        _audit.Record($"solver.tool.{call.Name}.finish", new Dictionary<string, object?>
        {
            ["solver_id"] = "?",
            ["args_sha256"] = argsDigest,
            ["call_id"] = call.Id,
            ["error"] = "invalid_arguments_json",
        });
        return result;
    }

    // ------------------------------------------------------------------
    // Individual tool implementations
    // ------------------------------------------------------------------

    private static async Task<ToolCallResult> DoSandboxExecAsync(
        ISandboxSession session, JsonElement args, CancellationToken ct)
    {
        var command = GetString(args, "command");
        if (string.IsNullOrWhiteSpace(command))
        {
            return new ToolCallResult(
                JsonSerializer.Serialize(new { error = "missing_command" }, Json), null);
        }
        TimeSpan? timeout = null;
        if (args.TryGetProperty("timeout_seconds", out var tEl)
            && tEl.ValueKind == JsonValueKind.Number
            && tEl.TryGetInt32(out var t) && t > 0)
        {
            timeout = TimeSpan.FromSeconds(t);
        }

        var res = await session.ExecAsync(command!, timeout, ct).ConfigureAwait(false);
        var stdoutBytes = Encoding.UTF8.GetByteCount(res.Stdout);
        var stderrBytes = Encoding.UTF8.GetByteCount(res.Stderr);
        var payload = new
        {
            exit = res.ExitCode,
            timed_out = res.TimedOut,
            elapsed_ms = (long)res.Elapsed.TotalMilliseconds,
            stdout_truncated = Truncate(res.Stdout, ToolStdoutBudgetBytes),
            stderr_truncated = Truncate(res.Stderr, ToolStdoutBudgetBytes),
            stdout_bytes = stdoutBytes,
            stderr_bytes = stderrBytes,
            stdout_sha256 = Sha256Hex(res.Stdout),
        };
        return new ToolCallResult(JsonSerializer.Serialize(payload, Json), null);
    }

    private static async Task<ToolCallResult> DoSandboxReadAsync(
        ISandboxSession session, JsonElement args, CancellationToken ct)
    {
        var path = GetString(args, "path");
        if (string.IsNullOrWhiteSpace(path))
        {
            return new ToolCallResult(
                JsonSerializer.Serialize(new { error = "missing_path" }, Json), null);
        }
        long maxBytes = SandboxReadCapBytes;
        if (args.TryGetProperty("max_bytes", out var mEl)
            && mEl.ValueKind == JsonValueKind.Number
            && mEl.TryGetInt64(out var m) && m > 0)
        {
            maxBytes = Math.Min(m, SandboxReadCapBytes);
        }
        var bytes = await session.ReadFileAsync(path!, maxBytes, ct).ConfigureAwait(false);
        var payload = new
        {
            path,
            size = bytes.Length,
            sha256 = Sha256HexBytes(bytes),
            content_base64 = Convert.ToBase64String(bytes),
        };
        return new ToolCallResult(JsonSerializer.Serialize(payload, Json), null);
    }

    private static async Task<ToolCallResult> DoSandboxWriteAsync(
        ISandboxSession session, JsonElement args, CancellationToken ct)
    {
        var path = GetString(args, "path");
        var b64 = GetString(args, "content_base64");
        if (string.IsNullOrWhiteSpace(path) || b64 is null)
        {
            return new ToolCallResult(
                JsonSerializer.Serialize(new { error = "missing_args" }, Json), null);
        }
        byte[] bytes;
        try { bytes = Convert.FromBase64String(b64); }
        catch (FormatException)
        {
            return new ToolCallResult(
                JsonSerializer.Serialize(new { error = "invalid_base64" }, Json), null);
        }
        if (bytes.Length > SandboxWriteCapBytes)
        {
            return new ToolCallResult(
                JsonSerializer.Serialize(new
                {
                    error = "oversize",
                    max_bytes = SandboxWriteCapBytes,
                    bytes = bytes.Length,
                }, Json), null);
        }
        await session.WriteFileAsync(path!, bytes, ct).ConfigureAwait(false);
        var payload = new { ack = true, path, bytes = bytes.Length, sha256 = Sha256HexBytes(bytes) };
        return new ToolCallResult(JsonSerializer.Serialize(payload, Json), null);
    }

    private async Task<ToolCallResult> DoSubmitFlagAsync(
        JsonElement args, SolverState state, CtfdChallenge chal, CancellationToken ct)
    {
        var flag = GetString(args, "flag");
        if (string.IsNullOrEmpty(flag))
        {
            return new ToolCallResult(
                JsonSerializer.Serialize(new { error = "missing_flag" }, Json), null);
        }

        // The plaintext flag is passed straight to the coordinator which
        // hashes it before any audit write. We MUST NOT log it here.
        var candidate = new FlagCandidate(
            ChallengeId: chal.Id,
            ChallengeName: chal.Name,
            Flag: flag!,
            SolverId: state.SolverId,
            ModelId: state.ModelId,
            At: DateTimeOffset.UtcNow);

        var outcome = await _flagSubmit.SubmitCandidateAsync(candidate, ct).ConfigureAwait(false);
        var flagSha = FlagSubmitCoordinator.NormalizeFlag(flag!);
        var sha = Sha256Hex(flagSha);

        if (outcome is null)
        {
            // Deduped (same flag already submitted by this or another solver)
            var payload = new { correct = false, already_solved = false, deduped = true };
            return new ToolCallResult(JsonSerializer.Serialize(payload, Json), null);
        }
        if (outcome.Correct)
        {
            var payload = new { correct = true, already_solved = false, message = outcome.Message };
            return new ToolCallResult(
                JsonSerializer.Serialize(payload, Json),
                new DispatchTerminal(SolverOutcome.Solved, sha, "submit_correct"));
        }
        if (outcome.AlreadySolved)
        {
            var payload = new { correct = false, already_solved = true, message = outcome.Message };
            return new ToolCallResult(
                JsonSerializer.Serialize(payload, Json),
                new DispatchTerminal(SolverOutcome.GaveUp, null, "already_solved"));
        }
        {
            var payload = new { correct = false, already_solved = false, message = outcome.Message };
            // An incorrect guess is not terminal — give the model another
            // turn to iterate. It is terminal only when MaxTurns / budget /
            // wall-clock runs out.
            return new ToolCallResult(JsonSerializer.Serialize(payload, Json), null);
        }
    }

    private async Task<ToolCallResult> DoPublishInsightAsync(
        JsonElement args, SolverState state, SolverConfig cfg, CancellationToken ct)
    {
        if (!cfg.EnableBusInsights)
        {
            return new ToolCallResult(
                JsonSerializer.Serialize(new { ack = false, reason = "bus_disabled" }, Json), null);
        }
        var kindStr = GetString(args, "kind") ?? "Observation";
        if (!Enum.TryParse<InsightKind>(kindStr, ignoreCase: true, out var kind))
        {
            kind = InsightKind.Observation;
        }
        var summary = GetString(args, "summary") ?? string.Empty;
        if (summary.Length == 0)
        {
            return new ToolCallResult(
                JsonSerializer.Serialize(new { error = "missing_summary" }, Json), null);
        }
        if (summary.Length > 512) summary = summary[..512];

        var detailsSha = GetString(args, "details_sha256");
        var tags = Array.Empty<string>();
        if (args.TryGetProperty("tags", out var tagsEl) && tagsEl.ValueKind == JsonValueKind.Array)
        {
            var list = new List<string>();
            foreach (var t in tagsEl.EnumerateArray())
            {
                if (t.ValueKind == JsonValueKind.String)
                {
                    var s = t.GetString();
                    if (!string.IsNullOrEmpty(s)) list.Add(s);
                }
            }
            tags = list.ToArray();
        }

        // Refuse to let the solver publish a Flag insight via this tool —
        // that channel is reserved for FlagSubmitCoordinator so plaintext
        // flags cannot leak through the bus.
        if (kind == InsightKind.Flag)
        {
            return new ToolCallResult(
                JsonSerializer.Serialize(new { error = "flag_kind_forbidden" }, Json), null);
        }

        var insight = new SolverInsight(
            ChallengeId: state.ChallengeIdStr,
            SolverId: state.SolverId,
            ModelId: state.ModelId,
            Kind: kind,
            Summary: summary,
            DetailsSha256: detailsSha,
            Tags: tags,
            At: DateTimeOffset.UtcNow);

        await _bus.PublishAsync(insight, ct).ConfigureAwait(false);
        if (_loopDetector is LoopDetector concrete)
        {
            concrete.RecordInsight(state.SolverId, state.ChallengeIdStr, kind);
        }
        return new ToolCallResult(
            JsonSerializer.Serialize(new { ack = true, kind = kind.ToString() }, Json), null);
    }

    private ToolCallResult DoGetInsights(SolverState state)
    {
        var all = _bus.History(state.ChallengeIdStr);
        var peers = new List<object>();
        foreach (var i in all)
        {
            if (string.Equals(i.SolverId, state.SolverId, StringComparison.Ordinal))
            {
                continue; // hide own insights
            }
            peers.Add(new
            {
                solver_id = i.SolverId,
                model_id = i.ModelId,
                kind = i.Kind.ToString(),
                summary = i.Summary,
                tags = i.Tags,
                details_sha256 = i.DetailsSha256,
                at = i.At.ToString("o"),
            });
        }
        return new ToolCallResult(
            JsonSerializer.Serialize(new { count = peers.Count, insights = peers }, Json), null);
    }

    private static ToolCallResult DoGiveUp(JsonElement args)
    {
        var reason = GetString(args, "reason") ?? "unspecified";
        return new ToolCallResult(
            JsonSerializer.Serialize(new { acked = true, reason }, Json),
            new DispatchTerminal(SolverOutcome.GaveUp, null, "give_up:" + reason));
    }

    // ------------------------------------------------------------------
    // LLM retry, peer insight summary, fingerprinting, helpers
    // ------------------------------------------------------------------

    private async Task<CopilotChatResponse> ChatWithRetryAsync(
        string modelId,
        IReadOnlyList<CopilotChatMessage> messages,
        IReadOnlyList<AITool> tools,
        CancellationToken ct)
    {
        int attempt = 0;
        while (true)
        {
            try
            {
                return await _llm.ChatAsync(modelId, messages, tools, ct).ConfigureAwait(false);
            }
            catch (CopilotLlmException ex) when (IsTransient(ex) && attempt < 1)
            {
                attempt++;
                _audit.Record("solver.llm_retry", new Dictionary<string, object?>
                {
                    ["model"] = modelId,
                    ["status"] = ex.StatusCode.HasValue ? (int)ex.StatusCode.Value : (int?)null,
                });
                try { await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
            }
        }
    }

    private static bool IsTransient(CopilotLlmException ex)
    {
        if (!ex.StatusCode.HasValue) return false;
        var code = (int)ex.StatusCode.Value;
        return code == 429 || (code >= 500 && code < 600);
    }

    private string? BuildPeerInsightSummary(string chalIdStr, string solverId)
    {
        var history = _bus.History(chalIdStr);
        if (history.Count == 0) return null;

        var peers = new List<string>();
        foreach (var i in history)
        {
            if (string.Equals(i.SolverId, solverId, StringComparison.Ordinal)) continue;
            var tagStr = i.Tags.Count == 0 ? string.Empty : " [" + string.Join(",", i.Tags) + "]";
            peers.Add($"- ({i.Kind}) {i.SolverId}: {i.Summary}{tagStr}");
            if (peers.Count >= 32) break;
        }
        if (peers.Count == 0) return null;

        var sb = new StringBuilder();
        sb.AppendLine("Peer solvers have already reported the following observations. ");
        sb.AppendLine("Use them to skip duplicate work:");
        foreach (var p in peers) sb.AppendLine(p);
        return sb.ToString();
    }

    private async Task PublishLoopHintAsync(LoopReport report, CancellationToken ct)
    {
        if (_bus is SolverMessageBus concrete)
        {
            try
            {
                await concrete.PushCoordinatorHintAsync(
                    report.ChallengeId,
                    $"solver {report.SolverId} hit loop={report.LoopKind} reps={report.Repetitions}",
                    new[] { "loop", report.LoopKind },
                    ct).ConfigureAwait(false);
            }
            catch { /* best effort */ }
        }
    }

    private static string ComputeChatFingerprint(CopilotChatResponse response)
    {
        if (response.ToolCalls.Count == 0)
        {
            return Sha256Hex((response.Content ?? string.Empty).Trim());
        }
        var sb = new StringBuilder();
        foreach (var tc in response.ToolCalls)
        {
            sb.Append(tc.Name).Append('\x1f').Append(tc.ArgumentsJson).Append('\x1e');
        }
        return Sha256Hex(sb.ToString());
    }

    private static bool MentionsPossibleFlag(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        // Match common CTF flag shapes: <prefix>{...}. The submit_flag tool is
        // the only legitimate channel — this check only nags the model.
        int lb = text.IndexOf('{');
        int rb = text.IndexOf('}', Math.Max(0, lb));
        return lb > 0 && rb > lb + 1;
    }

    private SolverRunResult Finalize(
        SolverState state,
        SolverOutcome outcome,
        string? flagSha256,
        string? loopKind,
        string? failureReason,
        Stopwatch sw,
        DateTimeOffset started,
        ISandboxSession? session,
        SolverConfig cfg)
    {
        sw.Stop();
        var usd = _costs.UsdForChallenge(state.ChallengeIdStr);
        _audit.Record("solver.finish", new Dictionary<string, object?>
        {
            ["solver_id"] = state.SolverId,
            ["model"] = state.ModelId,
            ["challenge_id"] = state.ChallengeId,
            ["outcome"] = outcome.ToString(),
            ["turns"] = state.Turns,
            ["usd_cost"] = usd.ToString("F6", CultureInfo.InvariantCulture),
            ["elapsed_ms"] = sw.ElapsedMilliseconds,
            ["loop_kind"] = loopKind,
            ["failure_reason"] = failureReason,
        });
        _ = started;
        _ = session;
        _ = cfg;
        return new SolverRunResult(
            SolverId: state.SolverId,
            ModelId: state.ModelId,
            ChallengeId: state.ChallengeId,
            Outcome: outcome,
            FlagSubmitted: flagSha256,
            Turns: state.Turns,
            Elapsed: sw.Elapsed,
            UsdCost: usd,
            LoopKind: loopKind,
            FailureReason: failureReason);
    }

    // ------------------------------------------------------------------
    // AIFunction schemas (what the LLM sees). Every Description is the
    // literal text the model reads — keep it clear and action-oriented.
    // ------------------------------------------------------------------

    private IReadOnlyList<AITool> BuildAiTools()
    {
        var list = new List<AITool>
        {
            AIFunctionFactory.Create(ToolShapes.SandboxExec, name: "sandbox_exec"),
            AIFunctionFactory.Create(ToolShapes.SandboxReadFile, name: "sandbox_read_file"),
            AIFunctionFactory.Create(ToolShapes.SandboxWriteFile, name: "sandbox_write_file"),
            AIFunctionFactory.Create(ToolShapes.SubmitFlag, name: "submit_flag"),
            AIFunctionFactory.Create(ToolShapes.PublishInsight, name: "publish_insight"),
            AIFunctionFactory.Create(ToolShapes.GetInsights, name: "get_insights"),
            AIFunctionFactory.Create(ToolShapes.GiveUp, name: "give_up"),
        };
        return list;
    }

    /// <summary>
    /// The LLM-visible tool surface. These methods are NEVER called directly
    /// — they exist purely so <see cref="AIFunctionFactory"/> can derive the
    /// JSON schema + description the model sees. Actual dispatch happens in
    /// <see cref="InvokeToolAsync"/> so we can enforce audit / loop / flag
    /// hygiene uniformly.
    /// </summary>
    private static class ToolShapes
    {
        [Description(
            "Run a shell command inside the isolated Docker sandbox as the ctf " +
            "user. Use this for enumeration (ls, file, strings, hexdump), " +
            "tool invocation (python3, nm, objdump, binwalk, volatility, " +
            "gdb, nc, curl), and for any unix pipeline that turns the " +
            "challenge surface into flag material. stdout/stderr are " +
            "truncated at 16 KiB in the response; use sandbox_read_file if " +
            "you need the full artifact. Returns exit code, truncated " +
            "stdout/stderr, elapsed_ms, and stdout SHA-256 + byte count.")]
        public static object SandboxExec(
            [Description("Shell command to run. Multi-line and pipelines are fine; " +
                         "the wrapper uses `bash -c` with `set -o pipefail`.")]
            string command,
            [Description("Optional per-command timeout in seconds. Defaults to the " +
                         "sandbox spec timeout.")]
            int? timeout_seconds = null)
            => throw new InvalidOperationException("schema-only");

        [Description(
            "Read a file out of the sandbox and return its bytes as base64. " +
            "Use this when sandbox_exec output truncation loses data, or to " +
            "pull a generated artifact back for further reasoning. Files " +
            "larger than 1 MiB are refused — binwalk / split / head inside " +
            "the sandbox first.")]
        public static object SandboxReadFile(
            [Description("Absolute path inside the container, e.g. /home/ctf/work/flag.txt.")]
            string path,
            [Description("Max bytes to transfer; capped at 1048576. Default 65536.")]
            int? max_bytes = null)
            => throw new InvalidOperationException("schema-only");

        [Description(
            "Write a base64-encoded blob into the sandbox at the given path. " +
            "Use for scripts, payloads, and auxiliary input files. Max 10 MiB.")]
        public static object SandboxWriteFile(
            [Description("Absolute container path. Parent directory must exist.")]
            string path,
            [Description("Base64-encoded content. Max 10 MiB decoded.")]
            string content_base64)
            => throw new InvalidOperationException("schema-only");

        [Description(
            "Submit a candidate flag to CTFd. This is the ONLY legitimate way " +
            "to report a flag — never write a plaintext flag in free-text. " +
            "Returns {correct, already_solved, message}. On correct, the " +
            "solver terminates Solved; on already_solved another solver won " +
            "and this solver terminates GaveUp.")]
        public static object SubmitFlag(
            [Description("The flag string exactly as found. Normalization is handled " +
                         "downstream.")]
            string flag,
            [Description("Optional free-text note on confidence / provenance. Not sent " +
                         "to CTFd; recorded locally for post-mortem.")]
            string? confidence_note = null)
            => throw new InvalidOperationException("schema-only");

        [Description(
            "Publish a structured insight onto the cross-solver bus. Peer " +
            "solvers racing on this challenge see it via get_insights. " +
            "Kind is one of Observation, Dead_End, Partial, Hypothesis, " +
            "Error, OperatorHint, CoordinatorHint. Flag-kind insights are " +
            "rejected here — use submit_flag for those.")]
        public static object PublishInsight(
            [Description("Insight kind (Observation, Dead_End, Partial, Hypothesis, Error).")]
            string kind,
            [Description("<= 512-char summary. State what you found or ruled out, " +
                         "not what you plan to try next.")]
            string summary,
            [Description("Free-form tags (e.g. [\"pwn\",\"stack-canary\",\"pie\"]).")]
            string[]? tags = null,
            [Description("Optional SHA-256 of a larger artifact stored out-of-band.")]
            string? details_sha256 = null)
            => throw new InvalidOperationException("schema-only");

        [Description(
            "Fetch peer insights for this challenge published by OTHER " +
            "solvers. Returns a JSON array. Call periodically so the swarm's " +
            "knowledge compounds. Own insights are filtered out.")]
        public static object GetInsights()
            => throw new InvalidOperationException("schema-only");

        [Description(
            "Terminate this solver. Use when you are convinced the challenge " +
            "is out of scope for this model OR when a peer solver has " +
            "already reported a flag. Never give up just because a single " +
            "tool call failed.")]
        public static object GiveUp(
            [Description("Short operator-visible reason, e.g. " +
                         "'out of weight class: kernel-pwn with custom kaslr'.")]
            string reason)
            => throw new InvalidOperationException("schema-only");
    }

    // ------------------------------------------------------------------
    // Small helpers
    // ------------------------------------------------------------------

    private static string? GetString(JsonElement obj, string name)
    {
        if (obj.ValueKind != JsonValueKind.Object) return null;
        if (!obj.TryGetProperty(name, out var el)) return null;
        return el.ValueKind == JsonValueKind.String ? el.GetString() : null;
    }

    private static string Truncate(string s, int maxBytes)
    {
        if (string.IsNullOrEmpty(s)) return s ?? string.Empty;
        var bytes = Encoding.UTF8.GetByteCount(s);
        if (bytes <= maxBytes) return s;
        // Conservative: cut char-wise at half rate and re-check.
        var approx = Math.Max(1, Math.Min(s.Length, maxBytes));
        var candidate = s[..approx];
        while (Encoding.UTF8.GetByteCount(candidate) > maxBytes && candidate.Length > 0)
        {
            candidate = candidate[..(candidate.Length - 1)];
        }
        return candidate + "\n[...truncated]";
    }

    private static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string Sha256HexBytes(byte[] bytes)
    {
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private sealed class SolverState
    {
        public readonly string SolverId;
        public readonly string ModelId;
        public readonly int ChallengeId;
        public readonly string ChallengeIdStr;
        public int Turns;
        public int ConsecutiveEmptyResponses;

        public SolverState(string solverId, string modelId, int challengeId, string challengeIdStr)
        {
            SolverId = solverId;
            ModelId = modelId;
            ChallengeId = challengeId;
            ChallengeIdStr = challengeIdStr;
        }
    }
}
