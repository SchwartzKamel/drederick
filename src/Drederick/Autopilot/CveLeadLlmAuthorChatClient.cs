using System.ComponentModel;
using Drederick.Audit;
using Drederick.Exploit;
using Drederick.Scope;
using Microsoft.Extensions.AI;

namespace Drederick.Autopilot;

/// <summary>
/// Production <see cref="CveLeadLlmAuthorFunc"/> backed by an
/// <see cref="IChatClient"/>. One LLM round-trip per cve-lead, exposing
/// EXACTLY ONE tool — <c>exec_shell</c> — and capping invocations at one
/// (defense-in-depth: <see cref="CveLeadLlmAuthor.BudgetedShellRunner"/>
/// already enforces the same hard cap; this adapter just maps the result).
///
/// Design constraints (load-bearing):
/// <list type="bullet">
///   <item>Stateless after construction; safe under concurrent fan-out from
///         <see cref="AutopilotRunner"/>.</item>
///   <item>The bridge already does scope re-validation, audit emission, and
///         plaintext discipline. This adapter MUST NOT double-log: no
///         <see cref="AuditLog"/> writes from here.</item>
///   <item>Raw LLM response text is never logged anywhere. Decision shape
///         is the only thing returned upstream.</item>
///   <item>Error taxonomy mirrors <see cref="HybridAgentRunner"/>: any
///         operational failure (auth, network, rate limit, transient SDK
///         exception) returns <see cref="CveLeadLlmDecision.Error"/> with
///         a short kind. <see cref="OperationCanceledException"/> and
///         <see cref="ScopeException"/> propagate unchanged.</item>
/// </list>
/// </summary>
public sealed class CveLeadLlmAuthorChatClient
{
    /// <summary>Hard cap on FunctionInvokingChatClient iterations per call:
    /// one for the tool round-trip, one for the model's wrap-up. Anything
    /// past two is the model fighting the budget — stop the loop.</summary>
    private const int MaxIterationsPerRequest = 2;

    private readonly IChatClient _chat;
    private readonly string _modelId;

    public CveLeadLlmAuthorChatClient(IChatClient chat, string modelId)
    {
        _chat = chat ?? throw new ArgumentNullException(nameof(chat));
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);
        _modelId = modelId;
    }

    /// <summary>Adapt to the bridge's delegate type.</summary>
    public CveLeadLlmAuthorFunc AsFunc() => AuthorAsync;

    /// <summary>
    /// One-shot: build a system+user prompt, expose exactly one tool, drive
    /// <see cref="FunctionInvokingChatClient"/> for at most two iterations.
    /// Returns the bridge's decision shape.
    /// </summary>
    public async Task<CveLeadLlmDecision> AuthorAsync(
        CveLeadPromptContext ctx,
        ICveLeadShellRunner shell,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        ArgumentNullException.ThrowIfNull(shell);

        // Closure state — captured-by-tool. Marked volatile-via-Interlocked
        // because the FunctionInvokingChatClient may dispatch the tool on a
        // pool thread (we forbid concurrent invocation but do not assume the
        // call returns on the originating thread).
        ExecShellResult? captured = null;
        var callCount = 0;
        var budgetExceeded = false;
        var invalidToolCalled = false;

        async Task<object> ExecShellImpl(
            [Description("The full shell command to run on the operator workstation against the in-scope target. Examples: 'curl -sk -L https://TARGET/path', 'nuclei -t templates/cves/CVE-YYYY-NNNNN.yaml -u https://TARGET', 'searchsploit -m N && python3 N.py TARGET PORT'. Argv0 must be on the harness allow-list (curl, nmap, nuclei, searchsploit, etc.).")]
            string command,
            [Description("Optional working-directory hint relative to the run output dir. Pass null/empty for the default.")]
            string? working_dir_hint,
            CancellationToken cct)
        {
            var n = Interlocked.Increment(ref callCount);
            if (n > 1)
            {
                budgetExceeded = true;
                return new
                {
                    error = "budget_exceeded",
                    reason = "exec_shell may only be called ONCE per cve-lead.",
                };
            }

            try
            {
                var r = await shell.RunAsync(command, working_dir_hint, cct).ConfigureAwait(false);
                captured = r;
                return new
                {
                    exit_code = r.ExitCode,
                    argv_digest = r.ArgvDigest,
                    argv_count = r.ArgvCount,
                    binary = r.Binary,
                    stdout_truncated = r.StdoutTruncated,
                    stderr_truncated = r.StderrTruncated,
                    stdout_size = r.StdoutSize,
                    stderr_size = r.StderrSize,
                    timed_out = r.KilledOnTimeout,
                    elapsed_ms = r.ElapsedMs,
                };
            }
            catch (CveLeadShellBudgetExceededException)
            {
                budgetExceeded = true;
                return new
                {
                    error = "budget_exceeded",
                    reason = "exec_shell budget already consumed.",
                };
            }
            catch (ScopeException)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return new
                {
                    error = "exec_shell_failed",
                    reason = ex.Message,
                };
            }
        }

        var execShell = AIFunctionFactory.Create(
            (Func<string, string?, CancellationToken, Task<object>>)ExecShellImpl,
            name: "exec_shell",
            description:
                "Execute one shell command on the operator workstation against the in-scope target. " +
                "Use this AT MOST ONCE per call. The harness validates argv0 against an allow-list, " +
                "rejects shell metachars and scope-bypass argv, and re-checks scope on every host. " +
                "If you have no credible probe/exploit for this CVE, do NOT call this tool — respond " +
                "with the literal text 'skip' followed by a one-sentence reason.");

        var messages = new List<ChatMessage>
        {
            new(ChatRole.System, BuildSystemPrompt()),
            new(ChatRole.User, BuildUserPrompt(ctx)),
        };

        var options = new ChatOptions
        {
            ModelId = _modelId,
            Tools = new List<AITool> { execShell },
            ToolMode = ChatToolMode.Auto,
        };

        ChatResponse response;
        try
        {
            using var funcClient = new FunctionInvokingChatClient(_chat)
            {
                AllowConcurrentInvocation = false,
                MaximumIterationsPerRequest = MaxIterationsPerRequest,
            };
            response = await funcClient.GetResponseAsync(messages, options, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new CveLeadLlmDecision.Error("cancelled");
        }
        catch (OperationCanceledException)
        {
            // Internal timeout (not operator cancellation) — bucket as transient.
            return new CveLeadLlmDecision.Error("transient: timeout");
        }
        catch (ScopeException)
        {
            throw;
        }
        catch (CveLeadShellBudgetExceededException)
        {
            // BudgetedShellRunner threw past the closure's catch (e.g. the
            // FunctionInvokingChatClient surfaced it). Treat the first
            // captured result, if any, as authoritative; otherwise error.
            if (captured is not null)
                return new CveLeadLlmDecision.ShellAuthored(captured);
            return new CveLeadLlmDecision.Error("budget_exceeded");
        }
        catch (Exception ex)
        {
            return new CveLeadLlmDecision.Error(ClassifyOperationalKind(ex));
        }

        // First, did the model successfully invoke exec_shell? That is the
        // happy path regardless of any surrounding text.
        if (captured is not null)
        {
            return new CveLeadLlmDecision.ShellAuthored(captured);
        }

        // No tool call. Look for an explicit skip signal in the model's
        // output. Anything else collapses to a defensive skip — we do NOT
        // hallucinate a shell command on the model's behalf.
        if (invalidToolCalled)
        {
            return new CveLeadLlmDecision.Error("invalid_tool_call");
        }

        if (budgetExceeded)
        {
            return new CveLeadLlmDecision.Error("budget_exceeded");
        }

        var text = response.Text ?? string.Empty;
        if (LooksLikeSkip(text))
        {
            return new CveLeadLlmDecision.Skip(BuildSkipReason(text));
        }

        return new CveLeadLlmDecision.Skip(
            "model returned no tool call and no skip signal");
    }

    /// <summary>
    /// Heuristic: is the response a skip signal? We accept the literal
    /// 'skip' (case-insensitive, anywhere in the text), or common refusal
    /// phrases that indicate the model has no credible probe.
    /// </summary>
    private static bool LooksLikeSkip(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        var lower = text.Trim().ToLowerInvariant();
        if (lower.StartsWith("skip", StringComparison.Ordinal)) return true;
        if (lower.Contains("no idea", StringComparison.Ordinal)) return true;
        if (lower.Contains("cannot author", StringComparison.Ordinal)) return true;
        if (lower.Contains("i don't have", StringComparison.Ordinal)) return true;
        if (lower.Contains("i do not have", StringComparison.Ordinal)) return true;
        if (lower.Contains("insufficient information", StringComparison.Ordinal)) return true;
        return false;
    }

    /// <summary>Bounded one-line reason. Never log the full response.</summary>
    private static string BuildSkipReason(string text)
    {
        var trimmed = (text ?? "").Trim();
        if (trimmed.Length == 0) return "model declined";
        // Take the first line, capped at 200 chars. We deliberately do NOT
        // surface the entire response so prompt-injection echoes can't ride
        // upstream into reports.
        var nl = trimmed.IndexOfAny(['\n', '\r']);
        if (nl > 0) trimmed = trimmed[..nl];
        if (trimmed.Length > 200) trimmed = trimmed[..200];
        return trimmed;
    }

    /// <summary>
    /// Coarse exception → kind mapping. The bridge collapses every error
    /// outcome to <c>llm_error</c>; we still classify so operators reading
    /// audit context can see the bucket.
    /// </summary>
    private static string ClassifyOperationalKind(Exception ex)
    {
        var t = ex.GetType().Name;
        var msg = ex.Message ?? string.Empty;
        var lower = msg.ToLowerInvariant();

        if (ex is HttpRequestException)
            return $"network: {t}";
        if (ex is TaskCanceledException)
            return $"transient: {t}";
        if (ex is UnauthorizedAccessException)
            return $"auth: {t}";

        if (lower.Contains("401") || lower.Contains("unauthor"))
            return "auth: unauthorized";
        if (lower.Contains("403") || lower.Contains("forbidden"))
            return "auth: forbidden";
        if (lower.Contains("429") || lower.Contains("rate limit") || lower.Contains("too many requests"))
            return "rate_limit";
        if (lower.Contains("timeout") || lower.Contains("timed out"))
            return "transient: timeout";
        if (lower.Contains("connection") || lower.Contains("dns") || lower.Contains("network"))
            return "network";
        if (lower.Contains("api key") || lower.Contains("missing key") || lower.Contains("no_llm_key"))
            return "no_llm_key";

        return $"transient: {t}";
    }

    internal static string BuildSystemPrompt() =>
        """
        You are an offensive-security operator inside Drederick, a scope-enforced
        full-auto harness. The harness has matched a CVE on an in-scope target but
        could not fetch any cached PoC. Your job is to author ONE exec_shell command
        that probes or exploits this CVE on the given target.

        Rules — every one of these is load-bearing:
          - Call exec_shell AT MOST ONCE. A second call is refused at the harness
            layer; do not waste a turn on it.
          - If you do not have a credible probe/exploit for this CVE, respond with
            the literal text 'skip' followed by a one-sentence reason. Do NOT call
            exec_shell on a hunch — burned API quota does not help the operator.
          - The target appears verbatim in the user message. The harness re-checks
            scope on every host in argv; you cannot exfiltrate, pivot outside scope,
            or rewrite the target host into something it isn't. Argv0 must be on
            the harness allow-list (curl, nmap, nuclei, searchsploit, python3, etc.).
          - Prefer probing/PoC tools (curl, nuclei, searchsploit + python3) over
            destructive ones. The harness has a separate destructive-actions gate.
          - Do not embed multi-command pipelines via shell metacharacters; the
            harness rejects unsanitized shell expansion. If you need a chained
            workflow, pick the single most valuable command and run that.
        """;

    internal static string BuildUserPrompt(CveLeadPromptContext ctx)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("CVE: ").AppendLine(ctx.CveId);
        sb.Append("Target: ").AppendLine(ctx.Target);
        sb.Append("Port: ").AppendLine(ctx.Port.ToString());
        if (!string.IsNullOrWhiteSpace(ctx.Service))
            sb.Append("Service: ").AppendLine(ctx.Service);
        if (!string.IsNullOrWhiteSpace(ctx.Url))
            sb.Append("URL: ").AppendLine(ctx.Url);
        if (!string.IsNullOrWhiteSpace(ctx.Reason))
            sb.Append("Reason: ").AppendLine(ctx.Reason);
        if (!string.IsNullOrWhiteSpace(ctx.BannerHint))
            sb.Append("Banner hint: ").AppendLine(ctx.BannerHint);
        sb.AppendLine();
        sb.AppendLine(
            "Author one exec_shell command that probes or exploits this CVE on " +
            "the target above, OR respond with 'skip' + one-sentence reason if " +
            "you have no credible action.");
        return sb.ToString();
    }
}
