using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Cli;
using Drederick.Jeopardy.Ops;

namespace Drederick.Jeopardy.Cli;

/// <summary>
/// Entry point for the <c>drederick ctf-msg</c> subcommand. Appends one
/// operator directive to the JSONL inbox consumed by a running
/// <see cref="CtfCoordinator"/>. The file path is local-only and therefore
/// not scope-gated.
/// </summary>
public static class CtfMsgRunner
{
    private static readonly string[] ValidKinds =
        { "hint", "focus", "skip", "stop", "shutdown" };

    public static async Task<int> RunAsync(CommandLineOptions opts, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(opts);

        if (opts.Help)
        {
            Console.WriteLine(HelpText);
            return 0;
        }

        var kind = (opts.CtfMsgKind ?? "").Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(kind))
        {
            Console.Error.WriteLine("ctf-msg: --kind is required (one of hint|focus|skip|stop|shutdown).");
            Console.Error.WriteLine();
            Console.Error.WriteLine(HelpText);
            return 2;
        }
        if (Array.IndexOf(ValidKinds, kind) < 0)
        {
            Console.Error.WriteLine(
                $"ctf-msg: invalid --kind '{opts.CtfMsgKind}'. Expected one of: {string.Join("|", ValidKinds)}.");
            return 2;
        }

        var inboxPath = opts.CtfInboxPath;
        if (string.IsNullOrEmpty(inboxPath))
        {
            Console.Error.WriteLine("ctf-msg: could not determine inbox path (HOME unset).");
            return 1;
        }

        var parent = Path.GetDirectoryName(inboxPath);
        if (!string.IsNullOrEmpty(parent))
        {
            try { Directory.CreateDirectory(parent); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ctf-msg: cannot create parent dir '{parent}': {ex.Message}");
                return 1;
            }
        }

        var body = opts.CtfMsgBody ?? string.Empty;
        var msg = new OperatorMessage(
            At: DateTimeOffset.UtcNow,
            ChallengeId: opts.CtfMsgChallengeId,
            SolverId: opts.CtfMsgSolverId,
            Kind: kind,
            Body: body);

        // Best-effort audit. Plaintext body is NEVER logged — SHA-256 only.
        try
        {
            var auditDir = Path.Combine(opts.OutputDir, "ctf");
            Directory.CreateDirectory(auditDir);
            using var audit = new AuditLog(Path.Combine(auditDir, "audit.jsonl"));
            audit.Record("cli.ctf_msg.send", new Dictionary<string, object?>
            {
                ["kind"] = kind,
                ["challenge_id"] = opts.CtfMsgChallengeId,
                ["solver_id"] = opts.CtfMsgSolverId,
                ["body_sha256"] = Sha256Hex(body),
                ["body_len"] = body.Length,
                ["inbox_path"] = inboxPath,
            });
        }
        catch
        {
            // Audit is best-effort; failing to open the audit log must not
            // block the operator directive.
        }

        try
        {
            await OperatorSender.SendAsync(inboxPath, msg, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ctf-msg: dispatch failed: {ex.Message}");
            return 1;
        }

        Console.WriteLine(
            string.Format(CultureInfo.InvariantCulture,
                "[ctf-msg] dispatched {0} to {1}", kind, inboxPath));
        return 0;
    }

    internal static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input ?? ""));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public const string HelpText =
        """
        drederick ctf-msg — push an operator directive to a running ctf-solve coordinator

        USAGE:
          drederick ctf-msg --kind <hint|focus|skip|stop|shutdown>
                            [--chal <id>] [--solver <id>] [--body "text"]
                            [--inbox <path>]

        KINDS:
          hint        Broadcast or target-challenge hint text (requires --body).
          focus       Cancel all other in-flight challenges; concentrate on --chal.
          skip        Abort the active swarm for --chal.
          stop
          shutdown    Cleanly shut down the coordinator; partial report written.

        DEFAULTS:
          --inbox ~/.drederick/jeopardy-inbox.jsonl
        """;
}
