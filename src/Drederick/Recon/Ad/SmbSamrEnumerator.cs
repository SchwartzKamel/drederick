using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon.Ad;

/// <summary>
/// GAP-042-samr: SAMR-over-SMB-DCERPC anonymous AD user enumerator.
///
/// <para>
/// Modern hardened DCs deny anonymous LDAP user enumeration but commonly
/// still allow anonymous SAMR (which is why <c>enum4linux</c> /
/// <c>rpcclient -U "" -N</c> keep working). This enumerator wraps the
/// system <c>rpcclient</c> binary (Samba <c>samba-common-bin</c>) and
/// runs <c>enumdomusers</c> over the null-session SMB connection,
/// parsing <c>user:[Name] rid:[0xRID]</c> lines into typed
/// <see cref="DomainUser"/> records.
/// </para>
///
/// <para>
/// Native DCERPC implementation deferred — that is a much bigger lift.
/// This v1 ships the rpcclient subprocess path and the parser that the
/// downstream AS-REP / kerberoast / spray tools actually need.
/// </para>
///
/// <para>
/// <b>Invariants.</b> <see cref="EnumerateDomainUsersAsync"/> calls
/// <c>_scope.Require(ip)</c> as its first statement (defense-in-depth
/// even though <see cref="SmbLibraryBackend"/> already authorized the
/// IP). The IP is the only argv token that could reach the target;
/// rpcclient receives a literal <see cref="IPAddress"/> string, never
/// a hostname (no DNS/WINS surface). Plaintext usernames never enter
/// the audit log — only count and SHA-256 of the sorted list. Raw
/// rpcclient stdout/stderr never enter the audit log — only the
/// SHA-256 digest plus a structured error kind.
/// </para>
///
/// <para>
/// <b>Thread-safety.</b> Stateless after construction.
/// </para>
/// </summary>
public sealed class SmbSamrEnumerator
{
    /// <summary>Hard cap on user list. Mirrors
    /// <see cref="SmbNullSessionTool.MaxLdapUsers"/>.</summary>
    public const int MaxUsers = 1000;

    /// <summary>Default rpcclient timeout. Long enough to negotiate SMB
    /// + bind SAMR + enumerate ~1000 users on a slow link, short enough
    /// that an unreachable target never wedges the recon pipeline.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(45);

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly IRpcclientRunner _runner;
    private readonly Func<string?> _rpcclientLocator;
    private readonly TimeSpan _timeout;

    public SmbSamrEnumerator(Scope.Scope scope, AuditLog audit)
        : this(scope, audit, runner: null, rpcclientLocator: null, timeout: DefaultTimeout)
    {
    }

    internal SmbSamrEnumerator(
        Scope.Scope scope,
        AuditLog audit,
        IRpcclientRunner? runner,
        Func<string?>? rpcclientLocator,
        TimeSpan timeout)
    {
        _scope = scope;
        _audit = audit;
        _runner = runner ?? new DefaultRpcclientRunner();
        _rpcclientLocator = rpcclientLocator ?? DefaultLocateRpcclient;
        _timeout = timeout;
    }

    /// <summary>
    /// Run <c>rpcclient -U "" -N &lt;ip&gt; -c enumdomusers</c> against the
    /// scope-validated <paramref name="ip"/>. Returns a structured result
    /// carrying either the parsed user list or an error kind.
    /// </summary>
    public async Task<SamrEnumResult> EnumerateDomainUsersAsync(IPAddress ip, CancellationToken ct)
    {
        // INVARIANT @scope-in-every-tool: defense-in-depth re-check on
        // the IP that will appear in argv.
        _scope.Require(ip.ToString());

        _audit.Record("smb_null_session.samr.start", new Dictionary<string, object?>
        {
            ["host"] = ip.ToString(),
        });

        var rpcclientPath = _rpcclientLocator();
        var available = !string.IsNullOrEmpty(rpcclientPath);
        _audit.Record("smb_null_session.samr.detected_rpcclient", new Dictionary<string, object?>
        {
            ["available"] = available,
        });
        if (!available)
        {
            _audit.Record("smb_null_session.samr.error", new Dictionary<string, object?>
            {
                ["host"] = ip.ToString(),
                ["kind"] = "rpcclient_not_installed",
            });
            return new SamrEnumResult(
                Users: Array.Empty<DomainUser>(),
                ErrorKind: "rpcclient_not_installed");
        }

        // Argv shape: rpcclient -U "" -N <ip> -c enumdomusers
        // Empty username + -N (no password prompt) yields the anonymous
        // null-session bind. Order matters: rpcclient parses positional
        // server last. We pass each token as a discrete argv element so
        // /bin/sh never sees the command line and shell metachars in the
        // (already scope-validated) IP can't matter.
        var argv = new List<string>
        {
            "-U", "",
            "-N",
            ip.ToString(),
            "-c", "enumdomusers",
        };

        _audit.Record("smb_null_session.samr.enum_users.start", new Dictionary<string, object?>
        {
            ["host"] = ip.ToString(),
        });

        RpcclientResult sr;
        try
        {
            sr = await _runner.RunAsync(rpcclientPath!, argv, _timeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _audit.Record("smb_null_session.samr.error", new Dictionary<string, object?>
            {
                ["host"] = ip.ToString(),
                ["kind"] = "spawn_failed",
                ["detail"] = ex.GetType().Name,
            });
            return new SamrEnumResult(Array.Empty<DomainUser>(), ErrorKind: "spawn_failed");
        }

        var classified = ClassifyError(sr.ExitCode, sr.StdOut, sr.StdErr);
        if (classified is not null)
        {
            _audit.Record("smb_null_session.samr.error", new Dictionary<string, object?>
            {
                ["host"] = ip.ToString(),
                ["kind"] = classified,
            });
            return new SamrEnumResult(Array.Empty<DomainUser>(), ErrorKind: classified);
        }

        var users = ParseEnumDomUsers(sr.StdOut);
        if (users.Count > MaxUsers)
        {
            users = users.Take(MaxUsers).ToList();
        }

        _audit.Record("smb_null_session.samr.enum_users.finish", new Dictionary<string, object?>
        {
            ["host"] = ip.ToString(),
            ["user_count"] = users.Count,
            ["users_digest"] = SmbLibraryBackend.DigestUsernames(users.Select(u => u.SamAccountName)),
        });
        return new SamrEnumResult(users, ErrorKind: null);
    }

    // ----- pure parsers (testable in isolation) ---------------------------

    /// <summary>
    /// Parse rpcclient <c>enumdomusers</c> output. Lines look like:
    /// <code>user:[Administrator] rid:[0x1f4]</code>
    /// Anything else (banner text, blank lines) is ignored.
    /// </summary>
    public static List<DomainUser> ParseEnumDomUsers(string stdout)
    {
        var users = new List<DomainUser>();
        if (string.IsNullOrEmpty(stdout)) return users;

        // Tolerant of unexpected whitespace; strict on the literal
        // "user:[" / "rid:[" framing rpcclient produces.
        var rx = new Regex(
            @"^\s*user:\[(?<name>[^\]]+)\]\s+rid:\[(?<rid>0x[0-9a-fA-F]+|\d+)\]\s*$",
            RegexOptions.Compiled);
        foreach (var rawLine in stdout.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var m = rx.Match(line);
            if (!m.Success) continue;
            var name = m.Groups["name"].Value;
            if (string.IsNullOrEmpty(name)) continue;
            int? rid = TryParseRid(m.Groups["rid"].Value);
            users.Add(new DomainUser(
                SamAccountName: name,
                Rid: rid,
                UserAccountControl: null,
                MemberOf: Array.Empty<string>()));
        }
        return users;
    }

    private static int? TryParseRid(string s)
    {
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return int.TryParse(s.AsSpan(2), System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture, out var hx) ? hx : null;
        }
        return int.TryParse(s, out var dec) ? dec : null;
    }

    /// <summary>
    /// Classify a non-empty error from rpcclient's combined stdout/stderr
    /// + exit code. Returns null when no error is detected (i.e. the
    /// caller should attempt to parse the output as a user list).
    /// </summary>
    public static string? ClassifyError(int exitCode, string stdout, string stderr)
    {
        var combined = (stdout ?? string.Empty) + "\n" + (stderr ?? string.Empty);

        // Connection-layer rejections — rpc bind never happened.
        if (combined.Contains("NT_STATUS_CONNECTION_REFUSED", StringComparison.Ordinal) ||
            combined.Contains("NT_STATUS_HOST_UNREACHABLE", StringComparison.Ordinal) ||
            combined.Contains("NT_STATUS_IO_TIMEOUT", StringComparison.Ordinal) ||
            combined.Contains("Cannot connect to server", StringComparison.Ordinal) ||
            combined.Contains("Connection to ", StringComparison.Ordinal) && combined.Contains(" failed", StringComparison.Ordinal))
        {
            return "rpc_bind_rejected";
        }

        // SAMR refused the anonymous bind / enum.
        if (combined.Contains("NT_STATUS_ACCESS_DENIED", StringComparison.Ordinal) ||
            combined.Contains("NT_STATUS_LOGON_FAILURE", StringComparison.Ordinal))
        {
            return "access_denied";
        }

        // Other NT_STATUS_* — surface the raw kind so the caller can
        // distinguish unknown failures from "no users found".
        var ntMatch = Regex.Match(combined, @"NT_STATUS_[A-Z_]+");
        if (ntMatch.Success)
        {
            return ntMatch.Value.ToLowerInvariant();
        }

        // Non-zero exit without a recognized NT_STATUS — generic failure.
        if (exitCode != 0)
        {
            return "rpcclient_nonzero_exit";
        }

        return null;
    }

    // ----- rpcclient locator ---------------------------------------------

    private static string? DefaultLocateRpcclient()
    {
        // PATH search via `which`. Cheap and matches how the existing
        // doctor module locates tools.
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/usr/bin/which",
                ArgumentList = { "rpcclient" },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return null;
            if (!p.WaitForExit(2000))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                return null;
            }
            if (p.ExitCode != 0) return null;
            var path = p.StandardOutput.ReadToEnd().Trim();
            return string.IsNullOrEmpty(path) ? null : path;
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>Result of a SAMR enumeration call.</summary>
public sealed record SamrEnumResult(
    IReadOnlyList<DomainUser> Users,
    string? ErrorKind);

/// <summary>Subprocess-runner seam for <see cref="SmbSamrEnumerator"/>.
/// Exists only so tests can stub rpcclient without forking a real
/// process.</summary>
public interface IRpcclientRunner
{
    Task<RpcclientResult> RunAsync(
        string binaryPath,
        IReadOnlyList<string> argv,
        TimeSpan timeout,
        CancellationToken ct);
}

public sealed record RpcclientResult(int ExitCode, string StdOut, string StdErr);

internal sealed class DefaultRpcclientRunner : IRpcclientRunner
{
    public async Task<RpcclientResult> RunAsync(
        string binaryPath,
        IReadOnlyList<string> argv,
        TimeSpan timeout,
        CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = binaryPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in argv) psi.ArgumentList.Add(a);

        // Strip operator-identity env vars so an in-scope target never
        // sees the operator's Kerberos cache or workstation login.
        psi.Environment.Remove("KRB5CCNAME");
        psi.Environment.Remove("KRB5_KTNAME");

        using var p = Process.Start(psi)
            ?? throw new InvalidOperationException($"failed to start {binaryPath}");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderrTask = p.StandardError.ReadToEndAsync();
        try
        {
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            if (ct.IsCancellationRequested) throw;
            // Timeout (not caller cancel): synthesize a structured error.
            return new RpcclientResult(
                ExitCode: -1,
                StdOut: string.Empty,
                StdErr: "NT_STATUS_IO_TIMEOUT");
        }
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        return new RpcclientResult(p.ExitCode, stdout, stderr);
    }
}
