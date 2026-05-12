using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.Memory;
using Drederick.Scope;

namespace Drederick.PostEx;

/// <summary>
/// Thin abstraction over Empire's task-queue REST surface used by
/// <see cref="EmpirePostExDispatcher"/>. Real implementations POST to
/// <c>/api/v2/agents/&lt;agent_id&gt;/tasks</c> and poll for completion;
/// tests inject a canned fake that replays fixture JSON. Kept as an
/// interface so the dispatcher's scope / opt-in / audit invariants can be
/// exercised without standing up a real Empire server.
/// </summary>
public interface IEmpireTaskClient
{
    /// <summary>Queue <paramref name="module"/> on <paramref name="agentId"/>; returns Empire's task id.</summary>
    Task<string> QueueModuleAsync(
        string agentId,
        string module,
        IReadOnlyDictionary<string, string>? parameters,
        CancellationToken ct);

    /// <summary>Block until <paramref name="taskId"/> completes (or <paramref name="timeout"/> elapses).</summary>
    Task<EmpireTaskOutcome> WaitForTaskAsync(
        string agentId,
        string taskId,
        TimeSpan timeout,
        CancellationToken ct);
}

/// <summary>Outcome of an Empire task, as returned by polling.</summary>
public sealed record EmpireTaskOutcome(string Status, string Output);

/// <summary>
/// Orchestrates Empire post-exploitation modules. Given an
/// <see cref="EmpireSession"/> + an action class, the dispatcher:
///
/// <list type="number">
///   <item>Calls <c>_scope.Require(session.Host)</c> as its first
///   statement — even though the action is delivered through Empire,
///   the host is the actual target and stays inside the allow-list
///   gate.</item>
///   <item>Resolves the concrete Empire module via
///   <see cref="EmpireModuleCatalog"/> for the session OS + action
///   category.</item>
///   <item>Enforces <see cref="RunPermissions"/> opt-in: credential
///   modules require <c>--allow-cred-attacks</c>; persistence /
///   kernel-touching modules require <c>--allow-destructive</c>.</item>
///   <item>POSTs the module to Empire via
///   <see cref="IEmpireTaskClient.QueueModuleAsync"/> and polls for
///   completion.</item>
///   <item>Captures full output, records SHA-256 of the full bytes,
///   truncates the kept copy at 64 KB.</item>
///   <item>Parses known structured outputs (mimikatz logonpasswords,
///   portscan) into <see cref="EmpireParsedFinding"/>s. Plaintext
///   passwords flow into <see cref="CredentialStore"/> under realm
///   <c>empire-loot</c>; only their SHA-256 reaches the audit log.
///   Portscan hits feed
///   <see cref="KnowledgeBase.AddPivotFinding"/>.</item>
///   <item>Records <c>empire.postex.dispatch.{start,success,failure}</c>
///   and per-module <c>empire.module.&lt;name&gt;.{queued,result}</c>
///   events.</item>
/// </list>
/// </summary>
public sealed class EmpirePostExDispatcher
{
    /// <summary>Cap on output kept on the <see cref="EmpireModuleResult"/>; full bytes hashed + audited.</summary>
    public const int OutputTruncateBytes = 64 * 1024;

    public static readonly TimeSpan DefaultPollTimeout = TimeSpan.FromMinutes(5);

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly RunPermissions _permissions;
    private readonly IEmpireTaskClient _client;
    private readonly CredentialStore? _credStore;
    private readonly KnowledgeBase? _kb;
    private readonly TimeSpan _pollTimeout;

    public EmpirePostExDispatcher(
        Scope.Scope scope,
        AuditLog audit,
        RunPermissions permissions,
        IEmpireTaskClient client,
        CredentialStore? credStore = null,
        KnowledgeBase? knowledgeBase = null,
        TimeSpan? pollTimeout = null)
    {
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _permissions = permissions ?? throw new ArgumentNullException(nameof(permissions));
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _credStore = credStore;
        _kb = knowledgeBase;
        _pollTimeout = pollTimeout ?? DefaultPollTimeout;
    }

    /// <summary>
    /// Dispatch <paramref name="action"/> against <paramref name="session"/>.
    /// See class docs for the full pipeline.
    /// </summary>
    public async Task<EmpireModuleResult> RunAsync(
        EmpireSession session,
        EmpirePostExAction action,
        IReadOnlyDictionary<string, string>? parameters = null,
        CancellationToken ct = default)
    {
        if (session is null) throw new ArgumentNullException(nameof(session));

        // ============ SCOPE CHECK (first statement after null-guard) ============
        _scope.Require(session.Host);

        var platform = EmpireModuleCatalog.PlatformFor(session);
        var category = EmpireModuleCatalog.CategoryFor(action);

        string module;
        try
        {
            module = EmpireModuleCatalog.Lookup(platform, action);
        }
        catch (EmpireModuleNotSupportedException ex)
        {
            _audit.Record("empire.postex.dispatch.failure", new Dictionary<string, object?>
            {
                ["host"] = session.Host,
                ["agent_id"] = session.AgentId,
                ["action"] = action.ToString(),
                ["platform"] = platform.ToString(),
                ["error"] = ex.Message,
                ["error_kind"] = "unsupported",
            });
            return new EmpireModuleResult(
                session.AgentId, Module: action.ToString(), ExitStatus: "unsupported",
                OutputDigest: string.Empty, OutputBytes: 0, OutputTruncated: string.Empty,
                ParsedFindings: Array.Empty<EmpireParsedFinding>(),
                Error: ex.Message);
        }

        _audit.Record("empire.postex.dispatch.start", new Dictionary<string, object?>
        {
            ["host"] = session.Host,
            ["agent_id"] = session.AgentId,
            ["action"] = action.ToString(),
            ["platform"] = platform.ToString(),
            ["module"] = module,
            ["category"] = category.ToString(),
        });

        // Opt-in gate — placed AFTER dispatch.start so the audit trail
        // shows the attempted action, but BEFORE any network egress.
        try
        {
            _permissions.Require(category, $"empire-postex:{module}");
        }
        catch (PermissionRefusedException ex)
        {
            _audit.Record("empire.postex.dispatch.failure", new Dictionary<string, object?>
            {
                ["host"] = session.Host,
                ["agent_id"] = session.AgentId,
                ["action"] = action.ToString(),
                ["module"] = module,
                ["error"] = ex.Message,
                ["error_kind"] = "permission_refused",
                ["category"] = category.ToString(),
            });
            throw;
        }

        var moduleSlug = ModuleSlug(module);
        EmpireTaskOutcome outcome;
        string taskId;
        try
        {
            taskId = await _client.QueueModuleAsync(session.AgentId, module, parameters, ct).ConfigureAwait(false);
            _audit.Record($"empire.module.{moduleSlug}.queued", new Dictionary<string, object?>
            {
                ["agent_id"] = session.AgentId,
                ["module"] = module,
                ["task_id"] = taskId,
            });

            outcome = await _client.WaitForTaskAsync(session.AgentId, taskId, _pollTimeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _audit.Record("empire.postex.dispatch.failure", new Dictionary<string, object?>
            {
                ["host"] = session.Host,
                ["agent_id"] = session.AgentId,
                ["action"] = action.ToString(),
                ["module"] = module,
                ["error"] = ex.Message,
                ["error_kind"] = "transport",
            });
            return new EmpireModuleResult(
                session.AgentId, Module: module, ExitStatus: "error",
                OutputDigest: string.Empty, OutputBytes: 0, OutputTruncated: string.Empty,
                ParsedFindings: Array.Empty<EmpireParsedFinding>(),
                Error: ex.Message);
        }

        var fullOutput = outcome.Output ?? string.Empty;
        var fullBytes = Encoding.UTF8.GetByteCount(fullOutput);
        var digest = Sha256Hex(fullOutput);
        var truncated = fullOutput.Length <= OutputTruncateBytes
            ? fullOutput
            : fullOutput[..OutputTruncateBytes];

        var findings = ParseOutput(session, action, fullOutput);

        _audit.Record($"empire.module.{moduleSlug}.result", new Dictionary<string, object?>
        {
            ["agent_id"] = session.AgentId,
            ["module"] = module,
            ["task_id"] = taskId,
            ["status"] = outcome.Status,
            ["output_bytes"] = fullBytes,
            ["output_sha256"] = digest,
            ["parsed_count"] = findings.Count,
        });

        _audit.Record("empire.postex.dispatch.success", new Dictionary<string, object?>
        {
            ["host"] = session.Host,
            ["agent_id"] = session.AgentId,
            ["action"] = action.ToString(),
            ["module"] = module,
            ["status"] = outcome.Status,
            ["output_bytes"] = fullBytes,
            ["output_sha256"] = digest,
            ["parsed_count"] = findings.Count,
        });

        return new EmpireModuleResult(
            AgentId: session.AgentId,
            Module: module,
            ExitStatus: outcome.Status,
            OutputDigest: digest,
            OutputBytes: fullBytes,
            OutputTruncated: truncated,
            ParsedFindings: findings);
    }

    // ---------- output parsers ----------

    private IReadOnlyList<EmpireParsedFinding> ParseOutput(
        EmpireSession session, EmpirePostExAction action, string output)
    {
        if (string.IsNullOrEmpty(output)) return Array.Empty<EmpireParsedFinding>();

        return action switch
        {
            EmpirePostExAction.LogonPasswords or
            EmpirePostExAction.LsaDump or
            EmpirePostExAction.DcSync => ParseMimikatz(output),
            EmpirePostExAction.Portscan => ParsePortscan(session, output),
            _ => Array.Empty<EmpireParsedFinding>(),
        };
    }

    /// <summary>
    /// Parse mimikatz <c>logonpasswords</c>/<c>lsadump</c>/<c>dcsync</c>-style
    /// output into one finding per credential block.
    ///
    /// Plaintext passwords are extracted in-memory and pushed straight into
    /// <see cref="CredentialStore"/> under realm <c>empire-loot</c>; only
    /// their SHA-256 ever reaches the parsed finding or the audit log.
    /// NTLM / AES / SHA1 hashes are already non-reversible and ride along
    /// in the finding as-is.
    /// </summary>
    internal IReadOnlyList<EmpireParsedFinding> ParseMimikatz(string output)
    {
        var findings = new List<EmpireParsedFinding>();
        foreach (var row in SplitMimikatzRows(output))
        {
            string? user = null, domain = null, ntlm = null, sha1 = null, aes256 = null;
            string? plaintext = null;
            foreach (var raw in row.Split('\n'))
            {
                var line = raw.Trim();
                var m = Regex.Match(line, @"^[*\s]*Username\s*:\s*(?<v>.+?)\s*$", RegexOptions.IgnoreCase);
                if (m.Success) { user = NullIfEmpty(m.Groups["v"].Value); continue; }
                m = Regex.Match(line, @"^[*\s]*Domain\s*:\s*(?<v>.+?)\s*$", RegexOptions.IgnoreCase);
                if (m.Success) { domain = NullIfEmpty(m.Groups["v"].Value); continue; }
                m = Regex.Match(line, @"^[*\s]*NTLM\s*:\s*(?<v>[0-9a-fA-F]{32})\s*$");
                if (m.Success) { ntlm = m.Groups["v"].Value.ToLowerInvariant(); continue; }
                m = Regex.Match(line, @"^[*\s]*SHA1\s*:\s*(?<v>[0-9a-fA-F]{40})\s*$");
                if (m.Success) { sha1 = m.Groups["v"].Value.ToLowerInvariant(); continue; }
                m = Regex.Match(line, @"^[*\s]*AES256\s*:\s*(?<v>[0-9a-fA-F]{64})\s*$", RegexOptions.IgnoreCase);
                if (m.Success) { aes256 = m.Groups["v"].Value.ToLowerInvariant(); continue; }
                m = Regex.Match(line, @"^[*\s]*Password\s*:\s*(?<v>.+?)\s*$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var v = m.Groups["v"].Value;
                    if (!string.Equals(v, "(null)", StringComparison.OrdinalIgnoreCase)) plaintext = v;
                    continue;
                }
            }

            if (user is null && ntlm is null && plaintext is null) continue;

            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            if (user is not null) fields["username"] = user;
            if (domain is not null) fields["domain"] = domain;
            if (ntlm is not null) fields["ntlm"] = ntlm;
            if (sha1 is not null) fields["sha1"] = sha1;
            if (aes256 is not null) fields["aes256"] = aes256;

            if (plaintext is not null)
            {
                var pwdSha = Sha256Hex(plaintext);
                fields["password_sha256"] = pwdSha;
                // CredentialStore swallows plaintext; only SHA-256 surfaces.
                _credStore?.Add(user ?? "(unknown)", plaintext, realm: "empire-loot", source: "empire-mimikatz");
                _audit.Record("empire.loot.credential", new Dictionary<string, object?>
                {
                    ["user"] = user,
                    ["domain"] = domain,
                    ["realm"] = "empire-loot",
                    ["password_sha256"] = pwdSha,
                    ["has_ntlm"] = ntlm is not null,
                });
            }
            else if (ntlm is not null)
            {
                _audit.Record("empire.loot.credential", new Dictionary<string, object?>
                {
                    ["user"] = user,
                    ["domain"] = domain,
                    ["realm"] = "empire-loot",
                    ["ntlm"] = ntlm,
                    ["has_plaintext"] = false,
                });
            }

            findings.Add(new EmpireParsedFinding("credential", fields));
        }
        return findings;
    }

    private static IEnumerable<string> SplitMimikatzRows(string output)
    {
        // Mimikatz prints one credential block per session, separated by
        // blank lines. We split on two-or-more-newline boundaries.
        var parts = Regex.Split(output, @"\r?\n\s*\r?\n");
        foreach (var part in parts)
        {
            if (!string.IsNullOrWhiteSpace(part)) yield return part;
        }
    }

    /// <summary>
    /// Parse Empire's portscan module output. Supported line shapes:
    /// <list type="bullet">
    ///   <item><c>[+] 10.10.10.5:445 - Open</c></item>
    ///   <item><c>10.10.10.5:22 OPEN</c></item>
    ///   <item><c>Host 10.10.10.5 port 80 open</c></item>
    /// </list>
    /// Open ports per host are aggregated and pushed into
    /// <see cref="KnowledgeBase.AddPivotFinding"/> tagged
    /// <c>session:&lt;agent_id&gt;</c>.
    /// </summary>
    internal IReadOnlyList<EmpireParsedFinding> ParsePortscan(EmpireSession session, string output)
    {
        var byHost = new Dictionary<string, SortedSet<int>>(StringComparer.Ordinal);
        var rx = new Regex(
            @"(?ix)
              (?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
              \s*[:\s]\s*(?:port\s*)?(?<port>\d{1,5})
              [^\n]*?(?<state>open)",
            RegexOptions.Compiled);
        foreach (Match m in rx.Matches(output))
        {
            var ip = m.Groups["ip"].Value;
            if (!int.TryParse(m.Groups["port"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p))
                continue;
            if (p <= 0 || p > 65535) continue;
            if (!byHost.TryGetValue(ip, out var set))
            {
                set = new SortedSet<int>();
                byHost[ip] = set;
            }
            set.Add(p);
        }

        var findings = new List<EmpireParsedFinding>();
        foreach (var (ip, ports) in byHost)
        {
            var portsCsv = string.Join(",", ports);
            findings.Add(new EmpireParsedFinding("open_ports", new Dictionary<string, string>
            {
                ["ip"] = ip,
                ["ports"] = portsCsv,
            }));

            if (_kb is not null)
            {
                // KnowledgeBase records every pivot-side discovery;
                // downstream tools re-check scope before acting on a pivot.
                _kb.AddPivotFinding(session.AgentId,
                    new PivotTarget(ip, Reachable: true, OpenPorts: ports.ToList(), Banner: null));
            }
        }
        return findings;
    }

    // ---------- helpers ----------

    private static string ModuleSlug(string module)
    {
        var sb = new StringBuilder(module.Length);
        foreach (var ch in module)
        {
            sb.Append(ch switch
            {
                '/' or '\\' or ' ' or '.' => '_',
                _ => ch,
            });
        }
        return sb.ToString();
    }

    private static string? NullIfEmpty(string s) => string.IsNullOrWhiteSpace(s) ? null : s;

    internal static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

/// <summary>
/// Fixture-backed <see cref="IEmpireTaskClient"/> for tests and offline
/// rehearsals: every <c>(agent_id, module)</c> pair maps to a canned task
/// id and a canned response body. The dispatcher itself is unaware of
/// where the bytes came from.
/// </summary>
public sealed class FixtureEmpireTaskClient : IEmpireTaskClient
{
    private readonly Dictionary<string, (string TaskId, EmpireTaskOutcome Outcome)> _byModule = new(StringComparer.Ordinal);
    private readonly List<(string AgentId, string Module, IReadOnlyDictionary<string, string>? Parameters)> _queued = new();
    private int _counter;

    public IReadOnlyList<(string AgentId, string Module, IReadOnlyDictionary<string, string>? Parameters)> Queued => _queued;

    /// <summary>Register a canned response for an exact module name.</summary>
    public void Register(string module, string output, string status = "completed", string? taskId = null)
    {
        var id = taskId ?? $"task-{Interlocked.Increment(ref _counter)}";
        _byModule[module] = (id, new EmpireTaskOutcome(status, output));
    }

    public Task<string> QueueModuleAsync(string agentId, string module,
        IReadOnlyDictionary<string, string>? parameters, CancellationToken ct)
    {
        _queued.Add((agentId, module, parameters));
        if (!_byModule.TryGetValue(module, out var canned))
        {
            throw new InvalidOperationException(
                $"FixtureEmpireTaskClient has no canned response for module '{module}'. " +
                "Call Register(module, output) in the test setup.");
        }
        return Task.FromResult(canned.TaskId);
    }

    public Task<EmpireTaskOutcome> WaitForTaskAsync(string agentId, string taskId, TimeSpan timeout, CancellationToken ct)
    {
        foreach (var kv in _byModule)
        {
            if (kv.Value.TaskId == taskId) return Task.FromResult(kv.Value.Outcome);
        }
        throw new InvalidOperationException($"FixtureEmpireTaskClient: unknown task id '{taskId}'.");
    }
}
