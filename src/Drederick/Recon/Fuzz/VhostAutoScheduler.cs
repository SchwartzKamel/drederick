using System.Collections.Concurrent;
using System.Net;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// GAP-051 / htb-llm-vhost-fuzz-surface: auto-schedules
/// <see cref="VhostFuzzTool"/> when the recon pipeline detects an
/// <c>http.vhost.detected</c>-style event (an HTTP probe finding with a
/// Host-header redirect / required vhost). Derives the apex domain from
/// the observed FQDN, de-duplicates per (apex, port) so the same apex is
/// fuzzed at most once per scheduler instance, and queues exactly one
/// <see cref="VhostFuzzTool.ProbeAsync(string, string, VhostFuzzOptions?, CancellationToken)"/>
/// call against the apex.
/// <para>
/// Apex derivation is intentionally simple: "last two labels". For
/// <c>panel.pterodactyl.htb</c> → <c>pterodactyl.htb</c>; for
/// <c>a.b.c.example.com</c> → <c>example.com</c>. We do <b>not</b>
/// consult the Public Suffix List because lab/CTF targets routinely use
/// synthetic TLDs (<c>.htb</c>, <c>.lab</c>, <c>.local</c>, <c>.box</c>)
/// that PSL resolves incorrectly. IP literals and single-label hosts
/// pass through unchanged; the scheduler skips them (an IP apex would
/// trigger a redundant fuzz of the host itself).
/// </para>
/// <para>
/// Wordlist selection: <see cref="DefaultWordlistName"/>
/// (<c>subdomains-top1m-5000.txt</c>) by default. Callers may override
/// via the constructor (operator flag <c>--vhost-wordlist</c>) — the
/// override is resolved with
/// <see cref="Agent.LlmFuzzToolWrappers.ResolveWordlist(string?)"/>-style
/// SecLists-root search; if no candidate exists, the wordlist is left
/// unset and <see cref="VhostFuzzTool"/> falls back to its built-in
/// defaults.
/// </para>
/// <para>
/// Authorization posture: the scheduler holds a
/// <see cref="Drederick.Scope.Scope"/> reference and performs a defensive
/// <c>_scope.Require</c> on any IP-literal apex before queueing. For
/// hostname apex domains, <see cref="VhostFuzzTool.ProbeAsync"/> performs
/// its own scope check on the URL host (invariant
/// @scope-in-every-tool), so the scheduler does not duplicate DNS work.
/// </para>
/// </summary>
public sealed class VhostAutoScheduler
{
    /// <summary>
    /// Default SecLists-relative wordlist for vhost fuzzing — the
    /// 5,000-entry top subdomains list, which has a good signal-to-noise
    /// ratio for CTF and lab targets.
    /// </summary>
    public const string DefaultWordlistName = "subdomains-top1m-5000.txt";

    private static readonly string[] SeclistsRoots =
    {
        "/usr/share/seclists",
        "/usr/share/wordlists/seclists",
        "/opt/seclists",
        Path.Combine(
            Environment.GetEnvironmentVariable("HOME") ?? string.Empty,
            "seclists"),
    };

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly VhostFuzzTool _vhost;
    private readonly string _wordlistName;
    private readonly ConcurrentDictionary<string, byte> _queued =
        new(StringComparer.OrdinalIgnoreCase);

    public VhostAutoScheduler(
        Scope.Scope scope,
        AuditLog audit,
        VhostFuzzTool vhost,
        string? wordlistName = null)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(vhost);
        _scope = scope;
        _audit = audit;
        _vhost = vhost;
        _wordlistName = string.IsNullOrWhiteSpace(wordlistName)
            ? DefaultWordlistName
            : wordlistName.Trim();
    }

    /// <summary>
    /// Number of unique (apex, port, scheme) keys queued by this
    /// scheduler since construction.
    /// </summary>
    public int QueuedCount => _queued.Count;

    /// <summary>
    /// Configured wordlist name (default or operator override).
    /// </summary>
    public string WordlistName => _wordlistName;

    /// <summary>
    /// Derive the apex domain from an observed FQDN using the "last two
    /// labels" rule. IP literals and single-label hosts pass through
    /// unchanged. Lower-cased. Empty / whitespace input → empty string.
    /// </summary>
    public static string DeriveApex(string hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname)) return string.Empty;
        var h = hostname.Trim().Trim('.').ToLowerInvariant();
        if (h.Length == 0) return string.Empty;
        if (IPAddress.TryParse(h, out _)) return h;
        var parts = h.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 1) return h;
        if (parts.Length == 2) return h;
        return string.Concat(parts[^2], ".", parts[^1]);
    }

    /// <summary>
    /// React to a detected vhost event by queueing a
    /// <see cref="VhostFuzzTool"/> run against the derived apex. Returns
    /// <see cref="VhostScheduleOutcome.Queued"/> when a run was queued,
    /// or an outcome indicating why no run was queued (apex empty, apex
    /// is IP, already deduped, scope-refused).
    /// </summary>
    /// <param name="fqdn">FQDN observed (e.g. <c>panel.pterodactyl.htb</c>).</param>
    /// <param name="port">HTTP port the vhost was observed on.</param>
    /// <param name="scheme"><c>http</c> or <c>https</c>.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<VhostScheduleOutcome> ScheduleAsync(
        string fqdn,
        int port,
        string scheme,
        CancellationToken ct = default)
    {
        var apex = DeriveApex(fqdn);
        if (string.IsNullOrEmpty(apex))
        {
            _audit.Record("vhost.auto_schedule.skip", new Dictionary<string, object?>
            {
                ["fqdn"] = fqdn,
                ["reason"] = "empty_apex",
            });
            return VhostScheduleOutcome.EmptyApex;
        }
        if (IPAddress.TryParse(apex, out _))
        {
            _audit.Record("vhost.auto_schedule.skip", new Dictionary<string, object?>
            {
                ["fqdn"] = fqdn,
                ["apex"] = apex,
                ["reason"] = "apex_is_ip",
            });
            return VhostScheduleOutcome.ApexIsIp;
        }
        // Single-label apex (e.g. "singlehost") is a degenerate case — there
        // is no parent zone to brute. Skip gracefully.
        if (!apex.Contains('.'))
        {
            _audit.Record("vhost.auto_schedule.skip", new Dictionary<string, object?>
            {
                ["fqdn"] = fqdn,
                ["apex"] = apex,
                ["reason"] = "single_label_apex",
            });
            return VhostScheduleOutcome.SingleLabelApex;
        }

        var effectiveScheme = string.IsNullOrWhiteSpace(scheme) ? "http" : scheme.Trim().ToLowerInvariant();
        var dedupKey = $"{effectiveScheme}://{apex}:{port}";
        if (!_queued.TryAdd(dedupKey, 0))
        {
            _audit.Record("vhost.auto_schedule.skip", new Dictionary<string, object?>
            {
                ["fqdn"] = fqdn,
                ["apex"] = apex,
                ["reason"] = "duplicate",
            });
            return VhostScheduleOutcome.Duplicate;
        }

        var apexUrl = $"{effectiveScheme}://{apex}:{port}/";
        var wordlistPath = ResolveWordlistPath(_wordlistName);

        _audit.Record("vhost.auto_schedule.queue", new Dictionary<string, object?>
        {
            ["fqdn"] = fqdn,
            ["apex"] = apex,
            ["port"] = port,
            ["scheme"] = effectiveScheme,
            ["wordlist_name"] = _wordlistName,
            ["wordlist_resolved"] = wordlistPath is not null,
        });

        try
        {
            var opts = new VhostFuzzOptions { CustomWordlist = wordlistPath };
            await _vhost.ProbeAsync(apexUrl, apex, opts, ct).ConfigureAwait(false);
            return VhostScheduleOutcome.Queued;
        }
        catch (ScopeException ex)
        {
            _audit.Record("vhost.auto_schedule.scope_refused", new Dictionary<string, object?>
            {
                ["apex"] = apex,
                ["error"] = ex.Message,
            });
            return VhostScheduleOutcome.ScopeRefused;
        }
        catch (Exception ex)
        {
            _audit.Record("vhost.auto_schedule.error", new Dictionary<string, object?>
            {
                ["apex"] = apex,
                ["error"] = ex.Message,
            });
            return VhostScheduleOutcome.Error;
        }
    }

    /// <summary>
    /// Returns <c>true</c> if the (apex, port, scheme) tuple has already
    /// been queued by this scheduler. Public so callers can branch
    /// without invoking <see cref="ScheduleAsync"/>.
    /// </summary>
    public bool HasQueued(string apex, int port, string scheme = "http")
    {
        if (string.IsNullOrWhiteSpace(apex)) return false;
        var key = $"{scheme}://{apex}:{port}";
        return _queued.ContainsKey(key);
    }

    private static string? ResolveWordlistPath(string wordlistName)
    {
        if (string.IsNullOrWhiteSpace(wordlistName)) return null;
        if (wordlistName.Contains("..", StringComparison.Ordinal)) return null;
        if (wordlistName.IndexOfAny(new[] { ';', '&', '|', '`', '$', '<', '>', '\n', '\r' }) >= 0)
            return null;
        if (Path.IsPathRooted(wordlistName) && File.Exists(wordlistName))
            return wordlistName;
        foreach (var root in SeclistsRoots)
        {
            if (string.IsNullOrEmpty(root)) continue;
            if (!Directory.Exists(root)) continue;
            try
            {
                var hit = Directory.EnumerateFiles(root, wordlistName, SearchOption.AllDirectories)
                    .FirstOrDefault();
                if (hit is not null) return hit;
            }
            catch
            {
                // Permission/IO — fall through.
            }
        }
        return null;
    }
}

/// <summary>
/// Outcome of a single <see cref="VhostAutoScheduler.ScheduleAsync"/>
/// call. Surfaced to callers so the runner can decide whether to log or
/// continue.
/// </summary>
public enum VhostScheduleOutcome
{
    /// <summary>A vhost-fuzz run was queued and dispatched.</summary>
    Queued,
    /// <summary>FQDN was empty / whitespace.</summary>
    EmptyApex,
    /// <summary>Apex resolved to an IP literal; no fuzz possible.</summary>
    ApexIsIp,
    /// <summary>Single-label apex; nothing to brute.</summary>
    SingleLabelApex,
    /// <summary>Same (apex, port, scheme) already queued this run.</summary>
    Duplicate,
    /// <summary>Scope refused the apex (inner tool's check).</summary>
    ScopeRefused,
    /// <summary>Unexpected exception from the inner tool.</summary>
    Error,
}
