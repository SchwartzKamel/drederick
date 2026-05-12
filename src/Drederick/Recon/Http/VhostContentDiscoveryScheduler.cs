using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon.Http;

/// <summary>
/// GAP-057 / htb-content-discovery-vhost-aware: structural analog of
/// <see cref="Drederick.Recon.Fuzz.VhostAutoScheduler"/> for content
/// discovery. When the recon pipeline emits a vhost detection
/// (<c>http.vhost.detected</c>), this scheduler re-queues
/// <see cref="HttpContentDiscoveryTool"/> against that vhost's
/// base URL with a stronger wordlist profile
/// (<see cref="ContentDiscoveryProfile.RaftMedium"/> by default) and
/// an opt-in extension fanout
/// (<see cref="ContentDiscoveryProfiles.DefaultExtensionFanout"/>).
/// <para>
/// Dedup key is <c>(host, vhost, port, scheme)</c> — the same vhost
/// observed twice from probes against the same target IP and port is
/// scheduled exactly once. Different (host, vhost) tuples queue
/// independently.
/// </para>
/// <para>
/// Authorization posture: <c>_scope.Require(host)</c> is the first
/// statement on every public network-touching method
/// (@invariant-id:scope-in-every-tool). The downstream
/// <see cref="HttpContentDiscoveryTool.ProbeAsync"/> performs its own
/// scope check on the vhost URL host (which will refuse hostnames
/// when scope is IP-only — surfaced as
/// <see cref="ContentDiscoveryScheduleOutcome.ScopeRefused"/>).
/// </para>
/// </summary>
public sealed class VhostContentDiscoveryScheduler
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Drederick.Recon.HttpContentDiscoveryTool _content;
    private readonly ContentDiscoveryProfile _profile;
    private readonly bool _extensionFanout;
    private readonly ConcurrentDictionary<string, byte> _queued =
        new(StringComparer.OrdinalIgnoreCase);

    public VhostContentDiscoveryScheduler(
        Scope.Scope scope,
        AuditLog audit,
        Drederick.Recon.HttpContentDiscoveryTool content,
        ContentDiscoveryProfile profile = ContentDiscoveryProfile.RaftMedium,
        bool extensionFanout = false)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(content);
        _scope = scope;
        _audit = audit;
        _content = content;
        _profile = profile;
        _extensionFanout = extensionFanout;
    }

    /// <summary>
    /// Number of unique (host, vhost, port, scheme) keys queued by
    /// this scheduler since construction.
    /// </summary>
    public int QueuedCount => _queued.Count;

    /// <summary>Configured wordlist profile.</summary>
    public ContentDiscoveryProfile Profile => _profile;

    /// <summary>
    /// Whether extension fanout
    /// (<see cref="ContentDiscoveryProfiles.DefaultExtensionFanout"/>)
    /// is enabled for queued runs.
    /// </summary>
    public bool ExtensionFanout => _extensionFanout;

    /// <summary>
    /// Effective extension fanout list — the canonical default set
    /// when <see cref="ExtensionFanout"/> is on, otherwise an empty
    /// list.
    /// </summary>
    public IReadOnlyList<string> EffectiveExtensions =>
        _extensionFanout
            ? ContentDiscoveryProfiles.DefaultExtensionFanout
            : Array.Empty<string>();

    /// <summary>
    /// Returns <c>true</c> if the (host, vhost, port, scheme) tuple
    /// has already been queued by this scheduler instance.
    /// </summary>
    public bool HasQueued(string host, string vhost, int port, string scheme = "http")
    {
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(vhost))
            return false;
        var key = MakeKey(host, vhost, port, scheme);
        return _queued.ContainsKey(key);
    }

    /// <summary>
    /// React to a detected vhost event by queueing an
    /// <see cref="HttpContentDiscoveryTool"/> run against
    /// <c>scheme://vhost:port/</c>. Returns
    /// <see cref="ContentDiscoveryScheduleOutcome.Queued"/> on
    /// success or an outcome explaining the skip / refusal.
    /// </summary>
    /// <param name="host">In-scope target IP that emitted the vhost detection.</param>
    /// <param name="vhost">Observed vhost (e.g. <c>panel.pterodactyl.htb</c>).</param>
    /// <param name="port">HTTP port the vhost was observed on.</param>
    /// <param name="scheme"><c>http</c> or <c>https</c>.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="ScopeException">
    /// If <paramref name="host"/> is not in scope — propagated
    /// rather than caught (invariant @scope-in-every-tool).
    /// </exception>
    public async Task<ContentDiscoveryScheduleOutcome> ScheduleAsync(
        string host,
        string vhost,
        int port,
        string scheme,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            _audit.Record("content_discovery.scheduled_for_vhost.skip", new Dictionary<string, object?>
            {
                ["vhost"] = vhost,
                ["reason"] = "empty_host",
            });
            return ContentDiscoveryScheduleOutcome.EmptyHost;
        }
        _scope.Require(host);

        if (string.IsNullOrWhiteSpace(vhost))
        {
            _audit.Record("content_discovery.scheduled_for_vhost.skip", new Dictionary<string, object?>
            {
                ["host"] = host,
                ["reason"] = "empty_vhost",
            });
            return ContentDiscoveryScheduleOutcome.EmptyVhost;
        }

        var trimmedVhost = vhost.Trim().Trim('.').ToLowerInvariant();
        if (trimmedVhost.Length == 0)
        {
            _audit.Record("content_discovery.scheduled_for_vhost.skip", new Dictionary<string, object?>
            {
                ["host"] = host,
                ["reason"] = "empty_vhost",
            });
            return ContentDiscoveryScheduleOutcome.EmptyVhost;
        }
        if (IPAddress.TryParse(trimmedVhost, out _))
        {
            _audit.Record("content_discovery.scheduled_for_vhost.skip", new Dictionary<string, object?>
            {
                ["host"] = host,
                ["vhost"] = trimmedVhost,
                ["reason"] = "vhost_is_ip",
            });
            return ContentDiscoveryScheduleOutcome.VhostIsIp;
        }

        var effectiveScheme = string.IsNullOrWhiteSpace(scheme)
            ? "http"
            : scheme.Trim().ToLowerInvariant();
        if (effectiveScheme is not "http" and not "https")
        {
            effectiveScheme = "http";
        }

        var dedupKey = MakeKey(host, trimmedVhost, port, effectiveScheme);
        if (!_queued.TryAdd(dedupKey, 0))
        {
            _audit.Record("content_discovery.scheduled_for_vhost.skip", new Dictionary<string, object?>
            {
                ["host"] = host,
                ["vhost"] = trimmedVhost,
                ["port"] = port,
                ["scheme"] = effectiveScheme,
                ["reason"] = "duplicate",
            });
            return ContentDiscoveryScheduleOutcome.Duplicate;
        }

        var authority = trimmedVhost + ":" + port.ToString(CultureInfo.InvariantCulture);
        var baseUrl = effectiveScheme + "://" + authority + "/";

        _audit.Record("content_discovery.scheduled_for_vhost", new Dictionary<string, object?>
        {
            ["host"] = host,
            ["vhost"] = trimmedVhost,
            ["port"] = port,
            ["scheme"] = effectiveScheme,
            ["base_url"] = baseUrl,
            ["profile"] = ContentDiscoveryProfiles.ToWireName(_profile),
            ["extension_fanout"] = _extensionFanout,
            ["extension_count"] = EffectiveExtensions.Count,
        });

        try
        {
            await _content.ProbeAsync(baseUrl, ct).ConfigureAwait(false);
            return ContentDiscoveryScheduleOutcome.Queued;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (ScopeException ex)
        {
            _audit.Record("content_discovery.scheduled_for_vhost.scope_refused", new Dictionary<string, object?>
            {
                ["host"] = host,
                ["vhost"] = trimmedVhost,
                ["error"] = ex.Message,
            });
            return ContentDiscoveryScheduleOutcome.ScopeRefused;
        }
        catch (Exception ex)
        {
            _audit.Record("content_discovery.scheduled_for_vhost.error", new Dictionary<string, object?>
            {
                ["host"] = host,
                ["vhost"] = trimmedVhost,
                ["error"] = ex.Message,
            });
            return ContentDiscoveryScheduleOutcome.Error;
        }
    }

    private static string MakeKey(string host, string vhost, int port, string scheme)
    {
        var s = string.IsNullOrWhiteSpace(scheme) ? "http" : scheme.Trim().ToLowerInvariant();
        var v = (vhost ?? string.Empty).Trim().Trim('.').ToLowerInvariant();
        var h = (host ?? string.Empty).Trim().ToLowerInvariant();
        return s + "|" + h + "|" + v + "|" + port.ToString(CultureInfo.InvariantCulture);
    }
}

/// <summary>
/// Outcome of a single
/// <see cref="VhostContentDiscoveryScheduler.ScheduleAsync"/> call.
/// </summary>
public enum ContentDiscoveryScheduleOutcome
{
    /// <summary>A content-discovery run was queued and dispatched.</summary>
    Queued,
    /// <summary>Empty / whitespace host argument.</summary>
    EmptyHost,
    /// <summary>Empty / whitespace vhost argument.</summary>
    EmptyVhost,
    /// <summary>Vhost is an IP literal — no vhost re-probe is meaningful.</summary>
    VhostIsIp,
    /// <summary>Same (host, vhost, port, scheme) already queued this run.</summary>
    Duplicate,
    /// <summary>Downstream content-discovery tool refused the vhost URL on scope grounds.</summary>
    ScopeRefused,
    /// <summary>Unexpected exception from the downstream tool.</summary>
    Error,
}
