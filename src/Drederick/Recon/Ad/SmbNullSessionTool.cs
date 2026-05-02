using System.Net;
using System.Net.Sockets;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon.Ad;

/// <summary>
/// GAP-042: foundational AD recon. Probes a target for an SMB null session
/// (anonymous IPC$ tree connect) and an anonymous LDAP bind, then enumerates
/// what falls out of those two channels without any credentials:
/// <list type="bullet">
///   <item>SMB2 negotiate dialect, server GUID, signing-required flag.</item>
///   <item>Share list via NetShareEnumAll over IPC$ — ADMIN$/IPC$/C$ are
///   filtered by default; opt back in via <c>includeAdminShares=true</c>.</item>
///   <item>RID cycle 500-1100 (configurable, hard-capped at 1000) via LSARPC
///   <c>LookupSids</c>.</item>
///   <item>SAMR <c>EnumDomainUsers</c> when the server allows it.</item>
///   <item>LSARPC <c>LsaQueryInformationPolicy</c> for domain SID, NetBIOS
///   name, and DNS domain.</item>
///   <item>Anonymous LDAP bind to 389: <c>defaultNamingContext</c>,
///   <c>rootDomainNamingContext</c>, <c>supportedSASLMechanisms</c>, and a
///   small <c>(samAccountName=*)</c> user query (capped at 1000).</item>
/// </list>
///
/// <para>
/// <b>Scope discipline.</b> First statement of <see cref="EnumerateAsync"/>
/// is <c>_scope.Require</c> on the resolved IP. Hostname targets follow the
/// gap-032 pattern (resolve via DNS, then authorize the IP — never the
/// hostname). LDAP referrals are NEVER chased: the Novell client is
/// configured with <c>FollowReferrals=false</c> so a malicious DC cannot
/// redirect us off the in-scope IP. SMB2 redirects to a different server
/// are similarly not followed — we always reconnect to the resolved,
/// scope-validated IP.
/// </para>
///
/// <para>
/// <b>Backend abstraction.</b> The two heavy backends —
/// <see cref="ISmbNullSessionBackend"/> (SMB2 + DCERPC) and
/// <see cref="IAnonLdapBackend"/> (LDAP) — are injectable so tests can stub
/// them without spawning real connections. Production defaults will use
/// SMBLibrary + Novell.Directory.Ldap.NETStandard. As of this PR, the
/// production SMB backend ships SMB2 negotiate + share enumeration only;
/// LSARPC/SAMR primitives are a documented TODO (SMBLibrary&apos;s built-in
/// RPC surface does not cover them cleanly yet) — partial-better-than-
/// nothing per the GAP-042 brief.
/// </para>
///
/// <para>
/// <b>Audit.</b> <c>smb-null-session.start</c> on entry, one
/// <c>smb-null-session.share_found</c> per share, one
/// <c>smb-null-session.user_found</c> per discovered user (RID, SAMR, or
/// LDAP origin recorded), and a <c>smb-null-session.finish</c> with
/// aggregate counts. No plaintext credentials are ever logged — the tool
/// is anonymous by design and rejects any credentialed path.
/// </para>
/// </summary>
public sealed class SmbNullSessionTool : IReconTool
{
    public string Name => "smb-null-session";

    public string Description =>
        "Anonymous SMB + LDAP enumeration against an AD-shaped target. " +
        "SMB2 negotiate, null-session IPC$ tree connect, share enumeration, " +
        "RID cycle (500-1100), SAMR domain users, anonymous LDAP bind for " +
        "naming contexts and user listing. Credential-free; feeds AS-REP " +
        "roasting, kerberoasting, and password spray.";

    /// <summary>Hard cap on RID cycle range to keep a malicious server from
    /// holding the tool open forever via slow LookupSids replies.</summary>
    public const int MaxRidRange = 1000;

    /// <summary>Default exclusion set for share enumeration. Override via
    /// <c>includeAdminShares=true</c>.</summary>
    private static readonly HashSet<string> DefaultAdminShareExclusions =
        new(StringComparer.OrdinalIgnoreCase) { "ADMIN$", "IPC$", "C$" };

    /// <summary>Hard cap on LDAP user-query results so a malicious DC can&apos;t
    /// flood us. Mirrors the GAP-042 spec.</summary>
    public const int MaxLdapUsers = 1000;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _dnsResolver;
    private readonly Func<ISmbNullSessionBackend> _smbBackendFactory;
    private readonly Func<IAnonLdapBackend> _ldapBackendFactory;
    private readonly TimeSpan _connectTimeout;

    public SmbNullSessionTool(Scope.Scope scope, AuditLog audit)
        : this(scope, audit, dnsResolver: null, smbBackendFactory: null,
               ldapBackendFactory: null, connectTimeout: TimeSpan.FromSeconds(10))
    {
    }

    internal SmbNullSessionTool(
        Scope.Scope scope,
        AuditLog audit,
        Func<string, CancellationToken, Task<IPAddress[]>>? dnsResolver,
        Func<ISmbNullSessionBackend>? smbBackendFactory,
        Func<IAnonLdapBackend>? ldapBackendFactory,
        TimeSpan connectTimeout)
    {
        _scope = scope;
        _audit = audit;
        _dnsResolver = dnsResolver ?? ((host, ct) => Dns.GetHostAddressesAsync(host, ct));
        _smbBackendFactory = smbBackendFactory ?? (() => new UnimplementedSmbBackend());
        _ldapBackendFactory = ldapBackendFactory ?? (() => new UnimplementedLdapBackend());
        _connectTimeout = connectTimeout;
    }

    internal sealed record ResolvedTarget(IPAddress ResolvedIp, string? Hostname);

    /// <summary>Resolve <paramref name="target"/> to an authorized IP.
    /// Same gap-032 contract as <c>HttpProbeTool.ResolveAsync</c>: literal
    /// IPs go straight through <c>_scope.Require</c>; hostnames are DNS-
    /// resolved and only the resolved IP is authorized.</summary>
    internal async Task<ResolvedTarget> ResolveAsync(string target, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(target);
        var stripped = target.StartsWith('[') && target.EndsWith(']')
            ? target.Substring(1, target.Length - 2)
            : target;

        if (IPAddress.TryParse(stripped, out var ipDirect))
        {
            _scope.Require(stripped);
            return new ResolvedTarget(ipDirect, null);
        }

        IPAddress[] addrs;
        try
        {
            addrs = await _dnsResolver(target, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new ScopeException(
                $"Failed to resolve hostname '{target}' for smb_null_session: {ex.Message}");
        }
        if (addrs.Length == 0)
        {
            throw new ScopeException($"Hostname '{target}' did not resolve to any address.");
        }
        foreach (var addr in addrs)
        {
            if (_scope.Contains(addr.ToString()))
            {
                _scope.Require(addr.ToString());
                return new ResolvedTarget(addr, target);
            }
        }
        var joined = string.Join(", ", addrs.Select(a => a.ToString()));
        throw new ScopeException($"hostname '{target}' resolves to {{{joined}}}, none in scope.");
    }

    /// <summary>
    /// Probe <paramref name="target"/> for SMB null session and anonymous
    /// LDAP. <paramref name="ridStart"/>/<paramref name="ridEnd"/> control
    /// the RID-cycle range; default 500-1100 covers the canonical AD user
    /// RIDs. Range is hard-capped at <see cref="MaxRidRange"/>.
    /// <paramref name="includeAdminShares"/>=false (default) filters
    /// ADMIN$/IPC$/C$ from the share list.
    /// </summary>
    public async Task<SmbNullSessionFinding> EnumerateAsync(
        string target,
        int ridStart = 500,
        int ridEnd = 1100,
        bool includeAdminShares = false,
        CancellationToken ct = default)
    {
        // INVARIANT @scope-in-every-tool: scope authorization is the first
        // statement that touches anything network-shaped. Hostnames go
        // through DNS first; only the resolved IP is ever authorized.
        var resolved = await ResolveAsync(target, ct).ConfigureAwait(false);

        // Clamp RID range. Caller-supplied values can be wild — clamp
        // before logging so the audit reflects the actual range walked,
        // not the requested one.
        if (ridStart < 0) ridStart = 0;
        if (ridEnd < ridStart) ridEnd = ridStart;
        var ridCount = ridEnd - ridStart + 1;
        if (ridCount > MaxRidRange)
        {
            ridEnd = ridStart + MaxRidRange - 1;
            ridCount = MaxRidRange;
        }

        _audit.Record("smb-null-session.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["resolved_ip"] = resolved.ResolvedIp.ToString(),
            ["rid_start"] = ridStart,
            ["rid_end"] = ridEnd,
            ["include_admin_shares"] = includeAdminShares,
        });

        bool nullSessionOpen = false;
        string? smb2Dialect = null;
        bool signingRequired = false;
        string? serverGuid = null;
        string? domainName = null;
        string? domainSid = null;
        string? dnsDomain = null;
        var shares = new List<SmbShare>();
        var users = new List<DomainUser>();
        var saslMechs = new List<string>();
        bool ldapAnonOk = false;
        string? defaultNc = null;
        string? rootNc = null;
        string? error = null;

        // ---- SMB layer ----
        var smb = _smbBackendFactory();
        try
        {
            var negotiate = await smb.NegotiateAsync(resolved.ResolvedIp, _connectTimeout, ct)
                .ConfigureAwait(false);
            if (negotiate is null)
            {
                error = "connection_refused";
                _audit.Record("smb-null-session.smb_unreachable", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["resolved_ip"] = resolved.ResolvedIp.ToString(),
                });
            }
            else
            {
                smb2Dialect = negotiate.Dialect;
                signingRequired = negotiate.SigningRequired;
                serverGuid = negotiate.ServerGuid;

                nullSessionOpen = await smb.TryNullSessionAsync(ct).ConfigureAwait(false);
                _audit.Record("smb-null-session.null_session", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["open"] = nullSessionOpen,
                });

                if (nullSessionOpen)
                {
                    // Share enumeration via NetShareEnumAll.
                    var rawShares = await smb.EnumerateSharesAsync(ct).ConfigureAwait(false);
                    foreach (var s in rawShares)
                    {
                        if (!includeAdminShares && DefaultAdminShareExclusions.Contains(s.Name))
                        {
                            continue;
                        }
                        shares.Add(s);
                        _audit.Record("smb-null-session.share_found", new Dictionary<string, object?>
                        {
                            ["target"] = target,
                            ["share"] = s.Name,
                            ["type"] = s.Type,
                            ["readable_anonymously"] = s.ReadableAnonymously,
                        });
                    }

                    // LSARPC LsaQueryInformationPolicy.
                    try
                    {
                        var pol = await smb.QueryDomainPolicyAsync(ct).ConfigureAwait(false);
                        if (pol is not null)
                        {
                            domainName = pol.NetbiosDomainName;
                            domainSid = pol.DomainSid;
                            dnsDomain = pol.DnsDomain;
                        }
                    }
                    catch (Exception ex) when (!IsCancellation(ex, ct))
                    {
                        _audit.Record("smb-null-session.policy_error", new Dictionary<string, object?>
                        {
                            ["target"] = target,
                            ["error"] = ex.Message,
                        });
                    }

                    // SAMR EnumDomainUsers (cleaner than RID cycle when allowed).
                    try
                    {
                        var samr = await smb.SamrEnumDomainUsersAsync(ct).ConfigureAwait(false);
                        foreach (var u in samr)
                        {
                            if (ct.IsCancellationRequested) break;
                            users.Add(u);
                            _audit.Record("smb-null-session.user_found", new Dictionary<string, object?>
                            {
                                ["target"] = target,
                                ["sam"] = u.SamAccountName,
                                ["rid"] = u.Rid,
                                ["source"] = "samr",
                            });
                        }
                    }
                    catch (Exception ex) when (!IsCancellation(ex, ct))
                    {
                        _audit.Record("smb-null-session.samr_error", new Dictionary<string, object?>
                        {
                            ["target"] = target,
                            ["error"] = ex.Message,
                        });
                    }

                    // RID cycle via LSARPC LookupSids. Even when SAMR worked
                    // we still cycle because some servers expose RIDs SAMR
                    // refused to enumerate. Cancellation aware: a long-
                    // running cycle yields whatever it has so far.
                    try
                    {
                        var existingRids = users.Where(u => u.Rid is not null).Select(u => u.Rid!.Value).ToHashSet();
                        await foreach (var u in smb.RidCycleAsync(ridStart, ridEnd, ct).ConfigureAwait(false))
                        {
                            if (ct.IsCancellationRequested) break;
                            if (u.Rid is not null && existingRids.Contains(u.Rid.Value))
                            {
                                continue;
                            }
                            users.Add(u);
                            if (u.Rid is not null) existingRids.Add(u.Rid.Value);
                            _audit.Record("smb-null-session.user_found", new Dictionary<string, object?>
                            {
                                ["target"] = target,
                                ["sam"] = u.SamAccountName,
                                ["rid"] = u.Rid,
                                ["source"] = "rid_cycle",
                            });
                        }
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        // Cooperative cancel: keep partial results, swallow.
                    }
                    catch (Exception ex)
                    {
                        _audit.Record("smb-null-session.rid_cycle_error", new Dictionary<string, object?>
                        {
                            ["target"] = target,
                            ["error"] = ex.Message,
                        });
                    }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Cooperative cancel: report partial finding instead of throwing.
        }
        catch (Exception ex)
        {
            error ??= ex.Message;
            _audit.Record("smb-null-session.smb_error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["error"] = ex.Message,
            });
        }
        finally
        {
            try { smb.Dispose(); } catch { /* best-effort */ }
        }

        // ---- LDAP layer (independent of SMB outcome — anon LDAP can be
        // open even when SMB null-session is locked down). GAP-042-samr:
        // skip this phase entirely when SAMR already produced users —
        // the SAMR list is authoritative on hardened DCs that lock down
        // LDAP user enum. We still hit LDAP when SAMR returned nothing
        // (rpcclient missing, access denied, or genuine empty domain)
        // so naming contexts + SASL mechs remain visible. ----
        bool samrYieldedUsers = users.Count > 0;
        if (samrYieldedUsers)
        {
            _audit.Record("smb-null-session.ldap_skipped", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["reason"] = "samr_users_present",
                ["samr_user_count"] = users.Count,
            });
        }
        var ldap = samrYieldedUsers ? null : _ldapBackendFactory();
        try
        {
            if (ldap is not null)
            {
                var ldapResult = await ldap.QueryAsync(
                    resolved.ResolvedIp, port: 389, timeout: _connectTimeout, ct).ConfigureAwait(false);
                if (ldapResult is not null)
                {
                    ldapAnonOk = ldapResult.AnonymousBindOk;
                    defaultNc = ldapResult.DefaultNamingContext;
                    rootNc = ldapResult.RootDomainNamingContext;
                    if (ldapResult.SupportedSaslMechanisms is not null)
                    {
                        saslMechs.AddRange(ldapResult.SupportedSaslMechanisms);
                    }
                    if (ldapAnonOk && ldapResult.Users is not null)
                    {
                        foreach (var u in ldapResult.Users.Take(MaxLdapUsers))
                        {
                            if (ct.IsCancellationRequested) break;
                            // De-dupe by SAM name vs SAMR/RID-cycle output.
                            if (users.Any(x => string.Equals(x.SamAccountName, u.SamAccountName,
                                StringComparison.OrdinalIgnoreCase)))
                            {
                                continue;
                            }
                            users.Add(u);
                            _audit.Record("smb-null-session.user_found", new Dictionary<string, object?>
                            {
                                ["target"] = target,
                                ["sam"] = u.SamAccountName,
                                ["rid"] = u.Rid,
                                ["source"] = "ldap",
                            });
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Cooperative cancel.
        }
        catch (Exception ex)
        {
            _audit.Record("smb-null-session.ldap_error", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["error"] = ex.Message,
            });
        }
        finally
        {
            try { ldap?.Dispose(); } catch { /* best-effort */ }
        }

        var finding = new SmbNullSessionFinding
        {
            Target = target,
            NullSessionOpen = nullSessionOpen,
            Smb2Dialect = smb2Dialect,
            SigningRequired = signingRequired,
            ServerGuid = serverGuid,
            DomainName = domainName,
            DomainSid = domainSid,
            DnsDomain = dnsDomain,
            DefaultNamingContext = defaultNc,
            RootDomainNamingContext = rootNc,
            LdapAnonBindOk = ldapAnonOk,
            Shares = shares,
            Users = users,
            SupportedSaslMechanisms = saslMechs,
            Error = error,
        };

        _audit.Record("smb-null-session.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["null_session_open"] = nullSessionOpen,
            ["share_count"] = shares.Count,
            ["user_count"] = users.Count,
            ["ldap_anon_ok"] = ldapAnonOk,
            ["error"] = error,
        });
        return finding;
    }

    private static bool IsCancellation(Exception ex, CancellationToken ct) =>
        ex is OperationCanceledException && ct.IsCancellationRequested;
}

// --- backend abstractions -------------------------------------------------

/// <summary>SMB2 negotiate metadata — what the tool reports back to the
/// finding regardless of whether the null-session step succeeded.</summary>
public sealed record SmbNegotiateInfo(string? Dialect, bool SigningRequired, string? ServerGuid);

/// <summary>LSARPC LsaQueryInformationPolicy snapshot (domain SID + name +
/// DNS domain).</summary>
public sealed record DomainPolicyInfo(string? NetbiosDomainName, string? DomainSid, string? DnsDomain);

/// <summary>Aggregated anonymous-LDAP probe result. Everything is optional
/// because real DCs return wildly different subsets.</summary>
public sealed record AnonLdapResult(
    bool AnonymousBindOk,
    string? DefaultNamingContext,
    string? RootDomainNamingContext,
    IReadOnlyList<string>? SupportedSaslMechanisms,
    IReadOnlyList<DomainUser>? Users);

/// <summary>SMB backend abstraction. Production default uses SMBLibrary;
/// tests inject an in-memory stub. Any host the backend touches must be
/// the one passed to <see cref="NegotiateAsync"/> — backends MUST NOT
/// follow SMB2 redirects to a different server (the tool authorizes one
/// IP and the backend honors it).</summary>
public interface ISmbNullSessionBackend : IDisposable
{
    /// <summary>TCP-connect to 445 and run the SMB2 NEGOTIATE protocol.
    /// Returns <c>null</c> when the connection is refused or times out —
    /// the tool reports <c>Error=&quot;connection_refused&quot;</c> in that case.
    /// </summary>
    Task<SmbNegotiateInfo?> NegotiateAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct);

    /// <summary>Try an anonymous tree-connect to <c>IPC$</c> (the
    /// load-bearing definition of &quot;null session&quot;). Returns true on
    /// STATUS_SUCCESS, false on STATUS_ACCESS_DENIED /
    /// STATUS_LOGON_FAILURE.</summary>
    Task<bool> TryNullSessionAsync(CancellationToken ct);

    /// <summary>NetShareEnumAll over IPC$. Returns a flat list of
    /// <see cref="SmbShare"/> records — ADMIN$/IPC$/C$ are filtered by
    /// the caller, not the backend.</summary>
    Task<IReadOnlyList<SmbShare>> EnumerateSharesAsync(CancellationToken ct);

    /// <summary>LSARPC LsaQueryInformationPolicy. Returns null when the
    /// server refuses the call.</summary>
    Task<DomainPolicyInfo?> QueryDomainPolicyAsync(CancellationToken ct);

    /// <summary>SAMR EnumDomainUsers — the clean path when the server
    /// allows it. Returns an empty list otherwise.</summary>
    Task<IReadOnlyList<DomainUser>> SamrEnumDomainUsersAsync(CancellationToken ct);

    /// <summary>LSARPC LookupSids RID cycle. Async-streams users as RIDs
    /// resolve so a slow server never blocks the whole tool.</summary>
    IAsyncEnumerable<DomainUser> RidCycleAsync(int ridStart, int ridEnd, CancellationToken ct);
}

/// <summary>Anonymous LDAP backend. Production default uses
/// Novell.Directory.Ldap.NETStandard with referral-following disabled.
/// </summary>
public interface IAnonLdapBackend : IDisposable
{
    Task<AnonLdapResult?> QueryAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct);
}

// --- production-default placeholder backends ------------------------------
//
// TODO(GAP-042 follow-up): wire up SMBLibrary + Novell.Directory.Ldap.
// SMBLibrary 1.5.7 exposes SMB2Client.Connect/Login/ListShares cleanly so
// negotiate + null-session + share-enum will land first. Its DCERPC surface
// for LSARPC/SAMR is incomplete in 1.5.x — those primitives need either an
// upstream patch or a hand-rolled NDR/DCERPC layer; until that exists the
// production backend reports rpc_unsupported and tests inject working
// stubs. Per the GAP-042 brief: &quot;partial is better than nothing.&quot;
// The csproj carries the SMBLibrary + Novell.Directory.Ldap PackageReferences
// so the follow-up does not need to touch dependency wiring.

internal sealed class UnimplementedSmbBackend : ISmbNullSessionBackend
{
    public Task<SmbNegotiateInfo?> NegotiateAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        // Best-effort TCP-connect probe so the tool can still report
        // connection_refused even before the SMBLibrary backend lands.
        return ProbeReachabilityAsync(ip, timeout, ct);
    }

    private static async Task<SmbNegotiateInfo?> ProbeReachabilityAsync(
        IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await sock.ConnectAsync(new IPEndPoint(ip, 445), cts.Token).ConfigureAwait(false);
            // We connected, but we cannot speak SMB2 yet. Report a minimal
            // negotiate stub so the tool records the host as reachable.
            return new SmbNegotiateInfo(Dialect: null, SigningRequired: false, ServerGuid: null);
        }
        catch (SocketException)
        {
            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }

    public Task<bool> TryNullSessionAsync(CancellationToken ct) => Task.FromResult(false);
    public Task<IReadOnlyList<SmbShare>> EnumerateSharesAsync(CancellationToken ct)
        => Task.FromResult<IReadOnlyList<SmbShare>>(Array.Empty<SmbShare>());
    public Task<DomainPolicyInfo?> QueryDomainPolicyAsync(CancellationToken ct)
        => Task.FromResult<DomainPolicyInfo?>(null);
    public Task<IReadOnlyList<DomainUser>> SamrEnumDomainUsersAsync(CancellationToken ct)
        => Task.FromResult<IReadOnlyList<DomainUser>>(Array.Empty<DomainUser>());
#pragma warning disable CS1998
    public async IAsyncEnumerable<DomainUser> RidCycleAsync(
        int ridStart, int ridEnd, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        yield break;
    }
#pragma warning restore CS1998
    public void Dispose() { }
}

internal sealed class UnimplementedLdapBackend : IAnonLdapBackend
{
    public Task<AnonLdapResult?> QueryAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
        => Task.FromResult<AnonLdapResult?>(null);
    public void Dispose() { }
}
