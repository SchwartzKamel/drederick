using System.Net;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Novell.Directory.Ldap;

namespace Drederick.Recon.Ad;

/// <summary>
/// Adapter around a <see cref="LdapConnection"/>-shaped client. Carved out
/// so tests can inject a fake connection without standing up a real LDAP
/// server. Production uses <see cref="NovellLdapAdapter"/>.
/// </summary>
internal interface ILdapAdapter : IDisposable
{
    Task ConnectAsync(string host, int port, CancellationToken ct);
    Task BindAnonymousAsync(CancellationToken ct);
    Task<LdapEntryDto?> ReadRootDseAsync(CancellationToken ct);
    Task<IReadOnlyList<LdapUserDto>> SearchUsersAsync(string baseDn, int max, CancellationToken ct);
}

internal sealed record LdapEntryDto(string? DefaultNamingContext, string? RootDomainNamingContext, IReadOnlyList<string> SupportedSaslMechanisms);
internal sealed record LdapUserDto(string SamAccountName, int? Rid, string? UserAccountControl, IReadOnlyList<string> MemberOf);

/// <summary>
/// Production <see cref="ILdapAdapter"/> backed by
/// <see cref="LdapConnection"/>. Hop-limit is set to 0 (no referral
/// chasing) so a malicious DC cannot redirect us to an out-of-scope
/// server. Connection timeout is bounded and bind credentials are
/// always empty (anonymous).
/// </summary>
internal sealed class NovellLdapAdapter : ILdapAdapter
{
    private readonly LdapConnection _conn;
    private bool _disposed;

    public NovellLdapAdapter(int connectTimeoutMs)
    {
        _conn = new LdapConnection { ConnectionTimeout = connectTimeoutMs };
        var sc = _conn.SearchConstraints;
        sc.HopLimit = 0;
        sc.ReferralFollowing = false;
        _conn.Constraints = sc;
    }

    public Task ConnectAsync(string host, int port, CancellationToken ct)
        => _conn.ConnectAsync(host, port, ct);

    public Task BindAnonymousAsync(CancellationToken ct)
        => _conn.BindAsync(LdapConnection.LdapV3, string.Empty, string.Empty, ct);

    public async Task<LdapEntryDto?> ReadRootDseAsync(CancellationToken ct)
    {
        try
        {
            var entry = await _conn.ReadAsync(string.Empty,
                new[] { "defaultNamingContext", "rootDomainNamingContext", "supportedSASLMechanisms" }, ct)
                .ConfigureAwait(false);
            if (entry is null) return null;
            string? defaultNc = entry.GetStringValueOrDefault("defaultNamingContext", null!);
            string? rootNc = entry.GetStringValueOrDefault("rootDomainNamingContext", null!);
            var sasl = new List<string>();
            var saslAttr = entry.Get("supportedSASLMechanisms");
            if (saslAttr is not null && saslAttr.StringValueArray is not null)
            {
                foreach (var v in saslAttr.StringValueArray) sasl.Add(v);
            }
            return new LdapEntryDto(defaultNc, rootNc, sasl);
        }
        catch (LdapException)
        {
            return null;
        }
    }

    public async Task<IReadOnlyList<LdapUserDto>> SearchUsersAsync(string baseDn, int max, CancellationToken ct)
    {
        var users = new List<LdapUserDto>();
        var sc = new LdapSearchConstraints
        {
            MaxResults = max,
            HopLimit = 0,
            ReferralFollowing = false,
            TimeLimit = 30,
        };
        var results = await _conn.SearchAsync(
            baseDn,
            LdapConnection.ScopeSub,
            "(&(objectClass=user)(samAccountName=*))",
            new[] { "samAccountName", "objectSid", "userAccountControl", "memberOf" },
            typesOnly: false,
            sc,
            ct).ConfigureAwait(false);

        await foreach (var entry in results.ConfigureAwait(false))
        {
            if (entry is null) continue;
            if (users.Count >= max) break;
            var sam = entry.GetStringValueOrDefault("samAccountName", string.Empty);
            if (string.IsNullOrEmpty(sam)) continue;
            var uac = entry.GetStringValueOrDefault("userAccountControl", null!);
            var sidBytes = entry.GetBytesValueOrDefault("objectSid", null!);
            int? rid = SidToRid(sidBytes);
            var memberOf = new List<string>();
            var mo = entry.Get("memberOf");
            if (mo?.StringValueArray is not null) memberOf.AddRange(mo.StringValueArray);
            users.Add(new LdapUserDto(sam, rid, uac, memberOf));
        }
        return users;
    }

    private static int? SidToRid(byte[]? sid)
    {
        if (sid is null || sid.Length < 8) return null;
        // Last 4 bytes of binary SID, little-endian, are the RID.
        int len = sid.Length;
        return sid[len - 4] | (sid[len - 3] << 8) | (sid[len - 2] << 16) | (sid[len - 1] << 24);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _conn.Disconnect(); } catch { /* best effort */ }
        try { _conn.Dispose(); } catch { /* best effort */ }
    }
}

/// <summary>
/// GAP-042 production <see cref="IAnonLdapBackend"/>: anonymous bind on
/// 389 + RootDSE read + <c>(samAccountName=*)</c> search.
///
/// <para>
/// <b>Caveat (documented loud).</b> Modern AD typically refuses anonymous
/// LDAP user enumeration: the default ACL on
/// <c>CN=Users,DC=&lt;domain&gt;,DC=&lt;tld&gt;</c> denies <c>List Contents</c>
/// to <c>ANONYMOUS LOGON</c>. RootDSE reads still succeed (those
/// attributes are explicitly readable anonymously per RFC 4512), so
/// naming-context discovery works, but the user list will usually be
/// empty against a hardened DC. The proper fix is SAMR-over-SMB-DCERPC
/// over the null session, which SMBLibrary 1.5.7 does not expose
/// publicly. Tracked as <c>gap-042-samr-over-smb-rpc</c>.
/// </para>
///
/// <para>
/// <b>Plaintext discipline.</b> The audit emits user <i>count</i> plus a
/// SHA-256 digest of the sorted, joined username list — never the names
/// themselves. The structured <see cref="AnonLdapResult.Users"/> shape
/// keeps the names so downstream consumers (gap-043 AS-REP roast,
/// password spray) can use them.
/// </para>
///
/// <para>
/// <b>No referral chasing.</b> The Novell adapter sets
/// <c>HopLimit=0</c> and <c>ReferralFollowing=false</c> so a malicious
/// DC cannot redirect us off the in-scope IP.
/// </para>
/// </summary>
internal sealed class SmbLibraryLdapBackend : IAnonLdapBackend
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<int, ILdapAdapter> _adapterFactory;
    private const int DefaultMaxUsers = 1000;

    public SmbLibraryLdapBackend(Scope.Scope scope, AuditLog audit)
        : this(scope, audit, ms => new NovellLdapAdapter(ms))
    {
    }

    internal SmbLibraryLdapBackend(Scope.Scope scope, AuditLog audit, Func<int, ILdapAdapter> adapterFactory)
    {
        _scope = scope;
        _audit = audit;
        _adapterFactory = adapterFactory;
    }
    public async Task<AnonLdapResult?> QueryAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
    {
        // INVARIANT @scope-in-every-tool: defense-in-depth re-check.
        _scope.Require(ip.ToString());

        bool bound = false;
        string? defaultNc = null;
        string? rootNc = null;
        var sasl = new List<string>();
        var users = new List<DomainUser>();

        var adapter = _adapterFactory((int)timeout.TotalMilliseconds);
        try
        {
            _audit.Record("smb-null-session.ldap_anon_bind.start", new Dictionary<string, object?>
            {
                ["ip"] = ip.ToString(),
                ["port"] = port,
            });

            try
            {
                await adapter.ConnectAsync(ip.ToString(), port, ct).ConfigureAwait(false);
                await adapter.BindAnonymousAsync(ct).ConfigureAwait(false);
                bound = true;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _audit.Record("smb-null-session.ldap_anon_bind.finish", new Dictionary<string, object?>
                {
                    ["ip"] = ip.ToString(),
                    ["bound"] = false,
                    ["error"] = ex.Message,
                });
                return new AnonLdapResult(
                    AnonymousBindOk: false,
                    DefaultNamingContext: null,
                    RootDomainNamingContext: null,
                    SupportedSaslMechanisms: Array.Empty<string>(),
                    Users: Array.Empty<DomainUser>());
            }

            _audit.Record("smb-null-session.ldap_anon_bind.finish", new Dictionary<string, object?>
            {
                ["ip"] = ip.ToString(),
                ["bound"] = true,
            });

            // RootDSE read — naming contexts + SASL mechanisms.
            try
            {
                var dse = await adapter.ReadRootDseAsync(ct).ConfigureAwait(false);
                if (dse is not null)
                {
                    defaultNc = dse.DefaultNamingContext;
                    rootNc = dse.RootDomainNamingContext;
                    sasl.AddRange(dse.SupportedSaslMechanisms);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // RootDSE read failed; non-fatal.
            }

            // User search — only when we have a base DN.
            if (!string.IsNullOrEmpty(defaultNc))
            {
                _audit.Record("smb-null-session.ldap_user_search.start", new Dictionary<string, object?>
                {
                    ["ip"] = ip.ToString(),
                    ["base_dn_present"] = true,
                });
                IReadOnlyList<LdapUserDto> raw = Array.Empty<LdapUserDto>();
                string? error = null;
                try
                {
                    raw = await adapter.SearchUsersAsync(defaultNc, DefaultMaxUsers, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                }

                foreach (var u in raw)
                {
                    users.Add(new DomainUser(u.SamAccountName, u.Rid, u.UserAccountControl, u.MemberOf));
                }

                // PLAINTEXT DISCIPLINE: count + SHA-256 digest only.
                _audit.Record("smb-null-session.ldap_user_search.finish", new Dictionary<string, object?>
                {
                    ["ip"] = ip.ToString(),
                    ["user_count"] = users.Count,
                    ["users_digest"] = SmbLibraryBackend.DigestUsernames(users.Select(u => u.SamAccountName)),
                    ["error"] = error,
                });
            }
        }
        finally
        {
            try { adapter.Dispose(); } catch { /* best effort */ }
        }

        return new AnonLdapResult(
            AnonymousBindOk: bound,
            DefaultNamingContext: defaultNc,
            RootDomainNamingContext: rootNc,
            SupportedSaslMechanisms: sasl,
            Users: users);
    }

    public void Dispose()
    {
        // Per-call adapter is disposed in QueryAsync's finally; nothing to clean up.
    }
}
