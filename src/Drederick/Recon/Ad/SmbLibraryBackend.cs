using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using SMBLibrary;
using SMBLibrary.Client;

namespace Drederick.Recon.Ad;

/// <summary>
/// GAP-042 production backend. Drives <see cref="SMB2Client"/> for SMB2
/// negotiate + null-session login + ListShares + per-share TreeConnect to
/// gauge accessibility. SMBLibrary 1.5.7 does NOT expose LSARPC/SAMR
/// primitives publicly, so <see cref="QueryDomainPolicyAsync"/>,
/// <see cref="SamrEnumDomainUsersAsync"/>, and <see cref="RidCycleAsync"/>
/// return null/empty here; the LDAP backend (and a future
/// gap-042-samr-over-smb-rpc follow-up) covers user enumeration.
///
/// <para>
/// <b>Defense-in-depth scope check.</b> First statement of every public
/// network method is <c>_scope.Require(ip.ToString())</c> even though the
/// tool already authorized the resolved IP — the backend must re-validate
/// in case it is reused with a different host (gap-042 invariant).
/// </para>
///
/// <para>
/// <b>SMB2 first, SMB1 fallback.</b> SMB2 is attempted via
/// <c>SMBTransportType.DirectTCPTransport</c> on 445; on connect failure
/// the backend falls back to <see cref="SMB1Client"/> for share
/// enumeration only (NetBIOS/445). A target that speaks neither yields
/// a null negotiate (-> tool reports <c>connection_refused</c>).
/// </para>
///
/// <para>
/// <b>No phone-home.</b> SMBLibrary's <see cref="SMB2Client.Connect(IPAddress, SMBTransportType)"/>
/// is given a literal scope-validated <see cref="IPAddress"/>; we never
/// pass a hostname (which could trigger DNS/WINS resolution outside the
/// in-scope IP). SMB2 redirects are not honored by SMBLibrary's client
/// API in 1.5.7 so there is no separate guard needed.
/// </para>
///
/// <para>
/// <b>Thread-safety.</b> Each <see cref="SmbLibraryBackend"/> instance owns
/// a single connected <see cref="SMB2Client"/>/<see cref="SMB1Client"/>
/// and is intended for use from a single async flow per
/// <see cref="SmbNullSessionTool.EnumerateAsync"/> invocation. The factory
/// in <see cref="SmbNullSessionTool"/> creates a fresh backend per call.
/// </para>
/// </summary>
internal sealed class SmbLibraryBackend : ISmbNullSessionBackend
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private SMB2Client? _smb2;
    private SMB1Client? _smb1;
    private IPAddress? _ip;
    private bool _disposed;

    public SmbLibraryBackend(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope;
        _audit = audit;
    }

    public async Task<SmbNegotiateInfo?> NegotiateAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        // INVARIANT @scope-in-every-tool: defense-in-depth re-check.
        _scope.Require(ip.ToString());
        _ip = ip;

        _audit.Record("smb-null-session.smb2_negotiate.start", new Dictionary<string, object?>
        {
            ["ip"] = ip.ToString(),
        });

        // Pre-flight TCP probe: SMBLibrary's blocking Connect doesn't
        // honor a CancellationToken, so we use a short TCP probe to
        // bail fast on closed/filtered 445 instead of blocking on the
        // synchronous Connect call.
        if (!await TcpReachableAsync(ip, 445, timeout, ct).ConfigureAwait(false))
        {
            _audit.Record("smb-null-session.smb2_negotiate.finish", new Dictionary<string, object?>
            {
                ["ip"] = ip.ToString(),
                ["reachable"] = false,
            });
            return null;
        }

        var info = await Task.Run(() =>
        {
            try
            {
                var c = new SMB2Client();
                if (c.Connect(ip, SMBTransportType.DirectTCPTransport))
                {
                    _smb2 = c;
                    // SMBLibrary 1.5.7 does not surface dialect / signing /
                    // server-guid via a public property after Connect.
                    // Report a minimal positive negotiate so the tool
                    // marks the host reachable.
                    return new SmbNegotiateInfo(Dialect: "SMB2", SigningRequired: false, ServerGuid: null);
                }
                try { c.Disconnect(); } catch { /* best effort */ }
            }
            catch (Exception)
            {
                // fall through to SMB1
            }

            try
            {
                var c1 = new SMB1Client();
                if (c1.Connect(ip, SMBTransportType.DirectTCPTransport))
                {
                    _smb1 = c1;
                    return new SmbNegotiateInfo(Dialect: "SMB1", SigningRequired: false, ServerGuid: null);
                }
                try { c1.Disconnect(); } catch { /* best effort */ }
            }
            catch (Exception)
            {
                // give up
            }

            return (SmbNegotiateInfo?)null;
        }, ct).ConfigureAwait(false);

        _audit.Record("smb-null-session.smb2_negotiate.finish", new Dictionary<string, object?>
        {
            ["ip"] = ip.ToString(),
            ["dialect"] = info?.Dialect,
            ["reachable"] = info is not null,
        });

        return info;
    }

    public Task<bool> TryNullSessionAsync(CancellationToken ct)
    {
        if (_ip is null) return Task.FromResult(false);
        _scope.Require(_ip.ToString());

        return Task.Run(() =>
        {
            try
            {
                NTStatus s;
                if (_smb2 is not null)
                {
                    s = _smb2.Login(string.Empty, string.Empty, string.Empty);
                }
                else if (_smb1 is not null)
                {
                    s = _smb1.Login(string.Empty, string.Empty, string.Empty);
                }
                else
                {
                    return false;
                }
                return s == NTStatus.STATUS_SUCCESS;
            }
            catch (Exception)
            {
                return false;
            }
        }, ct);
    }

    public Task<IReadOnlyList<SmbShare>> EnumerateSharesAsync(CancellationToken ct)
    {
        if (_ip is null) return Task.FromResult<IReadOnlyList<SmbShare>>(Array.Empty<SmbShare>());
        _scope.Require(_ip.ToString());

        _audit.Record("smb-null-session.list_shares.start", new Dictionary<string, object?>
        {
            ["ip"] = _ip.ToString(),
        });

        return Task.Run<IReadOnlyList<SmbShare>>(() =>
        {
            var result = new List<SmbShare>();
            try
            {
                List<string>? names = null;
                if (_smb2 is not null)
                {
                    names = _smb2.ListShares(out var s);
                    if (s != NTStatus.STATUS_SUCCESS) names = null;
                }
                else if (_smb1 is not null)
                {
                    names = _smb1.ListShares(out var s);
                    if (s != NTStatus.STATUS_SUCCESS) names = null;
                }

                if (names is not null)
                {
                    foreach (var n in names)
                    {
                        if (ct.IsCancellationRequested) break;
                        var (accessible, type) = TryTreeConnect(n);
                        result.Add(new SmbShare(
                            Name: n,
                            Type: type,
                            Comment: null,
                            ReadableAnonymously: accessible));
                    }
                }
            }
            catch (Exception ex)
            {
                _audit.Record("smb-null-session.list_shares.error", new Dictionary<string, object?>
                {
                    ["ip"] = _ip.ToString(),
                    ["error"] = ex.Message,
                });
            }

            _audit.Record("smb-null-session.list_shares.finish", new Dictionary<string, object?>
            {
                ["ip"] = _ip.ToString(),
                ["share_count"] = result.Count,
            });
            return result;
        }, ct);
    }

    private (bool accessible, string type) TryTreeConnect(string shareName)
    {
        _audit.Record("smb-null-session.tree_connect.start", new Dictionary<string, object?>
        {
            ["ip"] = _ip!.ToString(),
            ["share"] = shareName,
        });
        bool accessible = false;
        string? statusCode = null;
        string type = "DISK";
        try
        {
            ISMBFileStore? store = null;
            NTStatus status = NTStatus.STATUS_NOT_SUPPORTED;
            if (_smb2 is not null)
            {
                store = _smb2.TreeConnect(shareName, out status);
            }
            else if (_smb1 is not null)
            {
                store = _smb1.TreeConnect(shareName, out status);
            }
            statusCode = status.ToString();
            accessible = status == NTStatus.STATUS_SUCCESS && store is not null;
            if (string.Equals(shareName, "IPC$", StringComparison.OrdinalIgnoreCase))
            {
                type = "IPC";
            }
            try { store?.Disconnect(); } catch { /* best effort */ }
        }
        catch (Exception ex)
        {
            statusCode = "exception:" + ex.GetType().Name;
        }
        _audit.Record("smb-null-session.tree_connect.finish", new Dictionary<string, object?>
        {
            ["ip"] = _ip!.ToString(),
            ["share"] = shareName,
            ["accessible"] = accessible,
            ["status"] = statusCode,
        });
        return (accessible, type);
    }

    public Task<DomainPolicyInfo?> QueryDomainPolicyAsync(CancellationToken ct)
    {
        // SMBLibrary 1.5.7 does not expose LSARPC primitives publicly.
        // Tracked as gap-042-samr-over-smb-rpc follow-up.
        return Task.FromResult<DomainPolicyInfo?>(null);
    }

    public Task<IReadOnlyList<DomainUser>> SamrEnumDomainUsersAsync(CancellationToken ct)
    {
        // SMBLibrary 1.5.7 does not expose SAMR primitives publicly.
        // Tracked as gap-042-samr-over-smb-rpc follow-up.
        return Task.FromResult<IReadOnlyList<DomainUser>>(Array.Empty<DomainUser>());
    }

#pragma warning disable CS1998
    public async IAsyncEnumerable<DomainUser> RidCycleAsync(
        int ridStart, int ridEnd,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // SMBLibrary 1.5.7 does not expose LSARPC LookupSids publicly.
        // Tracked as gap-042-samr-over-smb-rpc follow-up.
        yield break;
    }
#pragma warning restore CS1998

    private static async Task<bool> TcpReachableAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
    {
        using var sock = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await sock.ConnectAsync(new IPEndPoint(ip, port), cts.Token).ConfigureAwait(false);
            return sock.Connected;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _smb2?.Logoff(); } catch { /* best effort */ }
        try { _smb2?.Disconnect(); } catch { /* best effort */ }
        try { _smb1?.Logoff(); } catch { /* best effort */ }
        try { _smb1?.Disconnect(); } catch { /* best effort */ }
    }

    /// <summary>SHA-256 of the sorted, joined username list. Used by the
    /// LDAP backend audit so usernames never leak into <c>audit.jsonl</c>
    /// while remaining correlatable across runs. Empty list yields the
    /// literal string <c>"empty"</c> (not a SHA of empty input) so the
    /// audit reader can distinguish "no users found" from "users hashed".</summary>
    internal static string DigestUsernames(IEnumerable<string> sams)
    {
        var sorted = sams.Where(s => !string.IsNullOrEmpty(s))
                         .OrderBy(s => s, StringComparer.Ordinal)
                         .ToList();
        if (sorted.Count == 0) return "empty";
        var joined = string.Join("\n", sorted);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(joined), hash);
        var sb = new StringBuilder(64);
        foreach (var b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
