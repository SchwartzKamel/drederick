using System.Net;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Ad;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Ad;

/// <summary>
/// Tests for the production <see cref="SmbLibraryLdapBackend"/>. The Novell
/// connection is wedged behind <see cref="ILdapAdapter"/> so we never spin
/// up a real LDAP server. SMB-side <see cref="SmbLibraryBackend"/> is
/// covered indirectly: SMBLibrary 1.5.7's surface has no public seam for
/// dependency-injecting the transport, so the SMB backend's contract is
/// asserted only at the scope-rejection boundary (no network reach is
/// attempted on out-of-scope IPs because <c>_scope.Require</c> is the
/// first statement of every public method). End-to-end SMB exercise lives
/// in the existing <see cref="SmbNullSessionToolTests"/> via the
/// <c>StubSmbBackend</c> seam — the production class we ship here is a
/// thin SMBLibrary driver, so the seam-level coverage is the durable
/// path.
/// </summary>
public class SmbLibraryBackendTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-smblib-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static List<string> ReadLines(string path)
        => File.Exists(path) ? File.ReadAllLines(path).ToList() : new();

    // ---------------- Fake LDAP adapter --------------------------------

    private sealed class FakeLdapAdapter : ILdapAdapter
    {
        public bool BindShouldThrow { get; set; }
        public LdapEntryDto? RootDse { get; set; }
        public List<LdapUserDto> Users { get; set; } = new();
        public bool ConnectCalled { get; private set; }
        public bool BindCalled { get; private set; }
        public bool SearchCalled { get; private set; }
        public bool Disposed { get; private set; }
        public TimeSpan SearchDelay { get; set; }

        public Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            ConnectCalled = true;
            return Task.CompletedTask;
        }
        public Task BindAnonymousAsync(CancellationToken ct)
        {
            BindCalled = true;
            if (BindShouldThrow) throw new InvalidOperationException("STATUS_LOGON_FAILURE");
            return Task.CompletedTask;
        }
        public Task<LdapEntryDto?> ReadRootDseAsync(CancellationToken ct)
            => Task.FromResult(RootDse);
        public async Task<IReadOnlyList<LdapUserDto>> SearchUsersAsync(string baseDn, int max, CancellationToken ct)
        {
            SearchCalled = true;
            if (SearchDelay > TimeSpan.Zero) await Task.Delay(SearchDelay, ct).ConfigureAwait(false);
            return Users;
        }
        public void Dispose() => Disposed = true;
    }

    private static SmbLibraryLdapBackend Build(Scope.Scope scope, AuditLog audit, ILdapAdapter adapter)
        => new SmbLibraryLdapBackend(scope, audit, _ => adapter);

    // ---------------- Tests --------------------------------------------

    [Fact]
    public async Task Backend_OutOfScopeIp_ThrowsScopeException_BeforeConnect()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var fake = new FakeLdapAdapter();
        var backend = Build(scope, audit, fake);

        await Assert.ThrowsAsync<ScopeException>(() => backend.QueryAsync(
            IPAddress.Parse("8.8.8.8"), 389, TimeSpan.FromSeconds(2), default));
        Assert.False(fake.ConnectCalled);
        Assert.False(fake.BindCalled);
    }

    [Fact]
    public async Task BindRejected_NoUsers_FindingErrorPropagated()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var fake = new FakeLdapAdapter { BindShouldThrow = true };
        var backend = Build(scope, audit, fake);

        var result = await backend.QueryAsync(IPAddress.Parse("10.0.0.5"), 389, TimeSpan.FromSeconds(2), default);
        Assert.NotNull(result);
        Assert.False(result!.AnonymousBindOk);
        Assert.Empty(result.Users!);
        Assert.False(fake.SearchCalled);
        audit.Dispose();
        var lines = ReadLines(path);
        Assert.Contains(lines, l => l.Contains("ldap_anon_bind.start"));
        Assert.Contains(lines, l => l.Contains("ldap_anon_bind.finish") && l.Contains("\"bound\":false"));
    }

    [Fact]
    public async Task BindOk_RootDseRead_NamingContextAndSaslPopulated()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var fake = new FakeLdapAdapter
        {
            RootDse = new LdapEntryDto("DC=lab,DC=htb", "DC=lab,DC=htb",
                new[] { "GSSAPI", "GSS-SPNEGO" }),
            Users = new List<LdapUserDto>
            {
                new("alice", 1103, "0x200", new[] { "CN=Domain Users,DC=lab,DC=htb" }),
                new("bob", 1104, null, Array.Empty<string>()),
            },
        };
        var backend = Build(scope, audit, fake);

        var result = await backend.QueryAsync(IPAddress.Parse("10.0.0.5"), 389, TimeSpan.FromSeconds(2), default);
        Assert.NotNull(result);
        Assert.True(result!.AnonymousBindOk);
        Assert.Equal("DC=lab,DC=htb", result.DefaultNamingContext);
        Assert.Contains("GSSAPI", result.SupportedSaslMechanisms!);
        Assert.Equal(2, result.Users!.Count);
        Assert.Contains(result.Users, u => u.SamAccountName == "alice" && u.Rid == 1103);
    }

    [Fact]
    public async Task PlaintextDiscipline_AuditNeverLogsUsernames_FindingDoes()
    {
        const string canary = "PLAINTEXT_CANARY_HUNTER2";
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var fake = new FakeLdapAdapter
        {
            RootDse = new LdapEntryDto("DC=lab,DC=htb", null, Array.Empty<string>()),
            Users = new List<LdapUserDto>
            {
                new("alice", null, null, Array.Empty<string>()),
                new(canary, null, null, Array.Empty<string>()),
                new("bob", null, null, Array.Empty<string>()),
            },
        };
        var backend = Build(scope, audit, fake);

        var result = await backend.QueryAsync(IPAddress.Parse("10.0.0.5"), 389, TimeSpan.FromSeconds(2), default);
        audit.Dispose();

        // Structured finding MUST contain the canary (downstream gap-043 needs it).
        Assert.Contains(result!.Users!, u => u.SamAccountName == canary);

        // Audit log MUST NOT contain the canary anywhere.
        var auditText = File.ReadAllText(path);
        Assert.DoesNotContain(canary, auditText);

        // Audit MUST contain count + digest.
        var lines = ReadLines(path);
        var finishLine = lines.Single(l => l.Contains("ldap_user_search.finish"));
        Assert.Contains("\"user_count\":3", finishLine);
        Assert.Contains("\"users_digest\":", finishLine);
    }

    [Fact]
    public async Task EmptyUserList_DigestIsEmptySentinel_NotShaOfEmptyString()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var fake = new FakeLdapAdapter
        {
            RootDse = new LdapEntryDto("DC=lab,DC=htb", null, Array.Empty<string>()),
            Users = new List<LdapUserDto>(),
        };
        var backend = Build(scope, audit, fake);

        await backend.QueryAsync(IPAddress.Parse("10.0.0.5"), 389, TimeSpan.FromSeconds(2), default);
        audit.Dispose();
        var lines = ReadLines(path);
        var finishLine = lines.Single(l => l.Contains("ldap_user_search.finish"));
        Assert.Contains("\"user_count\":0", finishLine);
        Assert.Contains("\"users_digest\":\"empty\"", finishLine);
    }

    [Fact]
    public async Task UsernameWithControlChars_NoLogInjection_FindingPreservesValue()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var weird = "alice\r\nadmin";
        var fake = new FakeLdapAdapter
        {
            RootDse = new LdapEntryDto("DC=lab,DC=htb", null, Array.Empty<string>()),
            Users = new List<LdapUserDto> { new(weird, null, null, Array.Empty<string>()) },
        };
        var backend = Build(scope, audit, fake);

        var result = await backend.QueryAsync(IPAddress.Parse("10.0.0.5"), 389, TimeSpan.FromSeconds(2), default);
        audit.Dispose();
        // Finding preserves the value verbatim so downstream callers see what was returned.
        Assert.Equal(weird, result!.Users!.Single().SamAccountName);
        // Audit must not split into a new line and inject a fake event header.
        var auditLines = ReadLines(path);
        Assert.DoesNotContain(auditLines, l => l.StartsWith("admin"));
        // Each line must still parse as JSON (no broken records).
        foreach (var l in auditLines)
        {
            Assert.StartsWith("{", l);
            Assert.EndsWith("}", l);
        }
    }

    [Fact]
    public async Task NoBaseDn_NoUserSearch_BindStillRecorded()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var fake = new FakeLdapAdapter
        {
            RootDse = new LdapEntryDto(null, null, new[] { "GSSAPI" }),
        };
        var backend = Build(scope, audit, fake);

        var result = await backend.QueryAsync(IPAddress.Parse("10.0.0.5"), 389, TimeSpan.FromSeconds(2), default);
        Assert.True(result!.AnonymousBindOk);
        Assert.Empty(result.Users!);
        Assert.False(fake.SearchCalled);
        audit.Dispose();
        var lines = ReadLines(path);
        Assert.Contains(lines, l => l.Contains("ldap_anon_bind.finish") && l.Contains("\"bound\":true"));
        Assert.DoesNotContain(lines, l => l.Contains("ldap_user_search"));
    }

    [Fact]
    public async Task AdapterDisposed_AfterQuery()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var fake = new FakeLdapAdapter
        {
            RootDse = new LdapEntryDto("DC=lab,DC=htb", null, Array.Empty<string>()),
        };
        var backend = Build(scope, audit, fake);
        await backend.QueryAsync(IPAddress.Parse("10.0.0.5"), 389, TimeSpan.FromSeconds(2), default);
        Assert.True(fake.Disposed);
    }

    [Fact]
    public async Task Cancellation_DuringSearch_PropagatesAndDisposesAdapter()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var fake = new FakeLdapAdapter
        {
            RootDse = new LdapEntryDto("DC=lab,DC=htb", null, Array.Empty<string>()),
            Users = new List<LdapUserDto> { new("alice", null, null, Array.Empty<string>()) },
            SearchDelay = TimeSpan.FromSeconds(2),
        };
        var backend = Build(scope, audit, fake);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            backend.QueryAsync(IPAddress.Parse("10.0.0.5"), 389, TimeSpan.FromSeconds(2), cts.Token));
        Assert.True(fake.Disposed);
    }

    // ---------------- DigestUsernames helper ---------------------------

    [Fact]
    public void DigestUsernames_DeterministicSortedHash()
    {
        var d1 = SmbLibraryBackend.DigestUsernames(new[] { "bob", "alice" });
        var d2 = SmbLibraryBackend.DigestUsernames(new[] { "alice", "bob" });
        Assert.Equal(d1, d2);
        Assert.NotEqual("empty", d1);
        Assert.Equal(64, d1.Length);
    }

    [Fact]
    public void DigestUsernames_EmptyOrNullsOnly_ReturnsEmptySentinel()
    {
        Assert.Equal("empty", SmbLibraryBackend.DigestUsernames(Array.Empty<string>()));
        Assert.Equal("empty", SmbLibraryBackend.DigestUsernames(new[] { "", "" }));
    }

    // ---------------- SMB backend scope guard --------------------------

    [Fact]
    public async Task SmbBackend_OutOfScopeIp_ThrowsScopeException_NoNetworkReach()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        using var smb = new SmbLibraryBackend(scope, audit);
        await Assert.ThrowsAsync<ScopeException>(() =>
            smb.NegotiateAsync(IPAddress.Parse("8.8.8.8"), TimeSpan.FromMilliseconds(50), default));
    }

    [Fact]
    public async Task SmbBackend_RpcMethodsReturnEmpty_PendingSamrFollowup()
    {
        // SMBLibrary 1.5.7 does not expose LSARPC/SAMR primitives. Until
        // gap-042-samr-over-smb-rpc lands, these methods deliberately
        // return empty so the LDAP path remains the user-enum source of
        // truth. Lock the contract so a future refactor can't accidentally
        // start spawning RPC traffic without the proper invariants in place.
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        using var smb = new SmbLibraryBackend(scope, audit);
        Assert.Null(await smb.QueryDomainPolicyAsync(default));
        Assert.Empty(await smb.SamrEnumDomainUsersAsync(default));
        var rids = new List<DomainUser>();
        await foreach (var u in smb.RidCycleAsync(500, 600, default)) rids.Add(u);
        Assert.Empty(rids);
    }
}
