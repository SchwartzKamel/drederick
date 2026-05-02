using System.Net;
using System.Runtime.CompilerServices;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Ad;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Ad;

public class SmbNullSessionToolTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-smb-null-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static List<string> ReadAuditEvents(string path)
    {
        if (!File.Exists(path)) return new();
        return File.ReadAllLines(path).ToList();
    }

    private sealed class StubSmbBackend : ISmbNullSessionBackend
    {
        public SmbNegotiateInfo? Negotiate { get; set; }
        public bool NullSessionSucceeds { get; set; }
        public List<SmbShare> Shares { get; set; } = new();
        public DomainPolicyInfo? Policy { get; set; }
        public List<DomainUser> SamrUsers { get; set; } = new();
        public List<DomainUser> RidCycleUsers { get; set; } = new();
        public TimeSpan RidCycleDelay { get; set; } = TimeSpan.Zero;
        public bool ThrowOnNegotiate { get; set; }

        public Task<SmbNegotiateInfo?> NegotiateAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
        {
            if (ThrowOnNegotiate) throw new InvalidOperationException("boom");
            return Task.FromResult(Negotiate);
        }
        public Task<bool> TryNullSessionAsync(CancellationToken ct) => Task.FromResult(NullSessionSucceeds);
        public Task<IReadOnlyList<SmbShare>> EnumerateSharesAsync(CancellationToken ct)
            => Task.FromResult<IReadOnlyList<SmbShare>>(Shares);
        public Task<DomainPolicyInfo?> QueryDomainPolicyAsync(CancellationToken ct)
            => Task.FromResult(Policy);
        public Task<IReadOnlyList<DomainUser>> SamrEnumDomainUsersAsync(CancellationToken ct)
            => Task.FromResult<IReadOnlyList<DomainUser>>(SamrUsers);
        public async IAsyncEnumerable<DomainUser> RidCycleAsync(
            int ridStart, int ridEnd, [EnumeratorCancellation] CancellationToken ct)
        {
            foreach (var u in RidCycleUsers)
            {
                if (RidCycleDelay > TimeSpan.Zero)
                {
                    await Task.Delay(RidCycleDelay, ct).ConfigureAwait(false);
                }
                ct.ThrowIfCancellationRequested();
                yield return u;
            }
        }
        public bool Disposed { get; private set; }
        public void Dispose() => Disposed = true;
    }

    private sealed class StubLdapBackend : IAnonLdapBackend
    {
        public AnonLdapResult? Result { get; set; }
        public Task<AnonLdapResult?> QueryAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
            => Task.FromResult(Result);
        public bool Disposed { get; private set; }
        public void Dispose() => Disposed = true;
    }

    private static SmbNullSessionTool Build(
        Scope.Scope scope,
        AuditLog audit,
        ISmbNullSessionBackend? smb = null,
        IAnonLdapBackend? ldap = null,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null)
    {
        return new SmbNullSessionTool(
            scope, audit,
            dnsResolver: resolver,
            smbBackendFactory: smb is null ? null : () => smb,
            ldapBackendFactory: ldap is null ? null : () => ldap,
            connectTimeout: TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task OutOfScope_Throws_NoBackendCalls()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var smb = new StubSmbBackend { Negotiate = new SmbNegotiateInfo("3.1.1", true, "guid") };
        var ldap = new StubLdapBackend();
        var tool = Build(scope, audit, smb, ldap);

        await Assert.ThrowsAsync<ScopeException>(() => tool.EnumerateAsync("8.8.8.8"));
        Assert.False(smb.Disposed);
        Assert.False(ldap.Disposed);
    }

    [Fact]
    public async Task Hostname_ResolvedIp_ScopeValidated()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.0", false, null),
            NullSessionSucceeds = false,
        };
        var ldap = new StubLdapBackend();
        var tool = Build(scope, audit, smb, ldap,
            resolver: (_, _) => Task.FromResult(new[] { IPAddress.Parse("10.0.0.42") }));

        var f = await tool.EnumerateAsync("dc.lab.htb");
        Assert.Equal("dc.lab.htb", f.Target);
        Assert.Equal("3.0", f.Smb2Dialect);
    }

    [Fact]
    public async Task Hostname_ResolvedToOutOfScope_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var tool = Build(scope, audit,
            smb: new StubSmbBackend(),
            ldap: new StubLdapBackend(),
            resolver: (_, _) => Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") }));
        await Assert.ThrowsAsync<ScopeException>(() => tool.EnumerateAsync("evil.example.com"));
    }

    [Fact]
    public async Task ConnectionRefused_RecordsErrorWithoutThrowing()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var smb = new StubSmbBackend { Negotiate = null };
        var ldap = new StubLdapBackend();
        var tool = Build(scope, audit, smb, ldap);

        var f = await tool.EnumerateAsync("10.0.0.5");
        Assert.Equal("connection_refused", f.Error);
        Assert.False(f.NullSessionOpen);
        Assert.Empty(f.Shares);
        audit.Dispose();
        Assert.Contains(ReadAuditEvents(path), l => l.Contains("smb-null-session.smb_unreachable"));
    }

    [Fact]
    public async Task Smb2NegotiateParsed_ReflectedInFinding()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.1.1", true, "abc-guid"),
            NullSessionSucceeds = false,
        };
        var tool = Build(scope, audit, smb, new StubLdapBackend());

        var f = await tool.EnumerateAsync("10.0.0.5");
        Assert.Equal("3.1.1", f.Smb2Dialect);
        Assert.True(f.SigningRequired);
        Assert.Equal("abc-guid", f.ServerGuid);
        Assert.False(f.NullSessionOpen);
    }

    [Fact]
    public async Task NullSessionRefused_NullSessionOpenFalse_AuditReflects()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("2.1", false, null),
            NullSessionSucceeds = false,
        };
        var tool = Build(scope, audit, smb, new StubLdapBackend());

        var f = await tool.EnumerateAsync("10.0.0.5");
        Assert.False(f.NullSessionOpen);
        audit.Dispose();
        var events = ReadAuditEvents(path);
        Assert.Contains(events, l => l.Contains("smb-null-session.null_session") && l.Contains("\"open\":false"));
    }

    [Fact]
    public async Task NullSessionOpen_ShareEnum_FiltersAdminSharesByDefault()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.1.1", false, null),
            NullSessionSucceeds = true,
            Shares = new()
            {
                new SmbShare("public", "DISK", "world readable", true),
                new SmbShare("internal", "DISK", "auth required", false),
                new SmbShare("ADMIN$", "DISK", "remote admin", false),
            },
        };
        var tool = Build(scope, audit, smb, new StubLdapBackend());

        var f = await tool.EnumerateAsync("10.0.0.5");
        Assert.True(f.NullSessionOpen);
        Assert.Equal(2, f.Shares.Count);
        Assert.DoesNotContain(f.Shares, s => s.Name == "ADMIN$");
        Assert.True(f.Shares.Single(s => s.Name == "public").ReadableAnonymously);
        Assert.False(f.Shares.Single(s => s.Name == "internal").ReadableAnonymously);
    }

    [Fact]
    public async Task IncludeAdminShares_KeepsAllShares()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.1.1", false, null),
            NullSessionSucceeds = true,
            Shares = new()
            {
                new SmbShare("public", "DISK", null, true),
                new SmbShare("ADMIN$", "DISK", null, false),
                new SmbShare("IPC$", "IPC", null, false),
            },
        };
        var tool = Build(scope, audit, smb, new StubLdapBackend());
        var f = await tool.EnumerateAsync("10.0.0.5", includeAdminShares: true);
        Assert.Equal(3, f.Shares.Count);
    }

    [Fact]
    public async Task RidCycle_FindsFiveUsers()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var users = Enumerable.Range(0, 5)
            .Select(i => new DomainUser($"user{i}", 500 + i, "0x10", Array.Empty<string>()))
            .ToList();
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.1.1", false, null),
            NullSessionSucceeds = true,
            RidCycleUsers = users,
        };
        var tool = Build(scope, audit, smb, new StubLdapBackend());

        var f = await tool.EnumerateAsync("10.0.0.5");
        Assert.Equal(5, f.Users.Count);
        Assert.Equal(new[] { "user0", "user1", "user2", "user3", "user4" },
            f.Users.Select(u => u.SamAccountName).ToArray());
        audit.Dispose();
        var events = ReadAuditEvents(path);
        Assert.Equal(5, events.Count(l => l.Contains("smb-null-session.user_found") && l.Contains("rid_cycle")));
    }

    [Fact]
    public async Task AnonymousLdapBind_Succeeds_PopulatesNamingContextAndUsers()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.1.1", false, null),
            NullSessionSucceeds = false,
        };
        var ldapUsers = new List<DomainUser>
        {
            new("alice", null, "0x200", new[] { "CN=Domain Admins,DC=lab,DC=htb" }),
            new("bob", null, null, Array.Empty<string>()),
            new("svc-sql", null, "0x10000", Array.Empty<string>()),
        };
        var ldap = new StubLdapBackend
        {
            Result = new AnonLdapResult(
                AnonymousBindOk: true,
                DefaultNamingContext: "DC=lab,DC=htb",
                RootDomainNamingContext: "DC=lab,DC=htb",
                SupportedSaslMechanisms: new[] { "GSSAPI", "GSS-SPNEGO" },
                Users: ldapUsers),
        };
        var tool = Build(scope, audit, smb, ldap);

        var f = await tool.EnumerateAsync("10.0.0.5");
        Assert.True(f.LdapAnonBindOk);
        Assert.Equal("DC=lab,DC=htb", f.DefaultNamingContext);
        Assert.Equal(3, f.Users.Count);
        Assert.Contains("GSSAPI", f.SupportedSaslMechanisms);
    }

    [Fact]
    public async Task AnonymousLdapBind_Rejected_NoUsers_StillCapturesSasl()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.1.1", false, null),
            NullSessionSucceeds = false,
        };
        var ldap = new StubLdapBackend
        {
            Result = new AnonLdapResult(
                AnonymousBindOk: false,
                DefaultNamingContext: null,
                RootDomainNamingContext: null,
                SupportedSaslMechanisms: new[] { "GSSAPI" },
                Users: null),
        };
        var tool = Build(scope, audit, smb, ldap);

        var f = await tool.EnumerateAsync("10.0.0.5");
        Assert.False(f.LdapAnonBindOk);
        Assert.Empty(f.Users);
        Assert.Contains("GSSAPI", f.SupportedSaslMechanisms);
    }

    [Fact]
    public async Task AuditEvents_StartFinishUserFoundShareFound_AllEmitted()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.1.1", true, "guid"),
            NullSessionSucceeds = true,
            Shares = new() { new SmbShare("share1", "DISK", null, true) },
            SamrUsers = new() { new DomainUser("admin", 500, null, Array.Empty<string>()) },
        };
        var tool = Build(scope, audit, smb, new StubLdapBackend());

        var f = await tool.EnumerateAsync("10.0.0.5");
        audit.Dispose();
        var events = ReadAuditEvents(path);
        Assert.Contains(events, l => l.Contains("smb-null-session.start"));
        Assert.Contains(events, l => l.Contains("smb-null-session.share_found") && l.Contains("share1"));
        Assert.Contains(events, l => l.Contains("smb-null-session.user_found") && l.Contains("admin"));
        Assert.Contains(events, l => l.Contains("smb-null-session.finish"));
        Assert.Single(f.Shares);
        Assert.Single(f.Users);
    }

    [Fact]
    public async Task Cancellation_DuringRidCycle_ReturnsPartialAndDoesNotEscape()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var users = Enumerable.Range(0, 50)
            .Select(i => new DomainUser($"user{i}", 500 + i, null, Array.Empty<string>()))
            .ToList();
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.1.1", false, null),
            NullSessionSucceeds = true,
            RidCycleUsers = users,
            RidCycleDelay = TimeSpan.FromMilliseconds(50),
        };
        var tool = Build(scope, audit, smb, new StubLdapBackend());

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(120));
        var f = await tool.EnumerateAsync("10.0.0.5", ct: cts.Token);
        // Some users found, but not all 50 — partial result, no exception escapes.
        Assert.True(f.Users.Count < 50, $"expected partial, got {f.Users.Count}");
    }

    [Fact]
    public async Task RidRange_HardCappedAt1000()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var requestedStart = 0;
        var requestedEnd = 999999;
        var smb = new StubSmbBackend
        {
            Negotiate = new SmbNegotiateInfo("3.1.1", false, null),
            NullSessionSucceeds = false,
        };
        var tool = Build(scope, audit, smb, new StubLdapBackend());
        await tool.EnumerateAsync("10.0.0.5", ridStart: requestedStart, ridEnd: requestedEnd);
        audit.Dispose();
        var events = ReadAuditEvents(path);
        var startLine = events.First(l => l.Contains("smb-null-session.start"));
        // After clamping, rid_end - rid_start + 1 == 1000 so rid_end should be 999.
        Assert.Contains("\"rid_end\":999", startLine);
    }
}
