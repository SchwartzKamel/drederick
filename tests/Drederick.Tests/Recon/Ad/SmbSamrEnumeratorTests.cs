using System.Net;
using System.Runtime.CompilerServices;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Ad;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Ad;

/// <summary>
/// GAP-042-samr: tests for <see cref="SmbSamrEnumerator"/> and the
/// SAMR / LDAP fallthrough wiring in <see cref="SmbLibraryBackend"/> +
/// <see cref="SmbNullSessionTool"/>. The rpcclient subprocess is
/// stubbed end-to-end via <see cref="IRpcclientRunner"/> so no real
/// fork happens.
/// </summary>
public class SmbSamrEnumeratorTests
{
    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-samr-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static List<string> ReadLines(string path)
        => File.Exists(path) ? File.ReadAllLines(path).ToList() : new();

    private sealed class FakeRpcclientRunner : IRpcclientRunner
    {
        public RpcclientResult Result { get; set; } = new(0, string.Empty, string.Empty);
        public List<string>? LastArgv { get; private set; }
        public string? LastBinary { get; private set; }
        public int CallCount { get; private set; }
        public Exception? Throw { get; set; }

        public Task<RpcclientResult> RunAsync(
            string binaryPath, IReadOnlyList<string> argv, TimeSpan timeout, CancellationToken ct)
        {
            CallCount++;
            LastBinary = binaryPath;
            LastArgv = argv.ToList();
            if (Throw is not null) throw Throw;
            return Task.FromResult(Result);
        }
    }

    private static SmbSamrEnumerator Build(
        Scope.Scope scope, AuditLog audit, FakeRpcclientRunner runner,
        Func<string?>? locator = null)
    {
        return new SmbSamrEnumerator(
            scope, audit,
            runner: runner,
            rpcclientLocator: locator ?? (() => "/usr/bin/rpcclient"),
            timeout: TimeSpan.FromSeconds(5));
    }

    // ---- 1. rpcclient missing ------------------------------------------

    [Fact]
    public async Task Detect_RpcclientMissing_GracefulError()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var runner = new FakeRpcclientRunner();
        var enumerator = Build(scope, audit, runner, locator: () => null);

        var result = await enumerator.EnumerateDomainUsersAsync(IPAddress.Parse("10.0.0.5"), default);
        audit.Dispose();

        Assert.Equal("rpcclient_not_installed", result.ErrorKind);
        Assert.Empty(result.Users);
        Assert.Equal(0, runner.CallCount);
        var events = ReadLines(path);
        Assert.Contains(events, l => l.Contains("smb_null_session.samr.detected_rpcclient") && l.Contains("\"available\":false"));
        Assert.Contains(events, l => l.Contains("smb_null_session.samr.error") && l.Contains("rpcclient_not_installed"));
    }

    // ---- 2. canonical happy path ---------------------------------------

    [Fact]
    public async Task Parse_EnumDomUsers_StandardOutput()
    {
        const string output = """
            user:[Administrator] rid:[0x1f4]
            user:[Guest] rid:[0x1f5]
            user:[krbtgt] rid:[0x1f6]
            user:[svc-sql] rid:[0x10f1]
            """;
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var runner = new FakeRpcclientRunner { Result = new(0, output, string.Empty) };
        var enumerator = Build(scope, audit, runner);

        var result = await enumerator.EnumerateDomainUsersAsync(IPAddress.Parse("10.0.0.5"), default);
        audit.Dispose();

        Assert.Null(result.ErrorKind);
        Assert.Equal(4, result.Users.Count);
        Assert.Equal("Administrator", result.Users[0].SamAccountName);
        Assert.Equal(0x1f4, result.Users[0].Rid);
        Assert.Equal("krbtgt", result.Users[2].SamAccountName);
        Assert.Equal(0x1f6, result.Users[2].Rid);
        Assert.Equal(0x10f1, result.Users[3].Rid);

        // Argv re-validation: the IP is in argv exactly once, no shell.
        Assert.NotNull(runner.LastArgv);
        Assert.Contains("10.0.0.5", runner.LastArgv!);
        Assert.Contains("-N", runner.LastArgv);
        Assert.Contains("enumdomusers", runner.LastArgv);
        // -U "" anonymity
        Assert.Equal("-U", runner.LastArgv[0]);
        Assert.Equal(string.Empty, runner.LastArgv[1]);

        var events = ReadLines(path);
        Assert.Contains(events, l => l.Contains("smb_null_session.samr.enum_users.finish") && l.Contains("\"user_count\":4"));
    }

    // ---- 3. empty output ------------------------------------------------

    [Fact]
    public async Task Parse_EnumDomUsers_EmptyOutput()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var runner = new FakeRpcclientRunner { Result = new(0, string.Empty, string.Empty) };
        var enumerator = Build(scope, audit, runner);

        var result = await enumerator.EnumerateDomainUsersAsync(IPAddress.Parse("10.0.0.5"), default);

        Assert.Null(result.ErrorKind);
        Assert.Empty(result.Users);
    }

    // ---- 4. access denied ----------------------------------------------

    [Fact]
    public async Task Parse_EnumDomUsers_AccessDenied()
    {
        const string stderr = "result was NT_STATUS_ACCESS_DENIED";
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var runner = new FakeRpcclientRunner { Result = new(1, string.Empty, stderr) };
        var enumerator = Build(scope, audit, runner);

        var result = await enumerator.EnumerateDomainUsersAsync(IPAddress.Parse("10.0.0.5"), default);
        audit.Dispose();

        Assert.Equal("access_denied", result.ErrorKind);
        Assert.Empty(result.Users);
        var events = ReadLines(path);
        Assert.Contains(events, l => l.Contains("smb_null_session.samr.error") && l.Contains("access_denied"));
    }

    // ---- 5. rpc bind rejected ------------------------------------------

    [Fact]
    public async Task Parse_EnumDomUsers_RpcBindRejected()
    {
        const string stderr = "Cannot connect to server. Error was NT_STATUS_CONNECTION_REFUSED";
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var runner = new FakeRpcclientRunner { Result = new(1, string.Empty, stderr) };
        var enumerator = Build(scope, audit, runner);

        var result = await enumerator.EnumerateDomainUsersAsync(IPAddress.Parse("10.0.0.5"), default);

        Assert.Equal("rpc_bind_rejected", result.ErrorKind);
        Assert.Empty(result.Users);
    }

    // ---- 6. plaintext discipline ---------------------------------------

    [Fact]
    public async Task Plaintext_UsernameNotInAudit()
    {
        const string canary = "PLAINTEXT_CANARY_HUNTER2_USER";
        var output = $"user:[{canary}] rid:[0x1f4]\n";
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out var path);
        var runner = new FakeRpcclientRunner { Result = new(0, output, string.Empty) };
        var enumerator = Build(scope, audit, runner);

        var result = await enumerator.EnumerateDomainUsersAsync(IPAddress.Parse("10.0.0.5"), default);
        audit.Dispose();

        Assert.Single(result.Users);
        Assert.Equal(canary, result.Users[0].SamAccountName);

        var auditBlob = string.Join("\n", ReadLines(path));
        Assert.DoesNotContain(canary, auditBlob);
    }

    // ---- 7. scope guard ------------------------------------------------

    [Fact]
    public async Task Scope_OutOfScopeHost_Throws()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var runner = new FakeRpcclientRunner();
        var enumerator = Build(scope, audit, runner);

        await Assert.ThrowsAsync<ScopeException>(() =>
            enumerator.EnumerateDomainUsersAsync(IPAddress.Parse("8.8.8.8"), default));
        Assert.Equal(0, runner.CallCount);
    }

    // ---- 8 & 9. backend integration: LDAP fallback gating --------------

    private sealed class StubSmbBackendForFallback : ISmbNullSessionBackend
    {
        public SmbNegotiateInfo? Negotiate { get; set; } = new("3.1.1", false, null);
        public bool NullSessionSucceeds { get; set; } = true;
        public List<DomainUser> SamrUsers { get; set; } = new();
        public Task<SmbNegotiateInfo?> NegotiateAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
            => Task.FromResult(Negotiate);
        public Task<bool> TryNullSessionAsync(CancellationToken ct) => Task.FromResult(NullSessionSucceeds);
        public Task<IReadOnlyList<SmbShare>> EnumerateSharesAsync(CancellationToken ct)
            => Task.FromResult<IReadOnlyList<SmbShare>>(Array.Empty<SmbShare>());
        public Task<DomainPolicyInfo?> QueryDomainPolicyAsync(CancellationToken ct)
            => Task.FromResult<DomainPolicyInfo?>(null);
        public Task<IReadOnlyList<DomainUser>> SamrEnumDomainUsersAsync(CancellationToken ct)
            => Task.FromResult<IReadOnlyList<DomainUser>>(SamrUsers);
        public async IAsyncEnumerable<DomainUser> RidCycleAsync(
            int ridStart, int ridEnd, [EnumeratorCancellation] CancellationToken ct)
        {
            await Task.CompletedTask;
            yield break;
        }
        public void Dispose() { }
    }

    private sealed class TrackingLdapBackend : IAnonLdapBackend
    {
        public int CallCount;
        public Task<AnonLdapResult?> QueryAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
        {
            CallCount++;
            return Task.FromResult<AnonLdapResult?>(new AnonLdapResult(
                AnonymousBindOk: true,
                DefaultNamingContext: "DC=test",
                RootDomainNamingContext: "DC=test",
                SupportedSaslMechanisms: Array.Empty<string>(),
                Users: new List<DomainUser>
                {
                    new("from_ldap", null, null, Array.Empty<string>()),
                }));
        }
        public void Dispose() { }
    }

    [Fact]
    public async Task Backend_LdapFallbackOnlyIfSamrEmpty_SamrPopulated_LdapSkipped()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var smb = new StubSmbBackendForFallback
        {
            SamrUsers = new()
            {
                new DomainUser("Administrator", 500, null, Array.Empty<string>()),
                new DomainUser("Guest", 501, null, Array.Empty<string>()),
                new DomainUser("krbtgt", 502, null, Array.Empty<string>()),
            },
        };
        var ldap = new TrackingLdapBackend();
        var tool = new SmbNullSessionTool(
            scope, audit,
            dnsResolver: null,
            smbBackendFactory: () => smb,
            ldapBackendFactory: () => ldap,
            connectTimeout: TimeSpan.FromSeconds(2));

        var f = await tool.EnumerateAsync("10.0.0.5");

        Assert.Equal(3, f.Users.Count);
        Assert.Equal(0, ldap.CallCount);
        Assert.DoesNotContain(f.Users, u => u.SamAccountName == "from_ldap");
    }

    [Fact]
    public async Task Backend_LdapFallbackOnlyIfSamrEmpty_SamrEmpty_LdapAttempted()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var smb = new StubSmbBackendForFallback { SamrUsers = new() };
        var ldap = new TrackingLdapBackend();
        var tool = new SmbNullSessionTool(
            scope, audit,
            dnsResolver: null,
            smbBackendFactory: () => smb,
            ldapBackendFactory: () => ldap,
            connectTimeout: TimeSpan.FromSeconds(2));

        var f = await tool.EnumerateAsync("10.0.0.5");

        Assert.Equal(1, ldap.CallCount);
        Assert.Contains(f.Users, u => u.SamAccountName == "from_ldap");
    }

    // ---- 10. backend wiring: production SmbLibraryBackend uses SAMR ----

    [Fact]
    public async Task SmbLibraryBackend_WithSamrEnumerator_DelegatesUserEnum()
    {
        var scope = ScopeLoader.Parse("10.0.0.0/24");
        using var audit = NewAudit(out _);
        var runner = new FakeRpcclientRunner
        {
            Result = new(0, "user:[Administrator] rid:[0x1f4]\n", string.Empty),
        };
        var samr = new SmbSamrEnumerator(
            scope, audit,
            runner: runner,
            rpcclientLocator: () => "/usr/bin/rpcclient",
            timeout: TimeSpan.FromSeconds(5));
        using var backend = new SmbLibraryBackend(scope, audit, samr);

        // Drive Negotiate first to populate the backend's _ip. Out-of-
        // scope IP would throw before reaching the network — we use an
        // in-scope IP and accept that the real connect will fail in CI;
        // the contract under test is that SAMR delegation still happens
        // when _ip is set.
        // Use a private invocation pattern: call SamrEnumDomainUsersAsync
        // after manually warming up via a NegotiateAsync that probes a
        // closed port (NegotiateAsync caches _ip even on failure).
        await backend.NegotiateAsync(IPAddress.Parse("10.0.0.99"), TimeSpan.FromMilliseconds(50), default);
        var users = await backend.SamrEnumDomainUsersAsync(default);

        Assert.Single(users);
        Assert.Equal("Administrator", users[0].SamAccountName);
        Assert.Equal(1, runner.CallCount);
    }

    // ---- pure-parser unit tests ----------------------------------------

    [Fact]
    public void ParseEnumDomUsers_DecimalRid_AlsoAccepted()
    {
        var users = SmbSamrEnumerator.ParseEnumDomUsers("user:[bob] rid:[1234]\n");
        Assert.Single(users);
        Assert.Equal(1234, users[0].Rid);
    }

    [Fact]
    public void ParseEnumDomUsers_IgnoresBannerAndJunk()
    {
        const string output = """
            Domain Name: LAB
            user:[alice] rid:[0x1f4]
            -- end of users --
            user:[bob] rid:[0x1f5]
            """;
        var users = SmbSamrEnumerator.ParseEnumDomUsers(output);
        Assert.Equal(2, users.Count);
        Assert.Equal("alice", users[0].SamAccountName);
        Assert.Equal("bob", users[1].SamAccountName);
    }

    [Fact]
    public void ClassifyError_MapsCommonNtStatuses()
    {
        Assert.Equal("rpc_bind_rejected", SmbSamrEnumerator.ClassifyError(1, "", "NT_STATUS_CONNECTION_REFUSED"));
        Assert.Equal("access_denied", SmbSamrEnumerator.ClassifyError(1, "NT_STATUS_ACCESS_DENIED", ""));
        Assert.Equal("access_denied", SmbSamrEnumerator.ClassifyError(1, "", "NT_STATUS_LOGON_FAILURE"));
        Assert.Null(SmbSamrEnumerator.ClassifyError(0, "user:[admin] rid:[0x1f4]", ""));
        Assert.Equal("rpcclient_nonzero_exit", SmbSamrEnumerator.ClassifyError(2, "", "totally unknown"));
    }
}
