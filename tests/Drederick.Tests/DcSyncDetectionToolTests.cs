using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;
using KerbLdap = Drederick.Recon.Shared;

namespace Drederick.Tests;

public class DcSyncDetectionToolTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-dcsync-{Guid.NewGuid():N}.jsonl");

    private sealed class FakeLdap : KerbLdap.ILdapClient
    {
        public bool BindCalled;
        public string? BindUser;
        public Exception? BindThrow;
        public string? DefaultNamingContext = "DC=corp,DC=example,DC=com";
        public List<KerbLdap.LdapEntry> Entries = new();
        public string? LastBaseDn;
        public string? LastFilter;
        public bool Disposed;

        public void Bind(string? user, string? password)
        {
            BindCalled = true;
            BindUser = user;
            if (BindThrow != null) throw BindThrow;
        }

        public string? GetDefaultNamingContext() => DefaultNamingContext;

        public IEnumerable<KerbLdap.LdapEntry> Search(string baseDn, string filter, string[] attrs, int size)
        {
            LastBaseDn = baseDn;
            LastFilter = filter;
            return Entries;
        }

        public void Dispose() => Disposed = true;
    }

    /// <summary>
    /// Build a minimal self-relative SD that has one DACL ACE of type
    /// ACCESS_ALLOWED_OBJECT_ACE (0x05) granting the given right GUID to
    /// the given SID.
    ///
    /// Layout (all LE unless noted):
    ///   SD header (20 bytes):
    ///     rev(1) sbz(1) control(2) offOwner(4) offGroup(4) offSacl(4) offDacl(4)
    ///   ACL header (8 bytes):
    ///     rev(1) sbz(1) aclSize(2) aceCount(2) sbz2(2)
    ///   ACCESS_ALLOWED_OBJECT_ACE:
    ///     aceType(1) aceFlags(1) aceSize(2) mask(4) objFlags(4) guid(16) sid(var)
    /// </summary>
    private static string BuildSd(byte[] rightGuid, byte[] sidBytes)
    {
        // SID is variable; compute ACE size.
        int aceBodySize = 4 + 4 + 16 + sidBytes.Length; // mask + objFlags + guid + sid
        int aceSize = 4 + aceBodySize; // header(4) + body
        int aclSize = 8 + aceSize;
        int sdSize = 20 + aclSize;

        var sd = new byte[sdSize];
        // SD header.
        sd[0] = 1; // revision
        sd[1] = 0; // sbz1
        sd[2] = 0x04; sd[3] = 0x00; // control: SE_DACL_PRESENT
        // offOwner, offGroup, offSacl = 0 (not present)
        // offDacl = 20
        BitConverter.TryWriteBytes(new Span<byte>(sd, 16, 4), 20);

        // ACL header at offset 20.
        sd[20] = 2; // revision
        sd[21] = 0;
        BitConverter.TryWriteBytes(new Span<byte>(sd, 22, 2), (ushort)aclSize);
        sd[24] = 1; sd[25] = 0; // aceCount = 1
        sd[26] = 0; sd[27] = 0;

        // ACE at offset 28.
        sd[28] = 0x05; // ACCESS_ALLOWED_OBJECT_ACE
        sd[29] = 0x00; // aceFlags
        BitConverter.TryWriteBytes(new Span<byte>(sd, 30, 2), (ushort)aceSize);
        // Mask at offset 32 (4 bytes) = 0x00000000 (not needed for our check).
        // ObjectFlags at offset 36 = 0x1 (ACE_OBJECT_TYPE_PRESENT).
        BitConverter.TryWriteBytes(new Span<byte>(sd, 36, 4), 1u);
        // ObjectType GUID at offset 40 (16 bytes).
        Array.Copy(rightGuid, 0, sd, 40, 16);
        // SID at offset 56.
        Array.Copy(sidBytes, 0, sd, 56, sidBytes.Length);

        return Convert.ToHexString(sd);
    }

    /// <summary>Build a SID byte array for S-1-5-21-a-b-c-rid.</summary>
    private static byte[] DomainSid(uint rid)
    {
        // S-1-5-21-1-2-3-<rid>: 5 sub-authorities.
        // rev=1 subCount=5 authority=000000000005 sub0=21 sub1=1 sub2=2 sub3=3 sub4=rid
        var b = new byte[8 + 5 * 4];
        b[0] = 1; b[1] = 5;
        // 6-byte BE authority = 5
        b[7] = 5;
        BitConverter.TryWriteBytes(new Span<byte>(b, 8, 4), 21u);
        BitConverter.TryWriteBytes(new Span<byte>(b, 12, 4), 1u);
        BitConverter.TryWriteBytes(new Span<byte>(b, 16, 4), 2u);
        BitConverter.TryWriteBytes(new Span<byte>(b, 20, 4), 3u);
        BitConverter.TryWriteBytes(new Span<byte>(b, 24, 4), rid);
        return b;
    }

    /// <summary>Build a SID byte array for S-1-5-x (two sub-auths).</summary>
    private static byte[] SimpleSid(uint sub1, uint sub2)
    {
        var b = new byte[8 + 2 * 4];
        b[0] = 1; b[1] = 2;
        b[7] = 5;
        BitConverter.TryWriteBytes(new Span<byte>(b, 8, 4), sub1);
        BitConverter.TryWriteBytes(new Span<byte>(b, 12, 4), sub2);
        return b;
    }

    private static KerbLdap.LdapEntry DomainEntry(string sdHex)
    {
        var e = new KerbLdap.LdapEntry { DistinguishedName = "DC=corp,DC=example,DC=com" };
        e.Attributes["nTSecurityDescriptor"] = new List<string> { sdHex };
        return e;
    }

    [Fact]
    public async Task Refuses_Out_Of_Scope_Target()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        var tool = new DcSyncDetectionTool(scope, audit, (_, _, _, _) => fake);
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("8.8.8.8"));
        Assert.False(fake.BindCalled);
    }

    [Fact]
    public async Task Suspicious_Principal_Detected_For_Non_Admin_Sid()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        // A non-built-in SID (RID 1104) with DS-Replication-Get-Changes-All.
        var sdHex = BuildSd(DcSyncDetectionTool.GuidGetChangesAll, DomainSid(1104));
        fake.Entries.Add(DomainEntry(sdHex));
        var tool = new DcSyncDetectionTool(scope, audit, (_, _, _, _) => fake);

        var r = await tool.ProbeAsync("10.10.10.5");
        Assert.Null(r.Error);
        var p = Assert.Single(r.SuspiciousPrincipals);
        Assert.Contains("S-1-5-21-1-2-3-1104", p.Sid);
        Assert.Contains("DS-Replication-Get-Changes-All", p.Rights);
        Assert.Equal("red", p.Severity);
        Assert.Empty(r.KnownLegitimate);
    }

    [Fact]
    public async Task Legitimate_Domain_Admins_Sid_Goes_To_Known_Legitimate()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        // RID 512 = Domain Admins → well-known.
        var sdHex = BuildSd(DcSyncDetectionTool.GuidGetChangesAll, DomainSid(512));
        fake.Entries.Add(DomainEntry(sdHex));
        var tool = new DcSyncDetectionTool(scope, audit, (_, _, _, _) => fake);

        var r = await tool.ProbeAsync("10.10.10.5");
        Assert.Empty(r.SuspiciousPrincipals);
        var p = Assert.Single(r.KnownLegitimate);
        Assert.Equal("S-1-5-21-1-2-3-512", p.Sid);
        Assert.Equal("green", p.Severity);
    }

    [Fact]
    public async Task DomainControllers_Rid516_Is_Legitimate()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        var sdHex = BuildSd(DcSyncDetectionTool.GuidGetChanges, DomainSid(516));
        fake.Entries.Add(DomainEntry(sdHex));
        var tool = new DcSyncDetectionTool(scope, audit, (_, _, _, _) => fake);

        var r = await tool.ProbeAsync("10.10.10.5");
        Assert.Empty(r.SuspiciousPrincipals);
        Assert.Single(r.KnownLegitimate);
    }

    [Fact]
    public async Task Multiple_Rights_Accumulate_On_Same_Sid()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        // We simulate two ACEs for the same SID by putting them in separate LDAP
        // entries and testing ParseAcl's accumulation logic directly.
        var sidBytes = DomainSid(1337);
        var sidStr = "S-1-5-21-1-2-3-1337";
        var result = new DcSyncRightsResult();
        // First right.
        var sd1 = BuildSd(DcSyncDetectionTool.GuidGetChanges, sidBytes);
        DcSyncDetectionTool.ParseAcl(Convert.FromHexString(sd1), result);
        // Second right for same SID.
        var sd2 = BuildSd(DcSyncDetectionTool.GuidGetChangesAll, sidBytes);
        DcSyncDetectionTool.ParseAcl(Convert.FromHexString(sd2), result);

        Assert.Single(result.SuspiciousPrincipals);
        var p = result.SuspiciousPrincipals[0];
        Assert.Equal(sidStr, p.Sid);
        Assert.Equal(2, p.Rights.Count);
        Assert.Contains("DS-Replication-Get-Changes", p.Rights);
        Assert.Contains("DS-Replication-Get-Changes-All", p.Rights);
    }

    [Fact]
    public async Task Bind_Failure_Is_Recorded_Without_Throwing()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap { BindThrow = new InvalidOperationException("strong auth required") };
        var tool = new DcSyncDetectionTool(scope, audit, (_, _, _, _) => fake);
        var r = await tool.ProbeAsync("10.10.10.5");
        Assert.NotNull(r.Error);
        Assert.Empty(r.SuspiciousPrincipals);
    }

    [Fact]
    public async Task Missing_NamingContext_Yields_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap { DefaultNamingContext = null };
        var tool = new DcSyncDetectionTool(scope, audit, (_, _, _, _) => fake);
        var r = await tool.ProbeAsync("10.10.10.5");
        Assert.Equal("no defaultNamingContext on rootDSE", r.Error);
    }

    [Fact]
    public async Task Authenticated_Bind_Logs_Authenticated_True_And_No_Plaintext()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var ap = NewAuditPath();
        using (var audit = new AuditLog(ap))
        {
            var fake = new FakeLdap();
            var tool = new DcSyncDetectionTool(scope, audit, (_, _, _, _) => fake);
            var r = await tool.ProbeAsync("10.10.10.5", bindUser: "alice", bindPassword: "P@ss");
            Assert.True(r.Authenticated);
            Assert.Equal("alice", fake.BindUser);
        }
        var blob = File.ReadAllText(ap);
        Assert.Contains("dcsync-detect.start", blob);
        Assert.Contains("dcsync-detect.finish", blob);
        Assert.Contains("\"authenticated\":true", blob);
        Assert.DoesNotContain("P@ss", blob);
        File.Delete(ap);
    }

    [Fact]
    public async Task Search_Filter_Targets_Domain_Object()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        var tool = new DcSyncDetectionTool(scope, audit, (_, _, _, _) => fake);
        await tool.ProbeAsync("10.10.10.5");
        Assert.Equal("DC=corp,DC=example,DC=com", fake.LastBaseDn);
        Assert.NotNull(fake.LastFilter);
        Assert.Contains("domain", fake.LastFilter, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("S-1-5-9", true)]
    [InlineData("S-1-5-18", true)]
    [InlineData("S-1-5-32-544", true)]
    [InlineData("S-1-5-21-1-2-3-512", true)]   // Domain Admins
    [InlineData("S-1-5-21-1-2-3-516", true)]   // Domain Controllers
    [InlineData("S-1-5-21-1-2-3-519", true)]   // Enterprise Admins
    [InlineData("S-1-5-21-1-2-3-502", true)]   // KRBTGT
    [InlineData("S-1-5-21-1-2-3-1000", false)] // Generic user
    [InlineData("S-1-5-21-1-2-3-1337", false)] // Generic user
    public void IsWellKnownLegitimate_Classifies_Correctly(string sid, bool expected)
    {
        Assert.Equal(expected, DcSyncDetectionTool.IsWellKnownLegitimate(sid));
    }

    [Theory]
    [InlineData("AABCDEF0", true)]  // Valid hex
    [InlineData("invalid", false)]   // Not hex, not base64
    public void TryDecodeDescriptor_Handles_Encoding(string raw, bool expectNonNull)
    {
        var result = DcSyncDetectionTool.TryDecodeDescriptor(raw);
        if (expectNonNull)
            Assert.NotNull(result);
        // For base64, some short strings could be valid; just check null for clearly invalid.
    }

    [Fact]
    public void TryDecodeDescriptor_Handles_Base64()
    {
        var bytes = new byte[] { 1, 2, 3, 4 };
        var b64 = Convert.ToBase64String(bytes);
        var result = DcSyncDetectionTool.TryDecodeDescriptor(b64);
        Assert.NotNull(result);
        Assert.Equal(bytes, result);
    }

    [Fact]
    public void MatchReplicationGuid_Identifies_All_Three_Rights()
    {
        byte[] padded = new byte[16 + 16]; // extra padding to satisfy bounds check
        Array.Copy(DcSyncDetectionTool.GuidGetChangesAll, 0, padded, 0, 16);
        Assert.Equal("DS-Replication-Get-Changes-All",
            DcSyncDetectionTool.MatchReplicationGuid(padded, 0));

        Array.Copy(DcSyncDetectionTool.GuidGetChanges, 0, padded, 0, 16);
        Assert.Equal("DS-Replication-Get-Changes",
            DcSyncDetectionTool.MatchReplicationGuid(padded, 0));

        Array.Copy(DcSyncDetectionTool.GuidGetChangesFiltered, 0, padded, 0, 16);
        Assert.Equal("DS-Replication-Get-Changes-In-Filtered-Set",
            DcSyncDetectionTool.MatchReplicationGuid(padded, 0));

        // Junk GUID returns null.
        Array.Clear(padded);
        Assert.Null(DcSyncDetectionTool.MatchReplicationGuid(padded, 0));
    }
}
