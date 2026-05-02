using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;
using KerbLdap = Drederick.Recon.Shared;

namespace Drederick.Tests;

public class DelegationEnumToolTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-deleg-{Guid.NewGuid():N}.jsonl");

    private sealed class FakeLdap : KerbLdap.ILdapClient
    {
        public bool BindCalled;
        public string? BindUser;
        public string? BindPassword;
        public Exception? BindThrow;
        public string? DefaultNamingContext = "DC=corp,DC=example,DC=com";
        public List<KerbLdap.LdapEntry> Entries = new();
        public string? LastFilter;
        public string? LastBaseDn;
        public string[]? LastAttributes;
        public int LastSizeLimit;
        public bool Disposed;

        public void Bind(string? user, string? password)
        {
            BindCalled = true;
            BindUser = user;
            BindPassword = password;
            if (BindThrow != null) throw BindThrow;
        }

        public string? GetDefaultNamingContext() => DefaultNamingContext;

        public IEnumerable<KerbLdap.LdapEntry> Search(string baseDn, string filter, string[] attributes, int sizeLimit)
        {
            LastBaseDn = baseDn;
            LastFilter = filter;
            LastAttributes = attributes;
            LastSizeLimit = sizeLimit;
            return Entries;
        }

        public void Dispose() => Disposed = true;
    }

    /// <summary>Build a delegation entry with the most common attribute shape.</summary>
    private static KerbLdap.LdapEntry Entry(
        string sam,
        int uac,
        IEnumerable<string>? allowedToDelegateTo = null,
        string? rbcdRaw = null)
    {
        var e = new KerbLdap.LdapEntry { DistinguishedName = $"CN={sam},CN=Users,DC=corp,DC=example,DC=com" };
        e.Attributes["sAMAccountName"] = new List<string> { sam };
        e.Attributes["userAccountControl"] = new List<string> { uac.ToString() };
        if (allowedToDelegateTo is not null)
            e.Attributes["msDS-AllowedToDelegateTo"] = allowedToDelegateTo.ToList();
        if (rbcdRaw is not null)
            e.Attributes["msDS-AllowedToActOnBehalfOfOtherIdentity"] = new List<string> { rbcdRaw };
        return e;
    }

    [Fact]
    public async Task Refuses_Out_Of_Scope_Target()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        var tool = new DelegationEnumTool(scope, audit, (_, _, _, _) => fake);
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("8.8.8.8"));
        Assert.False(fake.BindCalled);
    }

    [Fact]
    public async Task Anonymous_Bind_And_Buckets_Are_Populated()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        // Unconstrained: TRUSTED_FOR_DELEGATION (0x80000), no T2A4D.
        fake.Entries.Add(Entry("WEB01$", uac: 0x80000));
        // Constrained without protocol transition.
        fake.Entries.Add(Entry("svc-iis", uac: 0x200,
            allowedToDelegateTo: new[] { "HTTP/web.corp.lab", "HTTP/web.corp.lab:443" }));
        // Constrained with protocol transition: TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000).
        fake.Entries.Add(Entry("svc-mssql", uac: 0x1000200,
            allowedToDelegateTo: new[] { "MSSQLSvc/sql.corp.lab:1433" }));
        // RBCD: SDDL with two principal SIDs.
        fake.Entries.Add(Entry("FILE01$", uac: 0x1000,
            rbcdRaw: "O:S-1-5-21-1-2-3-512G:S-1-5-21-1-2-3-512D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1104)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1105)"));
        var tool = new DelegationEnumTool(scope, audit, (_, _, _, _) => fake);

        var r = await tool.ProbeAsync("10.10.10.5");

        Assert.Null(r.Error);
        Assert.Equal("DC=corp,DC=example,DC=com", r.BaseDn);
        Assert.Equal("CORP.EXAMPLE.COM", r.Realm);
        Assert.True(fake.BindCalled);
        Assert.Null(fake.BindUser); // anonymous

        // Filter should reference the BIT_AND OID and both UAC bits.
        Assert.Contains("1.2.840.113556.1.4.803", fake.LastFilter);
        Assert.Contains(":=524288", fake.LastFilter);   // 0x80000
        Assert.Contains(":=16777216", fake.LastFilter); // 0x1000000
        Assert.Contains("msDS-AllowedToDelegateTo=*", fake.LastFilter);
        Assert.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity=*", fake.LastFilter);

        // Buckets.
        var unc = Assert.Single(r.Unconstrained);
        Assert.Equal("WEB01$", unc.SamAccountName);
        Assert.True(unc.IsComputer);
        Assert.Equal("red", unc.Severity);

        var con = Assert.Single(r.Constrained);
        Assert.Equal("svc-iis", con.SamAccountName);
        Assert.False(con.IsComputer);
        Assert.Equal(2, con.AllowedToDelegateTo.Count);
        Assert.Equal("yellow", con.Severity);

        var conPt = Assert.Single(r.ConstrainedWithProtocolTransition);
        Assert.Equal("svc-mssql", conPt.SamAccountName);
        Assert.Single(conPt.AllowedToDelegateTo);
        Assert.Equal("red", conPt.Severity);

        var rb = Assert.Single(r.Rbcd);
        Assert.Equal("FILE01$", rb.SamAccountName);
        Assert.Contains("S-1-5-21-1-2-3-1104", rb.AllowedToActPrincipalSids);
        Assert.Contains("S-1-5-21-1-2-3-1105", rb.AllowedToActPrincipalSids);
        Assert.Equal("red", rb.Severity);
    }

    [Fact]
    public async Task Bind_Failure_Is_Recorded_Without_Throwing()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap { BindThrow = new InvalidOperationException("anonymous denied") };
        var tool = new DelegationEnumTool(scope, audit, (_, _, _, _) => fake);
        var r = await tool.ProbeAsync("10.10.10.5");
        Assert.NotNull(r.Error);
        Assert.Contains("anonymous", r.Error, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(r.Unconstrained);
    }

    [Fact]
    public async Task No_NamingContext_Yields_Error_Result()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap { DefaultNamingContext = null };
        var tool = new DelegationEnumTool(scope, audit, (_, _, _, _) => fake);
        var r = await tool.ProbeAsync("10.10.10.5");
        Assert.Equal("no defaultNamingContext on rootDSE", r.Error);
    }

    [Fact]
    public async Task Authenticated_Bind_Records_Authenticated_Flag()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        var auditPath = NewAuditPath();
        using (var audit = new AuditLog(auditPath))
        {
            var fake = new FakeLdap();
            var tool = new DelegationEnumTool(scope, audit, (_, _, _, _) => fake);
            var r = await tool.ProbeAsync("10.10.10.5", bindUser: "alice", bindPassword: "P@ss");
            Assert.True(r.Authenticated);
            Assert.Equal("alice", fake.BindUser);
        }
        var blob = File.ReadAllText(auditPath);
        Assert.Contains("delegation-enum.start", blob);
        Assert.Contains("delegation-enum.finish", blob);
        Assert.Contains("\"authenticated\":true", blob);
        // Plaintext bind password must never land in the audit log.
        Assert.DoesNotContain("P@ss", blob);
        File.Delete(auditPath);
    }

    [Fact]
    public void Classify_Unconstrained_Only_Sets_Single_Bucket()
    {
        var r = new DelegationEnumResult();
        DelegationEnumTool.Classify(Entry("DC01$", uac: 0x80000), r);
        Assert.Single(r.Unconstrained);
        Assert.Empty(r.Constrained);
        Assert.Empty(r.ConstrainedWithProtocolTransition);
        Assert.Empty(r.Rbcd);
    }

    [Fact]
    public void Classify_T2A4D_Implies_Constrained_With_Protocol_Transition_Even_Without_Allowed_To()
    {
        // A principal can have T2A4D (0x1000000) without msDS-AllowedToDelegateTo
        // populated yet — still report it. The hint warns the operator.
        var r = new DelegationEnumResult();
        DelegationEnumTool.Classify(Entry("svc-app", uac: 0x1000200), r);
        Assert.Empty(r.Unconstrained);
        Assert.Empty(r.Constrained);
        var pt = Assert.Single(r.ConstrainedWithProtocolTransition);
        Assert.Equal("red", pt.Severity);
        Assert.Empty(pt.AllowedToDelegateTo);
    }

    [Fact]
    public void Classify_Constrained_Requires_AllowedTo_And_No_T2A4D()
    {
        var r = new DelegationEnumResult();
        // T2A4D set + AllowedTo set → should land in PT bucket only.
        DelegationEnumTool.Classify(
            Entry("svc-mix", uac: 0x1000200, allowedToDelegateTo: new[] { "HTTP/x" }), r);
        Assert.Empty(r.Constrained);
        Assert.Single(r.ConstrainedWithProtocolTransition);
    }

    [Theory]
    [InlineData("S-1-5-21-1234567890-1234567890-1234567890-512", true)]
    [InlineData("S-1-5-32-544", true)]
    [InlineData("notasid", false)]
    public void ExtractSids_Sddl_Form(string token, bool found)
    {
        var raw = $"O:DAG:DAD:(A;;CCDC;;;{token})";
        var sids = DelegationEnumTool.ExtractSidsFromSecurityDescriptor(raw);
        if (found)
            Assert.Contains(token, sids);
        else
            Assert.Empty(sids);
    }

    [Fact]
    public void ExtractSids_Hex_Binary_Form_Walks_Acl()
    {
        // Hand-crafted self-relative SD with one DACL ACE granting to S-1-5-21-1-2-3-1104.
        // SD header (20 bytes):
        //  rev=01 sbz=00 control=0004 (DACL present) - little-endian
        //  off_owner=00000000 off_group=00000000
        //  off_sacl=00000000 off_dacl=00000014 (= 20)
        //
        // ACL header at offset 20 (8 bytes):
        //  rev=02 sbz1=00 size=0024 (=36) ace_count=0001 sbz2=0000
        //
        // ACE header (8 bytes) + SID body:
        //  type=00 (ACCESS_ALLOWED) flags=00 size=001C (=28) mask=000F01FF
        //  SID: rev=01 subCount=04 auth=000000000005 (NT)
        //       sub0=00000015 sub1=00000001 sub2=00000002 sub3=00000003 sub4=00000450 (=1104)
        //
        // Wait: subCount=4 means 4 subauths total = 16 bytes of sub. Header
        // 8 + sub 16 = 24 bytes. ACE size 8 + 24 = 32. We'll use 4 subauths
        // and SID for S-1-5-21-1-2-3 (subs: 21,1,2,3).
        //
        // Let me redo more carefully:
        //  Want sid: S-1-5-21-1-2-3-1104 → 5 subauths.
        //  SID size = 8 + 5*4 = 28.
        //  ACE size = 8 + 28 = 36.
        //  ACL size = 8 + 36 = 44 = 0x2C.

        var hex =
            // SD header: rev,sbz,control_le,offOwner,offGroup,offSacl,offDacl(20)
            "01" + "00" + "0400" +
            "00000000" + "00000000" + "00000000" + "14000000" +
            // ACL: rev,sbz1,size_le(44=0x2C),aceCount(1),sbz2
            "02" + "00" + "2C00" + "0100" + "0000" +
            // ACE: type,flags,size_le(36=0x24),mask
            "00" + "00" + "2400" + "FF010F00" +
            // SID: rev=01, subCount=05, authority=000000000005,
            //   sub0=21=0x00000015 LE 15000000
            //   sub1=1            LE 01000000
            //   sub2=2            LE 02000000
            //   sub3=3            LE 03000000
            //   sub4=1104=0x450   LE 50040000
            "01" + "05" + "000000000005" +
            "15000000" + "01000000" + "02000000" + "03000000" + "50040000";

        var sids = DelegationEnumTool.ExtractSidsFromSecurityDescriptor(hex);
        Assert.Single(sids);
        Assert.Equal("S-1-5-21-1-2-3-1104", sids[0]);
    }

    [Fact]
    public void ExtractSids_Junk_Returns_Empty()
    {
        Assert.Empty(DelegationEnumTool.ExtractSidsFromSecurityDescriptor(""));
        Assert.Empty(DelegationEnumTool.ExtractSidsFromSecurityDescriptor("not hex and no sids"));
    }

    [Fact]
    public void TryFormatSid_Handles_Subauth_Boundaries()
    {
        // Identical bytes as the previous test, focusing on SID slice only:
        //   01 05 000000000005 15000000 01000000 02000000 03000000 50040000
        var bytes = Convert.FromHexString(
            "0105000000000005" + "15000000" + "01000000" + "02000000" + "03000000" + "50040000");
        var s = DelegationEnumTool.TryFormatSid(bytes, 0, bytes.Length);
        Assert.Equal("S-1-5-21-1-2-3-1104", s);
    }

    [Fact]
    public void TryFormatSid_Truncated_Returns_Null()
    {
        // Header says 5 subauths but only 1 is present.
        var bytes = Convert.FromHexString("0105000000000005" + "15000000");
        var s = DelegationEnumTool.TryFormatSid(bytes, 0, bytes.Length);
        Assert.Null(s);
    }
}
