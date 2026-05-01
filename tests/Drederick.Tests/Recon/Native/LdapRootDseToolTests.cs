using Drederick.Recon;
using Drederick.Recon.Native;
using Drederick.Recon.Shared;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Native;

public class LdapRootDseToolTests
{
    private sealed class StubLdapClient : ILdapClient
    {
        private readonly LdapRootDse _dse;
        private readonly bool _refuse;
        public bool BoundAnonymous { get; private set; }

        public StubLdapClient(LdapRootDse dse, bool refuse = false)
        {
            _dse = dse;
            _refuse = refuse;
        }
        public void BindAnonymous(TimeSpan timeout)
        {
            if (_refuse) throw new LdapAnonymousRefusedException("anon refused");
            BoundAnonymous = true;
        }
        public LdapRootDse QueryRootDse(string[] attributes, TimeSpan timeout) => _dse;
        public void Dispose() { }
    }

    [Fact]
    public async Task OutOfScope_Throws_ScopeException()
    {
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new LdapRootDseTool(NativeTestHelpers.SmallScope(), audit,
            (_, _) => new StubLdapClient(new LdapRootDse()));
        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("172.16.0.1"));
    }

    [Fact]
    public async Task Anonymous_Bind_Populates_RootDse()
    {
        var dse = new LdapRootDse
        {
            NamingContexts = { "DC=lab,DC=local" },
            SupportedControls = { "1.2.840.113556.1.4.319" },
            SupportedLdapVersions = { "3" },
            SupportedSaslMechanisms = { "GSSAPI" },
        };
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new LdapRootDseTool(NativeTestHelpers.SmallScope(), audit,
            (_, _) => new StubLdapClient(dse));
        var r = await tool.ProbeAsync("10.10.10.5", 389);
        Assert.True(r.AnonymousBind);
        Assert.Contains("DC=lab,DC=local", r.NamingContexts);
        Assert.Contains("GSSAPI", r.SupportedSaslMechanisms);
        Assert.Null(r.Error);
    }

    [Fact]
    public async Task Anonymous_Refused_Records_Error_Without_Throwing()
    {
        using var audit = NativeTestHelpers.NewAudit();
        var tool = new LdapRootDseTool(NativeTestHelpers.SmallScope(), audit,
            (_, _) => new StubLdapClient(new LdapRootDse(), refuse: true));
        var r = await tool.ProbeAsync("10.10.10.5", 389);
        Assert.False(r.AnonymousBind);
        Assert.NotNull(r.Error);
    }
}
