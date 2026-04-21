using System.Reflection;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Shared;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class LdapToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-ldap-{Guid.NewGuid():N}.jsonl"));

    private sealed class FakeLdapClient : ILdapClient
    {
        public int BindAnonymousCalls;
        public int QueryCalls;
        public bool Disposed;
        public Exception? BindThrows;
        public LdapRootDse? DseToReturn;
        public string[]? LastAttributes;

        public void BindAnonymous(TimeSpan timeout)
        {
            BindAnonymousCalls++;
            if (BindThrows is not null) throw BindThrows;
        }

        public LdapRootDse QueryRootDse(string[] attributes, TimeSpan timeout)
        {
            QueryCalls++;
            LastAttributes = attributes;
            return DseToReturn ?? new LdapRootDse();
        }

        public void Dispose() => Disposed = true;
    }

    [Fact]
    public async Task OutOfScope_Throws_ScopeException_And_Does_Not_Connect()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var called = false;
        var tool = new LdapTool(scope, audit, (_, _) =>
        {
            called = true;
            return new FakeLdapClient();
        });

        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("192.168.1.1"));
        Assert.False(called);
    }

    [Fact]
    public async Task Anonymous_Bind_Success_Populates_RootDse()
    {
        var fake = new FakeLdapClient
        {
            DseToReturn = new LdapRootDse
            {
                NamingContexts = { "DC=example,DC=com", "CN=Configuration,DC=example,DC=com" },
                SupportedControls = { "1.2.840.113556.1.4.319", "1.2.840.113556.1.4.473" },
                SupportedLdapVersions = { "3" },
                SupportedSaslMechanisms = { "GSSAPI", "DIGEST-MD5" },
            },
        };
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new LdapTool(scope, audit, (_, _) => fake);

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.Equal(389, result.Port);
        Assert.True(result.AnonymousBind);
        Assert.Equal(2, result.NamingContexts.Count);
        Assert.Contains("DC=example,DC=com", result.NamingContexts);
        Assert.Equal(2, result.SupportedControls.Count);
        Assert.Contains("1.2.840.113556.1.4.319", result.SupportedControls);
        Assert.Null(result.Error);
        Assert.Equal(1, fake.BindAnonymousCalls);
        Assert.Equal(1, fake.QueryCalls);
        Assert.True(fake.Disposed);
        Assert.NotNull(fake.LastAttributes);
        Assert.Contains("namingContexts", fake.LastAttributes!);
        Assert.Contains("supportedControl", fake.LastAttributes!);
        Assert.Contains("supportedLDAPVersion", fake.LastAttributes!);
        Assert.Contains("supportedSASLMechanisms", fake.LastAttributes!);
    }

    [Fact]
    public async Task Anonymous_Refused_Sets_False_With_No_Error_And_No_Query()
    {
        var fake = new FakeLdapClient
        {
            BindThrows = new LdapAnonymousRefusedException("refused"),
        };
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new LdapTool(scope, audit, (_, _) => fake);

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.False(result.AnonymousBind);
        Assert.Null(result.Error);
        Assert.Empty(result.NamingContexts);
        Assert.Empty(result.SupportedControls);
        Assert.Equal(0, fake.QueryCalls);
        Assert.True(fake.Disposed);
    }

    [Fact]
    public async Task Connection_Refused_Factory_Throws_Sets_Error_Without_Crash()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new LdapTool(scope, audit, (_, _) =>
            throw new System.Net.Sockets.SocketException(111) /* ECONNREFUSED */);

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.False(result.AnonymousBind);
        Assert.False(string.IsNullOrEmpty(result.Error));
        Assert.Empty(result.NamingContexts);
        Assert.Empty(result.SupportedControls);
    }

    [Fact]
    public async Task Bind_Transport_Error_Is_Reported_As_Error_Not_As_Refusal()
    {
        var fake = new FakeLdapClient
        {
            BindThrows = new InvalidOperationException("socket closed"),
        };
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new LdapTool(scope, audit, (_, _) => fake);

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.False(result.AnonymousBind);
        Assert.Equal("socket closed", result.Error);
        Assert.Equal(0, fake.QueryCalls);
        Assert.True(fake.Disposed);
    }

    [Fact]
    public void LdapTool_Never_Invokes_Credentialed_Bind()
    {
        // Structural/negative test: after the ILdapClient consolidation the
        // shared interface surfaces a credentialed Bind(user, password) for
        // the Kerberos probe, so we can no longer enforce "no credentialed
        // bind" at the type-system level. Instead, assert at the source
        // level that LdapTool.cs never invokes it — the tool must only
        // call BindAnonymous on its client.
        string? dir = AppContext.BaseDirectory;
        string? sourcePath = null;
        for (int i = 0; i < 10 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "src", "Drederick", "Recon", "LdapTool.cs");
            if (File.Exists(candidate)) { sourcePath = candidate; break; }
            dir = Path.GetDirectoryName(dir);
        }
        Assert.NotNull(sourcePath);
        var src = File.ReadAllText(sourcePath!);

        // Strip // line comments and XML doc so the prose in the class
        // summary (which legitimately mentions credentialed binds as
        // something we do NOT do) cannot trip the guard.
        var lines = src.Split('\n');
        var code = string.Join('\n', lines
            .Select(l =>
            {
                var trimmed = l.TrimStart();
                if (trimmed.StartsWith("//")) return string.Empty;
                return l;
            }));

        // The anonymous-only contract method:
        Assert.Contains("BindAnonymous", code);
        // Forbidden: any non-anonymous bind invocation, or NetworkCredential use.
        Assert.DoesNotContain("client.Bind(", code);
        Assert.DoesNotContain(".Bind(user", code);
        Assert.DoesNotContain("NetworkCredential", code);
    }

    [Fact]
    public void ILdapClient_LdapTool_Surface_Exposes_No_Credentialed_Bind()
    {
        // The specific methods LdapTool consumes (BindAnonymous, QueryRootDse)
        // must never surface credential-shaped parameters, even though the
        // unified ILdapClient also carries a Bind(user, password) overload
        // used only by the Kerberos probe.
        var methods = typeof(ILdapClient).GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.Name is "BindAnonymous" or "QueryRootDse");
        foreach (var m in methods)
        {
            foreach (var p in m.GetParameters())
            {
                var n = p.Name ?? "";
                Assert.False(n.Contains("user", StringComparison.OrdinalIgnoreCase),
                    $"{m.Name} parameter {n} looks credential-taking");
                Assert.False(n.Contains("pass", StringComparison.OrdinalIgnoreCase),
                    $"{m.Name} parameter {n} looks credential-taking");
                Assert.False(n.Contains("cred", StringComparison.OrdinalIgnoreCase),
                    $"{m.Name} parameter {n} looks credential-taking");
                Assert.NotEqual("System.Net.NetworkCredential", p.ParameterType.FullName);
            }
        }
    }
}
