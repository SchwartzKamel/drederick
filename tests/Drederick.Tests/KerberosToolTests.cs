using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;
using KerbLdap = Drederick.Recon.Kerberos;

namespace Drederick.Tests;

public class KerberosToolTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-kerb-{Guid.NewGuid():N}.jsonl");

    private sealed class FakeLdap : KerbLdap.ILdapClient
    {
        public bool BindCalled;
        public string? BindUser;
        public string? BindPassword;
        public Exception? BindThrow;
        public string? DefaultNamingContext = "DC=corp,DC=example,DC=com";
        public Exception? RootDseThrow;
        public List<KerbLdap.LdapEntry> Entries = new();
        public Exception? SearchThrow;
        public int LastSizeLimit;
        public string? LastFilter;
        public string? LastBaseDn;
        public string[]? LastAttributes;
        public bool Disposed;

        public void Bind(string? user, string? password)
        {
            BindCalled = true;
            BindUser = user;
            BindPassword = password;
            if (BindThrow != null) throw BindThrow;
        }

        public string? GetDefaultNamingContext()
        {
            if (RootDseThrow != null) throw RootDseThrow;
            return DefaultNamingContext;
        }

        public IEnumerable<KerbLdap.LdapEntry> Search(string baseDn, string filter, string[] attributes, int sizeLimit)
        {
            LastBaseDn = baseDn;
            LastFilter = filter;
            LastAttributes = attributes;
            LastSizeLimit = sizeLimit;
            if (SearchThrow != null) throw SearchThrow;
            return Entries;
        }

        public void Dispose() => Disposed = true;
    }

    private static KerbLdap.LdapEntry Entry(string sam, params string[] spns)
    {
        var e = new KerbLdap.LdapEntry { DistinguishedName = $"CN={sam},CN=Users,DC=corp,DC=example,DC=com" };
        e.Attributes["sAMAccountName"] = new List<string> { sam };
        e.Attributes["servicePrincipalName"] = new List<string>(spns);
        return e;
    }

    [Fact]
    public async Task ProbeAsync_Throws_When_Target_Out_Of_Scope()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        var tool = new KerberosTool(scope, audit, (_, _, _, _) => fake);

        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("192.0.2.9"));
        Assert.False(fake.BindCalled);
    }

    [Fact]
    public async Task ProbeAsync_Anonymous_Allowed_Lists_Spns()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap
        {
            Entries =
            {
                Entry("WEB01$", "HTTP/web01.corp.example.com", "HOST/web01"),
                Entry("svc_sql", "MSSQLSvc/sql01.corp.example.com:1433"),
            },
        };
        var tool = new KerberosTool(scope, audit, (h, p, u, pw) =>
        {
            Assert.Equal("10.10.10.5", h);
            Assert.Equal(389, p);
            Assert.Null(u);
            Assert.Null(pw);
            return fake;
        });

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.True(fake.BindCalled);
        Assert.Null(fake.BindUser);
        Assert.Null(result.Error);
        Assert.Equal("CORP.EXAMPLE.COM", result.Realm);
        Assert.Equal(389, result.Port);
        Assert.Equal(3, result.Spns.Count);
        Assert.Contains("HTTP/web01.corp.example.com", result.Spns);
        Assert.Contains("HOST/web01", result.Spns);
        Assert.Contains("MSSQLSvc/sql01.corp.example.com:1433", result.Spns);
        Assert.Equal("(servicePrincipalName=*)", fake.LastFilter);
        Assert.Equal("DC=corp,DC=example,DC=com", fake.LastBaseDn);
        Assert.Contains("servicePrincipalName", fake.LastAttributes!);
        Assert.Contains("sAMAccountName", fake.LastAttributes!);
        Assert.True(fake.Disposed);
    }

    [Fact]
    public async Task ProbeAsync_Anonymous_Refused_No_Creds_Sets_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap
        {
            BindThrow = new InvalidOperationException("strongerAuthRequired (8)"),
        };
        var tool = new KerberosTool(scope, audit, (_, _, _, _) => fake);

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.NotNull(result.Error);
        Assert.Contains("anonymous bind refused", result.Error);
        Assert.Empty(result.Spns);
        Assert.True(fake.Disposed);
    }

    [Fact]
    public async Task ProbeAsync_Creds_Provided_And_Accepted_Proceeds()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap
        {
            Entries = { Entry("adm", "HOST/dc01.corp.example.com") },
        };
        var tool = new KerberosTool(scope, audit, (h, p, u, pw) =>
        {
            Assert.Equal("admin@corp.example.com", u);
            Assert.Equal("hunter2", pw);
            return fake;
        });

        var result = await tool.ProbeAsync("10.10.10.5", 389, "admin@corp.example.com", "hunter2");

        Assert.Null(result.Error);
        Assert.Equal("admin@corp.example.com", fake.BindUser);
        Assert.Equal("hunter2", fake.BindPassword);
        Assert.Single(result.Spns);
        Assert.Equal("HOST/dc01.corp.example.com", result.Spns[0]);
    }

    [Fact]
    public async Task ProbeAsync_Caps_Spns_At_500()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var fake = new FakeLdap();
        for (int i = 0; i < 700; i++)
        {
            fake.Entries.Add(Entry($"u{i}", $"HOST/host{i}.corp.example.com"));
        }
        var tool = new KerberosTool(scope, audit, (_, _, _, _) => fake);

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.Null(result.Error);
        Assert.Equal(500, result.Spns.Count);
        Assert.Equal(500, fake.LastSizeLimit);
    }

    [Fact]
    public void Source_Never_Speaks_Kerberos_Protocol()
    {
        // Guard that the implementation never performs AS-REP roasting,
        // Kerberoasting, or direct Kerberos packet exchange. Find the source
        // file by walking up from the test binary.
        string? dir = AppContext.BaseDirectory;
        string? sourcePath = null;
        for (int i = 0; i < 10 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "src", "Drederick", "Recon", "KerberosTool.cs");
            if (File.Exists(candidate)) { sourcePath = candidate; break; }
            dir = Path.GetDirectoryName(dir);
        }
        Assert.NotNull(sourcePath);
        var raw = File.ReadAllText(sourcePath!);

        // Strip comments and string literal contents so that the documentation
        // and Description field (which enumerate the very things we're
        // prohibiting) do not trip the guard. We only care that the
        // *executable* source never references these terms.
        var text = StripComments(raw);

        string[] forbidden =
        {
            "krb5-enum-users",
            "GetNPUsers",
            "KRB_AS_REQ",
            "KRB-AS-REQ",
            "AS-REP",
            "AsRep",
            "kerberoast",
            "Kerberoast",
            "TGS-REQ",
            "TgsReq",
            "KerberosRequestorSecurityToken",
            "asreproast",
        };
        foreach (var needle in forbidden)
        {
            Assert.DoesNotContain(needle, text, StringComparison.Ordinal);
        }

        // Also ensure we don't point at UDP/88 or TCP/88 (Kerberos) anywhere.
        Assert.DoesNotContain(":88", text, StringComparison.Ordinal);
        Assert.DoesNotContain("port 88", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("UdpClient", text, StringComparison.Ordinal);
    }

    private static string StripComments(string src)
    {
        var sb = new System.Text.StringBuilder(src.Length);
        int i = 0;
        while (i < src.Length)
        {
            // Line comment (covers both // and /// XML doc comments)
            if (i + 1 < src.Length && src[i] == '/' && src[i + 1] == '/')
            {
                while (i < src.Length && src[i] != '\n') i++;
                continue;
            }
            // Block comment
            if (i + 1 < src.Length && src[i] == '/' && src[i + 1] == '*')
            {
                i += 2;
                while (i + 1 < src.Length && !(src[i] == '*' && src[i + 1] == '/')) i++;
                i += 2;
                continue;
            }
            // String literal (plain "..."): strip contents but keep quotes as
            // markers. Description text often repeats the prohibited terms
            // verbatim as guidance — we only care about executable code.
            if (src[i] == '"')
            {
                sb.Append('"');
                i++;
                while (i < src.Length && src[i] != '"')
                {
                    if (src[i] == '\\' && i + 1 < src.Length) i++;
                    i++;
                }
                if (i < src.Length) { sb.Append('"'); i++; }
                continue;
            }
            sb.Append(src[i]);
            i++;
        }
        return sb.ToString();
    }
}
