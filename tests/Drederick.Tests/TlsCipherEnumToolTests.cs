using System.Runtime.CompilerServices;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class TlsCipherEnumToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-tls-cipher-{Guid.NewGuid():N}.jsonl"));

    private static string FixturePath([CallerFilePath] string thisFile = "")
    {
        // tests/Drederick.Tests/TlsCipherEnumToolTests.cs -> tests/fixtures/ssl-enum-ciphers.xml
        var testsDir = Path.GetDirectoryName(thisFile)!;
        var root = Path.GetDirectoryName(testsDir)!;
        return Path.Combine(root, "fixtures", "ssl-enum-ciphers.xml");
    }

    [Fact]
    public async Task ProbeAsync_Refuses_Out_Of_Scope_Target()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new TlsCipherEnumTool(scope, audit, nmapPath: "/bin/true",
            runner: (_, _, _) => Task.FromResult(new TlsCipherEnumTool.ProcessResult(0, "", "")));

        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("8.8.8.8", 443));
    }

    [Fact]
    public async Task ProbeAsync_Parses_Fixture_Versions_Ciphers_And_Grade()
    {
        var xml = await File.ReadAllTextAsync(FixturePath());
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new TlsCipherEnumTool(scope, audit, nmapPath: "/bin/true",
            runner: (_, _, _) => Task.FromResult(new TlsCipherEnumTool.ProcessResult(0, xml, "")));

        var res = await tool.ProbeAsync("10.10.10.5", 443);

        Assert.Null(res.Error);
        Assert.Equal(443, res.Port);
        Assert.Equal(2, res.Versions.Count);
        Assert.True(res.Versions.ContainsKey("TLSv1.2"));
        Assert.True(res.Versions.ContainsKey("TLSv1.3"));

        var tls12 = res.Versions["TLSv1.2"];
        Assert.Contains("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls12.Ciphers);
        Assert.Contains("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", tls12.Ciphers);
        Assert.Equal("A", tls12.Grade);

        var tls13 = res.Versions["TLSv1.3"];
        Assert.Single(tls13.Ciphers);
        Assert.Equal("TLS_AES_128_GCM_SHA256", tls13.Ciphers[0]);
        Assert.Equal("A", tls13.Grade);
    }

    [Fact]
    public async Task ProbeAsync_Populates_Error_When_Nmap_Missing()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new TlsCipherEnumTool(scope, audit, nmapPath: "/definitely/not/nmap",
            runner: (_, _, _) => Task.FromResult(
                new TlsCipherEnumTool.ProcessResult(-1, "", "No such file or directory")));

        var res = await tool.ProbeAsync("10.10.10.5", 443);

        Assert.NotNull(res.Error);
        Assert.Contains("-1", res.Error);
        Assert.Empty(res.Versions);
    }

    [Fact]
    public async Task ProbeAsync_NonTls_Port_Returns_Empty_Versions_Without_Crash()
    {
        // A plain nmap XML document with no ssl-enum-ciphers script (port not TLS).
        const string xml = """
            <?xml version="1.0"?>
            <nmaprun>
              <host>
                <address addr="10.10.10.5" addrtype="ipv4"/>
                <ports>
                  <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh"/>
                  </port>
                </ports>
              </host>
            </nmaprun>
            """;
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new TlsCipherEnumTool(scope, audit, nmapPath: "/bin/true",
            runner: (_, _, _) => Task.FromResult(new TlsCipherEnumTool.ProcessResult(0, xml, "")));

        var res = await tool.ProbeAsync("10.10.10.5", 22);

        Assert.Null(res.Error);
        Assert.Empty(res.Versions);
    }
}
