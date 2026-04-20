using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class SshToolTests
{
    private static AuditLog NewAudit() =>
        new(Path.Combine(Path.GetTempPath(), $"drederick-ssh-{Guid.NewGuid():N}.jsonl"));

    private static string LoadFixture(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "fixtures", name);
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException($"fixture not found: {name}");
    }

    private static Func<string, int, CancellationToken, Task<Stream>> BannerStream(string text)
        => (_, _, _) => Task.FromResult<Stream>(new MemoryStream(Encoding.ASCII.GetBytes(text)));

    private static Func<string, int, CancellationToken, Task<Stream>> ThrowingTcp(Exception ex)
        => (_, _, _) => Task.FromException<Stream>(ex);

    private static Func<string, IReadOnlyList<string>, CancellationToken, Task<ProcessRunResult>> StaticRunner(
        ProcessRunResult res) => (_, _, _) => Task.FromResult(res);

    [Fact]
    public async Task ProbeAsync_Refuses_Out_Of_Scope_Target()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var ssh = new SshTool(scope, audit,
            nmapPath: "/bin/true",
            tcpFactory: BannerStream("SSH-2.0-OpenSSH_9.3\r\n"),
            processRunner: StaticRunner(new ProcessRunResult(0, "", "")));

        await Assert.ThrowsAsync<ScopeException>(
            () => ssh.ProbeAsync("192.0.2.1"));
    }

    [Fact]
    public async Task ProbeAsync_Parses_Banner_Without_Crlf()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var ssh = new SshTool(scope, audit,
            nmapPath: "/bin/true",
            tcpFactory: BannerStream("SSH-2.0-OpenSSH_9.3\r\n"),
            processRunner: StaticRunner(new ProcessRunResult(0, "<nmaprun/>", "")));

        var result = await ssh.ProbeAsync("10.10.10.5");

        Assert.Equal("SSH-2.0-OpenSSH_9.3", result.Banner);
        Assert.Equal(22, result.Port);
    }

    [Fact]
    public async Task ProbeAsync_Parses_Algorithms_From_Fixture()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var xml = LoadFixture("ssh2-enum-algos.xml");
        var ssh = new SshTool(scope, audit,
            nmapPath: "/bin/true",
            tcpFactory: BannerStream("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\n"),
            processRunner: StaticRunner(new ProcessRunResult(0, xml, "")));

        var result = await ssh.ProbeAsync("10.10.10.5");

        Assert.Equal("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1", result.Banner);
        Assert.Contains("curve25519-sha256", result.KexAlgorithms);
        Assert.Contains("diffie-hellman-group16-sha512", result.KexAlgorithms);
        Assert.Equal(4, result.KexAlgorithms.Count);
        Assert.Contains("rsa-sha2-512", result.HostKeyAlgorithms);
        Assert.Contains("ssh-ed25519", result.HostKeyAlgorithms);
        Assert.Contains("chacha20-poly1305@openssh.com", result.EncryptionAlgorithms);
        Assert.Contains("aes128-ctr", result.EncryptionAlgorithms);
        Assert.Contains("hmac-sha2-512-etm@openssh.com", result.MacAlgorithms);
        Assert.Null(result.Error);
    }

    [Fact]
    public async Task ProbeAsync_When_Nmap_Missing_Returns_Banner_With_Empty_Algos_And_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var ssh = new SshTool(scope, audit,
            nmapPath: "/no/such/nmap",
            tcpFactory: BannerStream("SSH-2.0-OpenSSH_9.3\r\n"),
            processRunner: StaticRunner(new ProcessRunResult(-1, "", "nmap: not found")));

        var result = await ssh.ProbeAsync("10.10.10.5");

        Assert.Equal("SSH-2.0-OpenSSH_9.3", result.Banner);
        Assert.Empty(result.KexAlgorithms);
        Assert.Empty(result.HostKeyAlgorithms);
        Assert.Empty(result.EncryptionAlgorithms);
        Assert.Empty(result.MacAlgorithms);
        Assert.False(string.IsNullOrEmpty(result.Error));
        Assert.Contains("algo-enum", result.Error);
    }

    [Fact]
    public async Task ProbeAsync_Connection_Refused_Still_Runs_Algo_Enum()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var xml = LoadFixture("ssh2-enum-algos.xml");
        var ssh = new SshTool(scope, audit,
            nmapPath: "/bin/true",
            tcpFactory: ThrowingTcp(new System.Net.Sockets.SocketException(111)), // ECONNREFUSED
            processRunner: StaticRunner(new ProcessRunResult(0, xml, "")));

        var result = await ssh.ProbeAsync("10.10.10.5");

        Assert.Null(result.Banner);
        Assert.False(string.IsNullOrEmpty(result.Error));
        Assert.Contains("banner", result.Error);
        // Algo enum still ran:
        Assert.Contains("curve25519-sha256", result.KexAlgorithms);
        Assert.NotEmpty(result.HostKeyAlgorithms);
        Assert.NotEmpty(result.EncryptionAlgorithms);
        Assert.NotEmpty(result.MacAlgorithms);
    }

    [Fact]
    public void NseCategories_Is_Safe_Discovery_Only()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var ssh = new SshTool(scope, audit, nmapPath: "/bin/true");
        Assert.Equal("safe,discovery", ssh.NseCategories);
        Assert.DoesNotContain("exploit", ssh.NseCategories);
        Assert.DoesNotContain("brute", ssh.NseCategories);
        Assert.DoesNotContain("vuln", ssh.NseCategories);
        Assert.DoesNotContain("intrusive", ssh.NseCategories);
    }
}
