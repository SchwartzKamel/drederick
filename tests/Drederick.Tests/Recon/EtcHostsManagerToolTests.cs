using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

/// <summary>
/// Tests for <see cref="EtcHostsManagerTool"/> (GAP-006 pair with batch 2).
/// All on-disk fixtures live under a per-test scratch directory rooted at
/// <see cref="AppContext.BaseDirectory"/>; nothing is written to /tmp.
/// </summary>
public class EtcHostsManagerToolTests : IDisposable
{
    private readonly string _scratch;

    public EtcHostsManagerToolTests()
    {
        _scratch = Path.Combine(AppContext.BaseDirectory, "etc-hosts-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_scratch);
    }

    public void Dispose()
    {
        try { Directory.Delete(_scratch, recursive: true); } catch { }
    }

    private string ScratchPath(string name) => Path.Combine(_scratch, name);

    private AuditLog NewAudit() => new(ScratchPath($"audit-{Guid.NewGuid():N}.jsonl"));

    private string WriteHostsFile(string content)
    {
        var path = ScratchPath($"hosts-{Guid.NewGuid():N}");
        File.WriteAllText(path, content);
        return path;
    }

    private static EtcHostsManagerTool BuildTool(
        Scope.Scope scope,
        AuditLog audit,
        Dictionary<string, string[]>? dns = null)
    {
        Func<string, CancellationToken, Task<string[]>> resolver =
            (host, _) => Task.FromResult(dns is not null && dns.TryGetValue(host, out var ips) ? ips : Array.Empty<string>());
        return new EtcHostsManagerTool(scope, audit, resolver);
    }

    private static string Sha256Of(string path)
    {
        using var s = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(s));
    }

    [Fact]
    public async Task Reads_Existing_Entries()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);

        var hosts = WriteHostsFile(
            "127.0.0.1 localhost\n" +
            "10.10.10.5 lab.htb www.lab.htb\n" +
            "# comment line\n" +
            "10.10.10.6 other.htb   # inline\n");

        var r = await tool.AnalyzeAsync("10.10.10.5", Array.Empty<EtcHostsProposal>(), hosts);

        Assert.Equal("127.0.0.1", r.CurrentEntries["localhost"]);
        Assert.Equal("10.10.10.5", r.CurrentEntries["lab.htb"]);
        Assert.Equal("10.10.10.5", r.CurrentEntries["www.lab.htb"]);
        Assert.Equal("10.10.10.6", r.CurrentEntries["other.htb"]);
        Assert.Empty(r.Proposals);
    }

    [Fact]
    public async Task Add_Proposal_When_Hostname_Missing()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);

        var hosts = WriteHostsFile("127.0.0.1 localhost\n");
        var input = new[]
        {
            new EtcHostsProposal { Hostname = "api.lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-san" },
        };

        var r = await tool.AnalyzeAsync("10.10.10.5", input, hosts);

        var p = Assert.Single(r.Proposals);
        Assert.Equal("add", p.Action);
        Assert.Equal("api.lab.htb", p.Hostname);
        Assert.Equal("10.10.10.5", p.ProposedIp);
        Assert.Equal("ssl-cert-san", p.Source);
        Assert.Null(p.CurrentIp);
        Assert.Equal(100, p.Priority);
    }

    [Fact]
    public async Task Conflict_When_Hostname_Different_Ip()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);

        var hosts = WriteHostsFile("10.10.10.9 lab.htb\n");
        var input = new[]
        {
            new EtcHostsProposal { Hostname = "lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-cn" },
        };

        var r = await tool.AnalyzeAsync("10.10.10.5", input, hosts);

        var p = Assert.Single(r.Proposals);
        Assert.Equal("conflict", p.Action);
        Assert.Equal("10.10.10.9", p.CurrentIp);
        Assert.Equal("10.10.10.5", p.ProposedIp);
        Assert.Equal(50, p.Priority);
    }

    [Fact]
    public async Task Skip_When_Hostname_Already_Correct()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);

        var hosts = WriteHostsFile("10.10.10.5 lab.htb\n");
        var input = new[]
        {
            new EtcHostsProposal { Hostname = "lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-san" },
        };

        var r = await tool.AnalyzeAsync("10.10.10.5", input, hosts);

        var p = Assert.Single(r.Proposals);
        Assert.Equal("skip", p.Action);
        Assert.Equal(0, p.Priority);
        // No "add" snippet when nothing to add.
        Assert.Equal("", r.SuggestedSnippet);
    }

    [Fact]
    public async Task InfoOnly_When_Dns_Resolves_To_Target()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var dns = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["dns-works.lab.htb"] = new[] { "10.10.10.5" },
        };
        var tool = BuildTool(scope, audit, dns);

        var hosts = WriteHostsFile("127.0.0.1 localhost\n");
        var input = new[]
        {
            new EtcHostsProposal { Hostname = "dns-works.lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-san" },
        };

        var r = await tool.AnalyzeAsync("10.10.10.5", input, hosts);

        var p = Assert.Single(r.Proposals);
        Assert.Equal("info_only", p.Action);
        Assert.Equal(25, p.Priority);
    }

    [Fact]
    public async Task Generates_Snippet_With_All_New_Hostnames()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);

        var hosts = WriteHostsFile("127.0.0.1 localhost\n");
        var input = new[]
        {
            new EtcHostsProposal { Hostname = "lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-cn" },
            new EtcHostsProposal { Hostname = "api.lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-san" },
            new EtcHostsProposal { Hostname = "admin.lab.htb", TargetIp = "10.10.10.5", Source = "vhost" },
        };

        var r = await tool.AnalyzeAsync("10.10.10.5", input, hosts);

        Assert.Contains("# drederick-proposed: target=10.10.10.5", r.SuggestedSnippet);
        Assert.Contains("10.10.10.5", r.SuggestedSnippet);
        Assert.Contains("lab.htb", r.SuggestedSnippet);
        Assert.Contains("api.lab.htb", r.SuggestedSnippet);
        Assert.Contains("admin.lab.htb", r.SuggestedSnippet);

        // ONE line per IP grouping.
        var ipLines = r.SuggestedSnippet
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(l => !l.StartsWith('#'))
            .ToList();
        Assert.Single(ipLines);
        Assert.StartsWith("10.10.10.5 ", ipLines[0]);
    }

    [Fact]
    public async Task Refuses_OutOfScope_Target()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);
        var hosts = WriteHostsFile("127.0.0.1 localhost\n");

        await Assert.ThrowsAsync<ScopeException>(async () =>
            await tool.AnalyzeAsync("8.8.8.8", Array.Empty<EtcHostsProposal>(), hosts));
    }

    [Fact]
    public async Task Refuses_Arbitrary_HostsPath()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await tool.AnalyzeAsync("10.10.10.5", Array.Empty<EtcHostsProposal>(), "/etc/passwd"));

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await tool.AnalyzeAsync("10.10.10.5", Array.Empty<EtcHostsProposal>(), "/root/.ssh/id_rsa"));
    }

    [Fact]
    public async Task Never_Writes_HostsFile()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);

        var hosts = WriteHostsFile("10.10.10.9 lab.htb\n10.10.10.5 already.htb\n");
        var sha256Before = Sha256Of(hosts);
        var mtimeBefore = File.GetLastWriteTimeUtc(hosts);
        var sizeBefore = new FileInfo(hosts).Length;

        var input = new[]
        {
            new EtcHostsProposal { Hostname = "new.lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-san" },
            new EtcHostsProposal { Hostname = "lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-cn" },
            new EtcHostsProposal { Hostname = "already.htb", TargetIp = "10.10.10.5", Source = "vhost" },
        };

        var r = await tool.AnalyzeAsync("10.10.10.5", input, hosts);
        Assert.NotEmpty(r.Proposals);

        Assert.Equal(sizeBefore, new FileInfo(hosts).Length);
        Assert.Equal(mtimeBefore, File.GetLastWriteTimeUtc(hosts));
        Assert.Equal(sha256Before, Sha256Of(hosts));
    }

    [Fact]
    public async Task Argv_Injection_In_Hostname_Rejected()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);

        var hosts = WriteHostsFile("127.0.0.1 localhost\n");
        var input = new[]
        {
            new EtcHostsProposal { Hostname = "evil.htb; rm -rf /", TargetIp = "10.10.10.5", Source = "x" },
            new EtcHostsProposal { Hostname = "$(whoami).htb", TargetIp = "10.10.10.5", Source = "x" },
            new EtcHostsProposal { Hostname = "`id`.htb", TargetIp = "10.10.10.5", Source = "x" },
            new EtcHostsProposal { Hostname = "ok.lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-san" },
        };

        var r = await tool.AnalyzeAsync("10.10.10.5", input, hosts);

        Assert.Single(r.Proposals);
        Assert.Equal("ok.lab.htb", r.Proposals[0].Hostname);
        Assert.DoesNotContain(";", r.SuggestedSnippet);
        Assert.DoesNotContain("$", r.SuggestedSnippet);
        Assert.DoesNotContain("`", r.SuggestedSnippet);
        Assert.DoesNotContain("rm -rf", r.SuggestedSnippet);
    }

    [Fact]
    public async Task EmptyProposals_ProducesEmptySnippet()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = BuildTool(scope, audit);

        var hosts = WriteHostsFile("127.0.0.1 localhost\n");
        var r = await tool.AnalyzeAsync("10.10.10.5", Array.Empty<EtcHostsProposal>(), hosts);

        Assert.Empty(r.Proposals);
        Assert.Equal("", r.SuggestedSnippet);
    }

    [Fact]
    public async Task Priority_AddOutranksInfoOnly()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var dns = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["resolvable.lab.htb"] = new[] { "10.10.10.5" },
        };
        var tool = BuildTool(scope, audit, dns);

        var hosts = WriteHostsFile("127.0.0.1 localhost\n");
        var input = new[]
        {
            new EtcHostsProposal { Hostname = "resolvable.lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-san" },
            new EtcHostsProposal { Hostname = "missing.lab.htb", TargetIp = "10.10.10.5", Source = "ssl-cert-san" },
        };

        var r = await tool.AnalyzeAsync("10.10.10.5", input, hosts);

        var add = r.Proposals.Single(p => p.Action == "add");
        var info = r.Proposals.Single(p => p.Action == "info_only");
        Assert.True(add.Priority > info.Priority,
            $"add priority ({add.Priority}) must outrank info_only priority ({info.Priority})");
    }
}
