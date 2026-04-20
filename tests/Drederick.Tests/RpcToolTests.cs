using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class RpcToolTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-rpc-{Guid.NewGuid():N}.jsonl");

    private sealed class QueueRunner : IProcessRunner
    {
        private readonly Queue<(int ExitCode, string StdOut, string StdErr)> _responses;
        public List<(string File, string Arguments)> Calls { get; } = new();

        public QueueRunner(params (int, string, string)[] responses)
        {
            _responses = new Queue<(int, string, string)>(responses);
        }

        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
        {
            Calls.Add((file, arguments));
            if (_responses.Count == 0) return (0, string.Empty, string.Empty);
            return _responses.Dequeue();
        }

        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
            => throw new NotSupportedException();
    }

    private const string RpcInfoOutput =
        "   program vers proto   port  service\n" +
        "    100000    4   tcp    111  portmapper\n" +
        "    100000    3   tcp    111  portmapper\n" +
        "    100000    2   tcp    111  portmapper\n" +
        "    100000    4   udp    111  portmapper\n" +
        "    100003    3   tcp   2049  nfs\n" +
        "    100003    4   tcp   2049  nfs\n" +
        "    100005    1   udp  37521  mountd\n" +
        "    100005    3   tcp  45123  mountd\n" +
        "    100024    1   udp  55123  status\n" +
        "    100011    1   udp    875  rquotad\n";

    // rpc-grind reports program 100021 (nlockmgr) which is NOT in the rpcinfo
    // fixture above; the merge must keep both sources' programs.
    private const string NmapRpcGrindXml =
        "<?xml version=\"1.0\"?>\n" +
        "<nmaprun>\n" +
        "  <host>\n" +
        "    <ports>\n" +
        "      <port protocol=\"tcp\" portid=\"111\">\n" +
        "        <script id=\"rpc-grind\" output=\"rpc-grind results\">\n" +
        "          <table>\n" +
        "            <elem key=\"program\">100021</elem>\n" +
        "            <elem key=\"version\">4</elem>\n" +
        "            <elem key=\"name\">nlockmgr</elem>\n" +
        "            <elem key=\"protocol\">tcp</elem>\n" +
        "            <elem key=\"port\">54321</elem>\n" +
        "          </table>\n" +
        "          <table>\n" +
        "            <elem key=\"program\">100003</elem>\n" +
        "            <elem key=\"version\">3</elem>\n" +
        "            <elem key=\"name\">nfs</elem>\n" +
        "            <elem key=\"protocol\">tcp</elem>\n" +
        "            <elem key=\"port\">2049</elem>\n" +
        "          </table>\n" +
        "        </script>\n" +
        "      </port>\n" +
        "    </ports>\n" +
        "  </host>\n" +
        "</nmaprun>\n";

    [Fact]
    public async Task ProbeAsync_Throws_When_Target_Out_Of_Scope()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner();
        var tool = new RpcTool(scope, audit, runner, rpcinfoPath: "/bin/true", nmapPath: "/bin/true");

        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("192.0.2.9"));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task ProbeAsync_Parses_RpcInfo_Programs()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner(
            (0, RpcInfoOutput, string.Empty),
            (0, string.Empty, string.Empty));
        var tool = new RpcTool(scope, audit, runner, rpcinfoPath: "/bin/true", nmapPath: "/bin/true");

        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.Equal(111, result.Port);
        // 10 lines, all unique on (program, version, proto, port).
        Assert.Equal(10, result.Programs.Count);
        Assert.Contains(result.Programs, p => p.Program == 100000 && p.Name == "portmapper");
        Assert.Contains(result.Programs, p => p.Program == 100003 && p.Version == 4 && p.Port == 2049 && p.Name == "nfs");
        Assert.Contains(result.Programs, p => p.Program == 100005 && p.Protocol == "tcp" && p.Port == 45123 && p.Name == "mountd");
        Assert.Contains(result.Programs, p => p.Program == 100024 && p.Name == "status");
        Assert.Contains(result.Programs, p => p.Program == 100011 && p.Name == "rquotad");

        // rpcinfo then nmap — always two calls.
        Assert.Equal(2, runner.Calls.Count);
        Assert.Equal("/bin/true", runner.Calls[0].File);
        Assert.Contains("-p 10.10.10.5", runner.Calls[0].Arguments);
    }

    [Fact]
    public async Task ProbeAsync_Merges_RpcGrind_Programs_Not_In_RpcInfo()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner(
            (0, RpcInfoOutput, string.Empty),
            (0, NmapRpcGrindXml, string.Empty));
        var tool = new RpcTool(scope, audit, runner, rpcinfoPath: "/bin/true", nmapPath: "/bin/true");

        var result = await tool.ProbeAsync("10.10.10.5");

        // rpcinfo 10 programs + 1 new from rpc-grind (100021 v4 tcp/54321).
        // The second rpc-grind table (100003 v3 tcp/2049) is a dup of rpcinfo.
        Assert.Equal(11, result.Programs.Count);
        Assert.Contains(result.Programs, p => p.Program == 100021 && p.Version == 4 && p.Name == "nlockmgr" && p.Port == 54321);
        // Original rpcinfo entries still present.
        Assert.Contains(result.Programs, p => p.Program == 100003 && p.Version == 3 && p.Port == 2049);
        Assert.Null(result.Error);
    }

    [Fact]
    public async Task ProbeAsync_RpcInfo_Missing_Still_Runs_Nmap_And_Records_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner(
            (-1, string.Empty, "rpcinfo: command not found"),
            (0, NmapRpcGrindXml, string.Empty));
        var tool = new RpcTool(scope, audit, runner, rpcinfoPath: "rpcinfo", nmapPath: "/bin/true");

        var result = await tool.ProbeAsync("10.10.10.5");

        // nmap must still run despite rpcinfo failure.
        Assert.Equal(2, runner.Calls.Count);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
        Assert.Contains("rpcinfo", result.Error!, StringComparison.OrdinalIgnoreCase);

        // Programs discovered by rpc-grind must still populate.
        Assert.Contains(result.Programs, p => p.Program == 100021 && p.Name == "nlockmgr");
        Assert.Contains(result.Programs, p => p.Program == 100003 && p.Version == 3);
    }

    [Fact]
    public async Task ProbeAsync_Nmap_Command_Line_Is_Safe()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var runner = new QueueRunner(
            (0, RpcInfoOutput, string.Empty),
            (0, NmapRpcGrindXml, string.Empty));
        var tool = new RpcTool(scope, audit, runner, rpcinfoPath: "/bin/true", nmapPath: "/bin/true");

        await tool.ProbeAsync("10.10.10.5");

        Assert.Equal(2, runner.Calls.Count);
        var nmapArgs = runner.Calls[1].Arguments;

        Assert.Contains("--script rpc-grind", nmapArgs);
        Assert.Contains("-Pn", nmapArgs);
        Assert.Contains("-p 111", nmapArgs);
        Assert.Contains("-oX -", nmapArgs);
        Assert.Contains("10.10.10.5", nmapArgs);

        // The only --script value is rpc-grind.
        var tokens = nmapArgs.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < tokens.Length; i++)
        {
            if (tokens[i] == "--script")
            {
                Assert.True(i + 1 < tokens.Length);
                Assert.Equal("rpc-grind", tokens[i + 1]);
            }
        }

        // Forbidden NSE categories/keywords must never appear.
        foreach (var forbidden in new[] { "vuln", "brute", "exploit", "intrusive", "dos", "malware" })
        {
            Assert.DoesNotContain(forbidden, nmapArgs, StringComparison.OrdinalIgnoreCase);
        }
    }
}
