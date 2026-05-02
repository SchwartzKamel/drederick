using Drederick.Audit;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests.Recon.Scanning;

#if DISABLED_PENDING_SYN_WIRING
public class NativeScannerToolSynDispatchTests
{
    private static Scope.Scope MakeScope(params string[] entries)
    {
        var path = Path.Combine(Path.GetTempPath(), $"syndisp-scope-{Guid.NewGuid():N}.txt");
        File.WriteAllLines(path, entries);
        try
        {
            return Scope.ScopeLoader.LoadFile(path, allowBroad: false, labMode: true);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    private static AuditLog MakeAudit()
    {
        var path = Path.Combine(Path.GetTempPath(), $"syndisp-audit-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    [Fact(Skip="pending: NativeScannerTool useSyn overload not yet wired into recovery (WIP path)")]
    public async Task ScanAsync_DefaultUseSynFalse_StillWorks()
    {
        var scope = MakeScope("127.0.0.1/32");
        var tool = new NativeScannerTool(scope, MakeAudit());
        var result = await tool.ScanAsync(
            "127.0.0.1",
            ports: new[] { 1 }, // a port unlikely to be open; just exercise the path
            concurrency: 4,
            timeoutMs: 200);
        Assert.NotNull(result);
        Assert.NotNull(result.NativeScan);
    }

    [Fact(Skip="pending: NativeScannerTool useSyn overload not yet wired into recovery (WIP path)")]
    public async Task ScanAsync_UseSynTrue_ScopeStillRejected()
    {
        var scope = MakeScope("10.10.10.10/32");
        var tool = new NativeScannerTool(scope, MakeAudit());
        await Assert.ThrowsAsync<Scope.ScopeException>(async () =>
            await tool.ScanAsync("8.8.8.8", ports: new[] { 80 }, useSyn: true, timeoutMs: 200));
    }

    [Fact(Skip="pending: NativeScannerTool useSyn overload not yet wired into recovery (WIP path)")]
    public async Task ScanAsync_UseSynTrue_FallsBackToConnectScanWhenRawUnavailable()
    {
        // Whether or not raw sockets are available, useSyn=true must complete
        // and produce a NativeScanResult (either via SYN+connect-banner or via
        // the connect-scan fallback). The dispatch is logged either way.
        var scope = MakeScope("127.0.0.1/32");
        var tool = new NativeScannerTool(scope, MakeAudit());
        var result = await tool.ScanAsync(
            "127.0.0.1",
            ports: new[] { 1 },
            concurrency: 4,
            timeoutMs: 300,
            useSyn: true);
        Assert.NotNull(result);
        Assert.NotNull(result.NativeScan);
    }
}
#endif
