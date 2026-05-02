using System.Net;
using System.Net.Sockets;
using BenchmarkDotNet.Attributes;
using Drederick.Recon;

namespace Drederick.Bench;

/// <summary>
/// Compares <see cref="NativeScannerTool"/> (1 port, TCP connect) against
/// <c>nmap -p N 127.0.0.1</c>. Sets up an in-process <see cref="TcpListener"/>
/// on 127.0.0.1 so the connect succeeds without depending on any host service.
/// Scope is locked to <c>127.0.0.1/32</c>; the production tool's
/// <c>_scope.Require</c> guard runs unmodified.
/// </summary>
[MemoryDiagnoser]
public class NativeScannerBench
{
    private TcpListener _listener = null!;
    private int _port;
    private NativeScannerTool _tool = null!;

    [GlobalSetup]
    public void Setup()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        // Drain accepts in the background so scanner connects don't queue forever.
        _ = Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    var c = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    c.Close();
                }
                catch { return; }
            }
        });

        var scope = BenchHelpers.LoopbackScope();
        var audit = BenchHelpers.NewAuditLog();
        _tool = new NativeScannerTool(scope, audit);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        try { _listener.Stop(); } catch { /* best-effort */ }
    }

    [Benchmark(Baseline = true, Description = "NativeScannerTool 1-port connect (native)")]
    public int Native()
    {
        var finding = _tool.ScanAsync(
            "127.0.0.1",
            ports: new[] { _port },
            concurrency: 1,
            timeoutMs: 1000).GetAwaiter().GetResult();
        return finding.NativeScan?.OpenPorts.Count ?? 0;
    }

    [SkippableBenchmark(Reason = "Requires nmap on PATH", Description = "nmap -p N (subprocess)")]
    public string Subprocess()
    {
        if (!BenchHelpers.BinaryAvailable("nmap")) return string.Empty;
        return BenchHelpers.RunAndCapture("nmap", $"-p {_port} -Pn -n --max-retries 0 --host-timeout 2s 127.0.0.1");
    }
}
