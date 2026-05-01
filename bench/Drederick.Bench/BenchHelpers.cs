using System.Diagnostics;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Bench;

/// <summary>
/// Shared utilities for the benchmark harness. Keeps the per-bench setup
/// (loopback-only <see cref="Scope"/>, temp <see cref="AuditLog"/>) and the
/// subprocess capture path uniform across benchmark classes.
/// </summary>
internal static class BenchHelpers
{
    /// <summary>
    /// Loopback-only scope used by every benchmark. The corresponding
    /// production tools call <c>_scope.Require(target)</c> as their first
    /// statement; constructing scope here keeps that contract intact.
    /// </summary>
    public static Scope.Scope LoopbackScope() =>
        ScopeLoader.Parse("127.0.0.1/32", source: "<bench>", allowBroad: false, labMode: true);

    /// <summary>
    /// Per-bench audit log written to a unique temp path so concurrent runs
    /// don't trample each other and the host repo's <c>out/</c> is untouched.
    /// </summary>
    public static AuditLog NewAuditLog()
    {
        var dir = Path.Combine(Path.GetTempPath(), "drederick-bench", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return new AuditLog(Path.Combine(dir, "audit.jsonl"));
    }

    /// <summary>
    /// Runs <paramref name="fileName"/> with <paramref name="args"/> and
    /// returns its stdout. stderr is discarded. The benchmark arms that
    /// shell out use this so we measure end-to-end "operator typed it"
    /// latency, not just <see cref="Process.Start(ProcessStartInfo)"/>.
    /// Returns an empty string on failure — callers just need a comparable
    /// timing, not the parsed result.
    /// </summary>
    public static string RunAndCapture(string fileName, string args, int timeoutMs = 5000)
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };
            if (!p.Start()) return string.Empty;
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                return string.Empty;
            }
            return stdoutTask.GetAwaiter().GetResult();
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>True when <paramref name="binary"/> is resolvable on PATH.</summary>
    public static bool BinaryAvailable(string binary) => Drederick.Ops.PathResolver.IsAvailable(binary);
}
