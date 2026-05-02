using System.Diagnostics;
using System.Reflection;
using BenchmarkDotNet.Attributes;
using Xunit;

namespace Drederick.Tests;

/// <summary>
/// Smoke-tests for the <c>bench/Drederick.Bench</c> harness. Mirrors the
/// shape of <c>Drederick.Bench.dll --list flat</c> by reflecting over the
/// bench assembly: any method tagged <see cref="BenchmarkAttribute"/> (or
/// any subclass — covers <c>SkippableBenchmarkAttribute</c>) is treated as
/// a discovered benchmark. Asserts ≥5 benchmarks total and that the
/// PathResolver / Elf / NativeScanner classes each contribute at least
/// one method.
/// </summary>
public class BenchHarnessSmokeTests
{
    private static Assembly BenchAssembly()
    {
        // ProjectReference from this test csproj to the bench csproj copies
        // Drederick.Bench.dll into the test output dir.
        var path = Path.Combine(AppContext.BaseDirectory, "Drederick.Bench.dll");
        Assert.True(File.Exists(path), $"Bench assembly missing at {path}");
        return Assembly.LoadFrom(path);
    }

    private static IReadOnlyList<MethodInfo> DiscoverBenchmarks(Assembly asm) =>
        asm.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false } && t.IsPublic)
            .SelectMany(t => t.GetMethods(BindingFlags.Instance | BindingFlags.Public))
            .Where(m => m.GetCustomAttributes(typeof(BenchmarkAttribute), inherit: true).Length > 0)
            .ToList();

    [Fact]
    public void BenchAssembly_Discovers_AtLeast_FiveBenchmarks()
    {
        var asm = BenchAssembly();
        var benches = DiscoverBenchmarks(asm);
        Assert.True(
            benches.Count >= 5,
            $"Expected ≥5 [Benchmark] methods in Drederick.Bench, found {benches.Count}.");
    }

    [Theory]
    [InlineData("PathResolverBench")]
    [InlineData("ElfParserBench")]
    [InlineData("NativeScannerBench")]
    public void BenchAssembly_Contains_Class(string typeName)
    {
        var asm = BenchAssembly();
        var benches = DiscoverBenchmarks(asm);
        Assert.Contains(benches, m => m.DeclaringType?.Name == typeName);
    }

    [Fact]
    public void BenchAssembly_HasEntryPoint()
    {
        var asm = BenchAssembly();
        Assert.NotNull(asm.EntryPoint);
    }

    [Fact(Skip = "Optional: live `--list flat` invocation. Reflection-based discovery covers the same surface without spawning dotnet.")]
    public void BenchDll_ListFlat_Discovers_AtLeast_FiveBenchmarks()
    {
        var dll = Path.Combine(AppContext.BaseDirectory, "Drederick.Bench.dll");
        var psi = new ProcessStartInfo("dotnet", $"exec \"{dll}\" --list flat")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        var lines = stdout
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.Contains("Bench."))
            .ToList();
        Assert.True(lines.Count >= 5, $"--list flat returned {lines.Count} entries:\n{stdout}");
    }
}
