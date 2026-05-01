using BenchmarkDotNet.Running;

namespace Drederick.Bench;

/// <summary>
/// BenchmarkDotNet entrypoint. Discovers every <c>[Benchmark]</c>-annotated
/// method in this assembly and dispatches to <see cref="BenchmarkSwitcher"/>
/// so callers can select benchmarks by name, list them with
/// <c>--list flat</c>, or run the entire suite.
/// </summary>
public static class Program
{
    public static int Main(string[] args)
    {
        var summary = BenchmarkSwitcher
            .FromAssembly(typeof(Program).Assembly)
            .Run(args);
        return summary is null ? 0 : 0;
    }
}
