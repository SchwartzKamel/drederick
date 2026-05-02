using BenchmarkDotNet.Attributes;
using Drederick.Ops;

namespace Drederick.Bench;

/// <summary>
/// Compares the native managed PATH walk in <see cref="PathResolver.Which"/>
/// against shelling out to <c>which</c>. Maps to the
/// "PathResolver / `which`" row in <c>docs/SELF_SUFFICIENCY.md</c>.
/// </summary>
[MemoryDiagnoser]
public class PathResolverBench
{
    private const string Binary = "sh";

    [Benchmark(Baseline = true, Description = "PathResolver.Which (native)")]
    public string? Native() => PathResolver.Which(Binary);

    [Benchmark(Description = "which (subprocess)")]
    public string Subprocess() => BenchHelpers.RunAndCapture("/usr/bin/which", Binary);
}
