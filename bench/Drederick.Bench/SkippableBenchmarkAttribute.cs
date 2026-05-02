using BenchmarkDotNet.Attributes;

namespace Drederick.Bench;

/// <summary>
/// Marker that a benchmark may be skipped when its host-side prerequisite
/// (e.g., a tool on PATH, an in-process service responder) is not available.
/// BenchmarkDotNet itself has no first-class skip primitive, so the convention
/// here is: the benchmark method short-circuits with a single no-op when
/// <see cref="ShouldSkip"/> returns true. The attribute simply documents
/// that intent so reviewers (and the smoke test) can find the skip arms.
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
internal sealed class SkippableBenchmarkAttribute : BenchmarkAttribute
{
    /// <summary>Free-form reason the benchmark may be skipped.</summary>
    public string? Reason { get; init; }
}
