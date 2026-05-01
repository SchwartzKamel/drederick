using BenchmarkDotNet.Attributes;
using Drederick.Recon.Binary;

namespace Drederick.Bench;

/// <summary>
/// Compares the native managed <see cref="ElfParser"/> (header + program
/// headers + section headers) against <c>readelf -a</c>. Target is
/// <c>/bin/bash</c> if present, otherwise the first ELF binary that exists.
/// File access only — no networking — so no scope target check is needed,
/// but file readability is asserted via <see cref="Drederick.Scope.Scope.RequireFile"/>.
/// </summary>
[MemoryDiagnoser]
public class ElfParserBench
{
    private byte[] _bytes = [];
    private string _path = "/bin/bash";

    [GlobalSetup]
    public void Setup()
    {
        var candidates = new[] { "/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/ls" };
        foreach (var c in candidates)
        {
            if (File.Exists(c)) { _path = c; break; }
        }
        BenchHelpers.LoopbackScope().RequireFile(_path);
        _bytes = File.ReadAllBytes(_path);
    }

    [Benchmark(Baseline = true, Description = "ElfParser full parse (native)")]
    public int Native()
    {
        var hdr = ElfParser.ParseHeader(_bytes);
        if (hdr is null) return 0;
        var ph = ElfParser.ParseProgramHeaders(_bytes, hdr);
        var sh = ElfParser.ParseSectionHeaders(_bytes, hdr);
        return ph.Count + sh.Count;
    }

    [SkippableBenchmark(Reason = "Requires readelf on PATH", Description = "readelf -a (subprocess)")]
    public string Subprocess()
    {
        if (!BenchHelpers.BinaryAvailable("readelf")) return string.Empty;
        return BenchHelpers.RunAndCapture("readelf", $"-a {_path}");
    }
}
