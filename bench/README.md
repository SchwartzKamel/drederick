# Drederick.Bench

BenchmarkDotNet harness comparing **native managed code paths** against
their **subprocess equivalents**. Powers the perf table in
[`docs/SELF_SUFFICIENCY.md`](../docs/SELF_SUFFICIENCY.md).

## Run

```bash
dotnet run -c Release --project bench/Drederick.Bench
```

Filter to a single class or list discovered benchmarks:

```bash
dotnet run -c Release --project bench/Drederick.Bench -- --filter '*PathResolver*'
dotnet run -c Release --project bench/Drederick.Bench -- --list flat
```

## Benchmarks

| Class | Native arm | Subprocess arm | Maps to |
| ----- | ---------- | -------------- | ------- |
| `PathResolverBench` | `PathResolver.Which("sh")` | `which sh` | PATH resolution row |
| `DnsLookupBench` | `DnsClient` A-record (loopback resolver) | `dig +short` | DNS row |
| `SnmpSysNameBench` | SharpSNMP `sysName.0` GET | `snmpwalk` | SNMP row |
| `ElfParserBench` | `ElfParser` full parse | `readelf -a` | Binary analysis row |
| `NativeScannerBench` | `NativeScannerTool` 1-port connect (in-proc `TcpListener`) | `nmap -p N` | Port-scan row |

Each class has 2 arms → 10 `[Benchmark]` methods. Subprocess arms that
need a tool not on PATH or a service not listening are tagged
`[SkippableBenchmark]` and short-circuit to a no-op when the
prerequisite is missing — they still produce a timing, just one that
reflects the failure path.

## Invariants preserved by the harness

- **Per-bench scope is `127.0.0.1/32`.** Constructed in-memory via
  `ScopeLoader.Parse` in `BenchHelpers.LoopbackScope()`.
  `NativeScannerTool` runs unmodified; its `_scope.Require(target)`
  guard fires on every `ScanAsync` call.
- **Per-bench audit log** is written to a unique
  `Path.GetTempPath()`-rooted file (`BenchHelpers.NewAuditLog`) so
  concurrent runs don't trample each other and the repo's `out/`
  is untouched.
- **No production source is modified.** Bench is a leaf project
  referencing `src/Drederick/Drederick.csproj`.

## Mapping back to `docs/SELF_SUFFICIENCY.md`

After a run, BenchmarkDotNet drops a markdown summary in
`BenchmarkDotNet.Artifacts/results/`. Lift the
`Method | Mean | Ratio` columns into the perf table under each row;
the `Baseline = true` arm is always the native managed path so
`Ratio < 1` means native beats subprocess.
