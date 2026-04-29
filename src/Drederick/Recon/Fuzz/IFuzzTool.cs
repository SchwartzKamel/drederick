namespace Drederick.Recon.Fuzz;

/// <summary>
/// Marker interface for fuzzing-specialized recon scanners. Extends
/// <see cref="IReconTool"/> with category metadata so
/// <see cref="FuzzToolbox"/> can group tools by attack surface (web, API,
/// DNS, auth, network protocols, mutation) and <see cref="Agent.AdaptiveRunner"/>
/// can prioritize fuzz passes based on fingerprinted services.
///
/// Every implementation MUST adhere to the same <see cref="IReconTool"/>
/// invariants:
///   1. Accept <see cref="Scope.Scope"/> and <see cref="Audit.AuditLog"/> via
///      the constructor (no ambient state).
///   2. Call <c>_scope.Require(target)</c> as the first statement of its
///      public fuzz method — scope enforcement lives in the tool, not the
///      caller, so an LLM cannot route around it.
///   3. Bracket work with <c>audit.Record("&lt;Name&gt;.start", …)</c> and
///      <c>audit.Record("&lt;Name&gt;.finish", …)</c> events so every fuzz
///      campaign is traceable in <c>audit.jsonl</c>.
///   4. Return a typed result from <see cref="FuzzResult"/> (never leak
///      unbounded raw payloads except as a digest field).
///
/// Fuzzing tools are inherently higher-blast-radius than passive recon:
/// parameter fuzzers send hundreds of requests, subdomain brute forcers may
/// trigger rate-limit / WAF state, network protocol fuzzers can crash
/// services, file-format mutators can exhaust disk on the target. To protect
/// operators and targets, every fuzz tool MUST respect the per-run opt-in
/// flags (e.g. <c>--allow-fuzz-web</c>, <c>--allow-fuzz-network</c>,
/// <c>--allow-destructive</c>) and throw a descriptive
/// <see cref="InvalidOperationException"/> if invoked without the required
/// permission in the current <see cref="Cli.RunOptions"/>. Lab mode defaults
/// most fuzz categories on; strict mode requires explicit opt-in per category.
/// </summary>
public interface IFuzzTool : IReconTool
{
    /// <summary>
    /// Which fuzz category this tool belongs to. Drives
    /// <see cref="Agent.AdaptiveRunner"/> scheduling (e.g. "run webapi fuzzers
    /// only when GraphQL or REST detected"), <see cref="FuzzToolbox"/> budget
    /// metering, and per-run opt-in gating at the CLI layer.
    /// </summary>
    FuzzCategory Category { get; }
}
