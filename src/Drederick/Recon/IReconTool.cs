namespace Drederick.Recon;

/// <summary>
/// Contract for scanners orchestrated by <see cref="ReconToolbox"/>. This is a
/// deliberately minimal, metadata-only interface: call signatures for recon
/// tools are intentionally heterogeneous (nmap takes a port spec, http takes
/// port + TLS flag, dns takes nothing), so forcing a single uniform
/// <c>ScanAsync(target, ct)</c> would throw away useful parameters. Instead,
/// implementations keep their typed scan methods and <see cref="ReconToolbox"/>
/// dispatches by concrete type; this interface carries the cross-cutting
/// metadata that the LLM runner and budget/audit layers need.
///
/// Every implementation MUST:
///   1. Accept <see cref="Scope.Scope"/> and <see cref="Audit.AuditLog"/> via
///      the constructor (no ambient state).
///   2. Call <c>_scope.Require(target)</c> as the first statement of its
///      public scan method — scope enforcement lives in the tool, not the
///      caller, so an LLM cannot route around it.
///   3. Bracket its work with <c>audit.Record("&lt;Name&gt;.start", …)</c> and
///      <c>audit.Record("&lt;Name&gt;.finish", …)</c> events so every probe is
///      traceable in <c>audit.jsonl</c>.
///   4. Contribute a typed result onto <see cref="HostFinding"/> (never leak
///      raw stdout/stderr except as a bounded error field).
/// </summary>
public interface IReconTool
{
    /// <summary>
    /// Short, stable kebab/lowercase identifier used for audit event prefixes
    /// (<c>{Name}.start</c>, <c>{Name}.finish</c>) and for budget metering in
    /// <see cref="ReconToolbox"/>. Must be unique across registered tools.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Human- and LLM-readable description of what this tool does and how it
    /// should be used. Mirrors the <c>[Description]</c> attribute that
    /// <see cref="ReconToolbox"/> exposes on the LLM tool surface, so the same
    /// wording can be reused when registering custom tools dynamically.
    /// </summary>
    string Description { get; }
}
