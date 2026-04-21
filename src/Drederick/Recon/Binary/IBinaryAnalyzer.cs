namespace Drederick.Recon.Binary;

/// <summary>
/// Contract for binary analysis tools. Implementations perform static analysis
/// on binary files (ELF, PE, Mach-O, etc.) to extract metadata, dependencies,
/// and security posture, then report findings.
///
/// Every implementation MUST:
///   1. Accept <see cref="Scope.Scope"/> and <see cref="Audit.AuditLog"/> via
///      the constructor (no ambient state).
///   2. Enforce scope in <see cref="AnalyzeAsync"/> by calling
///      <c>_scope.RequireFile(filePath)</c> as the first statement — scope
///      enforcement lives in the tool, not the caller.
///   3. Throw <see cref="ScopeException"/> if filePath is outside allowed scope
///      or doesn't exist.
///   4. Bracket analysis work with <c>audit.Record("&lt;Name&gt;.start", …)</c>
///      and <c>audit.Record("&lt;Name&gt;.finish", …)</c> events for full
///      traceability in <c>audit.jsonl</c>.
///   5. Aggregate all issues as <see cref="BinaryFinding"/> objects — never
///      throw on recoverable errors; capture them as findings instead.
///   6. Produce a typed <see cref="BinaryAnalysisReport"/> with all metadata,
///      security properties, and findings.
/// </summary>
public interface IBinaryAnalyzer : IReconTool
{
    /// <summary>
    /// Analyzes a binary file at the given path and returns a comprehensive report.
    ///
    /// The implementation MUST:
    ///   - Enforce scope on filePath as the first operation.
    ///   - Verify the file exists and is readable.
    ///   - Extract and populate all report fields (metadata, dependencies, strings,
    ///     security, findings).
    ///   - Use timestamp at analysis start (ISO 8601).
    ///   - Capture all issues as BinaryFinding objects; never throw on recoverable
    ///     analysis errors.
    ///   - Return a complete BinaryAnalysisReport even if some analyses fail
    ///     (e.g., architecture detection fails, but string extraction succeeds).
    /// </summary>
    /// <param name="filePath">
    /// Absolute or relative path to the binary file. Will be scope-checked before
    /// analysis begins.
    /// </param>
    /// <param name="cancellationToken">Allows cancellation of long-running analysis.</param>
    /// <returns>A complete binary analysis report.</returns>
    /// <exception cref="ScopeException">
    /// Thrown if filePath is outside the authorized scope or doesn't exist.
    /// </exception>
    Task<BinaryAnalysisReport> AnalyzeAsync(string filePath, CancellationToken cancellationToken = default);
}
