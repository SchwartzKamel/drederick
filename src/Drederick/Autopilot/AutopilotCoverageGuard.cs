using Drederick.Audit;
using Drederick.Enrichment;
using Drederick.Exploit;
using Drederick.Recon;

namespace Drederick.Autopilot;

/// <summary>
/// GAP-031 — coverage guard. For every CVE that recon fingerprinted on a
/// host, the autopilot plan must contain at least one <c>nuclei</c>
/// candidate AND at least one <c>msfrc</c> candidate. If the deterministic
/// planner produced neither for a given CVE, the guard attempts to inject
/// the missing tool(s) from cached PoC metadata (nuclei templates under
/// <c>out/poc_cache/nuclei/</c>, Metasploit module refs in
/// <c>findings.db.poc_refs</c>). If still nothing can be produced for a
/// category, the guard records an <c>autopilot.planner.coverage_gap</c>
/// audit event with the host, CVE, and missing categories — the audit
/// trail proves no fingerprinted CVE was silently dropped from the plan.
///
/// Pure: identical inputs → identical augmented list + identical audit
/// events. Never touches the network. Never adds payload / cred / DoS
/// candidates — only nuclei + msfrc, both <see cref="ExploitCategory.ExecPocs"/>.
/// Scope is enforced by the executing tool at spawn time; this guard does
/// not make permission decisions.
/// </summary>
public sealed class AutopilotCoverageGuard
{
    /// <summary>Lookup CVE → cached nuclei template paths (absolute).</summary>
    public delegate IReadOnlyList<string> NucleiTemplateLookup(string cveId);

    /// <summary>Lookup CVE → Metasploit module names (e.g. <c>exploit/multi/http/foo</c>).</summary>
    public delegate IReadOnlyList<string> MsfModuleLookup(string cveId);

    private readonly AuditLog _audit;
    private readonly NucleiTemplateLookup _nucleiLookup;
    private readonly MsfModuleLookup _msfLookup;

    public AutopilotCoverageGuard(
        AuditLog audit,
        NucleiTemplateLookup nucleiLookup,
        MsfModuleLookup msfLookup)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _nucleiLookup = nucleiLookup ?? throw new ArgumentNullException(nameof(nucleiLookup));
        _msfLookup = msfLookup ?? throw new ArgumentNullException(nameof(msfLookup));
    }

    /// <summary>
    /// Inspect <paramref name="candidates"/> for the given <paramref name="host"/>
    /// and return an augmented list with any missing nuclei / msfrc candidates
    /// injected from cached PoC metadata. Emits
    /// <c>autopilot.planner.coverage_gap</c> for every CVE that still lacks a
    /// nuclei or msfrc candidate after injection.
    /// </summary>
    public IReadOnlyList<ExploitAction> EnsureCoverage(
        HostFinding host,
        IReadOnlyList<ExploitAction> candidates)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(candidates);

        // Zero-CVE fast path: skip coverage check entirely. No fingerprinted
        // CVE on the host means there's nothing to be missing coverage for.
        var cveSet = candidates
            .Where(c => !string.IsNullOrWhiteSpace(c.CveId))
            .Select(c => c.CveId!.ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (cveSet.Length == 0) return candidates;

        var augmented = candidates.ToList();

        foreach (var cveId in cveSet)
        {
            // Use the existing candidate's port for any injection so the
            // synthesized action targets a known-open service.
            var anchor = augmented.FirstOrDefault(a =>
                string.Equals(a.CveId, cveId, StringComparison.OrdinalIgnoreCase));
            var port = anchor?.Port ?? 0;
            var url = anchor?.Url;
            var isTls = url is not null && url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

            var hasNuclei = augmented.Any(a =>
                a.Tool == "nuclei"
                && string.Equals(a.CveId, cveId, StringComparison.OrdinalIgnoreCase));
            var hasMsf = augmented.Any(a =>
                a.Tool == "msfrc"
                && string.Equals(a.CveId, cveId, StringComparison.OrdinalIgnoreCase));

            if (!hasNuclei)
            {
                var templates = _nucleiLookup(cveId);
                if (templates is { Count: > 0 })
                {
                    foreach (var templatePath in templates.Distinct(StringComparer.Ordinal).Take(4))
                    {
                        augmented.Add(new ExploitAction
                        {
                            Id = ExploitationPlanner.StableId(
                                "nuclei-coverage", host.Target, port.ToString(), cveId, templatePath),
                            Tool = "nuclei",
                            Target = host.Target,
                            Port = port,
                            Url = url,
                            Artifact = templatePath,
                            CveId = cveId,
                            Priority = 500,
                            Category = ExploitCategory.ExecPocs.ToString(),
                            Reason = $"GAP-031 coverage: CVE {cveId} → cached nuclei template {Path.GetFileName(templatePath)} for {host.Target}:{port}",
                        });
                    }
                    hasNuclei = true;
                }
            }

            if (!hasMsf)
            {
                var modules = _msfLookup(cveId);
                if (modules is { Count: > 0 })
                {
                    foreach (var module in modules.Distinct(StringComparer.Ordinal).Take(4))
                    {
                        augmented.Add(new ExploitAction
                        {
                            Id = ExploitationPlanner.StableId(
                                "msfrc-coverage", host.Target, port.ToString(), cveId, module),
                            Tool = "msfrc",
                            Target = host.Target,
                            Port = port,
                            Module = module,
                            Options = ExploitationPlanner.BuildMsfOptions(
                                host.Target, port, isTls, url is not null),
                            CveId = cveId,
                            Priority = 490,
                            Category = ExploitCategory.ExecPocs.ToString(),
                            Reason = $"GAP-031 coverage: CVE {cveId} → Metasploit module {module} for {host.Target}:{port}",
                        });
                    }
                    hasMsf = true;
                }
            }

            if (!hasNuclei || !hasMsf)
            {
                var missing = new List<string>();
                if (!hasNuclei) missing.Add("nuclei");
                if (!hasMsf) missing.Add("msf");
                var label = missing.Count == 2 ? "both" : missing[0];

                _audit.Record("autopilot.planner.coverage_gap",
                    new Dictionary<string, object?>
                    {
                        ["host"] = host.Target,
                        ["cve"] = cveId,
                        ["missing"] = missing.ToArray(),
                        ["missing_label"] = label,
                    });
            }
        }

        return augmented;
    }
}
