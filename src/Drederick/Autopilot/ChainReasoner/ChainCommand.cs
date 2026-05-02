using System.Text.Json;
using Drederick.Audit;
using Drederick.Cli;
using Drederick.Memory;

namespace Drederick.Autopilot.ChainReasoner;

/// <summary>
/// Handler for <c>drederick chain</c>. Loads the cross-run knowledge base,
/// asks <see cref="ChainReasoner"/> for ranked candidates, and prints either
/// a human-readable text table or JSON. No network calls; no scope check
/// (the reasoner only manipulates already-collected data).
/// </summary>
public static class ChainCommand
{
    public static int Execute(
        CommandLineOptions opts,
        TextWriter stdout,
        TextWriter stderr,
        AuditLog? audit = null,
        IChainAugmenter? augmenter = null)
    {
        Directory.CreateDirectory(opts.OutputDir);
        var auditPath = Path.Combine(opts.OutputDir, "audit.jsonl");
        var ownsAudit = audit is null;
        audit ??= new AuditLog(auditPath);

        try
        {
            var kb = KnowledgeBase.Load(opts.MemoryPath);
            var reasoner = new ChainReasoner(audit);
            var chains = reasoner.ReasonAsync(kb, creds: null, sessions: null, top: opts.ChainTopN, augmenter: augmenter, ct: default)
                .GetAwaiter().GetResult();

            if (opts.ChainJson)
            {
                stdout.WriteLine(JsonSerializer.Serialize(chains, new JsonSerializerOptions { WriteIndented = true }));
            }
            else
            {
                if (chains.Count == 0)
                {
                    stdout.WriteLine("No attack chains satisfied current preconditions.");
                    stdout.WriteLine($"  knowledge base: {opts.MemoryPath}");
                    stdout.WriteLine($"  hosts: {kb.Hosts.Count}");
                    stdout.WriteLine("Hint: run a recon pass first, or pass --memory <path>.");
                }
                else
                {
                    stdout.WriteLine($"Top {chains.Count} attack chain(s):");
                    int n = 1;
                    foreach (var c in chains)
                    {
                        stdout.WriteLine($"  {n,2}. [{c.Source}] {c.Name} (id={c.Id})");
                        stdout.WriteLine($"      score={c.Score:F3}  likelihood={c.Likelihood:F3}  impact={c.Impact:F2}  cost={c.Cost}");
                        if (opts.ChainExplain)
                        {
                            stdout.WriteLine($"      reason: {c.Reason}");
                            int i = 1;
                            foreach (var s in c.Steps)
                            {
                                stdout.WriteLine($"        step {i}: {s.Name} [{s.Tool}] conf={s.Confidence:F2} cost={s.Cost}");
                                if (!string.IsNullOrEmpty(s.Rationale))
                                    stdout.WriteLine($"          why: {s.Rationale}");
                                i++;
                            }
                        }
                        n++;
                    }
                }
            }

            return 0;
        }
        catch (Exception ex)
        {
            stderr.WriteLine($"chain: {ex.Message}");
            audit.Record("chain.command.error", new Dictionary<string, object?>
            {
                ["error_type"] = ex.GetType().Name,
                ["message"] = ex.Message,
            });
            return 1;
        }
        finally
        {
            if (ownsAudit) audit.Dispose();
        }
    }
}
