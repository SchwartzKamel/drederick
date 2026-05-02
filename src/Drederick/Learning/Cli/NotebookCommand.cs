using System.Text.Json;
using Drederick.Cli;
using Drederick.Learning;

namespace Drederick.Learning.Cli;

/// <summary>
/// Implements the <c>drederick notebook</c> subcommand. Reads the
/// LLM-authored fight notes JSONL (per-run + optional cross-fight
/// aggregate) and renders them for the operator to review between
/// fights.
///
/// Subcommands:
/// <list type="bullet">
///   <item><c>list</c> (default) — newest-first table, optional
///   filtering by <c>--notebook-category</c> / <c>--notebook-tag</c>.</item>
///   <item><c>tail</c> — same shape as list, but only the per-run
///   file (i.e. the current fight).</item>
///   <item><c>show</c> — JSON dump of all matching notes (machine-
///   readable for piping into review pipelines).</item>
///   <item><c>help</c> — usage.</item>
/// </list>
/// </summary>
public static class NotebookCommand
{
    public static async Task<int> RunAsync(CommandLineOptions opts, CancellationToken ct)
    {
        var sub = (opts.NotebookSubcommand ?? "list").ToLowerInvariant();

        if (sub == "help" || sub == "--help" || sub == "-h")
        {
            PrintHelp();
            return 0;
        }

        var runPath = Path.Combine(opts.OutputDir, "fight-notes.jsonl");
        var aggregatePath = FightNotebook.DefaultAggregatePath();
        var notebook = new FightNotebook(runPath, aggregatePath, audit: null, enabled: true);

        bool includeAggregate = sub != "tail" && opts.NotebookIncludeAggregate;
        var notes = await notebook.ReadAsync(
            includeAggregate: includeAggregate,
            category: opts.NotebookCategory,
            anyTags: opts.NotebookTags,
            since: null,
            limit: Math.Max(1, opts.NotebookLimit),
            ct: ct).ConfigureAwait(false);

        if (sub == "show")
        {
            var json = JsonSerializer.Serialize(notes, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(json);
            return 0;
        }

        if (notes.Count == 0)
        {
            Console.Error.WriteLine($"no notes found (run={runPath}, aggregate={(includeAggregate ? aggregatePath : "skipped")}).");
            return 0;
        }

        Console.WriteLine($"# Drederick fight notebook — {notes.Count} note(s)");
        Console.WriteLine($"# run:       {runPath}");
        if (includeAggregate)
            Console.WriteLine($"# aggregate: {aggregatePath}");
        Console.WriteLine();

        foreach (var n in notes)
        {
            var ts = n.Timestamp.Length > 19 ? n.Timestamp[..19] : n.Timestamp;
            var tags = n.Tags.Count == 0 ? "" : $"  [{string.Join(", ", n.Tags)}]";
            var host = string.IsNullOrEmpty(n.TargetHost) ? "" : $"  ({n.TargetHost})";
            Console.WriteLine($"- [{ts}] {n.Category}{host}{tags}");
            Console.WriteLine($"    {n.Body}");
        }

        return 0;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Usage: drederick notebook [list|tail|show|help] [flags]");
        Console.WriteLine();
        Console.WriteLine("Browse the LLM fight notebook (operator-readable JSONL).");
        Console.WriteLine();
        Console.WriteLine("Subcommands:");
        Console.WriteLine("  list   newest-first render of per-run + cross-fight notes (default)");
        Console.WriteLine("  tail   newest-first render of just the current run's notes");
        Console.WriteLine("  show   JSON dump for piping into review tools");
        Console.WriteLine("  help   this message");
        Console.WriteLine();
        Console.WriteLine("Flags:");
        Console.WriteLine("  -o, --out <dir>             output dir (default: out/)");
        Console.WriteLine("      --notebook-category <c> filter to category (observation|tactic|gap|mistake|winning_move|lesson|general)");
        Console.WriteLine("      --notebook-tag <t>      filter to tag (repeatable; any-match)");
        Console.WriteLine("      --notebook-limit <n>    max notes returned (default 50)");
        Console.WriteLine("      --notebook-no-aggregate skip the cross-fight aggregate file");
    }
}
