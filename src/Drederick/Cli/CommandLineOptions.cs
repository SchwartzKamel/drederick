namespace Drederick.Cli;

public sealed class CommandLineOptions
{
    public string? ScopePath { get; set; }
    public List<string> Targets { get; } = new();
    public string OutputDir { get; set; } = "out";
    public string MemoryPath { get; set; } = "memory/findings.json";
    public bool AllowBroad { get; set; }
    public bool UseAgent { get; set; } // -a / --agent: use MS Agent Framework
    public bool Expand { get; set; }   // --expand: expand scope to all hosts
    public int Parallelism { get; set; } = 4;
    public bool Help { get; set; }

    public static CommandLineOptions Parse(string[] args)
    {
        var o = new CommandLineOptions();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "-h":
                case "--help":
                    o.Help = true; break;
                case "-s":
                case "--scope":
                    o.ScopePath = RequireNext(args, ref i, a); break;
                case "-t":
                case "--target":
                    o.Targets.Add(RequireNext(args, ref i, a)); break;
                case "-o":
                case "--out":
                    o.OutputDir = RequireNext(args, ref i, a); break;
                case "--memory":
                    o.MemoryPath = RequireNext(args, ref i, a); break;
                case "--allow-broad":
                    o.AllowBroad = true; break;
                case "-a":
                case "--agent":
                    o.UseAgent = true; break;
                case "--expand":
                    o.Expand = true; break;
                case "-j":
                case "--parallel":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1)
                            throw new ArgumentException($"--parallel value must be a positive integer, got '{v}'.");
                        o.Parallelism = n;
                        break;
                    }
                default:
                    throw new ArgumentException($"Unknown argument: {a}");
            }
        }
        return o;
    }

    private static string RequireNext(string[] args, ref int i, string flag)
    {
        if (i + 1 >= args.Length)
            throw new ArgumentException($"Flag {flag} requires a value.");
        return args[++i];
    }

    public static string HelpText =>
        """
        drederick - authorized-lab adaptive recon harness

        USAGE:
          drederick --scope <file> [--target <ip>]... [options]

        REQUIRED:
          -s, --scope <file>   Scope file (one CIDR/IP per line, '#' comments).

        TARGETS:
          -t, --target <ip>    Add a target (repeatable). If omitted and --expand
                               is set, the full scope is enumerated.
          --expand             Enumerate all hosts in the scope file.

        RUNNER:
          -a, --agent          Use Microsoft Agent Framework runner (needs
                               OPENAI_API_KEY; model via DREDERICK_MODEL).
                               Default: deterministic AdaptiveRunner.

        OUTPUT:
          -o, --out <dir>      Output directory (default: out/).
          --memory <path>      Cross-run knowledge base (default: memory/findings.json).

        TUNING:
          -j, --parallel <n>   Per-host concurrency for the deterministic runner (default: 4).
          --allow-broad        Permit scope entries broader than /16 (v4) or /48 (v6).

          -h, --help           Show this help.

        Drederick performs discovery and fingerprinting only. It does not
        exploit, brute force, or deliver payloads. Every target must be in
        the scope file.
        """;
}
