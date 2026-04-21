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

    /// <summary>
    /// Enable HTTP content discovery (bounded, path-only wordlist probe) on
    /// discovered HTTP(S) services during an AdaptiveRunner run. Off by
    /// default: content discovery generates many more requests than a plain
    /// HTTP probe and should be an explicit operator opt-in even inside a lab
    /// scope. The LLM runner can still invoke the tool on request regardless
    /// of this flag — this gates only the deterministic auto-dispatch.
    /// </summary>
    public bool ContentDiscovery { get; set; }

    /// <summary>
    /// Number of hosts scanned concurrently by the bounded worker pool.
    /// Default 4, hard cap 32. Driven by <c>--host-concurrency</c>; when the
    /// flag is omitted, falls back to <see cref="Parallelism"/> for backward
    /// compatibility with <c>-j / --parallel</c>.
    /// </summary>
    public int HostConcurrency { get; set; } = 4;

    /// <summary>
    /// Number of per-service probes (HTTP / TLS / nmap follow-ups) that a
    /// single host worker may fan out in parallel. Default 8, hard cap 64.
    /// </summary>
    public int ServiceConcurrency { get; set; } = 8;
    public bool Help { get; set; }

    public const int MaxHostConcurrency = 32;
    public const int MaxServiceConcurrency = 64;

    /// <summary>
    /// Lab/CTF mode. Default: true. In lab mode drederick allows a slightly
    /// broader scope prefix (up to /8 v4, /32 v6), enables the additional
    /// *enumeration* NSE categories (safe,default,discovery,version), and
    /// emits a per-host manual-commands cheatsheet. Lab mode never unlocks
    /// exploitation, brute force, or payload delivery — those stay disabled.
    /// Pass <c>--no-lab</c> to opt into the strictest posture.
    /// </summary>
    public bool LabMode { get; set; } = true;

    // ANCHOR: vpn-preflight-options (owned by vpn-htb-ergonomics task)
    /// <summary>Abort the run if an HTB CIDR target is passed but no tun*/tap* VPN interface is up.</summary>
    public bool RequireVpn { get; set; }
    /// <summary>Skip the VPN preflight check entirely (including the HTB CIDR detection).</summary>
    public bool SkipVpnCheck { get; set; }
    /// <summary>Explicit <c>.htb</c> hostnames to resolve via /etc/hosts and add to the target set.</summary>
    public List<string> HtbHosts { get; } = new();
    // END ANCHOR: vpn-preflight-options

    // ANCHOR: poc-aggregator-option (owned by poc-aggregator task)
    /// <summary>
    /// When true (the DEFAULT), the post-recon PoC aggregator copies public
    /// PoC artefacts (currently Exploit-DB mirror entries) into
    /// <c>&lt;out&gt;/poc_cache/</c> with a SHA-256 recorded in the findings
    /// DB. When false, only references (URLs / module names / template paths)
    /// are recorded — no bytes are copied locally. Invariant: drederick only
    /// aggregates and presents PoC content; it never executes it.
    /// </summary>
    public bool FetchPoc { get; set; } = true;
    // END ANCHOR: poc-aggregator-option

    /// <summary>Doctor subcommand selected (first positional arg "doctor").</summary>
    public bool DoctorSubcommand { get; set; }
    /// <summary>With --install / --doctor-fix: attempt to install missing tools.</summary>
    public bool DoctorInstall { get; set; }
    /// <summary>Skip the interactive [y/N] confirmation before running installs.</summary>
    public bool AssumeYes { get; set; }

    // --- init subcommand: first-time setup wizard ---------------------------------
    /// <summary>Init subcommand selected (first positional arg "init"). Interactive setup wizard.</summary>
    public bool InitSubcommand { get; set; }
    /// <summary>With --skip-creds: skip credential setup step.</summary>
    public bool InitSkipCreds { get; set; }
    /// <summary>With --skip-scope: skip scope file creation step.</summary>
    public bool InitSkipScope { get; set; }
    // --- end init subcommand --------------------------------------------------

    // --- datasette-integration: serve subcommand --------------------------------
    /// <summary>Serve subcommand selected (first positional arg "serve"). Launches datasette against out/findings.db.</summary>
    public bool ServeSubcommand { get; set; }

    // --- binary-analyzer subcommand ------------------------------------------
    /// <summary>Analyze subcommand selected (first positional arg "analyze"). Performs binary analysis on a file.</summary>
    public bool AnalyzeSubcommand { get; set; }
    /// <summary>Path to the binary file to analyze.</summary>
    public string? BinaryPath { get; set; }
    /// <summary>Output as JSON (for machine parsing).</summary>
    public bool AnalyzeJson { get; set; }
    /// <summary>Include extra details (all strings, all dependencies, etc.).</summary>
    public bool AnalyzeVerbose { get; set; }
    /// <summary>Write results to file (default: stdout).</summary>
    public string? AnalyzeOutput { get; set; }
    // --- end binary-analyzer subcommand ----------------------------------------
    /// <summary>Bind host for `drederick serve`. Default 127.0.0.1.</summary>
    public string ServeHost { get; set; } = "127.0.0.1";
    /// <summary>Bind port for `drederick serve`. Default 8001.</summary>
    public int ServePort { get; set; } = 8001;
    /// <summary>Whether `drederick serve` should pass --open to datasette. Default true.</summary>
    public bool ServeOpenBrowser { get; set; } = true;

    // ANCHOR: datasette-bootstrap-options
    /// <summary>Explicit path to a datasette binary. Skips discovery / bootstrap.</summary>
    public string? DatasettePath { get; set; }
    /// <summary>When true, refuse to auto-install datasette; require an already-present binary.</summary>
    public bool NoAutoInstall { get; set; }
    // END ANCHOR: datasette-bootstrap-options
    // --- end datasette-integration ----------------------------------------------

    // ANCHOR: note-subcommand-options
    /// <summary>Note subcommand: add, list, view, archive, delete, flags, search</summary>
    public string? NoteSubcommand { get; set; }
    /// <summary>Note ID for view/archive/delete operations</summary>
    public string? NoteId { get; set; }
    /// <summary>Title for new note</summary>
    public string? NoteTitle { get; set; }
    /// <summary>Content for new note</summary>
    public string? NoteContent { get; set; }
    /// <summary>Flag format (HTB, CTF, etc)</summary>
    public string? NoteFlag { get; set; }
    /// <summary>Comma-separated tags</summary>
    public string? NoteTags { get; set; }
    /// <summary>Note category</summary>
    public string? NoteCategory { get; set; }
    /// <summary>Associated host IP</summary>
    public string? NoteHost { get; set; }
    /// <summary>File attachment path</summary>
    public string? NoteFile { get; set; }
    /// <summary>Search term for search subcommand</summary>
    public string? NoteSearch { get; set; }
    /// <summary>Include archived notes in list/search</summary>
    public bool NoteIncludeArchived { get; set; }
    /// <summary>Output as JSON</summary>
    public bool NoteJson { get; set; }
    // END ANCHOR: note-subcommand-options

    public static CommandLineOptions Parse(string[] args)
    {
        var o = new CommandLineOptions();
        int start = 0;
        if (args.Length > 0 && args[0] == "doctor")
        {
            o.DoctorSubcommand = true;
            start = 1;
        }
        // --- datasette-integration: serve subcommand dispatch ------------------
        else if (args.Length > 0 && args[0] == "serve")
        {
            o.ServeSubcommand = true;
            start = 1;
        }
        // --- end datasette-integration -----------------------------------------
        // --- init subcommand dispatch ------------------------------------------
        else if (args.Length > 0 && args[0] == "init")
        {
            o.InitSubcommand = true;
            start = 1;
        }
        // --- end init subcommand -----------------------------------------------
        // --- binary-analyzer subcommand dispatch -----
        else if (args.Length > 0 && args[0] == "analyze")
        {
            o.AnalyzeSubcommand = true;
            start = 1;
            if (start < args.Length && !args[start].StartsWith("--") && !args[start].StartsWith("-"))
            {
                o.BinaryPath = args[start];
                start++;
            }
        }
        // --- end binary-analyzer subcommand ---------
        // ANCHOR: note-subcommand-dispatch
        else if (args.Length > 0 && args[0] == "note")
        {
            start = 1;
            if (start < args.Length && !args[start].StartsWith("--") && !args[start].StartsWith("-"))
            {
                o.NoteSubcommand = args[start];
                start++;
                // For view/archive/delete, capture the note ID as first positional arg
                if ((o.NoteSubcommand == "view" || o.NoteSubcommand == "archive" || o.NoteSubcommand == "delete")
                    && start < args.Length && !args[start].StartsWith("--"))
                {
                    o.NoteId = args[start];
                    start++;
                }
                // For search, capture search term
                if (o.NoteSubcommand == "search" && start < args.Length && !args[start].StartsWith("--"))
                {
                    o.NoteSearch = args[start];
                    start++;
                }
            }
            else
            {
                o.NoteSubcommand = "help";
            }
        }
        // END ANCHOR: note-subcommand-dispatch
        // --- end note-subcommand ---
        for (int i = start; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "--install":
                case "--doctor-fix":
                    o.DoctorInstall = true; break;
                case "-y":
                case "--yes":
                    o.AssumeYes = true; break;
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
                case "--lab":
                    o.LabMode = true; break;
                case "--no-lab":
                    o.LabMode = false; break;
                case "-a":
                case "--agent":
                    o.UseAgent = true; break;
                case "--expand":
                    o.Expand = true; break;
                case "--content-discovery":
                    o.ContentDiscovery = true; break;
                // ANCHOR: poc-aggregator-flag-parse
                case "--fetch-poc":
                    o.FetchPoc = true; break;
                case "--no-fetch-poc":
                    o.FetchPoc = false; break;
                // END ANCHOR: poc-aggregator-flag-parse
                // ANCHOR: vpn-preflight-flag-parse (owned by vpn-htb-ergonomics task)
                case "--require-vpn":
                    o.RequireVpn = true; break;
                case "--skip-vpn-check":
                    o.SkipVpnCheck = true; break;
                case "--htb-host":
                    o.HtbHosts.Add(RequireNext(args, ref i, a)); break;
                // END ANCHOR: vpn-preflight-flag-parse
                case "-j":
                case "--parallel":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1)
                            throw new ArgumentException($"--parallel value must be a positive integer, got '{v}'.");
                        o.Parallelism = n;
                        break;
                    }
                case "--host-concurrency":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > MaxHostConcurrency)
                            throw new ArgumentException(
                                $"--host-concurrency must be an integer in [1, {MaxHostConcurrency}], got '{v}'.");
                        o.HostConcurrency = n;
                        o._hostConcurrencyExplicit = true;
                        break;
                    }
                // --- datasette-integration: serve flags ------------------------
                case "--host":
                    if (o.ServeSubcommand)
                    {
                        o.ServeHost = RequireNext(args, ref i, a);
                    }
                    else if (o.NoteSubcommand == "add" || o.NoteSubcommand == "list")
                    {
                        o.NoteHost = RequireNext(args, ref i, a);
                    }
                    else
                    {
                        throw new ArgumentException($"Unknown argument: {a}");
                    }
                    break;
                case "--port":
                    if (!o.ServeSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > 65535)
                            throw new ArgumentException($"--port must be a TCP port in [1, 65535], got '{v}'.");
                        o.ServePort = n;
                        break;
                    }
                case "--no-open":
                    if (!o.ServeSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.ServeOpenBrowser = false;
                    break;
                // ANCHOR: datasette-bootstrap-flag-parse
                case "--datasette-path":
                    if (!o.ServeSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.DatasettePath = RequireNext(args, ref i, a);
                    break;
                case "--no-auto-install":
                    if (!o.ServeSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.NoAutoInstall = true;
                    break;
                // END ANCHOR: datasette-bootstrap-flag-parse
                // --- end datasette-integration ---------------------------------
                // --- init subcommand flags ---------------------------------
                case "--skip-creds":
                    if (!o.InitSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.InitSkipCreds = true;
                    break;
                case "--skip-scope":
                    if (!o.InitSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.InitSkipScope = true;
                    break;
                // --- end init subcommand flags ----------------------------
                // --- binary-analyzer subcommand flags -----------
                case "--json":
                    if (o.AnalyzeSubcommand)
                    {
                        o.AnalyzeJson = true;
                    }
                    else if (o.NoteSubcommand != null)
                    {
                        o.NoteJson = true;
                    }
                    else
                    {
                        throw new ArgumentException($"Unknown argument: {a}");
                    }
                    break;
                case "--verbose":
                    if (!o.AnalyzeSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.AnalyzeVerbose = true;
                    break;
                case "--output":
                    if (!o.AnalyzeSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.AnalyzeOutput = RequireNext(args, ref i, a);
                    break;
                // --- end binary-analyzer subcommand flags -------
                // ANCHOR: note-subcommand-flags
                case "--title":
                    if (o.NoteSubcommand != "add")
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.NoteTitle = RequireNext(args, ref i, a);
                    break;
                case "--content":
                    if (o.NoteSubcommand != "add")
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.NoteContent = RequireNext(args, ref i, a);
                    break;
                case "--flag":
                    if (o.NoteSubcommand != "add")
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.NoteFlag = RequireNext(args, ref i, a);
                    break;
                case "--tags":
                    if (o.NoteSubcommand != "add")
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.NoteTags = RequireNext(args, ref i, a);
                    break;
                case "--category":
                    if (o.NoteSubcommand != "add" && o.NoteSubcommand != "list")
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.NoteCategory = RequireNext(args, ref i, a);
                    break;
                case "--file":
                    if (o.NoteSubcommand != "add")
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.NoteFile = RequireNext(args, ref i, a);
                    break;
                case "--archived":
                    if (o.NoteSubcommand != "list" && o.NoteSubcommand != "flags" && o.NoteSubcommand != "search")
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.NoteIncludeArchived = true;
                    break;
                // END ANCHOR: note-subcommand-flags
                // --- end note-subcommand flags -----------------------
                case "--service-concurrency":
                default:
                    throw new ArgumentException($"Unknown argument: {a}");
            }
        }
        if (!o._hostConcurrencyExplicit)
        {
            // Back-compat: if the user passed -j/--parallel but not
            // --host-concurrency, use the legacy knob as the host-level cap.
            o.HostConcurrency = Math.Min(MaxHostConcurrency, Math.Max(1, o.Parallelism));
        }
        return o;
    }

    private bool _hostConcurrencyExplicit;

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
          drederick doctor [--install | --doctor-fix] [-y|--yes]
          drederick serve [--host <ip>] [--port <n>] [--no-open] [-o <dir>]
                          [--datasette-path <path>] [--no-auto-install] [-y|--yes]
          drederick init [--skip-creds] [--skip-scope] [-y|--yes]
          drederick analyze <binary-path> [--json] [--verbose] [--output <file>] [-s <scope>]

        SUBCOMMANDS:
          doctor               Check operator-workstation tooling (nmap, searchsploit,
                               python3/2, go, ruby, git, curl, jq, datasette). With
                               --install, install missing tools via the system package
                               manager (never re-execs as root; asks [y/N] first).
          serve                Launch Datasette against <out>/findings.db with the
                               bundled metadata (datasette/metadata.json). Auto-
                               bootstraps datasette via uv / pipx / python venv
                               under ~/.drederick/ the first time it is missing.
                               Pass --datasette-path to use an explicit binary,
                               or --no-auto-install to require one already present.
                               Default bind 127.0.0.1:8001.
          init                 Interactive first-time setup wizard. Verifies tools,
                               optionally sets up credentials, and creates a sample
                               scope file. Pass --skip-creds to skip credential setup,
                               --skip-scope to skip scope file creation, or --yes for
                               non-interactive mode.
          analyze              Assess binary security hardening, dependencies, and
                               suspicious characteristics. Requires a binary path.
                               With --scope, enforces scope on the binary path.
                               --json: machine-readable output. --verbose: include
                               detailed strings and dependencies. --output: write
                               results to file (default: stdout).

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
          -j, --parallel <n>   Legacy knob; sets --host-concurrency if that flag is
                               not also passed. Default: 4.
          --host-concurrency <n>
                               Number of hosts scanned in parallel by the bounded
                               worker pool. Range [1, 32]. Default: 4.
          --service-concurrency <n>
                               Number of per-host service probes (HTTP/TLS/nmap
                               follow-ups) in flight per host. Range [1, 64].
                               Default: 8.
          --allow-broad        Permit scope entries broader than the active lab/strict cap.
          --content-discovery  Enable bounded, path-only HTTP content discovery against
                               discovered HTTP(S) services. Off by default (even in lab
                               mode) — content discovery generates extra request volume
                               and should be an explicit operator opt-in.
          --fetch-poc          Cache public PoC artefacts (Exploit-DB mirror) under
                               <out>/poc_cache/ with SHA-256 recorded. ON BY DEFAULT.
                               drederick still aggregates + presents only — it NEVER
                               executes fetched PoCs.
          --no-fetch-poc       Record PoC references (URLs, module names, template paths)
                               only; do not copy any PoC bytes locally.
          --require-vpn        Abort with a non-zero exit if any resolved target falls inside
                               a known Hack The Box CIDR and no tun*/tap* VPN interface is up.
          --skip-vpn-check     Disable the HTB / VPN preflight entirely.
          --htb-host <host>    Explicit .htb hostname to resolve via /etc/hosts and add to the
                               target set (repeatable). Useful when the scope file lists an IP
                               but the operator only knows the HTB hostname.
          --lab                Lab/CTF mode (DEFAULT). Relaxes scope-breadth cap to /8 (v4)
                               and /32 (v6), enables extra ENUMERATION NSE categories
                               (safe,default,discovery,version), and emits a per-host
                               manual-commands cheatsheet. Never unlocks exploit/brute/vuln
                               scripts or payload delivery.
          --no-lab             Opt out of lab mode. Strictest posture: scope cap /16 (v4) /
                               /48 (v6), NSE limited to safe+default, no cheatsheet.

          -h, --help           Show this help.

        Drederick performs discovery and fingerprinting only. It does not
        exploit, brute force, or deliver payloads. Every target must be in
        the scope file. Authorized lab/CTF targets only.
        """;
}
