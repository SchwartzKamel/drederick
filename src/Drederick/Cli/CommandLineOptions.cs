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

    // --- exploit opt-ins ----------------------------------------------------
    // Every category is OFF by default, even inside a lab scope. These flags
    // map 1:1 to Drederick.Exploit.ExploitCategory values and build the
    // per-run Drederick.Exploit.RunPermissions that every IExploitTool checks
    // at its entry point.
    /// <summary>Permit execution of cached PoCs / module-driven exploits
    /// (nuclei, metasploit). CLI: <c>--allow-exec-pocs</c>.</summary>
    public bool AllowExecPocs { get; set; }
    /// <summary>Permit credential attacks (spray, brute, roast). CLI:
    /// <c>--allow-cred-attacks</c>. Password spray additionally requires
    /// <see cref="AcknowledgeLockoutRisk"/>.</summary>
    public bool AllowCredAttacks { get; set; }
    /// <summary>Permit payload generation, staging, and delivery. CLI:
    /// <c>--allow-payloads</c>.</summary>
    public bool AllowPayloads { get; set; }
    /// <summary>Permit modules/scripts flagged destructive (filesystem
    /// mutation, reboot, wipe). CLI: <c>--allow-destructive</c>.</summary>
    public bool AllowDestructive { get; set; }
    /// <summary>Permit NSE <c>dos</c>/<c>malware</c> categories and anything
    /// intentionally denial-of-service. CLI: <c>--allow-dos</c>.</summary>
    public bool AllowDos { get; set; }
    /// <summary>Explicit acknowledgement that credential attacks can lock
    /// accounts. Required in addition to <see cref="AllowCredAttacks"/>. CLI:
    /// <c>--acknowledge-lockout-risk</c>.</summary>
    public bool AcknowledgeLockoutRisk { get; set; }
    // --- end exploit opt-ins ------------------------------------------------

    // --- autopilot options --------------------------------------------------
    /// <summary>
    /// Run the post-recon autopilot: <see cref="Drederick.Autopilot.ExploitationPlanner"/>
    /// builds a prioritised action list from the completed recon and
    /// <see cref="Drederick.Autopilot.AutopilotRunner"/> dispatches each
    /// action through the existing exploit tools. All scope + permission
    /// gates still fire on the underlying tool — <c>--autopilot</c> is not a
    /// way around any invariant, it is a way to batch invocations.
    /// </summary>
    public bool Autopilot { get; set; }

    /// <summary>Seed <see cref="Drederick.Autopilot.CredentialStore"/> with a
    /// small built-in lab-grade wordlist (admin/admin, root/root, etc.) so
    /// cred spray has something to work with when the operator has not
    /// captured creds yet. Off by default.</summary>
    public bool AutopilotDefaultCreds { get; set; }

    /// <summary>Hard cap on autopilot plan/execute iterations. Default 3.</summary>
    public int AutopilotMaxIterations { get; set; } = 3;

    /// <summary>Hard cap on actions dispatched per autopilot iteration.
    /// Default 64 — enough for a realistic lab run while still bounding
    /// blast radius and ToolBudget pressure.</summary>
    public int AutopilotMaxActionsPerIteration { get; set; } = 64;

    /// <summary>User:password (optionally realm\\user:password) pairs supplied
    /// on the command line and merged into the credential store before
    /// planning. Repeatable via <c>--cred user:password</c>.</summary>
    public List<string> AutopilotCreds { get; } = new();
    // --- end autopilot options ----------------------------------------------

    /// <summary>Doctor subcommand selected (first positional arg "doctor").</summary>
    public bool DoctorSubcommand { get; set; }
    /// <summary>With --install / --doctor-fix: attempt to install missing tools.</summary>
    public bool DoctorInstall { get; set; }
    /// <summary>Skip the interactive [y/N] confirmation before running installs.</summary>
    public bool AssumeYes { get; set; }
    // --- jeopardy-doctor-options ---
    /// <summary>Doctor category filter (e.g. <c>jeopardy</c>). Null = run the default tool-detection pass.</summary>
    public string? DoctorCategory { get; set; }
    /// <summary>Permit api.githubcopilot.com for LLM reachability check without adding it to the scope file.</summary>
    public bool AllowCopilotHost { get; set; } = true;
    // --- end jeopardy-doctor-options ---

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

    /// <summary>
    /// When true, suppress per-tool progress lines on stderr during a scan.
    /// The adaptive runner otherwise prints one line per tool invocation
    /// (`[+] &lt;tool&gt; &lt;target[:port]&gt;`) so operators can see live activity.
    /// </summary>
    public bool Quiet { get; set; }

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

    // --- jeopardy-cli-options ---
    /// <summary>ctf-solve subcommand selected.</summary>
    public bool CtfSolveSubcommand { get; set; }
    /// <summary>ctf-msg subcommand selected.</summary>
    public bool CtfMsgSubcommand { get; set; }

    /// <summary>CTFd base URL. Falls back to $CTFD_URL if unset at parse time.</summary>
    public string? CtfdUrl { get; set; }
    /// <summary>CTFd API token. Falls back to $CTFD_TOKEN if unset at parse time.</summary>
    public string? CtfdToken { get; set; }
    /// <summary>Comma-separated model ids for the solver swarm.</summary>
    public List<string> CtfModels { get; } = new();
    public int CtfWallClockMinutes { get; set; } = 20;
    public decimal? CtfRunBudgetUsd { get; set; }
    public decimal? CtfChallengeBudgetUsd { get; set; }
    public int CtfMaxConcurrent { get; set; } = 4;
    public int CtfPollIntervalSec { get; set; } = 5;
    /// <summary>Optional comma-separated category filter (e.g. "pwn,crypto").</summary>
    public List<string>? CtfCategoryFilter { get; set; }
    /// <summary>Optional comma-separated challenge-id filter.</summary>
    public List<int>? CtfChallengeIds { get; set; }
    /// <summary>Path to operator-hint JSONL inbox. Default ~/.drederick/jeopardy-inbox.jsonl.</summary>
    public string? CtfInboxPath { get; set; }
    /// <summary>Directory for report.json / report.md. Default ./out/ctf-report/.</summary>
    public string CtfReportDir { get; set; } = Path.Combine("out", "ctf-report");

    // ctf-msg fields
    public string? CtfMsgKind { get; set; }
    public string? CtfMsgChallengeId { get; set; }
    public string? CtfMsgSolverId { get; set; }
    public string? CtfMsgBody { get; set; }
    // --- end jeopardy-cli-options ---

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
        // --- jeopardy-cli-subcommand-dispatch ---
        else if (args.Length > 0 && args[0] == "ctf-solve")
        {
            o.CtfSolveSubcommand = true;
            start = 1;
        }
        else if (args.Length > 0 && args[0] == "ctf-msg")
        {
            o.CtfMsgSubcommand = true;
            start = 1;
        }
        // --- end jeopardy-cli-subcommand-dispatch ---
        for (int i = start; i < args.Length; i++)
        {
            var a = args[i];
            // --- jeopardy-doctor: accept --category=<name> shorthand ---
            if (a.StartsWith("--category=", StringComparison.Ordinal))
            {
                o.DoctorCategory = a.Substring("--category=".Length);
                continue;
            }
            // --- end jeopardy-doctor ---
            switch (a)
            {
                case "--install":
                case "--doctor-fix":
                    o.DoctorInstall = true; break;
                case "-y":
                case "--yes":
                    o.AssumeYes = true; break;
                // --- jeopardy-doctor-flag-parse ---
                case "--allow-copilot-host":
                    o.AllowCopilotHost = true; break;
                case "--no-allow-copilot-host":
                    o.AllowCopilotHost = false; break;
                // --category is handled by the unified case below (doctor + note subcommands)
                // --- end jeopardy-doctor-flag-parse ---
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
                // --- exploit opt-in flag parse ---
                case "--allow-exec-pocs":
                    o.AllowExecPocs = true; break;
                case "--allow-cred-attacks":
                    o.AllowCredAttacks = true; break;
                case "--allow-payloads":
                    o.AllowPayloads = true; break;
                case "--allow-destructive":
                    o.AllowDestructive = true; break;
                case "--allow-dos":
                    o.AllowDos = true; break;
                case "--acknowledge-lockout-risk":
                    o.AcknowledgeLockoutRisk = true; break;
                // --- end exploit opt-in flag parse ---
                // --- autopilot flag parse ---
                case "--autopilot":
                    o.Autopilot = true; break;
                case "--autopilot-default-creds":
                    o.AutopilotDefaultCreds = true; break;
                case "--autopilot-max-iterations":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > 100)
                            throw new ArgumentException($"--autopilot-max-iterations must be in [1,100], got '{v}'.");
                        o.AutopilotMaxIterations = n; break;
                    }
                case "--autopilot-max-actions":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > 1000)
                            throw new ArgumentException($"--autopilot-max-actions must be in [1,1000], got '{v}'.");
                        o.AutopilotMaxActionsPerIteration = n; break;
                    }
                case "--cred":
                    o.AutopilotCreds.Add(RequireNext(args, ref i, a)); break;
                // --- end autopilot flag parse ---
                // ANCHOR: vpn-preflight-flag-parse (owned by vpn-htb-ergonomics task)
                case "--require-vpn":
                    o.RequireVpn = true; break;
                case "--skip-vpn-check":
                    o.SkipVpnCheck = true; break;
                case "--quiet":
                case "-q":
                    o.Quiet = true; break;
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
                    if (o.DoctorSubcommand)
                    {
                        o.DoctorCategory = RequireNext(args, ref i, a);
                    }
                    else if (o.NoteSubcommand == "add" || o.NoteSubcommand == "list")
                    {
                        o.NoteCategory = RequireNext(args, ref i, a);
                    }
                    else
                    {
                        throw new ArgumentException($"Unknown argument: {a}");
                    }
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
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > MaxServiceConcurrency)
                            throw new ArgumentException(
                                $"--service-concurrency must be an integer in [1, {MaxServiceConcurrency}], got '{v}'.");
                        o.ServiceConcurrency = n;
                        break;
                    }
                // --- jeopardy-cli-flag-parse ---
                case "--ctfd":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.CtfdUrl = RequireNext(args, ref i, a);
                    break;
                case "--ctfd-token":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.CtfdToken = RequireNext(args, ref i, a);
                    break;
                case "--models":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    {
                        var v = RequireNext(args, ref i, a);
                        o.CtfModels.Clear();
                        foreach (var m in v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                            o.CtfModels.Add(m);
                        break;
                    }
                case "--wall-clock-min":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, System.Globalization.NumberStyles.Integer,
                                System.Globalization.CultureInfo.InvariantCulture, out var n) || n < 1 || n > 24 * 60)
                            throw new ArgumentException($"--wall-clock-min must be in [1,1440], got '{v}'.");
                        o.CtfWallClockMinutes = n;
                        break;
                    }
                case "--run-budget-usd":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!decimal.TryParse(v, System.Globalization.NumberStyles.Number,
                                System.Globalization.CultureInfo.InvariantCulture, out var d) || d <= 0)
                            throw new ArgumentException($"--run-budget-usd must be a positive decimal, got '{v}'.");
                        o.CtfRunBudgetUsd = d;
                        break;
                    }
                case "--challenge-budget-usd":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!decimal.TryParse(v, System.Globalization.NumberStyles.Number,
                                System.Globalization.CultureInfo.InvariantCulture, out var d) || d <= 0)
                            throw new ArgumentException($"--challenge-budget-usd must be a positive decimal, got '{v}'.");
                        o.CtfChallengeBudgetUsd = d;
                        break;
                    }
                case "--max-concurrent":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > 64)
                            throw new ArgumentException($"--max-concurrent must be in [1,64], got '{v}'.");
                        o.CtfMaxConcurrent = n;
                        break;
                    }
                case "--poll-interval-sec":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > 3600)
                            throw new ArgumentException($"--poll-interval-sec must be in [1,3600], got '{v}'.");
                        o.CtfPollIntervalSec = n;
                        break;
                    }
                case "--category-filter":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    {
                        var v = RequireNext(args, ref i, a);
                        o.CtfCategoryFilter = new List<string>(
                            v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                        break;
                    }
                case "--challenge-ids":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    {
                        var v = RequireNext(args, ref i, a);
                        var ids = new List<int>();
                        foreach (var tok in v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        {
                            if (!int.TryParse(tok, System.Globalization.NumberStyles.Integer,
                                    System.Globalization.CultureInfo.InvariantCulture, out var id))
                                throw new ArgumentException($"--challenge-ids: invalid id '{tok}'.");
                            ids.Add(id);
                        }
                        o.CtfChallengeIds = ids;
                        break;
                    }
                case "--inbox":
                    if (!o.CtfSolveSubcommand && !o.CtfMsgSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.CtfInboxPath = RequireNext(args, ref i, a);
                    break;
                case "--report-dir":
                    if (!o.CtfSolveSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.CtfReportDir = RequireNext(args, ref i, a);
                    break;
                case "--kind":
                    if (!o.CtfMsgSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.CtfMsgKind = RequireNext(args, ref i, a);
                    break;
                case "--chal":
                    if (!o.CtfMsgSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.CtfMsgChallengeId = RequireNext(args, ref i, a);
                    break;
                case "--solver":
                    if (!o.CtfMsgSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.CtfMsgSolverId = RequireNext(args, ref i, a);
                    break;
                case "--body":
                    if (!o.CtfMsgSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.CtfMsgBody = RequireNext(args, ref i, a);
                    break;
                // --- end jeopardy-cli-flag-parse ---
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
        // --- jeopardy-cli-defaults ---
        if (o.CtfSolveSubcommand)
        {
            if (string.IsNullOrWhiteSpace(o.CtfdUrl))
                o.CtfdUrl = Environment.GetEnvironmentVariable("CTFD_URL");
            if (string.IsNullOrWhiteSpace(o.CtfdToken))
                o.CtfdToken = Environment.GetEnvironmentVariable("CTFD_TOKEN");
            if (o.CtfModels.Count == 0)
            {
                o.CtfModels.Add("claude-opus-4.7");
                o.CtfModels.Add("gpt-5.4");
                o.CtfModels.Add("gemini-3.1-pro");
            }
        }
        if ((o.CtfSolveSubcommand || o.CtfMsgSubcommand) && string.IsNullOrWhiteSpace(o.CtfInboxPath))
        {
            var home = Environment.GetEnvironmentVariable("HOME")
                ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            o.CtfInboxPath = Path.Combine(home ?? ".", ".drederick", "jeopardy-inbox.jsonl");
        }
        // --- end jeopardy-cli-defaults ---
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
          note <op>            Manage operator notes in findings.db
                               (CTF flags, creds, screenshots, observations).
                               Ops: add, list, view, search, flags, archive,
                               delete. Flags: --title, --content, --flag,
                               --tags, --category, --host, --file, --archived,
                               --json. See 'drederick note' (no args) for help.

        Jeopardy CTF mode:
          drederick ctf-solve --scope <file> --ctfd <url> [--models <csv>]
                              [--wall-clock-min 20] [--run-budget-usd 100]
                              [--challenge-budget-usd 5] [--max-concurrent 4]
                              [--poll-interval-sec 5] [--category-filter pwn,crypto]
                              [--challenge-ids 1,5,42] [--inbox <path>]
                              [--report-dir <dir>] [--ctfd-token <tok>]
          drederick ctf-msg --kind <hint|focus|skip|stop|shutdown>
                            [--chal 42] [--solver <id>] [--body "try ret2libc"]
                            [--inbox <path>]
          drederick doctor --category=jeopardy

          See docs/JEOPARDY.md for the full guide.
          Env: COPILOT_TOKEN (or GH_TOKEN / GITHUB_TOKEN), CTFD_URL, CTFD_TOKEN.
          Default models: claude-opus-4.7,gpt-5.4,gemini-3.1-pro.
          Default inbox: ~/.drederick/jeopardy-inbox.jsonl.

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
          -q, --quiet          Suppress per-tool progress lines on stderr during scans.
                               (Progress output is on stderr by default so stdout stays
                                clean for piping the final 'done.' summary.)

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

        EXPLOIT OPT-INS:
          By default in LAB MODE, every exploit category EXCEPT --allow-dos is
          ON (matching the maximum-capability-inside-scope directive). In
          strict mode (--no-lab), all categories default OFF and the flags
          below opt them back in individually. Credential attacks always
          additionally require --acknowledge-lockout-risk.

          --allow-exec-pocs    Permit execution of cached PoCs / module-driven exploits
                               (nuclei, metasploit auxiliary + exploit modules, cached
                               Exploit-DB PoCs). Also unlocks the aggressive NSE
                               categories (intrusive, vuln, exploit). Every host in
                               argv is re-validated against the scope allow-list
                               before spawn.
          --allow-cred-attacks Permit credential attacks (spraying, targeted brute,
                               AS-REP roast, kerberoast). Plaintext passwords are never
                               logged; SHA-256 only. Also unlocks NSE auth scripts.
          --acknowledge-lockout-risk
                               Required in addition to --allow-cred-attacks. Attests that
                               the operator understands account-lockout impact.
          --allow-payloads     Permit payload generation, staging, delivery, and
                               driving post/* Metasploit modules. Unlocks PAYLOAD /
                               CMD / LHOST / SRVHOST options in msfconsole RC files;
                               every callback address is still re-validated against
                               the scope allow-list before spawn.
          --allow-destructive  Permit modules/scripts flagged destructive (filesystem
                               mutation, reboot, wipe).
          --allow-dos          Permit NSE dos/malware categories and intentional
                               denial-of-service. OFF by default even in lab mode.

        Autopilot (post-recon heavyweight loop — "step into the ring"):
          --autopilot          Ladies and gentlemen… after recon closes,
                               Drederick builds a fight card (prioritised
                               exploit plan) from the findings and works the
                               opponent round by round through the existing
                               exploit tools. Does NOT bypass any gate:
                               every punch is re-validated through scope +
                               per-category permission at the underlying
                               tool. (I must dissent from any bypass.)
          --autopilot-default-creds
                               Seed the credential store with a small
                               built-in lab wordlist (admin/admin etc).
                               Think of it as your cornerman slipping you
                               the obvious combinations.
          --cred USER:PASSWORD (Repeatable.) Add a credential to the store.
                               Use REALM\\USER:PASSWORD for AD-style
                               accounts. Known faces ringside.
          --autopilot-max-iterations N
                               Cap rounds in the autopilot loop (default
                               3, max 100). Tatum goes the distance when
                               the plan keeps finding work to do.
          --autopilot-max-actions N
                               Cap punches thrown per round (default 64,
                               max 1000).

          -h, --help           Show this help.

        Drederick performs authorized offensive operations against scope-listed
        targets only. Inside scope, per-category opt-in flags unlock exploit
        execution, credential attacks, and payload delivery. Outside scope, it
        does nothing — every network-touching tool re-checks the scope allow-list
        on entry.
        """;
}
