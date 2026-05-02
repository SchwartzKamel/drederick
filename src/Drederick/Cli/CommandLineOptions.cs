using Drederick.Jeopardy.Llm;

namespace Drederick.Cli;

public sealed class CommandLineOptions
{
    public string? ScopePath { get; set; }
    public List<string> Targets { get; } = new();
    public string OutputDir { get; set; } = "out";
    public string MemoryPath { get; set; } = "memory/findings.json";

    // --- in-fight scaffolding (LOADER_SPEC) ---------------------------------
    /// <summary>Override path to <c>briefing.md</c>. Defaults to
    /// <c>&lt;dir(scope.yaml)&gt;/briefing.md</c>. See
    /// <c>machines/SCAFFOLDING/LOADER_SPEC.md</c> §2.</summary>
    public string? BriefingPath { get; set; }
    /// <summary>Override path to <c>attack-graph.yaml</c>. Defaults to
    /// <c>&lt;dir(scope.yaml)&gt;/attack-graph.yaml</c>.</summary>
    public string? AttackGraphPath { get; set; }
    /// <summary>Disable scaffolding discovery entirely (CI fuzzing).</summary>
    public bool NoScaffolding { get; set; }
    // --- end scaffolding ----------------------------------------------------

    // --- learning -----------------------------------------------------------
    /// <summary>Override path to the operator-curated fight corpus
    /// (<c>~/HTB/fight-log.yaml</c>). When null, discovery falls through to
    /// <c>DREDERICK_FIGHT_CORPUS</c> and the default <c>~/HTB/fight-log.yaml</c>.
    /// CLI: <c>--fight-corpus &lt;path&gt;</c>. See docs/LEARNING_LOOP.md.</summary>
    public string? FightCorpusPath { get; set; }
    // --- end learning -------------------------------------------------------

    /// <summary>Use raw-socket TCP SYN scan (CAP_NET_RAW) before connect-scan;
    /// transparently falls back to connect-scan when raw sockets unavailable.
    /// CLI: <c>--scan-syn</c>. See <c>src/Drederick/Recon/Scanning/SynScanner.cs</c>.</summary>
    public bool ScanSyn { get; set; }

    // --- telemetry ----------------------------------------------------------
    /// <summary>Whether to record per-attempt structured telemetry to
    /// <see cref="TelemetryDbPath"/>. Default true. CLI: <c>--telemetry</c> /
    /// <c>--no-telemetry</c>. See <c>docs/LEARNING_LOOP.md</c>.</summary>
    public bool Telemetry { get; set; } = true;
    /// <summary>Override path to the telemetry SQLite database. When null
    /// (default), <c>{OutputDir}/telemetry.db</c> is used. CLI:
    /// <c>--telemetry-db &lt;path&gt;</c>.</summary>
    public string? TelemetryDbPath { get; set; }
    // --- end telemetry ------------------------------------------------------

    // --- chain-reasoner-cli-options ---
    /// <summary>chain subcommand selected: prints ranked AttackChain[] from KnowledgeBase.</summary>
    public bool ChainSubcommand { get; set; }
    /// <summary>If true, emit per-step explainability (rationale + confidence + cost).</summary>
    public bool ChainExplain { get; set; }
    /// <summary>If true, emit JSON instead of human-readable text.</summary>
    public bool ChainJson { get; set; }
    /// <summary>How many top-ranked chains to print. Default 5.</summary>
    public int ChainTopN { get; set; } = 5;
    // --- end chain-reasoner-cli-options ---
    public bool AllowBroad { get; set; }
    public bool UseAgent { get; set; } // -a / --agent: use MS Agent Framework

    /// <summary>
    /// Hybrid runner mode: try the LLM planner first, fall back to the
    /// deterministic runner on operational failure (no API key, network,
    /// auth, rate-limit, transient SDK error). Set by <c>--agent=hybrid</c>.
    /// Implies <see cref="UseAgent"/>. Scope rejections still propagate —
    /// the hybrid wrapper never swallows <c>ScopeException</c>.
    /// </summary>
    public bool UseHybridAgent { get; set; }
    public bool Expand { get; set; }   // --expand: expand scope to all hosts

    // --- gap-029 budget tuning ---
    /// <summary>Override the global per-target-per-tool budget cap. Null =
    /// use mode-aware default (3 for deterministic, 10 for LLM modes).
    /// 0 is interpreted as "deny-all" — every tool call exceeds it.
    /// Negative values are rejected at parse time. See
    /// <see cref="Drederick.Recon.ToolBudget"/>.</summary>
    public int? BudgetPerTool { get; set; }

    /// <summary>Override the global total tool-call budget. Null = use
    /// mode-aware default (200 for deterministic, 500 for LLM modes).</summary>
    public int? BudgetGlobal { get; set; }

    /// <summary>Per-tool overrides parsed from <c>--budget=tool:N,tool:N</c>.
    /// Tool name keys match <see cref="Drederick.Recon.IReconTool.Name"/> /
    /// <see cref="Drederick.Exploit.IExploitTool.Name"/> (e.g.
    /// <c>"http"</c>, <c>"nmap"</c>, <c>"nuclei"</c>). Empty when no
    /// per-tool overrides were supplied.</summary>
    public Dictionary<string, int> BudgetPerToolOverrides { get; } = new();
    // --- end gap-029 budget tuning ---

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

    // --- tenable-import options ---
    /// <summary>
    /// Path to a Tenable scan export file (Nessus XML <c>.nessus</c> or Tenable
    /// CSV). When set, the importer extracts all host IPs and adds any that are
    /// inside the scope as additional targets, then pre-seeds the
    /// <c>KnowledgeBase</c> with service data from the scan so the adaptive runner
    /// can focus on unexplored surface rather than re-discovering known ports.
    /// IPs from the Tenable file that fall outside the scope are logged and skipped.
    /// </summary>
    public string? TenableImportPath { get; set; }

    /// <summary>Tenable.io API base URL (default <c>https://cloud.tenable.com</c>). Falls back to <c>$TENABLE_URL</c>.</summary>
    public string? TenableApiUrl { get; set; }
    /// <summary>Tenable.io access key. Falls back to <c>$TENABLE_ACCESS_KEY</c>.</summary>
    public string? TenableAccessKey { get; set; }
    /// <summary>Tenable.io secret key. Falls back to <c>$TENABLE_SECRET_KEY</c>.</summary>
    public string? TenableSecretKey { get; set; }
    /// <summary>Specific scan id to pull via <c>--tenable-scan-id</c>.</summary>
    public int? TenableScanId { get; set; }
    /// <summary>Scan name (most recent completed match wins) via <c>--tenable-scan-name</c>.</summary>
    public string? TenableScanName { get; set; }
    /// <summary>Pull the most recently completed scan visible to the API key.</summary>
    public bool TenableLatest { get; set; }
    /// <summary>Export format requested from the API. Default <c>nessus</c>; <c>csv</c> also accepted.</summary>
    public string TenableFormat { get; set; } = "nessus";
    /// <summary>When true, ignore the on-disk export cache and force a fresh export.</summary>
    public bool TenableNoCache { get; set; }

    /// <summary>
    /// Backend dialect: <c>io</c> (Tenable.io, default), <c>nessus</c>
    /// (Nessus Professional on-prem), or <c>sc</c> (Tenable.sc / SecurityCenter).
    /// </summary>
    public string TenableBackend { get; set; } = "io";

    /// <summary>SC/Nessus username (SC only requires this when API keys are not set).</summary>
    public string? TenableUsername { get; set; }
    /// <summary>SC/Nessus password (paired with <see cref="TenableUsername"/>).</summary>
    public string? TenablePassword { get; set; }

    /// <summary>
    /// Skip TLS server certificate validation. Default <c>false</c> for Tenable.io,
    /// auto-on for the <c>nessus</c> and <c>sc</c> backends because both ship with
    /// self-signed certs out of the box. Set explicitly to override.
    /// </summary>
    public bool? TenableInsecureTls { get; set; }
    // --- end tenable-import options ---

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
    public bool AllowExecShell { get; set; }
    public bool AllowExecShellBash { get; set; }
    /// <summary>Master gate for the cve-lead → LLM-author fallback bridge
    /// (<see cref="Drederick.Autopilot.CveLeadLlmAuthor"/>). Lab default-on,
    /// strict default-off. Useful only when <see cref="AllowExecShell"/> is
    /// also enabled — without it the bridge short-circuits to skip. CLI:
    /// <c>--allow-cve-lead-llm-author</c> / <c>--no-allow-cve-lead-llm-author</c>.</summary>
    public bool AllowCveLeadLlmAuthor { get; set; }
    /// <summary>Explicit acknowledgement that credential attacks can lock
    /// accounts. Required in addition to <see cref="AllowCredAttacks"/>. CLI:
    /// <c>--acknowledge-lockout-risk</c>.</summary>
    public bool AcknowledgeLockoutRisk { get; set; }

    /// <summary>Override for the cred-spray subprocess timeout, in seconds.
    /// CLI: <c>--cred-spray-timeout=N</c>. When unset, the runner picks a
    /// mode-appropriate default via
    /// <see cref="Drederick.Exploit.PasswordSprayTool.ResolveDefaultTimeoutSeconds"/>:
    /// 60s for strict + adaptive, 120s for lab / hybrid / llm. Capped at
    /// <see cref="Drederick.Exploit.PasswordSprayTool.MaxAdaptiveTimeoutSeconds"/>.
    /// </summary>
    public int? CredSprayTimeoutSeconds { get; set; }

    /// <summary>Override for every netexec-driven replay-adapter
    /// subprocess timeout (SMB/WinRM/MSSQL/LDAP/SSH/RDP), in seconds. CLI:
    /// <c>--replay-timeout=N</c>. When unset, the runner picks a
    /// mode-appropriate default via
    /// <see cref="Drederick.Exploit.Replay.CrossProtocolReplay.ResolveDefaultTimeoutSeconds"/>:
    /// 60s for strict + adaptive, 120s for lab / hybrid / llm. Capped at
    /// <see cref="Drederick.Exploit.Replay.CrossProtocolReplay.MaxTimeoutSeconds"/>.
    /// Mirrors the <c>--cred-spray-timeout</c> plumbing from 95a328d so
    /// the same R5 slow-target pain doesn't regress in cross-protocol
    /// replay.</summary>
    public int? ReplayTimeoutSeconds { get; set; }

    /// <summary>Master gate for the phishing/macro subsystem
    /// (<see cref="Drederick.Exploit.ExploitCategory.Phishing"/>). Without
    /// this flag, every <see cref="Drederick.Exploit.Phishing.IPhishingTool"/>
    /// refuses cleanly. CLI: <c>--allow-phishing</c>.</summary>
    public bool AllowPhishing { get; set; }
    /// <summary>Sub-gate enabling SMTP relay phishing delivery on top of
    /// <see cref="AllowPhishing"/>. Default off in every mode (including
    /// lab). CLI: <c>--allow-smtp-relay</c>.</summary>
    public bool AllowSmtpRelay { get; set; }
    /// <summary>Bind for the one-shot HTTP phishing stager. Format
    /// <c>HOST:PORT</c>. Default <c>127.0.0.1:0</c> (loopback,
    /// kernel-assigned). Non-loopback hosts must also be in scope. CLI:
    /// <c>--phish-stager-bind</c>.</summary>
    public string PhishStagerBind { get; set; } = "127.0.0.1:0";
    /// <summary>Default payload command embedded in generated phishing
    /// artifacts. Literal string or <c>@/path/to/file</c> to read from
    /// disk. The plaintext is never logged; only its SHA-256 hits the
    /// audit trail. CLI: <c>--phish-payload-cmd</c>.</summary>
    public string? PhishPayloadCmd { get; set; }
    /// <summary>Master gate for the AD attack family (AS-REP roast,
    /// kerberoast, WinRM auth, NTDS dump). Default-on in lab mode.
    /// CLI: <c>--allow-ad-attacks</c> / <c>--no-allow-ad-attacks</c>.
    /// </summary>
    public bool AllowAdAttacks { get; set; }

    /// <summary>When non-null, overrides the lab-mode default-on for
    /// <see cref="AllowAdAttacks"/>. Used so <c>--no-allow-ad-attacks</c>
    /// can disable the family even in lab mode.</summary>
    public bool? AllowAdAttacksExplicit { get; set; }

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

    // --- windows-vulns subcommand --------------------------------------------
    /// <summary>Windows-vulns subcommand selected (first positional arg "windows-vulns").
    /// Lists the bundled MSRC corpus or analyses a captured PostExWindowsResult JSON
    /// against it. Read-only, offline, no network.</summary>
    public bool WindowsVulnsSubcommand { get; set; }
    /// <summary>--list: print every CVE in the bundled MSRC corpus and exit.</summary>
    public bool WindowsVulnsList { get; set; }
    /// <summary>--analyze: run the matcher against a PostExWindowsResult JSON file.</summary>
    public bool WindowsVulnsAnalyze { get; set; }
    /// <summary>--postex-json &lt;path&gt;: PostExWindowsResult JSON to feed the matcher.</summary>
    public string? WindowsVulnsPostExJson { get; set; }
    /// <summary>--json: emit machine-readable output (matches AnalyzeJson convention).</summary>
    public bool WindowsVulnsJson { get; set; }
    // --- end windows-vulns subcommand ----------------------------------------

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

    /// <summary>LLM fight notebook subcommand: <c>list</c> | <c>tail</c> | <c>show</c>.
    /// Browses the JSONL produced by <see cref="Drederick.Learning.FightNotebook"/>
    /// (per-run + cross-fight aggregate). Distinct from <see cref="NoteSubcommand"/>.</summary>
    public string? NotebookSubcommand { get; set; }
    /// <summary>Filter <c>notebook list</c> output to a single category.</summary>
    public string? NotebookCategory { get; set; }
    /// <summary>Filter <c>notebook list</c> output by tag (any-match).</summary>
    public List<string> NotebookTags { get; set; } = new();
    /// <summary>Maximum notes returned by <c>notebook list</c>. Default 50.</summary>
    public int NotebookLimit { get; set; } = 50;
    /// <summary>When false, <c>notebook list</c> reads only the per-run file.</summary>
    public bool NotebookIncludeAggregate { get; set; } = true;
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

    // --- jeopardy-llm-provider-options ---
    /// <summary>Which LLM backend to use. Applies to both ctf-solve swarm and --agent recon mode. Default <see cref="LlmProvider.Auto"/> (probes copilot → azure → openai).</summary>
    public LlmProvider LlmProvider { get; set; } = LlmProvider.Auto;

    /// <summary>Azure OpenAI endpoint override (e.g. https://my-resource.openai.azure.com). Falls back to $AZURE_OPENAI_ENDPOINT.</summary>
    public string? AzureEndpoint { get; set; }
    /// <summary>Azure OpenAI API version override. Falls back to $AZURE_OPENAI_API_VERSION, then the client default.</summary>
    public string? AzureApiVersion { get; set; }
    /// <summary>Repeatable <c>--azure-deployment=modelId=deploymentName</c>. Wins over $AZURE_OPENAI_DEPLOYMENT_MAP.</summary>
    public Dictionary<string, string> AzureDeploymentMap { get; }
        = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>llama-server base URL override. Falls back to $LLAMACPP_URL, then 127.0.0.1:8080.</summary>
    public string? LlamaCppUrl { get; set; }
    /// <summary>Repeatable <c>--llamacpp-model=modelId=modelName</c> (both sides registered as aliases). Wins over $LLAMACPP_MODELS.</summary>
    public Dictionary<string, string> LlamaCppModels { get; }
        = new(StringComparer.Ordinal);
    // --- end jeopardy-llm-provider-options ---
    // --- end jeopardy-cli-options ---

    // --- web-cli-options ---
    /// <summary>web subcommand selected: launches the Drederick REST/SignalR host.</summary>
    public bool WebSubcommand { get; set; }
    /// <summary>Bind host for `drederick web`. Default 127.0.0.1 (loopback; no auth required).</summary>
    public string WebBind { get; set; } = "127.0.0.1";
    /// <summary>Bind port for `drederick web`. Default 7070.</summary>
    public int WebPort { get; set; } = 7070;
    /// <summary>Explicit bearer token for non-loopback binds. Overrides $DREDERICK_WEB_TOKEN and auto-generation.</summary>
    public string? WebToken { get; set; }
    // --- web-cli-help anchor — help text for the `web` subcommand lives in
    // the raw-string HelpText property below, under a plain "web" heading.
    // --- end web-cli-options ---

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
        // --- windows-vulns subcommand dispatch -----
        else if (args.Length > 0 && args[0] == "windows-vulns")
        {
            o.WindowsVulnsSubcommand = true;
            start = 1;
        }
        // --- end windows-vulns subcommand ---
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
        // --- llm-fight-notebook-subcommand-dispatch ---
        // Browse / tail the LLM fight notebook (out/fight-notes.jsonl +
        // ~/.drederick/fight-notebook.jsonl). Distinct from `note` above,
        // which is the per-finding annotation table in findings.db.
        else if (args.Length > 0 && args[0] == "notebook")
        {
            o.NotebookSubcommand = args.Length > 1 && !args[1].StartsWith("-") ? args[1] : "list";
            start = o.NotebookSubcommand == "list" && (args.Length == 1 || args[1].StartsWith("-")) ? 1 : 2;
        }
        // --- end llm-fight-notebook-subcommand-dispatch ---
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
        // --- web-cli-subcommand-dispatch ---
        else if (args.Length > 0 && args[0] == "web")
        {
            o.WebSubcommand = true;
            start = 1;
        }
        // --- end web-cli-subcommand-dispatch ---
        // --- chain-reasoner-cli-subcommand-dispatch ---
        else if (args.Length > 0 && args[0] == "chain")
        {
            o.ChainSubcommand = true;
            start = 1;
        }
        // --- end chain-reasoner-cli-subcommand-dispatch ---
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
            // --- gap-029 budget shorthand: --budget-per-tool=N / --budget-global=N / --budget=tool:N[,tool:N] ---
            if (a.StartsWith("--budget-per-tool=", StringComparison.Ordinal))
            {
                o.BudgetPerTool = ParseBudgetCap("--budget-per-tool", a.Substring("--budget-per-tool=".Length));
                continue;
            }
            if (a.StartsWith("--budget-global=", StringComparison.Ordinal))
            {
                o.BudgetGlobal = ParseBudgetCap("--budget-global", a.Substring("--budget-global=".Length));
                continue;
            }
            if (a.StartsWith("--budget=", StringComparison.Ordinal))
            {
                ParseBudgetSpec(a.Substring("--budget=".Length), o.BudgetPerToolOverrides);
                continue;
            }
            // --- end gap-029 budget shorthand ---
            // --- cred-spray-timeout shorthand: --cred-spray-timeout=N ---
            if (a.StartsWith("--cred-spray-timeout=", StringComparison.Ordinal))
            {
                var v = a.Substring("--cred-spray-timeout=".Length);
                if (!int.TryParse(v, out var n) || n < 1 || n > Drederick.Exploit.PasswordSprayTool.MaxAdaptiveTimeoutSeconds)
                    throw new ArgumentException(
                        $"--cred-spray-timeout must be in [1,{Drederick.Exploit.PasswordSprayTool.MaxAdaptiveTimeoutSeconds}], got '{v}'.");
                o.CredSprayTimeoutSeconds = n;
                continue;
            }
            // --- end cred-spray-timeout shorthand ---
            // --- replay-timeout shorthand: --replay-timeout=N ---
            if (a.StartsWith("--replay-timeout=", StringComparison.Ordinal))
            {
                var v = a.Substring("--replay-timeout=".Length);
                if (!int.TryParse(v, out var n) || n < 1 || n > Drederick.Exploit.Replay.CrossProtocolReplay.MaxTimeoutSeconds)
                    throw new ArgumentException(
                        $"--replay-timeout must be in [1,{Drederick.Exploit.Replay.CrossProtocolReplay.MaxTimeoutSeconds}], got '{v}'.");
                o.ReplayTimeoutSeconds = n;
                continue;
            }
            // --- end replay-timeout shorthand ---
            // --- jeopardy-llm-provider: accept --flag=value shorthand ---
            // The provider flags are documented with --flag=value syntax
            // (e.g. --llm-provider=azure). Split those inline; everything else
            // continues to use the --flag <value> two-token form.
            {
                var eq = a.IndexOf('=');
                if (eq > 2 && a.StartsWith("--", StringComparison.Ordinal))
                {
                    var head = a[..eq];
                    if (head is "--llm-provider" or "--azure-endpoint" or "--azure-api-version"
                        or "--azure-deployment" or "--llamacpp-url" or "--llamacpp-model")
                    {
                        var val = a[(eq + 1)..];
                        // Rewrite and re-enter the loop body by replacing args in place.
                        // We can't mutate `args` (it's the caller's array), so splice
                        // into a local list that `i`/`args[i+1]` will read from next.
                        // Simpler: handle inline via a mini-switch.
                        switch (head)
                        {
                            case "--llm-provider":
                                if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                                    throw new ArgumentException($"Unknown argument: {a}");
                                o.LlmProvider = LlmProviderFactory.Parse(val);
                                break;
                            case "--azure-endpoint":
                                if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                                    throw new ArgumentException($"Unknown argument: {a}");
                                o.AzureEndpoint = val;
                                break;
                            case "--azure-api-version":
                                if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                                    throw new ArgumentException($"Unknown argument: {a}");
                                o.AzureApiVersion = val;
                                break;
                            case "--azure-deployment":
                                {
                                    if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                                        throw new ArgumentException($"Unknown argument: {a}");
                                    var eq2 = val.IndexOf('=');
                                    if (eq2 <= 0 || eq2 == val.Length - 1)
                                        throw new ArgumentException(
                                            $"--azure-deployment must be modelId=deploymentName, got '{val}'.");
                                    o.AzureDeploymentMap[val[..eq2].Trim()] = val[(eq2 + 1)..].Trim();
                                    break;
                                }
                            case "--llamacpp-url":
                                if (!o.CtfSolveSubcommand && !o.DoctorSubcommand)
                                    throw new ArgumentException($"Unknown argument: {a}");
                                o.LlamaCppUrl = val;
                                break;
                            case "--llamacpp-model":
                                {
                                    if (!o.CtfSolveSubcommand && !o.DoctorSubcommand)
                                        throw new ArgumentException($"Unknown argument: {a}");
                                    var eq2 = val.IndexOf('=');
                                    if (eq2 < 0)
                                    {
                                        o.LlamaCppModels[val.Trim()] = val.Trim();
                                    }
                                    else
                                    {
                                        if (eq2 == 0 || eq2 == val.Length - 1)
                                            throw new ArgumentException(
                                                $"--llamacpp-model must be modelId or modelId=modelName, got '{val}'.");
                                        o.LlamaCppModels[val[..eq2].Trim()] = val[(eq2 + 1)..].Trim();
                                    }
                                    break;
                                }
                        }
                        continue;
                    }
                }
            }
            // --- end jeopardy-llm-provider ---
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
                // --- learning flag parse ---
                case "--fight-corpus":
                    o.FightCorpusPath = RequireNext(args, ref i, a); break;
                case "--notebook-category":
                    o.NotebookCategory = RequireNext(args, ref i, a); break;
                case "--notebook-tag":
                    o.NotebookTags.Add(RequireNext(args, ref i, a)); break;
                case "--notebook-limit":
                    o.NotebookLimit = int.Parse(RequireNext(args, ref i, a)); break;
                case "--notebook-no-aggregate":
                    o.NotebookIncludeAggregate = false; break;
                // --- end learning flag parse ---
                // --- telemetry flag parse ---
                case "--telemetry":
                    o.Telemetry = true; break;
                case "--no-telemetry":
                    o.Telemetry = false; break;
                case "--telemetry-db":
                    o.TelemetryDbPath = RequireNext(args, ref i, a); break;
                // --- end telemetry flag parse ---
                // --- scan-syn flag parse ---
                case "--scan-syn":
                    o.ScanSyn = true; break;
                case "--no-scan-syn":
                    o.ScanSyn = false; break;
                // --- end scan-syn flag parse ---
                // --- chain-reasoner-flag-parse ---
                case "--explain":
                    if (!o.ChainSubcommand) throw new ArgumentException($"--explain only valid with `chain` subcommand");
                    o.ChainExplain = true; break;
                case "--top":
                    if (!o.ChainSubcommand) throw new ArgumentException($"--top only valid with `chain` subcommand");
                    if (!int.TryParse(RequireNext(args, ref i, a), out var topN) || topN < 1)
                        throw new ArgumentException("--top requires a positive integer");
                    o.ChainTopN = topN; break;
                // --- end chain-reasoner-flag-parse ---
                case "--allow-broad":
                    o.AllowBroad = true; break;
                case "--lab":
                    o.LabMode = true; break;
                case "--no-lab":
                    o.LabMode = false; break;
                case "-a":
                case "--agent":
                    o.UseAgent = true; break;
                // --- hybrid-runner-flag-parse ---
                case "--agent=hybrid":
                    o.UseAgent = true; o.UseHybridAgent = true; break;
                case "--agent=llm":
                    o.UseAgent = true; o.UseHybridAgent = false; break;
                case "--agent=adaptive":
                    o.UseAgent = false; o.UseHybridAgent = false; break;
                // --- end hybrid-runner-flag-parse ---
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
                case "--allow-exec-shell":
                    o.AllowExecShell = true; break;
                case "--no-allow-exec-shell":
                    o.AllowExecShell = false; break;
                case "--allow-exec-shell-bash":
                    o.AllowExecShellBash = true; break;
                case "--allow-cve-lead-llm-author":
                    o.AllowCveLeadLlmAuthor = true; break;
                case "--no-allow-cve-lead-llm-author":
                    o.AllowCveLeadLlmAuthor = false; break;
                case "--acknowledge-lockout-risk":
                    o.AcknowledgeLockoutRisk = true; break;
                case "--cred-spray-timeout":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > Drederick.Exploit.PasswordSprayTool.MaxAdaptiveTimeoutSeconds)
                            throw new ArgumentException(
                                $"--cred-spray-timeout must be in [1,{Drederick.Exploit.PasswordSprayTool.MaxAdaptiveTimeoutSeconds}], got '{v}'.");
                        o.CredSprayTimeoutSeconds = n;
                        break;
                    }
                case "--replay-timeout":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > Drederick.Exploit.Replay.CrossProtocolReplay.MaxTimeoutSeconds)
                            throw new ArgumentException(
                                $"--replay-timeout must be in [1,{Drederick.Exploit.Replay.CrossProtocolReplay.MaxTimeoutSeconds}], got '{v}'.");
                        o.ReplayTimeoutSeconds = n;
                        break;
                    }
                case "--allow-phishing":
                    o.AllowPhishing = true; break;
                case "--allow-smtp-relay":
                    o.AllowSmtpRelay = true; break;
                case "--phish-stager-bind":
                    o.PhishStagerBind = RequireNext(args, ref i, a); break;
                case "--phish-payload-cmd":
                    o.PhishPayloadCmd = RequireNext(args, ref i, a); break;
                case "--allow-ad-attacks":
                    o.AllowAdAttacks = true;
                    o.AllowAdAttacksExplicit = true; break;
                case "--no-allow-ad-attacks":
                    o.AllowAdAttacks = false;
                    o.AllowAdAttacksExplicit = false; break;
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
                case "--tenable-import":
                    o.TenableImportPath = RequireNext(args, ref i, a); break;
                case "--tenable-api-url":
                    o.TenableApiUrl = RequireNext(args, ref i, a); break;
                case "--tenable-access-key":
                    o.TenableAccessKey = RequireNext(args, ref i, a); break;
                case "--tenable-secret-key":
                    o.TenableSecretKey = RequireNext(args, ref i, a); break;
                case "--tenable-scan-id":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1)
                            throw new ArgumentException($"--tenable-scan-id must be a positive integer, got '{v}'.");
                        o.TenableScanId = n; break;
                    }
                case "--tenable-scan-name":
                    o.TenableScanName = RequireNext(args, ref i, a); break;
                case "--tenable-latest":
                    o.TenableLatest = true; break;
                case "--tenable-format":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!string.Equals(v, "nessus", StringComparison.OrdinalIgnoreCase) &&
                            !string.Equals(v, "csv", StringComparison.OrdinalIgnoreCase))
                            throw new ArgumentException($"--tenable-format must be 'nessus' or 'csv', got '{v}'.");
                        o.TenableFormat = v.ToLowerInvariant(); break;
                    }
                case "--tenable-no-cache":
                    o.TenableNoCache = true; break;
                case "--tenable-backend":
                    {
                        var v = RequireNext(args, ref i, a).ToLowerInvariant();
                        if (v != "io" && v != "nessus" && v != "sc")
                            throw new ArgumentException($"--tenable-backend must be 'io', 'nessus', or 'sc'; got '{v}'.");
                        o.TenableBackend = v; break;
                    }
                case "--tenable-username":
                    o.TenableUsername = RequireNext(args, ref i, a); break;
                case "--tenable-password":
                    o.TenablePassword = RequireNext(args, ref i, a); break;
                case "--tenable-insecure":
                    o.TenableInsecureTls = true; break;
                case "--tenable-secure":
                    o.TenableInsecureTls = false; break;
                // --- gap-029 budget tuning flag parse ---
                case "--budget-per-tool":
                    {
                        var v = RequireNext(args, ref i, a);
                        o.BudgetPerTool = ParseBudgetCap("--budget-per-tool", v);
                        break;
                    }
                case "--budget-global":
                    {
                        var v = RequireNext(args, ref i, a);
                        o.BudgetGlobal = ParseBudgetCap("--budget-global", v);
                        break;
                    }
                case "--budget":
                    {
                        var v = RequireNext(args, ref i, a);
                        ParseBudgetSpec(v, o.BudgetPerToolOverrides);
                        break;
                    }
                // --- end gap-029 budget tuning flag parse ---
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
                case "--briefing":
                    o.BriefingPath = RequireNext(args, ref i, a); break;
                case "--attack-graph":
                    o.AttackGraphPath = RequireNext(args, ref i, a); break;
                case "--no-scaffolding":
                    o.NoScaffolding = true; break;
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
                // --- web-cli-flag-parse ---
                case "--web-bind":
                    if (!o.WebSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.WebBind = RequireNext(args, ref i, a);
                    break;
                case "--web-port":
                    {
                        if (!o.WebSubcommand)
                            throw new ArgumentException($"Unknown argument: {a}");
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > 65535)
                            throw new ArgumentException($"--web-port must be a TCP port in [1, 65535], got '{v}'.");
                        o.WebPort = n;
                        break;
                    }
                case "--web-token":
                    if (!o.WebSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.WebToken = RequireNext(args, ref i, a);
                    break;
                // --- end web-cli-flag-parse ---
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
                    else if (o.WindowsVulnsSubcommand)
                    {
                        o.WindowsVulnsJson = true;
                    }
                    else if (o.NoteSubcommand != null)
                    {
                        o.NoteJson = true;
                    }
                    else if (o.ChainSubcommand)
                    {
                        o.ChainJson = true;
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
                // --- windows-vulns subcommand flags -----------
                case "--list":
                    if (!o.WindowsVulnsSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.WindowsVulnsList = true;
                    break;
                case "--analyze":
                    if (!o.WindowsVulnsSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.WindowsVulnsAnalyze = true;
                    break;
                case "--postex-json":
                    if (!o.WindowsVulnsSubcommand)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.WindowsVulnsPostExJson = RequireNext(args, ref i, a);
                    break;
                // --- end windows-vulns subcommand flags ---------
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
                // --- jeopardy-llm-provider-flag-parse ---
                case "--llm-provider":
                    {
                        if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                            throw new ArgumentException($"Unknown argument: {a}");
                        var v = RequireNext(args, ref i, a);
                        o.LlmProvider = LlmProviderFactory.Parse(v);
                        break;
                    }
                case "--azure-endpoint":
                    if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.AzureEndpoint = RequireNext(args, ref i, a);
                    break;
                case "--azure-api-version":
                    if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.AzureApiVersion = RequireNext(args, ref i, a);
                    break;
                case "--azure-deployment":
                    {
                        if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                            throw new ArgumentException($"Unknown argument: {a}");
                        var v = RequireNext(args, ref i, a);
                        var eq = v.IndexOf('=');
                        if (eq <= 0 || eq == v.Length - 1)
                            throw new ArgumentException(
                                $"--azure-deployment must be modelId=deploymentName, got '{v}'.");
                        o.AzureDeploymentMap[v[..eq].Trim()] = v[(eq + 1)..].Trim();
                        break;
                    }
                case "--llamacpp-url":
                    if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                        throw new ArgumentException($"Unknown argument: {a}");
                    o.LlamaCppUrl = RequireNext(args, ref i, a);
                    break;
                case "--llamacpp-model":
                    {
                        if (!o.CtfSolveSubcommand && !o.DoctorSubcommand && !o.UseAgent && !o.UseHybridAgent)
                            throw new ArgumentException($"Unknown argument: {a}");
                        var v = RequireNext(args, ref i, a);
                        var eq = v.IndexOf('=');
                        if (eq < 0)
                        {
                            o.LlamaCppModels[v.Trim()] = v.Trim();
                        }
                        else
                        {
                            if (eq == 0 || eq == v.Length - 1)
                                throw new ArgumentException(
                                    $"--llamacpp-model must be modelId or modelId=modelName, got '{v}'.");
                            o.LlamaCppModels[v[..eq].Trim()] = v[(eq + 1)..].Trim();
                        }
                        break;
                    }
                // --- end jeopardy-llm-provider-flag-parse ---
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

    // --- gap-029 budget tuning helpers ---
    /// <summary>Parse a single integer cap value for <c>--budget-per-tool</c>
    /// / <c>--budget-global</c>. Accepts 0 as "deny-all"; rejects negatives
    /// and non-integer values.</summary>
    private static int ParseBudgetCap(string flag, string value)
    {
        if (!int.TryParse(value, out var n) || n < 0)
            throw new ArgumentException(
                $"{flag} must be a non-negative integer (0 = deny-all), got '{value}'.");
        return n;
    }

    /// <summary>Parse a <c>--budget=tool:N[,tool:N]...</c> spec into the
    /// supplied dictionary, replacing any prior value for repeated tool
    /// keys. Throws <see cref="ArgumentException"/> on malformed input
    /// (missing colon, non-integer N, negative N, empty tool name).</summary>
    private static void ParseBudgetSpec(string spec, Dictionary<string, int> dest)
    {
        if (string.IsNullOrWhiteSpace(spec))
            throw new ArgumentException("--budget requires <tool>:<N>[,<tool>:<N>...] spec, got empty value.");
        foreach (var raw in spec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var colon = raw.IndexOf(':');
            if (colon <= 0 || colon == raw.Length - 1)
                throw new ArgumentException(
                    $"--budget entry must be <tool>:<N>, got '{raw}'.");
            var tool = raw[..colon].Trim();
            var capStr = raw[(colon + 1)..].Trim();
            if (tool.Length == 0)
                throw new ArgumentException($"--budget entry has empty tool name in '{raw}'.");
            if (!int.TryParse(capStr, out var n) || n < 0)
                throw new ArgumentException(
                    $"--budget entry '{raw}' must have a non-negative integer cap (0 = deny-all), got '{capStr}'.");
            dest[tool] = n;
        }
    }
    // --- end gap-029 budget tuning helpers ---

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
          drederick windows-vulns --list [--json]
          drederick windows-vulns --analyze --postex-json <file> [--json]
          drederick web [--web-bind <host>] [--web-port <n>] [--web-token <tok>] [-o <dir>]

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
          windows-vulns        Moriarty-style Windows privesc triage against the
                               bundled offline MSRC corpus (EternalBlue, ZeroLogon,
                               PrintNightmare, HiveNightmare, SMBGhost, ProxyLogon,
                               Log4Shell, Spring4Shell, AFD.sys, CLFS, …). --list
                               prints every CVE; --analyze --postex-json <file>
                               reads a captured PostExWindowsResult JSON and prints
                               prioritised candidates. Read-only, offline, no scope,
                               no subprocess.
          note <op>            Manage operator notes in findings.db
                               (CTF flags, creds, screenshots, observations).
                               Ops: add, list, view, search, flags, archive,
                               delete. Flags: --title, --content, --flag,
                               --tags, --category, --host, --file, --archived,
                               --json. See 'drederick note' (no args) for help.

          web                  Start the Drederick operator web console
                               (REST + SignalR host, default 127.0.0.1:7070).
                               Loopback binds require no auth; non-loopback
                               binds require a bearer token. Token sources
                               (priority): --web-token, $DREDERICK_WEB_TOKEN,
                               auto-generated 32-byte URL-safe random
                               (written to <out>/web-token.txt, mode 0600).
                               Flags: --web-bind <host>, --web-port <int>,
                               --web-token <value>, -o/--out <dir>.

        Jeopardy CTF mode:
          drederick ctf-solve --scope <file> --ctfd <url> [--models <csv>]
                              [--llm-provider auto|copilot|azure|llamacpp|openai]
                              [--azure-endpoint <url>] [--azure-api-version <v>]
                              [--azure-deployment modelId=deploymentName]...
                              [--llamacpp-url <url>] [--llamacpp-model modelId[=modelName]]...
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
          Env: COPILOT_TOKEN (or GH_TOKEN / GITHUB_TOKEN / gh auth login) for copilot,
               AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY (or
               AZURE_OPENAI_BEARER_TOKEN / AZURE_OPENAI_USE_ENTRA=1) for azure,
               LLAMACPP_URL for llamacpp; CTFD_URL, CTFD_TOKEN for the target.
          Default models: claude-opus-4.7,gpt-5.4,gemini-3.1-pro.
          Default inbox: ~/.drederick/jeopardy-inbox.jsonl.

        REQUIRED:
          -s, --scope <file>   Scope file (one CIDR/IP per line, '#' comments).

        TARGETS:
          -t, --target <ip>    Add a target (repeatable). If omitted and --expand
                               is set, the full scope is enumerated.
          --expand             Enumerate all hosts in the scope file.
          --tenable-import <file>
                               Path to a Tenable scan export (Nessus XML .nessus or
                               Tenable CSV). All host IPs found in the file that are
                               inside the scope are added as targets automatically.
                               Service data is pre-seeded into the cross-run knowledge
                               base so the adaptive runner focuses on unexplored surface.
                               IPs outside the scope are logged and skipped.
          --tenable-backend <io|nessus|sc>
                                      Tenable backend dialect. Default 'io'
                                      (Tenable.io cloud). 'nessus' = Nessus
                                      Professional on-prem (same wire protocol
                                      as Tenable.io, default URL
                                      https://localhost:8834, self-signed TLS
                                      tolerated by default). 'sc' = Tenable.sc
                                      / SecurityCenter (REST /rest/scanResult,
                                      ZIP-of-.nessus download, supports either
                                      API-key auth or username+password).
          --tenable-api-url <url>     Tenable management plane URL.
                                      Default https://cloud.tenable.com (io),
                                      https://localhost:8834 (nessus), or
                                      $TENABLE_URL.
          --tenable-access-key <key>  API access key. Env: $TENABLE_ACCESS_KEY.
          --tenable-secret-key <key>  API secret key. Env: $TENABLE_SECRET_KEY.
          --tenable-username <user>   SC username (when API keys are not set).
                                      Env: $TENABLE_USERNAME.
          --tenable-password <pw>     SC password. Env: $TENABLE_PASSWORD.
          --tenable-insecure          Skip TLS server-certificate validation.
                                      Default off for io, on for nessus and sc.
          --tenable-secure            Force TLS verification on (overrides the
                                      default-on behavior for nessus / sc).
          --tenable-scan-id <n>       Pull the export for scan id <n>.
          --tenable-scan-name <name>  Pull the most recently completed scan whose name
                                      matches (case-insensitive).
          --tenable-latest            Pull the most recently completed scan visible
                                      to the API key.
          --tenable-format <fmt>      Export format: nessus (default) or csv.
                                      SC backend supports nessus only.
          --tenable-no-cache          Force a fresh export, bypassing
                                      <out>/tenable_cache/. Cached exports are
                                      keyed by scan id + last_modification_date,
                                      so they automatically refresh when Tenable
                                      reruns the scan.

        RUNNER:
          -a, --agent          Use Microsoft Agent Framework runner (needs
                               OPENAI_API_KEY; model via DREDERICK_MODEL).
                               Default: deterministic AdaptiveRunner.
          --agent=hybrid       Try the LLM runner first; fall back to the
                               deterministic runner on operational failure
                               (no API key, network, auth, rate-limit,
                               transient SDK errors). ScopeException always
                               propagates — never swallowed.
          --agent=llm          Same as --agent (explicit LLM-only).
          --agent=adaptive     Force the deterministic runner.

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
          --briefing <path>    Override briefing.md path (default: dir(scope.yaml)/briefing.md).
                               See machines/SCAFFOLDING/LOADER_SPEC.md.
          --attack-graph <p>   Override attack-graph.yaml path (default: dir(scope.yaml)/attack-graph.yaml).
          --no-scaffolding     Disable scaffolding discovery entirely (CI fuzzing).
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
          --cred-spray-timeout=N
                               Override the per-attempt netexec subprocess timeout, in
                               seconds. Range [1,240]. Default: 60s in strict adaptive
                               mode (--no-lab without --agent), 120s in lab/hybrid/llm
                               mode. The runner adaptively doubles the timeout (up to
                               240s) for any target that has previously timed out, so
                               sluggish endpoints stop eating good punches.
          --replay-timeout=N
                               Override the per-attempt subprocess timeout for every
                               netexec-driven cross-protocol replay adapter
                               (SMB/WinRM/MSSQL/LDAP/SSH/RDP), in seconds. Range
                               [1,240]. Default: 60s in strict adaptive mode (--no-lab
                               without --agent), 120s in lab/hybrid/llm mode. Mirrors
                               --cred-spray-timeout for cross-protocol replay so slow
                               targets don't poison a working credential.
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
