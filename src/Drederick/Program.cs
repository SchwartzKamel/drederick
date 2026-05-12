using Drederick.Agent;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Bundling;
using Drederick.Cli;
using Drederick.Doctor;
using Drederick.Enrichment;
using Drederick.Exploit;
using Drederick.Exploit.Empire;
using Drederick.Memory;
using Drederick.Ops;
using Drederick.Recon;
using Drederick.Recon.Binary;
using Drederick.Reporting;
using Drederick.Scaffolding;
using Drederick.Scope;

CommandLineOptions opts;
try { opts = CommandLineOptions.Parse(args); }
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine();
    Console.Error.WriteLine(CommandLineOptions.HelpText);
    return 2;
}

if (opts.Help)
{
    Console.WriteLine(CommandLineOptions.HelpText);
    return 0;
}

if (opts.DoctorSubcommand)
{
    Directory.CreateDirectory(opts.OutputDir);
    var docAuditPath = Path.Combine(opts.OutputDir, "audit.jsonl");
    using var docAudit = new AuditLog(docAuditPath);

    // --- jeopardy-doctor-wiring ---
    // When --category=jeopardy is passed, run the Jeopardy-specific check
    // suite instead of the legacy tool-detection pass. Each check is an
    // independent IDoctorCheck; none short-circuit their siblings.
    if (string.Equals(opts.DoctorCategory, Drederick.Doctor.JeopardyDoctorChecks.CategoryName, StringComparison.OrdinalIgnoreCase))
    {
        Scope? jeoScope = null;
        try
        {
            if (!string.IsNullOrEmpty(opts.ScopePath) && File.Exists(opts.ScopePath))
            {
                jeoScope = ScopeLoader.LoadFile(opts.ScopePath, allowBroad: opts.AllowBroad, labMode: opts.LabMode);
            }
        }
        catch (ScopeException ex)
        {
            Console.Error.WriteLine($"doctor --category=jeopardy: scope load failed: {ex.Message}");
            // Continue with null scope — scope-dependent checks will warn/fail gracefully.
        }
        var deps = new Drederick.Doctor.JeopardyDoctorDeps(
            Audit: docAudit,
            Runner: new Drederick.Doctor.DefaultProcessRunner(),
            Env: new Drederick.Doctor.ProcessEnvReader(),
            Http: new Drederick.Doctor.DefaultHttpStatusProbe(),
            DiskFree: new Drederick.Doctor.DefaultDiskFreeReader(),
            Scope: jeoScope,
            AllowCopilotHost: opts.AllowCopilotHost,
            LlmProvider: opts.LlmProvider,
            AzureEndpoint: opts.AzureEndpoint,
            LlamaCppUrl: opts.LlamaCppUrl);
        var jeoResults = await Drederick.Doctor.JeopardyDoctorChecks.RunAllAsync(
            deps, install: opts.DoctorInstall, assumeYes: opts.AssumeYes,
            Console.In, Console.Out, CancellationToken.None);
        return jeoResults.Any(r => r.Status == Drederick.Doctor.DoctorCheckStatus.Fail) ? 1 : 0;
    }
    // --- end jeopardy-doctor-wiring ---

    // --- recon-doctor-wiring ---
    // When --category=recon is passed, run the recon-category check suite
    // (currently magika availability). Mirrors jeopardy-doctor-wiring above.
    if (string.Equals(opts.DoctorCategory, Drederick.Doctor.ReconDoctorChecks.CategoryName, StringComparison.OrdinalIgnoreCase))
    {
        var reconResults = await Drederick.Doctor.ReconDoctorChecks.RunAllAsync(
            docAudit,
            new Drederick.Doctor.DefaultProcessRunner(),
            install: opts.DoctorInstall,
            assumeYes: opts.AssumeYes,
            Console.In, Console.Out, CancellationToken.None);
        return reconResults.Any(r => r.Status == Drederick.Doctor.DoctorCheckStatus.Fail) ? 1 : 0;
    }
    // --- end recon-doctor-wiring ---

    var doctor = new DoctorRunner(docAudit);
    var tools = doctor.Detect();
    var pm = PackageManagerDetection.Detect(new PathToolLocator());
    DoctorRunner.PrintReport(tools, pm, Console.Out);
    // Best-effort findings.db upsert (no-op if schema not merged yet).
    var dbPath = Path.Combine(opts.OutputDir, "findings.db");
    if (File.Exists(dbPath)) SqliteToolingSink.TryUpsert(dbPath, tools);
    if (opts.DoctorInstall)
    {
        doctor.Install(tools, pm, opts.AssumeYes, Console.In, Console.Out);
    }
    return 0;
}

// --- init subcommand: first-time setup wizard --------------------------------
if (opts.InitSubcommand)
{
    Directory.CreateDirectory(opts.OutputDir);
    var initAuditPath = Path.Combine(opts.OutputDir, "audit.jsonl");
    using var initAudit = new AuditLog(initAuditPath);
    var initCmd = new InitCommand(Console.In, Console.Out, Console.Error, initAudit);
    return await initCmd.ExecuteAsync(opts);
}
// --- end init subcommand -------------------------------------------------------

// --- datasette-integration: serve subcommand -------------------------------
if (opts.ServeSubcommand)
{
    var dbPath = Path.Combine(opts.OutputDir, "findings.db");
    if (!File.Exists(dbPath))
    {
        Console.Error.WriteLine($"serve: no database at {dbPath}. Run a recon pass first.");
        return 2;
    }
    var metadataPath = Path.Combine("datasette", "metadata.json");
    var datasetteArgs = new List<string>
    {
        "serve", dbPath,
        "--host", opts.ServeHost,
        "--port", opts.ServePort.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };
    if (File.Exists(metadataPath))
    {
        datasetteArgs.Add("--metadata");
        datasetteArgs.Add(metadataPath);
    }
    else
    {
        Console.Error.WriteLine($"serve: warning: {metadataPath} not found; launching datasette without --metadata.");
    }
    if (opts.ServeOpenBrowser) datasetteArgs.Add("--open");

    Directory.CreateDirectory(opts.OutputDir);
    var serveAuditPath = Path.Combine(opts.OutputDir, "audit.jsonl");
    using var serveAudit = new AuditLog(serveAuditPath);

    // ANCHOR: datasette-bootstrap
    string datasetteBinary;
    try
    {
        var home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var cacheDir = Path.Combine(home, ".drederick");
        var bootOpts = new BootstrapOptions(
            ExplicitPath: opts.DatasettePath,
            AutoInstall: !opts.NoAutoInstall,
            AssumeYes: opts.AssumeYes,
            CacheDir: cacheDir);
        datasetteBinary = await DatasetteBootstrap.EnsureAsync(bootOpts, serveAudit, CancellationToken.None);
    }
    catch (DatasetteBootstrapException ex)
    {
        Console.Error.WriteLine($"serve: {ex.Message}");
        return 127;
    }
    // END ANCHOR: datasette-bootstrap

    var psi = new System.Diagnostics.ProcessStartInfo(datasetteBinary)
    {
        UseShellExecute = false,
    };
    foreach (var arg in datasetteArgs) psi.ArgumentList.Add(arg);
    try
    {
        using var proc = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Process.Start returned null.");
        proc.WaitForExit();
        return proc.ExitCode;
    }
    catch (System.ComponentModel.Win32Exception ex)
    {
        Console.Error.WriteLine($"serve: failed to launch datasette at {datasetteBinary}: {ex.Message}");
        return 127;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"serve: failed to launch datasette: {ex.Message}");
        return 1;
    }
}
// --- end datasette-integration ---------------------------------------------

// --- binary-analyzer-wiring: analyze subcommand handler -----------------------
if (opts.AnalyzeSubcommand)
{
    Scope? analyzeScope = null;
    if (!string.IsNullOrEmpty(opts.ScopePath))
    {
        try { analyzeScope = ScopeLoader.LoadFile(opts.ScopePath, allowBroad: opts.AllowBroad, labMode: opts.LabMode); }
        catch (ScopeException ex)
        {
            Console.Error.WriteLine($"scope: {ex.Message}");
            return 2;
        }
    }
    else
    {
        // Create a permissive default scope that allows any file on the local system.
        analyzeScope = new Scope(new List<ScopeEntry>(), "analyze (no scope file; local file access allowed)");
    }

    Directory.CreateDirectory(opts.OutputDir);
    var analyzeAuditPath = Path.Combine(opts.OutputDir, "audit.jsonl");
    using var analyzeAudit = new AuditLog(analyzeAuditPath);

    // ANCHOR: binary-analyzer-wiring
    var analyzer = new BinaryAnalyzer(analyzeScope, analyzeAudit);
    var command = new AnalyzeBinaryCommand(analyzer);
    var exitCode = await command.ExecuteAsync(opts);
    return exitCode;
}
// --- end binary-analyzer-wiring -----------------------------------------------

// --- windows-vulns subcommand wiring ------------------------------------------
if (opts.WindowsVulnsSubcommand)
{
    var winVulnsCmd = new WindowsVulnsCommand(Console.Out, Console.Error);
    return await winVulnsCmd.ExecuteAsync(opts);
}
// --- end windows-vulns subcommand wiring --------------------------------------

// ANCHOR: note-subcommand-wiring
if (!string.IsNullOrEmpty(opts.NoteSubcommand))
{
    var databasePath = Path.Combine(opts.OutputDir, "findings.db");
    var noteCmd = new NoteCommand(databasePath);
    var exitCode = noteCmd.Execute(opts);
    return exitCode;
}
// --- end note-subcommand-wiring -----------------------------------------------

// --- llm-fight-notebook-subcommand-wiring ---
if (!string.IsNullOrEmpty(opts.NotebookSubcommand))
{
    using var notebookCts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; notebookCts.Cancel(); };
    return await Drederick.Learning.Cli.NotebookCommand.RunAsync(opts, notebookCts.Token);
}
// --- end llm-fight-notebook-subcommand-wiring ---

// --- jeopardy-cli-wiring ---
if (opts.CtfSolveSubcommand)
{
    using var jeoCts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; jeoCts.Cancel(); };
    return await Drederick.Jeopardy.Cli.CtfSolveRunner.RunAsync(opts, jeoCts.Token);
}
if (opts.CtfMsgSubcommand)
{
    using var msgCts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; msgCts.Cancel(); };
    return await Drederick.Jeopardy.Cli.CtfMsgRunner.RunAsync(opts, msgCts.Token);
}
// --- end jeopardy-cli-wiring ---

// --- web-cli-wiring ---
// Dispatch `drederick web` to the standalone drederick-web binary produced
// by src/Drederick.Web/. Out-of-process dispatch (same pattern as
// `drederick serve` → datasette) keeps the project reference graph acyclic:
// Drederick.Web already references Drederick for AuditLog / Scope types, so
// a reverse project reference would be a build cycle. The web binary
// inherits the same invariant posture — it opens its own AuditLog in
// <out>/audit.jsonl and enforces the bearer-token / loopback rules at its
// middleware boundary.
if (opts.WebSubcommand)
{
    Directory.CreateDirectory(opts.OutputDir);
    var webAuditPath = Path.Combine(opts.OutputDir, "audit.jsonl");
    using var webAudit = new AuditLog(webAuditPath);

    var webArgs = new List<string>
    {
        "--web-bind", opts.WebBind,
        "--web-port", opts.WebPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "--out", opts.OutputDir,
    };
    if (!string.IsNullOrEmpty(opts.WebToken))
    {
        webArgs.Add("--web-token");
        webArgs.Add(opts.WebToken);
    }

    // Resolve drederick-web binary. Order: (1) PATH, (2) alongside the
    // running drederick executable, (3) dev-tree fallback via `dotnet run`.
    string? webBinary = null;
    var onPath = Environment.GetEnvironmentVariable("PATH")?.Split(Path.PathSeparator) ?? Array.Empty<string>();
    foreach (var dir in onPath)
    {
        if (string.IsNullOrEmpty(dir)) continue;
        foreach (var exe in new[] { "drederick-web", "drederick-web.exe" })
        {
            var candidate = Path.Combine(dir, exe);
            if (File.Exists(candidate)) { webBinary = candidate; break; }
        }
        if (webBinary is not null) break;
    }
    if (webBinary is null)
    {
        var self = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(self))
        {
            var selfDir = Path.GetDirectoryName(self);
            if (!string.IsNullOrEmpty(selfDir))
            {
                foreach (var exe in new[] { "drederick-web", "drederick-web.exe" })
                {
                    var candidate = Path.Combine(selfDir, exe);
                    if (File.Exists(candidate)) { webBinary = candidate; break; }
                }
            }
        }
    }

    webAudit.Record("web.cli.dispatch", new Dictionary<string, object?>
    {
        ["bind"] = opts.WebBind,
        ["port"] = opts.WebPort,
        ["binary"] = webBinary ?? "dotnet-run-fallback",
    });

    System.Diagnostics.ProcessStartInfo psi;
    if (webBinary is not null)
    {
        psi = new System.Diagnostics.ProcessStartInfo(webBinary) { UseShellExecute = false };
        foreach (var arg in webArgs) psi.ArgumentList.Add(arg);
    }
    else
    {
        // Dev fallback: `dotnet run --project src/Drederick.Web` from the
        // repo root. Fails cleanly if we're not in the dev tree.
        var projectPath = Path.Combine("src", "Drederick.Web", "Drederick.Web.csproj");
        if (!File.Exists(projectPath))
        {
            Console.Error.WriteLine(
                "drederick web: could not locate the drederick-web binary on PATH or alongside " +
                "the drederick executable, and no dev-tree project found at " +
                $"{projectPath}. Install drederick-web (see docs) or run from the repo root.");
            return 127;
        }
        psi = new System.Diagnostics.ProcessStartInfo("dotnet") { UseShellExecute = false };
        psi.ArgumentList.Add("run");
        psi.ArgumentList.Add("--project");
        psi.ArgumentList.Add(projectPath);
        psi.ArgumentList.Add("--");
        foreach (var arg in webArgs) psi.ArgumentList.Add(arg);
    }

    try
    {
        using var proc = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Process.Start returned null.");
        proc.WaitForExit();
        return proc.ExitCode;
    }
    catch (System.ComponentModel.Win32Exception ex)
    {
        Console.Error.WriteLine($"drederick web: failed to launch {webBinary ?? "dotnet"}: {ex.Message}");
        return 127;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"drederick web: launch failed: {ex.Message}");
        return 1;
    }
}
// --- end web-cli-wiring ---

if (string.IsNullOrEmpty(opts.ScopePath))
{
    Console.Error.WriteLine("--scope is required.");
    Console.Error.WriteLine();
    Console.Error.WriteLine(CommandLineOptions.HelpText);
    return 2;
}

Scope scope;
try { scope = ScopeLoader.LoadFile(opts.ScopePath, allowBroad: opts.AllowBroad, labMode: opts.LabMode); }
catch (ScopeException ex)
{
    Console.Error.WriteLine($"scope: {ex.Message}");
    return 2;
}

// --- tenable-api-pull ---
// "Smart" Tenable API pulling against any of three backends: Tenable.io
// (cloud), Nessus Professional (on-prem, same wire protocol), or Tenable.sc /
// SecurityCenter (REST /rest/scanResult). Picks the right client from
// --tenable-backend, authenticates, selects the scan, polls until ready,
// caches the bytes under <out>/tenable_cache/, and feeds the path into the
// existing file-based ingest path below.
if (string.IsNullOrEmpty(opts.TenableImportPath) &&
    (opts.TenableScanId.HasValue || !string.IsNullOrEmpty(opts.TenableScanName) || opts.TenableLatest))
{
    var backend = (opts.TenableBackend ?? "io").ToLowerInvariant();
    var defaultUrl = backend switch
    {
        "nessus" => "https://localhost:8834",
        "sc" => "https://localhost",
        _ => "https://cloud.tenable.com",
    };
    var apiUrl = opts.TenableApiUrl
        ?? Environment.GetEnvironmentVariable("TENABLE_URL")
        ?? defaultUrl;
    var accessKey = opts.TenableAccessKey ?? Environment.GetEnvironmentVariable("TENABLE_ACCESS_KEY");
    var secretKey = opts.TenableSecretKey ?? Environment.GetEnvironmentVariable("TENABLE_SECRET_KEY");
    var username = opts.TenableUsername ?? Environment.GetEnvironmentVariable("TENABLE_USERNAME");
    var password = opts.TenablePassword ?? Environment.GetEnvironmentVariable("TENABLE_PASSWORD");

    // Default-on insecure TLS for on-prem backends (self-signed certs); off for cloud.
    var insecure = opts.TenableInsecureTls ?? (backend == "nessus" || backend == "sc");

    Directory.CreateDirectory(opts.OutputDir);
    var pullAuditPath = Path.Combine(opts.OutputDir, "audit.jsonl");
    using var pullAudit = new AuditLog(pullAuditPath);

    var selector = new Drederick.Ops.Tenable.TenableScanSelector
    {
        ScanId = opts.TenableScanId,
        ScanName = opts.TenableScanName,
        Latest = opts.TenableLatest,
    };
    var pullOpts = new Drederick.Ops.Tenable.TenableApiPullOptions
    {
        Format = opts.TenableFormat,
        CacheRoot = Path.Combine(opts.OutputDir, "tenable_cache"),
        NoCache = opts.TenableNoCache,
    };

    try
    {
        Drederick.Ops.Tenable.ITenableExportBackend client;
        switch (backend)
        {
            case "io":
                if (string.IsNullOrEmpty(accessKey) || string.IsNullOrEmpty(secretKey))
                {
                    Console.Error.WriteLine(
                        "tenable-api (io): --tenable-access-key and --tenable-secret-key " +
                        "(or $TENABLE_ACCESS_KEY / $TENABLE_SECRET_KEY) are required.");
                    return 2;
                }
                client = new Drederick.Ops.Tenable.TenableApiClient(
                    apiUrl, accessKey, secretKey, insecureTls: insecure);
                break;
            case "nessus":
                if (string.IsNullOrEmpty(accessKey) || string.IsNullOrEmpty(secretKey))
                {
                    Console.Error.WriteLine(
                        "tenable-api (nessus): --tenable-access-key and --tenable-secret-key " +
                        "(or $TENABLE_ACCESS_KEY / $TENABLE_SECRET_KEY) are required. " +
                        "Generate them in the Nessus UI under Settings → My Account → API Keys.");
                    return 2;
                }
                client = Drederick.Ops.Tenable.TenableApiClient.ForNessusProfessional(
                    apiUrl, accessKey, secretKey, insecureTls: insecure);
                break;
            case "sc":
                if (!string.IsNullOrEmpty(accessKey) && !string.IsNullOrEmpty(secretKey))
                {
                    client = Drederick.Ops.Tenable.TenableScClient.WithApiKey(
                        apiUrl, accessKey, secretKey, insecureTls: insecure);
                }
                else if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    client = Drederick.Ops.Tenable.TenableScClient.WithUserPass(
                        apiUrl, username, password, insecureTls: insecure);
                }
                else
                {
                    Console.Error.WriteLine(
                        "tenable-api (sc): provide either --tenable-access-key + --tenable-secret-key " +
                        "or --tenable-username + --tenable-password (env: $TENABLE_ACCESS_KEY/$TENABLE_SECRET_KEY " +
                        "or $TENABLE_USERNAME/$TENABLE_PASSWORD).");
                    return 2;
                }
                break;
            default:
                Console.Error.WriteLine($"tenable-api: unknown backend '{backend}'.");
                return 2;
        }

        using (client)
        {
            var puller = new Drederick.Ops.Tenable.TenableApiPuller(client, pullAudit);
            var pullResult = await puller.PullAsync(selector, pullOpts);
            Console.WriteLine(
                $"tenable-api ({client.BackendName}): pulled scan {pullResult.ScanId} " +
                $"('{pullResult.ScanName}') format={pullResult.Format} " +
                $"from-cache={pullResult.FromCache} → {pullResult.CachedPath}");
            opts.TenableImportPath = pullResult.CachedPath;
        }
    }
    catch (Drederick.Ops.Tenable.TenableApiException ex)
    {
        Console.Error.WriteLine($"tenable-api: {ex.Message}");
        return 2;
    }
    catch (HttpRequestException ex)
    {
        Console.Error.WriteLine($"tenable-api: network error: {ex.Message}");
        return 2;
    }
}
// --- end tenable-api-pull ---

// --- tenable-import-prefill ---
// Parse the Tenable export early so its IPs can flow into the targets block
// below. Out-of-scope hosts are collected for later audit/warning output.
TenableImportResult? tenableResult = null;
var tenableOutOfScope = new List<string>();
if (!string.IsNullOrEmpty(opts.TenableImportPath))
{
    try
    {
        tenableResult = TenableScanImporter.Parse(opts.TenableImportPath);
        foreach (var ip in tenableResult.Hosts)
        {
            if (scope.Contains(ip))
            {
                if (!opts.Targets.Contains(ip, StringComparer.OrdinalIgnoreCase))
                    opts.Targets.Add(ip);
            }
            else
            {
                tenableOutOfScope.Add(ip);
            }
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"tenable-import: failed to parse '{opts.TenableImportPath}': {ex.Message}");
        return 2;
    }
}
// --- end tenable-import-prefill ---

List<string> targets;
if (opts.Targets.Count > 0)
{
    // Every explicit target must be inside the scope.
    foreach (var t in opts.Targets)
    {
        if (!scope.Contains(t))
        {
            Console.Error.WriteLine($"target {t} is not in scope {scope.Source}. Refusing.");
            return 2;
        }
    }
    targets = new List<string>(opts.Targets);
}
else if (opts.Expand)
{
    try { targets = scope.Expand().ToList(); }
    catch (ScopeException ex)
    {
        Console.Error.WriteLine($"scope: {ex.Message}");
        return 2;
    }
}
else
{
    Console.Error.WriteLine("No targets. Pass --target one or more times, or --expand to enumerate the scope.");
    return 2;
}

// --- locker collision (GAP-045) ---
// Refuse to reuse a non-empty locker unless --allow-locker-collision.
{
    var lockerExit = LockerCollisionGuard.Apply(opts.OutputDir, opts.AllowLockerCollision, Console.Error);
    if (lockerExit is int code) return code;
}
// --- end locker collision ---

Directory.CreateDirectory(opts.OutputDir);
var auditPath = Path.Combine(opts.OutputDir, "audit.jsonl");
using var audit = new AuditLog(auditPath);
audit.Record("session.start", new Dictionary<string, object?>
{
    ["scope_source"] = scope.Source,
    ["target_count"] = targets.Count,
    ["runner"] = opts.UseAgent ? "agent" : "adaptive",
    ["lab_mode"] = opts.LabMode,
});

// --- learning -----------------------------------------------------------
// Read-only access to the operator-curated fight corpus
// (~/HTB/fight-log.yaml). Discovery precedence: --fight-corpus > env
// DREDERICK_FIGHT_CORPUS > ~/HTB/fight-log.yaml > graceful no-op.
// Schema mismatch is fatal (exit code 4); a missing file is INFO-only.
{
    var fightCorpus = new Drederick.Learning.FightCorpus(opts.FightCorpusPath, audit);
    try
    {
        var log = await fightCorpus.LoadAsync();
        audit.Record("learning.fight_corpus.loaded", new Dictionary<string, object?>
        {
            ["path"] = fightCorpus.ResolvedPath,
            ["fight_count"] = log.Fights.Count,
            ["schema_version"] = log.SchemaVersion,
        });
    }
    catch (Drederick.Learning.FightCorpusSchemaException ex)
    {
        audit.Record("learning.fight_corpus.error", new Dictionary<string, object?>
        {
            ["path"] = ex.CorpusPath,
            ["found_version"] = ex.FoundVersion,
            ["expected_version"] = ex.ExpectedVersion,
            ["message"] = ex.Message,
        });
        Console.Error.WriteLine(ex.Message);
        return 4;
    }
}
// --- end learning -------------------------------------------------------

// --- in-fight scaffolding (LOADER_SPEC) --------------------------------
// Discover briefing.md / attack-graph.yaml relative to dir(scope.yaml),
// honoring --briefing / --attack-graph overrides. Emits the audit-event
// vocabulary defined in machines/SCAFFOLDING/LOADER_SPEC.md §3.
var scaffolding = ScaffoldingDiscovery.Load(
    opts.ScopePath!,
    opts.BriefingPath,
    opts.AttackGraphPath,
    opts.NoScaffolding,
    audit);
// --- end scaffolding ---------------------------------------------------

Console.WriteLine(opts.LabMode
    ? "drederick: lab/CTF mode ENABLED (default). Authorized lab/CTF targets only."
    : "drederick: strict mode. Lab-mode affordances disabled.");

// Implicit preflight: detect operator tooling and print a one-line summary.
// Report-only; never prompts or installs during a recon run.
{
    var preDoctor = new DoctorRunner(audit);
    var preTools = preDoctor.Detect();
    var prePm = PackageManagerDetection.Detect(new PathToolLocator());
    var missing = preTools.Where(t => !t.Found).Select(t => t.Name).ToList();
    if (missing.Count == 0)
    {
        Console.WriteLine($"preflight: all tooling present (pm={PackageManagerDetection.DisplayName(prePm)}).");
    }
    else
    {
        Console.WriteLine($"preflight: missing {string.Join(", ", missing)} — run `drederick doctor --install` to fix.");
    }
}

var kb = KnowledgeBase.Load(opts.MemoryPath);

// --- tenable-import-wiring ---
// Log the import outcome and seed the knowledge base with service data so the
// adaptive runner can treat Tenable-known ports as pre-discovered rather than
// re-scanning them from scratch on the first pass.
if (tenableResult is not null)
{
    int inScopeCount = tenableResult.Hosts.Count - tenableOutOfScope.Count;
    audit.Record("tenable.import", new Dictionary<string, object?>
    {
        ["source"] = opts.TenableImportPath,
        ["format"] = tenableResult.Format,
        ["host_count"] = tenableResult.Hosts.Count,
        ["in_scope_count"] = inScopeCount,
        ["skipped_count"] = tenableOutOfScope.Count,
    });
    foreach (var ip in tenableOutOfScope)
    {
        Console.Error.WriteLine($"tenable-import: {ip} is not in scope — skipping.");
        audit.Record("tenable.import.out_of_scope", new Dictionary<string, object?> { ["ip"] = ip });
    }
    Console.WriteLine(
        $"tenable-import: {tenableResult.Hosts.Count} host(s) in '{opts.TenableImportPath}' " +
        $"— {inScopeCount} in scope, {tenableOutOfScope.Count} skipped.");
    var tenableFindings = TenableScanImporter.ToHostFindings(tenableResult);
    kb.Merge(tenableFindings);
}
// --- end tenable-import-wiring ---

// ANCHOR: vpn-preflight (owned by vpn-htb-ergonomics task)
// Before queueing any scan jobs: resolve --htb-host aliases via /etc/hosts,
// then decide whether any target sits in a known HTB CIDR. If so, probe for
// an active tun*/tap* VPN and warn (or abort with --require-vpn) when the
// tunnel is down. Always records the outcome to audit + findings.db tooling.
foreach (var htbHost in opts.HtbHosts)
{
    var resolved = HtbRanges.TryResolve(htbHost);
    if (resolved is null)
    {
        Console.Error.WriteLine($"--htb-host {htbHost}: could not resolve via /etc/hosts or DNS; skipping.");
        audit.Record("vpn.htb_host.unresolved", new Dictionary<string, object?> { ["host"] = htbHost });
        continue;
    }
    var resolvedStr = resolved.ToString();
    // GAP-044: source attribution — /etc/hosts wins over DNS so the
    // post-fight reviewer can tell which path produced the address.
    var source = HtbRanges.LookupHostsFile(htbHost, "/etc/hosts") is not null
        ? "/etc/hosts"
        : "dns";
    // GAP-044: scope is authoritative. If the resolved IP is outside the
    // scope.yaml allowlist, emit out_of_scope and DROP — never fall back
    // to 127.0.0.1 (LOADER_SPEC §3.4 forbidden event).
    if (!scope.Contains(resolvedStr))
    {
        Console.Error.WriteLine($"--htb-host {htbHost}: resolved {resolvedStr} is outside scope; dropping.");
        audit.Record("vpn.htb_host.out_of_scope", new Dictionary<string, object?>
        {
            ["name"] = htbHost,
            ["resolved_ip"] = resolvedStr,
            ["reason"] = "not_in_scope",
        });
        continue;
    }
    if (!targets.Contains(resolvedStr, StringComparer.OrdinalIgnoreCase))
    {
        targets.Add(resolvedStr);
    }
    audit.Record("vpn.htb_host.resolved", new Dictionary<string, object?>
    {
        ["host"] = htbHost,
        ["name"] = htbHost,
        ["ip"] = resolvedStr,
        ["source"] = source,
    });
}
{
    var vpnReport = new SqliteReport(opts.OutputDir);
    var vpnOutcome = VpnPreflight.Run(
        new VpnPreflight.Options(targets, opts.RequireVpn, opts.SkipVpnCheck),
        audit,
        vpnReport,
        Console.Error);
    if (vpnOutcome == VpnPreflightOutcome.AbortNoVpn)
    {
        Console.Error.WriteLine("vpn-preflight: --require-vpn is set and no tun* interface is up. Aborting.");
        return 3;
    }
}
// END ANCHOR: vpn-preflight

// --- run permissions -------------------------------------------------------
// Built up front so both the recon toolbox (NSE category selection) and the
// exploit toolbox can share the same opt-in record.
//
// Default posture: in lab/CTF mode (the default), every exploit category
// EXCEPT --allow-dos is ON by default, matching the "maximum capability inside
// scope" directive. Credential attacks additionally require the explicit
// lockout-risk acknowledgement. Strict mode (--no-lab) flips everything OFF
// and forces the operator to opt into each category individually.
//
// Explicit flags always win: passing --allow-dos in lab mode enables DoS;
// passing --no-lab disables every category, and the operator can re-enable
// specific ones with --allow-exec-pocs / --allow-cred-attacks / etc.
var permissions = new RunPermissions(
    allowExecPocs: opts.AllowExecPocs || opts.LabMode,
    allowCredAttacks: opts.AllowCredAttacks || opts.LabMode,
    allowPayloads: opts.AllowPayloads || opts.LabMode,
    allowDestructive: opts.AllowDestructive || opts.LabMode,
    allowDos: opts.AllowDos,
    acknowledgeLockoutRisk: opts.AcknowledgeLockoutRisk,
    allowPhishing: opts.AllowPhishing,
    allowSmtpRelay: opts.AllowSmtpRelay,
    allowExecShell: opts.AllowExecShell,
    allowExecShellBash: opts.AllowExecShellBash,
    allowCveLeadLlmAuthor: opts.AllowCveLeadLlmAuthor || opts.LabMode,
    // GAP-043: AD attack family (AS-REP roast, kerberoast, WinRM auth,
    // NTDS dump). Default-on in lab mode; strict mode requires
    // --allow-ad-attacks. --no-allow-ad-attacks lets an operator
    // disable the family even inside lab.
    allowAdAttacks: opts.AllowAdAttacksExplicit ?? (opts.AllowAdAttacks || opts.LabMode));

var nmap = new NmapTool(scope, audit, labMode: opts.LabMode, permissions: permissions,
    // --- htb-crash-resilient-nmap --- (GAP-053)
    allowFallbackConnect: opts.AllowFallbackConnect);
    // --- end htb-crash-resilient-nmap ---
var http = new HttpProbeTool(scope, audit);
var tls = new TlsProbeTool(scope, audit);
var dns = new DnsProbeTool(scope, audit);
var smb = new SmbTool(scope, audit);
var ftp = new FtpTool(scope, audit);
var ssh = new SshTool(scope, audit);
var snmp = new SnmpTool(scope, audit);
var ldap = new LdapTool(scope, audit);
var rpc = new RpcTool(scope, audit);
var kerberos = new KerberosTool(scope, audit);
var dnsAxfr = new DnsZoneTransferTool(scope, audit);
var httpContentDiscovery = new HttpContentDiscoveryTool(scope, audit);
var tlsCipherEnum = new TlsCipherEnumTool(scope, audit);
// --- recon tools ---
var nativeScanner = new NativeScannerTool(scope, audit);
var nativeDns = new NativeDnsTool(scope, audit);
var fingerprintStack = new Drederick.Enrichment.FingerprintStack.FingerprintStackTool(scope, audit);
var nseProxy = new NseProxy(scope, audit, labMode: opts.LabMode, permissions: permissions);
// --- s3 minio probe (gap-037) ---
var s3Probe = new S3MinioProbeTool(scope, audit);
// --- cms fingerprint (gap-036) ---
var cmsFingerprint = new CmsFingerprintTool(scope, audit);
// --- smb null-session + anon ldap (gap-042) ---
// Wire the production SMBLibrary + Novell.Directory.Ldap backends.
// Each EnumerateAsync call gets a fresh backend (factory pattern) so
// concurrent host fan-out does not share connection state.
var smbNullSession = new Drederick.Recon.Ad.SmbNullSessionTool(
    scope,
    audit,
    dnsResolver: null,
    smbBackendFactory: () => new Drederick.Recon.Ad.SmbLibraryBackend(
        scope, audit, samr: new Drederick.Recon.Ad.SmbSamrEnumerator(scope, audit)),
    ldapBackendFactory: () => new Drederick.Recon.Ad.SmbLibraryLdapBackend(scope, audit),
    connectTimeout: TimeSpan.FromSeconds(10));
// --- htb-smtp-enum --- (GAP-011)
var smtpEnum = new SmtpEnumTool(scope, audit);
// --- end htb-smtp-enum ---
// --- htb-nfs-enum --- (GAP-007)
// Anonymous write probe is technically a write to the target; default on
// in lab mode, gated by --allow-destructive in strict mode.
var nfsEnum = new NfsEnumTool(scope, audit,
    allowWriteProbe: opts.LabMode || opts.AllowDestructive);
// --- end htb-nfs-enum ---
// --- htb-locale-lfi-probe --- (GAP-035)
var localeLfi = new Drederick.Recon.Http.LocaleLfiProbe(scope, audit);
// --- end htb-locale-lfi-probe ---

// --- htb-cloud-storage-enum --- (GAP-018)
var cloudStorage = new CloudStorageEnumTool(scope, audit, opts.OutputDir);
// --- end htb-cloud-storage-enum ---

// --- gap-029 budget construction ---
// LLM-driven runs need substantially more headroom than deterministic
// passes (R5 JobTwo loss: planner starved on http=3 / nmap=3 after 17
// HTTP probes). Pick the mode-aware default, then apply per-flag CLI
// overrides on top. The budget is a runaway-loop rate-limit; scope is
// enforced inside every tool so adjusting caps does not weaken
// authorization.
var reconBudgetBase = opts.UseAgent
    ? Drederick.Recon.ToolBudget.LlmDefault
    : Drederick.Recon.ToolBudget.Default;
var reconBudget = new Drederick.Recon.ToolBudget(
    PerTargetPerTool: opts.BudgetPerTool ?? reconBudgetBase.PerTargetPerTool,
    MaxTotalCalls: opts.BudgetGlobal ?? reconBudgetBase.MaxTotalCalls)
{
    PerToolOverrides = opts.BudgetPerToolOverrides.Count > 0
        ? new Dictionary<string, int>(opts.BudgetPerToolOverrides)
        : null,
};
audit.Record("budget.config", new Dictionary<string, object?>
{
    ["domain"] = "recon",
    ["per_tool"] = reconBudget.PerTargetPerTool,
    ["global"] = reconBudget.MaxTotalCalls,
    ["overrides"] = opts.BudgetPerToolOverrides.Count > 0
        ? (object)opts.BudgetPerToolOverrides
        : null,
    ["agent_mode"] = opts.UseAgent ? (opts.UseHybridAgent ? "hybrid" : "llm") : "adaptive",
});
// --- end gap-029 budget construction ---

var toolbox = new ReconToolbox(
    new IReconTool[]
    {
        nmap, http, tls, dns,
        smb, ftp, ssh, snmp, ldap, rpc, kerberos,
        dnsAxfr, httpContentDiscovery, tlsCipherEnum,
        nativeScanner, nativeDns,
        fingerprintStack,
        nseProxy,
        s3Probe,
        cmsFingerprint,
        smbNullSession,
        // --- htb-smtp-enum ---
        smtpEnum,
        // --- end htb-smtp-enum ---
        // --- htb-nfs-enum ---
        nfsEnum,
        // --- end htb-nfs-enum ---
        // --- htb-locale-lfi-probe ---
        localeLfi,
        // --- end htb-locale-lfi-probe ---
        // --- htb-cloud-storage-enum --- (GAP-018)
        cloudStorage,
        // --- end htb-cloud-storage-enum ---
    },
    audit,
    reconBudget);
toolbox.SeedFromKnowledgeBase(kb, targets);

// --- empire c2 ---
// Empire C2 integration for post-exploitation orchestration.
var sessionAgentMapper = new SessionAgentMapper();
var empireModuleLibrary = new EmpireModuleLibrary(audit);
// --- end empire c2 ---

// --- exploit tools ---
// Offensive weapons are registered here. Every tool re-checks scope AND the
// per-run opt-in category on its own entry point — the toolbox is a registry,
// not the authorization boundary. Permissions are built above (shared with
// the recon toolbox for NSE category selection).
var exploitRunner = new ExploitRunner(scope, audit, opts.OutputDir);
var nuclei = new NucleiRunner(scope, audit, permissions, exploitRunner);
var msf = new MsfRcRunner(scope, audit, permissions, exploitRunner);
var spray = new PasswordSprayTool(
    scope, audit, permissions, exploitRunner,
    timeoutSeconds: PasswordSprayTool.ResolveDefaultTimeoutSeconds(
        labMode: opts.LabMode,
        useAgent: opts.UseAgent,
        explicitOverride: opts.CredSprayTimeoutSeconds));
var httpSpray = new NativeHttpSprayTool(
    scope, audit, permissions,
    timeoutSeconds: PasswordSprayTool.ResolveDefaultTimeoutSeconds(
        labMode: opts.LabMode,
        useAgent: opts.UseAgent,
        explicitOverride: opts.CredSprayTimeoutSeconds));
// GAP-038: auto-credential pillage from captured DBs (SQLite/MySQL).
// Reads embedded YAML corpus; pushes findings into CredentialStore.
var dbPillage = new Drederick.Exploit.PostEx.DbPillageTool(
    scope, audit, permissions, opts.OutputDir, credentialStore: null);

// GAP-039: SSH key brute — captured-key (key, user, host) attempts.
// Pushes successful auths into CredentialStore as ssh-key:<digest>.
var sshKeyBrute = new Drederick.Exploit.PostEx.SshKeyBruteTool(
    scope, audit, permissions, opts.OutputDir, credentialStore: null);

// gap-039-passphrase-brute: offline passphrase brute against a captured
// encrypted SSH private key. Sibling to sshKeyBrute (which sprays an
// already-decrypted key). Cracked passphrase pushes into CredentialStore
// as (user="ssh-key:<fingerprint>", realm=hostHint).
var sshKeyPassphraseBrute = new Drederick.Exploit.PostEx.SshKeyPassphraseBruteTool(
    scope, audit, permissions, credentialStore: null);

// GAP-040: sudo -l + GTFOBins one-shot privesc on a captured-key SSH
// foothold. Two-phase: enumerate then optionally auto-execute the safe
// variant of each match. Destructive candidates require
// --allow-destructive on top of --allow-exec-pocs.
var sudoGtfoBins = new Drederick.Exploit.PostEx.SudoGtfoBinsTool(
    scope, audit, permissions, opts.OutputDir, credentialStore: null);

// GAP-046: WinRM Windows post-ex. Authenticated WinRM/PSRP enumeration
// against scope-resolved Windows hosts using captured Windows creds
// (password, NT hash for PtH, or Kerberos ticket). Runs an embedded
// 20+ entry enumeration corpus; pushes structured findings (local
// users, admin group members, network interfaces, SeImpersonate
// privesc candidates) onto WinRmPostExResult. Master gate is
// ExploitCategory.ExecPocs (--allow-exec-pocs); CredAttacks is
// intentionally NOT required because we authenticate once with
// known-good material rather than spraying. v1 transport is the
// subprocess-wrap path via EvilWinrmSubprocessExecutor (Auto: probes
// evil-winrm first for PtH support, falls back to pwsh Invoke-Command
// for password-only credentials). KRB5/SSH/SUDO env vars are stripped
// from the spawned subprocess; argv assembled via ArgumentList (no
// shell); per-command timeout 60s with process-tree kill on cancel.
var winrmExecutor = new Drederick.Exploit.PostEx.EvilWinrmSubprocessExecutor(
    Drederick.Exploit.PostEx.EvilWinrmSubprocessExecutor.BackendStrategy.Auto,
    workdirRoot: opts.OutputDir);
var winrmPostEx = new Drederick.Exploit.PostEx.WinRmPostExTool(
    scope, audit, permissions, winrmExecutor);

// --- htb-loot-collector ---
// GAP-004: PostExLootTool — walks a live session foothold for curated
// high-value credential / secret paths (LootCatalog corpus, embedded
// from data/postex-loot-paths.json). Plaintext never logged; SHA-256
// only into audit + SQLite. ISessionExecutor is unwired here (Program
// has no live SessionManager-driven session abstraction yet); LLM /
// future AutopilotRunner hook will inject the live executor at call
// time. Registers as a normal IExploitTool so the LlmExploitTools
// surface can list it. Master gate is ExploitCategory.ExecPocs.
var lootExecutor = new Drederick.Exploit.PostEx.UnwiredSessionExecutor();
var postExLoot = new Drederick.Exploit.PostEx.PostExLootTool(
    scope, audit, permissions, lootExecutor, opts.OutputDir);
// --- end htb-loot-collector ---

// GAP-041: HTTP form-brute primitive that drives the cms_chain
// cred_runner action (default-creds against WP/Drupal/Joomla/etc).
// Master gate: ExploitCategory.CredAttacks; AcknowledgeLockoutRisk
// required when users*passwords > 50. CredentialStore is wired up
// later (autopilot constructs it); the toolbox surface here registers
// without one and the autopilot/CmsChainExecutor path re-instantiates
// with the live store.
var httpFormBrute = new Drederick.Exploit.Web.HttpFormBruteTool(
    scope, audit, permissions, credentialStore: null);
_ = httpFormBrute; // exposed via CmsChainExecutor; LLM surface lands in a follow-up.

// --- replay-timeout config (cross-protocol replay) ---
// CrossProtocolReplay isn't constructed here yet — it's built ad-hoc by
// callers via CrossProtocolReplay.BuildDefault(...) — but we resolve the
// mode-aware default and audit it so the operator can see the figure
// that future replay calls will use, and so the --replay-timeout flag
// has an observable effect even before replay is wired into the main
// pipeline. Mirrors the cred-spray-timeout pattern from 95a328d.
var replayTimeoutSeconds = Drederick.Exploit.Replay.CrossProtocolReplay.ResolveDefaultTimeoutSeconds(
    labMode: opts.LabMode,
    useAgent: opts.UseAgent,
    explicitOverride: opts.ReplayTimeoutSeconds);
audit.Record("replay.config", new Dictionary<string, object?>
{
    ["timeout_seconds"] = replayTimeoutSeconds,
    ["explicit_override"] = opts.ReplayTimeoutSeconds,
    ["mode"] = opts.UseAgent ? (opts.UseHybridAgent ? "hybrid" : "llm") : (opts.LabMode ? "lab" : "adaptive"),
});
// --- end replay-timeout config ---

// Empire tools
var empireStager = new EmpireAgentStager(scope, audit);
var empireExecutor = new EmpireModuleExecutor(scope, audit, empireModuleLibrary);

// GAP-043: AS-REP roasting (managed Kerberos.NET, no impacket subprocess).
// Master gate: ExploitCategory.AsRepRoast → RunPermissions.AllowAdAttacks.
// CredentialStore is wired up later (after autopilot constructs it); for
// the toolbox surface here we omit it — the LLM/AdaptiveRunner path
// captures hashes on the returned AsRepRoastResult and the Autopilot
// runner re-instantiates the tool with the live store.
var asRepRoast = new Drederick.Exploit.Ad.AsRepRoastTool(
    scope, audit, permissions, credentialStore: null);

// GAP-044: Kerberoasting (authenticated AD service-ticket roast).
// Sibling to gap-043 AsRepRoastTool. Master gate:
// ExploitCategory.AsRepRoast → RunPermissions.AllowAdAttacks. The
// production IKerberoastEngine + ILdapDirectory wire-up lands in a
// follow-up; here we register the tool with no directory so the
// LLM/AdaptiveRunner surface still advertises the capability while
// returning a structured "no_ldap_directory" short-circuit until the
// engine is wired.
var kerberoast = new Drederick.Exploit.Ad.KerberoastTool(
    scope, audit, permissions, credentialStore: null);

// GAP-047: Windows credential dump (SAM + LSA + NTDS) via impacket-secretsdump.
// Three modes: Remote (SAM+LSA over SMB), RemoteDcSync (NTDS via DRSUAPI),
// LocalHives (offline parse from extracted SYSTEM/SAM/NTDS files). Master
// gate ExploitCategory.CredAttacks; DCSync mode additionally requires
// AllowDestructive (Event 4662 / Defender ATA noise). Harvested NT hashes
// land in CredentialStore as ntlm-hash for chain-reuse PtH; cleartext
// service-account passwords from LSA land as cleartext-password-from-lsa.
var ntdsSamDump = new Drederick.Exploit.PostEx.Windows.NtdsSamDumpTool(
    scope, audit, permissions, opts.OutputDir, credentialStore: null);

// ZeroLogon (CVE-2020-1472): native C# Netlogon auth bypass for DC compromise.
// Exploits AES-CFB8 IV reuse to set DC machine password to empty, then optionally
// extracts domain credentials via secretsdump. Requires BOTH --allow-cred-attacks
// AND --allow-destructive (modifies DC state, breaks replication until restored).
// Lab/CTF use only. Master gates: CredAttacks + Destructive.
var zeroLogon = new ZeroLogonTool(scope, audit, permissions, exploitRunner);

var exploitBudgetBase = opts.UseAgent
    ? Drederick.Exploit.ToolBudget.LlmDefault
    : Drederick.Exploit.ToolBudget.Default;
var exploitBudget = new Drederick.Exploit.ToolBudget(
    PerTargetPerTool: opts.BudgetPerTool ?? exploitBudgetBase.PerTargetPerTool,
    MaxTotalCalls: opts.BudgetGlobal ?? exploitBudgetBase.MaxTotalCalls)
{
    PerToolOverrides = opts.BudgetPerToolOverrides.Count > 0
        ? new Dictionary<string, int>(opts.BudgetPerToolOverrides)
        : null,
};
var exploitToolbox = new ExploitToolbox(
    new IExploitTool[] { nuclei, msf, spray, httpSpray, empireExecutor, dbPillage, asRepRoast, kerberoast, sshKeyBrute, sshKeyPassphraseBrute, sudoGtfoBins, winrmPostEx, ntdsSamDump, zeroLogon, /* --- htb-loot-collector --- */ postExLoot /* --- end htb-loot-collector --- */ },
    audit,
    exploitBudget);

// Phishing/macro subsystem (GAP-030). Master gate is --allow-phishing on
// RunPermissions; SMTP relay is sub-gated on --allow-smtp-relay. The
// toolbox is a registry, not the authorization boundary — every tool
// re-checks scope + the phishing category on its own entry point.
var phishingGenerator = new Drederick.Exploit.Phishing.MacroPayloadGenerator(
    scope, audit, permissions, opts.OutputDir);
var phishingDelivery = new Drederick.Exploit.Phishing.PhishingDelivery(
    scope, audit, permissions);
var phishingToolbox = new Drederick.Exploit.Phishing.PhishingToolbox(
    new Drederick.Exploit.Phishing.IPhishingTool[] { phishingGenerator, phishingDelivery },
    audit);

audit.Record("exploit.toolbox.ready", new Dictionary<string, object?>
{
    ["tools"] = exploitToolbox.Tools.Select(t => t.Name).ToList(),
    ["allow_exec_pocs"] = permissions.AllowExecPocs,
    ["allow_cred_attacks"] = permissions.AllowCredAttacks,
    ["allow_payloads"] = permissions.AllowPayloads,
    ["allow_destructive"] = permissions.AllowDestructive,
    ["allow_dos"] = permissions.AllowDos,
    ["acknowledge_lockout_risk"] = permissions.AcknowledgeLockoutRisk,
    ["allow_phishing"] = permissions.AllowPhishing,
    ["allow_smtp_relay"] = permissions.AllowSmtpRelay,
    ["phishing_tools"] = phishingToolbox.Tools.Select(t => t.Name).ToList(),
});
// --- end exploit tools ---

// --- multi-stage-wiring ---
// Multi-stage kill-chain coordinator: preflight → PoC → stager → payload →
// handler → record. Every stage re-checks scope and the opt-in category at
// the load-bearing tool, so the coordinator is not an authorization bypass.
// Stubs stand in for the payload stager and callback listener until the
// concrete implementations land.
var multiStageStager = new StubPayloadStager();
var multiStageHandler = new StubHandlerListener();
var multiStage = new MultiStageExploitRunner(
    scope, audit, exploitRunner, msf, multiStageStager, multiStageHandler, permissions);
audit.Record("multistage.ready", new Dictionary<string, object?>
{
    ["stager"] = multiStageStager.GetType().Name,
    ["handler"] = multiStageHandler.GetType().Name,
});
_ = multiStage;  // reserved for autopilot / UI integration
// --- end multi-stage-wiring ---

// --- session-manager-wiring ---
// Registry of live post-ex sessions opened by the multi-stage chain (or by
// the operator). Dispatches platform-appropriate enumeration (PostExLinux /
// PostExWindows) through each session. Scope is re-checked on every entry
// point; platform is probed when a session is registered as Unknown.
var postExLinux = new PostExLinux(scope, audit, new DefaultProcessRunner());
var postExWindows = new PostExWindows(scope, audit, new DefaultProcessRunner());
var sessionManager = new SessionManager(scope, audit, postExLinux, postExWindows, permissions);
audit.Record("session.manager.ready", new Dictionary<string, object?>
{
    ["max_concurrent_enumerations"] = SessionManager.MaxConcurrentEnumerations,
});
_ = sessionManager;  // reserved for autopilot / UI integration
// --- end session-manager-wiring ---

// --- llm-exploit-wiring ---
// Expose the offensive surface (exploit planner, cred spray, post-ex,
// pivot, multi-stage chain, flag extraction) to the LLM runner as
// AIFunctions. Each underlying tool is already scope-checked and
// permission-gated; LlmExploitTools is belt + braces plus budget + audit
// for LLM-driven invocations.
var llmExploitCreds = new CredentialStore(audit);
var llmExploitPlanner = new ExploitationPlanner(audit, opts.OutputDir);
var llmExploitFlags = new FlagExtractor(audit);
var llmExploitSessionShell = OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/sh";
var llmExploitPivot = new SessionPivotProber(scope, audit, new DefaultProcessRunner(), llmExploitSessionShell, kb);
var llmExploitTools = new LlmExploitTools(
    scope: scope,
    audit: audit,
    permissions: permissions,
    outputRoot: opts.OutputDir,
    planner: llmExploitPlanner,
    kb: kb,
    creds: llmExploitCreds,
    spray: spray,
    linux: postExLinux,
    windows: postExWindows,
    pivot: llmExploitPivot,
    sessions: sessionManager,
    flags: llmExploitFlags,
    multiStage: multiStage,
    phishGen: phishingGenerator,
    phishDeliver: phishingDelivery);
audit.Record("llm.exploit_tools.ready", new Dictionary<string, object?>
{
    ["count"] = llmExploitTools.BuildAiTools().Count,
});
// --- end llm-exploit-wiring ---

// --- llm-notebook-wiring ---
// Long-term fight notebook. Persists LLM-authored observations,
// tactics, gaps, mistakes, winning moves, and lessons to JSONL so
// `drederick notes` can review them between fights and the planner
// can replay them into future engagements.
//
// Two sinks (mirrors docs/LEARNING_LOOP.md):
//   • <out>/fight-notes.jsonl                  (per-run)
//   • ~/.drederick/fight-notebook.jsonl        (cross-fight aggregate)
//
// Disabled when --no-telemetry is set: notes are part of the same
// learning-loop substrate as telemetry, so the same opt-out covers
// both. The audit log still records the take attempt regardless.
var fightNotebook = new Drederick.Learning.FightNotebook(
    runPath: Path.Combine(opts.OutputDir, "fight-notes.jsonl"),
    aggregatePath: Drederick.Learning.FightNotebook.DefaultAggregatePath(),
    audit: audit,
    enabled: opts.Telemetry);
var llmNotebookTool = new Drederick.Agent.LlmNotebookTool(
    fightNotebook,
    fightId: null,
    targetArchetype: null);
audit.Record("llm.notebook.ready", new Dictionary<string, object?>
{
    ["enabled"] = fightNotebook.Enabled,
    ["run_path"] = fightNotebook.RunPath,
    ["aggregate_path"] = fightNotebook.AggregatePath,
});
// --- end llm-notebook-wiring ---

if (!opts.Quiet)
{
    // Live progress: one-liner per tool invocation on stderr so stdout stays
    // clean for the final "done." summary. Use --quiet / -q to suppress.
    toolbox.Progress = Console.Error;
    Console.Error.WriteLine($"scan start: {targets.Count} target(s), {toolbox.Tools.Count} scanner(s) registered. Live progress on stderr; --quiet to hide.");
}

IReconAgentRunner runner;
if (opts.UseAgent)
{
    var agentRunner = MicrosoftAgentRunner.TryCreateFromProvider(
        opts.LlmProvider,
        opts.AzureDeploymentMap,
        audit,
        llmExploitTools,
        notebook: llmNotebookTool);
    if (agentRunner is null)
    {
        var requestedProviderName = opts.LlmProvider.ToString().ToLowerInvariant();
        if (opts.LlmProvider == Drederick.Jeopardy.Llm.LlmProvider.Auto)
        {
            Console.Error.WriteLine("--agent requested. No LLM provider configured (probed: copilot, azure, openai). Falling back to AdaptiveRunner.");
            Console.Error.WriteLine("To configure: 'gh auth login' for Copilot, or export AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY for Azure, or OPENAI_API_KEY for raw OpenAI.");
        }
        else
        {
            Console.Error.WriteLine($"--agent requested with --llm-provider={requestedProviderName} but that provider is not configured. Falling back to AdaptiveRunner.");
            Console.Error.WriteLine("Hint: try --llm-provider=auto to probe all providers and use the first ready one.");
        }
        audit.Record("runner.fallback", new Dictionary<string, object?>
        {
            ["requested_provider"] = requestedProviderName,
            ["reason"] = $"no_{requestedProviderName}_config",
        });
        runner = new AdaptiveRunner(audit, opts.HostConcurrency, opts.ServiceConcurrency, opts.ContentDiscovery);
    }
    else
    {
        runner = agentRunner;
    }
}
else
{
    runner = new AdaptiveRunner(audit, opts.HostConcurrency, opts.ServiceConcurrency, opts.ContentDiscovery);
}

// --- adaptive-exploit-wiring ---
// Fallback parity: when the user asked for --agent + --autopilot but the
// OpenAI key was missing (so we fell back to AdaptiveRunner above), wrap
// the AdaptiveRunner in an AdaptiveExploitRunner so the same RunAsync
// delivers recon + deterministic exploitation — the same shape a hybrid
// (LLM + autopilot) run would produce. The normal `--autopilot` path
// (without --agent) remains handled by the post-recon autopilot-wiring
// block below; this branch only activates in the fallback scenario to
// avoid double-execution.
if (opts.UseAgent && opts.Autopilot && runner is AdaptiveRunner adaptive)
{
    var adaptiveCreds = new CredentialStore(audit);
    if (opts.AutopilotDefaultCreds) adaptiveCreds.SeedDefaultLab();
    foreach (var spec in opts.AutopilotCreds)
    {
        var colon = spec.IndexOf(':');
        if (colon <= 0) continue;
        var left = spec[..colon];
        var pwd = spec[(colon + 1)..];
        string? realm = null;
        var user = left;
        var bs = left.IndexOf('\\');
        if (bs > 0) { realm = left[..bs]; user = left[(bs + 1)..]; }
        adaptiveCreds.Add(user, pwd, realm, source: "cli");
    }
    var adaptivePlanner = new ExploitationPlanner(audit, opts.OutputDir);
    var adaptiveFlags = new FlagExtractor(audit);
    // GAP-033 — share an on-demand PoC fetcher with AdaptiveExploitRunner
    // so cve-lead actions emitted by the deterministic path also route to
    // the aggregator instead of dead-ending.
    var adaptivePocAggregator = new Drederick.Enrichment.PocAggregator(audit: audit);
    runner = new AdaptiveExploitRunner(
        adaptive, audit, scope, permissions,
        adaptivePlanner, adaptiveCreds, adaptiveFlags,
        opts.OutputDir,
        nuclei: nuclei,
        spray: spray,
        multiStage: multiStage,
        pocAggregator: adaptivePocAggregator,
        fetchPoc: opts.FetchPoc,
        maxIterations: opts.AutopilotMaxIterations,
        maxActionsPerIteration: opts.AutopilotMaxActionsPerIteration);
}
// --- end adaptive-exploit-wiring ---

// --- hybrid-runner-wiring ---
// When `--agent=hybrid` is set, wrap the chosen runner so the LLM path is
// tried first and the deterministic AdaptiveRunner / AdaptiveExploitRunner
// is invoked as the fallback. Scope rejections always propagate; only
// operational failures (no API key, network, auth, rate-limit, transient
// SDK errors) trigger the fallback. See HybridAgentRunner for the full
// safety contract.
if (opts.UseHybridAgent)
{
    IReconAgentRunner? llmInner = null;
    var llmCandidate = MicrosoftAgentRunner.TryCreateFromProvider(
        opts.LlmProvider,
        opts.AzureDeploymentMap,
        audit,
        llmExploitTools,
        notebook: llmNotebookTool);
    if (llmCandidate is not null)
    {
        llmInner = llmCandidate;
    }

    IReconAgentRunner deterministicInner;
    if (runner is AdaptiveExploitRunner alreadyWrapped)
    {
        deterministicInner = alreadyWrapped;
    }
    else if (runner is AdaptiveRunner adaptiveOnly)
    {
        deterministicInner = adaptiveOnly;
    }
    else
    {
        // The chosen `runner` was the LLM runner itself (UseAgent=true and
        // an API key was present). Build a fresh deterministic runner for
        // the fallback path so we never re-enter the LLM on failure.
        deterministicInner = new AdaptiveRunner(
            audit, opts.HostConcurrency, opts.ServiceConcurrency, opts.ContentDiscovery);
    }

    runner = new HybridAgentRunner(llmInner, deterministicInner, audit);
}
// --- end hybrid-runner-wiring ---

// --- attach scaffolding to runners (LOADER_SPEC §4) ---
// Best-effort: set Scaffolding on whatever concrete runner we have so
// activation events fire and the user-message gets the prior context.
// Wrappers (AdaptiveExploitRunner / HybridAgentRunner) do not currently
// expose their inner runner; the pre-wrap construction sites where
// AdaptiveRunner / MicrosoftAgentRunner are first created are the
// authoritative attachment points and have already run by here.
static void AttachScaffolding(IReconAgentRunner r, ScaffoldingContext ctx)
{
    switch (r)
    {
        case AdaptiveRunner a: a.Scaffolding = ctx; break;
        case MicrosoftAgentRunner m: m.Scaffolding = ctx; break;
    }
}
AttachScaffolding(runner, scaffolding);

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

try
{
    await runner.RunAsync(targets, toolbox, kb, cts.Token);
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Cancelled.");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"runner error: {ex.Message}");
    audit.Record("session.error", new Dictionary<string, object?> { ["error"] = ex.Message });
}

// Persist findings. Sort by target at emit time so report.md / report.json are
// stable diffs regardless of the concurrent execution order of the worker pool.
var allFindings = targets
    .Select(t => toolbox.Findings.TryGetValue(t, out var f) ? f : null)
    .Where(f => f is not null)
    .Select(f => f!)
    .OrderBy(f => f.Target, StringComparer.Ordinal)
    .ToList();

JsonReport.Write(Path.Combine(opts.OutputDir, "report.json"), allFindings, scope.Source);
MarkdownReport.Write(Path.Combine(opts.OutputDir, "report.md"), allFindings, scope.Source);
ManualCommandsCheatsheet.Write(opts.OutputDir, allFindings, emitCheatsheet: opts.LabMode);
new SqliteReport(opts.OutputDir).WriteReport(allFindings);

// ANCHOR: cve-annotator-wiring (owned by cve-annotator task)
// On-by-default CVE enrichment: fingerprinted services are matched against
// the local NVD JSON feed. Disable with DREDERICK_SKIP_CVE=1 (no new CLI flag
// to avoid stepping on scanner-registration / datasette-integration edits).
if (!string.Equals(Environment.GetEnvironmentVariable("DREDERICK_SKIP_CVE"), "1", StringComparison.Ordinal))
{
    try
    {
        var annotator = new CveAnnotator();
        var annotation = await annotator.AnnotateAsync(allFindings, opts.OutputDir, cts.Token);
        audit.Record("cve.annotate", new Dictionary<string, object?>
        {
            ["cves"] = annotation.CveCount,
            ["findings"] = annotation.FindingCount,
            ["cache_loaded"] = annotation.CacheLoaded,
        });
    }
    catch (Exception ex) when (ex is not OperationCanceledException)
    {
        Console.Error.WriteLine($"cve-annotate: {ex.Message}");
        audit.Record("cve.annotate.error", new Dictionary<string, object?> { ["error"] = ex.Message });
    }
}

// ANCHOR: poc-aggregator-wiring (owned by poc-aggregator task)
// After CVE annotation, aggregate public PoC references for every CVE in
// findings.db. Default --fetch-poc is ON: Exploit-DB mirror entries are
// copied verbatim into out/poc_cache/ with SHA-256 recorded. Failures are
// audited and never abort the run. Invariant: aggregate + present, never
// execute.
try
{
    var pocAggregator = new PocAggregator(audit: audit);
    var pocResult = await pocAggregator.AggregateAsync(allFindings, opts.OutputDir, opts.FetchPoc, cts.Token);
    audit.Record("poc.aggregate", new Dictionary<string, object?>
    {
        ["cves"] = pocResult.CveCount,
        ["refs"] = pocResult.RefCount,
        ["cached"] = pocResult.CachedCount,
        ["fetch_poc"] = opts.FetchPoc,
    });
}
catch (Exception ex) when (ex is not OperationCanceledException)
{
    Console.Error.WriteLine($"poc-aggregate: {ex.Message}");
    audit.Record("poc.aggregate.error", new Dictionary<string, object?> { ["error"] = ex.Message });
}
// END ANCHOR: poc-aggregator-wiring

// --- autopilot-wiring (owned by autopilot task) ---
// Post-recon full-auto exploitation loop. Pure orchestrator over existing
// exploit tools: every action is re-validated through scope + permissions on
// the underlying tool, so --autopilot is not a bypass. Only runs when
// explicitly opted in.
if (opts.Autopilot)
{
    try
    {
        var credStore = new CredentialStore(audit);
        if (opts.AutopilotDefaultCreds) credStore.SeedDefaultLab();
        foreach (var spec in opts.AutopilotCreds)
        {
            // Accept  user:password  or  realm\user:password
            var colon = spec.IndexOf(':');
            if (colon <= 0) continue;
            var left = spec[..colon];
            var pwd = spec[(colon + 1)..];
            string? realm = null;
            var user = left;
            var bs = left.IndexOf('\\');
            if (bs > 0) { realm = left[..bs]; user = left[(bs + 1)..]; }
            credStore.Add(user, pwd, realm, source: "cli");
        }

        var planner = new ExploitationPlanner(audit, opts.OutputDir);
        var flagExtractor = new FlagExtractor(audit);
        // GAP-033 — wire the on-demand PoC fetcher so cve-lead actions
        // route to the aggregator when the recon-time cache was empty.
        var autopilotPocAggregator = new PocAggregator(audit: audit);

        // cve-lead-llm-author-fallback (R3+R4 facts.htb gap): when the
        // PoC aggregator returns nothing, prompt the LLM to author an
        // exec_shell command from CVE knowledge. The bridge enforces
        // permission gates, scope re-validation, plaintext discipline,
        // and a 1-LLM-call/1-exec_shell budget per cve-lead. With no
        // chat client wired the bridge cleanly audits no_llm_key and
        // the autopilot continues exactly like before. Production
        // chat-client wiring (Copilot/Azure/OpenAI) is a follow-up;
        // the gates and integration ship now so the loop closes the
        // moment a Func is provided.
        LlmExecShellTool? autopilotExecShell = null;
        if (permissions.AllowExecShell)
        {
            autopilotExecShell = new LlmExecShellTool(scope, audit, permissions, opts.OutputDir);
        }
        // Production LLM adapter: when --autopilot + AllowCveLeadLlmAuthor
        // are on AND a chat client can be built from the configured provider,
        // wire the IChatClient-backed adapter into the bridge. The bridge
        // still owns audit emissions, permission gates, scope re-validation,
        // and the 1-LLM-call/1-exec_shell budget. With no provider key, this
        // resolves to null and the bridge audits no_llm_key as before.
        Drederick.Autopilot.CveLeadLlmAuthorFunc? cveLeadLlmFunc = null;
        if (permissions.AllowCveLeadLlmAuthor && autopilotExecShell != null)
        {
            var built = MicrosoftAgentRunner.TryCreateChatClient(
                opts.LlmProvider, opts.AzureDeploymentMap, audit);
            if (built is { } b)
            {
                var adapter = new CveLeadLlmAuthorChatClient(b.Client, b.ModelId);
                cveLeadLlmFunc = adapter.AsFunc();
                audit.Record("cve.lead.llm_author.adapter_ready", new Dictionary<string, object?>
                {
                    ["provider"] = opts.LlmProvider,
                    ["model"] = b.ModelId,
                });
            }
        }
        var cveLeadLlmAuthor = new CveLeadLlmAuthor(
            scope, audit, permissions,
            execShell: autopilotExecShell,
            llm: cveLeadLlmFunc);

        var autopilot = new AutopilotRunner(
            scope, audit, permissions, planner, credStore, flagExtractor,
             opts.OutputDir,
             nuclei: nuclei,
             spray: spray,
             msf: msf,
             pocAggregator: autopilotPocAggregator,
             cveLeadLlmAuthor: cveLeadLlmAuthor,
             fetchPoc: opts.FetchPoc,
             maxIterations: opts.AutopilotMaxIterations,
             maxActionsPerIteration: opts.AutopilotMaxActionsPerIteration);

        var apReport = await autopilot.RunAsync(allFindings, cts.Token);
        AutopilotReporter.Write(opts.OutputDir, apReport);
        if (!opts.Quiet)
        {
            Console.Error.WriteLine(
                $"autopilot — final bell: rounds={apReport.Iterations} " +
                $"punches={apReport.Actions.Count} " +
                $"connects={apReport.Actions.Count(a => a.Succeeded)} " +
                $"knockouts={apReport.Flags.Count}");
        }
    }
    catch (OperationCanceledException) { Console.Error.WriteLine("autopilot cancelled."); }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"autopilot: {ex.Message}");
        audit.Record("autopilot.error", new Dictionary<string, object?> { ["error"] = ex.Message });
    }
}
// --- end autopilot-wiring ---

kb.Merge(allFindings);
kb.Save(opts.MemoryPath);

audit.Record("session.end", new Dictionary<string, object?>
{
    ["host_count"] = allFindings.Count,
    ["tool_calls"] = toolbox.ToolCallsTotal,
});

Console.WriteLine($"done. {allFindings.Count} host(s). report: {opts.OutputDir}/report.md  audit: {auditPath}");
return 0;
