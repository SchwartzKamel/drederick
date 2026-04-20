using Drederick.Agent;
using Drederick.Audit;
using Drederick.Bundling;
using Drederick.Cli;
using Drederick.Doctor;
using Drederick.Enrichment;
using Drederick.Memory;
using Drederick.Recon;
using Drederick.Reporting;
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

var nmap = new NmapTool(scope, audit, labMode: opts.LabMode);
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
var toolbox = new ReconToolbox(
    new IReconTool[]
    {
        nmap, http, tls, dns,
        smb, ftp, ssh, snmp, ldap, rpc, kerberos,
        dnsAxfr, httpContentDiscovery, tlsCipherEnum,
    },
    audit);
toolbox.SeedFromKnowledgeBase(kb, targets);

IReconAgentRunner runner;
if (opts.UseAgent)
{
    var agentRunner = MicrosoftAgentRunner.TryCreateFromEnvironment(audit);
    if (agentRunner is null)
    {
        Console.Error.WriteLine("--agent requested but OPENAI_API_KEY is not set. Falling back to AdaptiveRunner.");
        audit.Record("runner.fallback", new Dictionary<string, object?> { ["reason"] = "no_api_key" });
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
    var pocAggregator = new PocAggregator();
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

kb.Merge(allFindings);
kb.Save(opts.MemoryPath);

audit.Record("session.end", new Dictionary<string, object?>
{
    ["host_count"] = allFindings.Count,
    ["tool_calls"] = toolbox.ToolCallsTotal,
});

Console.WriteLine($"done. {allFindings.Count} host(s). report: {opts.OutputDir}/report.md  audit: {auditPath}");
return 0;
