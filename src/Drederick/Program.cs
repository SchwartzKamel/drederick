using Drederick.Agent;
using Drederick.Audit;
using Drederick.Cli;
using Drederick.Doctor;
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
var toolbox = new ReconToolbox(nmap, http, tls, dns, audit);
toolbox.SeedFromKnowledgeBase(kb, targets);

IReconAgentRunner runner;
if (opts.UseAgent)
{
    var agentRunner = MicrosoftAgentRunner.TryCreateFromEnvironment(audit);
    if (agentRunner is null)
    {
        Console.Error.WriteLine("--agent requested but OPENAI_API_KEY is not set. Falling back to AdaptiveRunner.");
        audit.Record("runner.fallback", new Dictionary<string, object?> { ["reason"] = "no_api_key" });
        runner = new AdaptiveRunner(audit, opts.HostConcurrency, opts.ServiceConcurrency);
    }
    else
    {
        runner = agentRunner;
    }
}
else
{
    runner = new AdaptiveRunner(audit, opts.HostConcurrency, opts.ServiceConcurrency);
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

kb.Merge(allFindings);
kb.Save(opts.MemoryPath);

audit.Record("session.end", new Dictionary<string, object?>
{
    ["host_count"] = allFindings.Count,
    ["tool_calls"] = toolbox.ToolCallsTotal,
});

Console.WriteLine($"done. {allFindings.Count} host(s). report: {opts.OutputDir}/report.md  audit: {auditPath}");
return 0;
