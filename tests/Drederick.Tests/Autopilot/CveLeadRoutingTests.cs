using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Doctor;
using Drederick.Enrichment;
using Drederick.Exploit;
using Drederick.Recon;
using Drederick.Reporting;
using Drederick.Scope;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Autopilot;

/// <summary>
/// GAP-033 — verifies that band-250 cve-lead actions actually route into
/// <see cref="PocAggregator.FetchOnDemandAsync"/> instead of dead-ending
/// the way they did in the JobTwo R2 fight tape (640 cve-lead skips, 0
/// exploitation against 31 matched CVEs).
/// </summary>
public sealed class CveLeadRoutingTests : IDisposable
{
    private readonly string _outDir;
    private readonly string _auditPath;

    public CveLeadRoutingTests()
    {
        _outDir = Path.Combine(Path.GetTempPath(), $"drederick-cvelead-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_outDir);
        _auditPath = Path.Combine(_outDir, "audit.jsonl");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_outDir, recursive: true); } catch { }
    }

    private sealed class StubSource : IPocSource
    {
        private readonly Func<string, PocQueryContext, IReadOnlyList<PocRef>> _factory;
        public int CallCount { get; private set; }

        public StubSource(string name, Func<string, PocQueryContext, IReadOnlyList<PocRef>> factory)
        {
            Name = name;
            _factory = factory;
        }

        public string Name { get; }

        public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
        {
            CallCount++;
            return Task.FromResult(_factory(cveId, ctx));
        }
    }

    private static HostFinding HostWithCveLead(string target, int port, string cveId, string product = "veeam-mp")
        => new()
        {
            Target = target,
            Nmap = new NmapResult
            {
                OpenPorts =
                {
                    new NmapPort
                    {
                        Port = port,
                        Service = "http",
                        Product = product,
                        Version = "12.1",
                        Scripts =
                        {
                            new NmapScript
                            {
                                Id = "vulners",
                                Output = $"  {cveId}  9.8  https://nvd.nist.gov/{cveId}",
                            },
                        },
                    },
                },
            },
        };

    [Fact]
    public async Task CveLead_Fetches_On_Demand_And_ReplansAs_Msfrc_NextIteration()
    {
        const string cve = "CVE-2026-27944";
        var scope = ScopeLoader.Parse("10.129.0.0/16");
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecPocs: true);

        // Stub source: when called for the lead's CVE, drop a fake msf
        // module into the metasploit cache so the next planner pass sees
        // an artifact and emits band-490 msfrc.
        var modulePath = Path.Combine(_outDir, "poc_cache", MetasploitSource.SourceName,
            "exploit_unix_http_nginx_ui_rce", "nginx_ui_rce.rb");
        var stub = new StubSource(MetasploitSource.SourceName, (id, ctx) =>
        {
            Assert.Equal(cve, id);
            Directory.CreateDirectory(Path.GetDirectoryName(modulePath)!);
            File.WriteAllText(modulePath, "# stub msf module for " + id);
            return new[]
            {
                new PocRef(MetasploitSource.SourceName,
                    Url: null,
                    ExternalId: "exploit/unix/http/nginx_ui_rce",
                    LocalPath: modulePath),
            };
        });

        var aggregator = new PocAggregator(new IPocSource[] { stub }, audit);
        var planner = new ExploitationPlanner(audit, _outDir);
        var creds = new CredentialStore(audit);
        var flagEx = new FlagExtractor(audit);

        // Canned msfrc runner so when the band-490 action fires next iter,
        // we can prove it spawned (proxy: msf.Calls captured).
        var proc = new CannedProcessRunner { Stdout = "msf auxiliary completed\n" };
        var exploitRunner = new ExploitRunner(scope, audit, _outDir, proc);
        var msf = new MsfRcRunner(scope, audit, perms, exploitRunner, msfconsolePath: "/bin/true");

        var autopilot = new AutopilotRunner(
            scope, audit, perms, planner, creds, flagEx, _outDir,
            msf: msf,
            pocAggregator: aggregator,
            fetchPoc: true,
            maxIterations: 3);

        var findings = new[] { HostWithCveLead("10.129.238.35", 9419, cve) };
        var report = await autopilot.RunAsync(findings);

        // Source was queried exactly once (loop guard).
        Assert.Equal(1, stub.CallCount);

        // The cve-lead executed (skipped=true with succeeded=true after fetch).
        var leadResult = Assert.Single(report.Actions, a => a.Action.Tool == "cve-lead");
        Assert.True(leadResult.Succeeded);
        Assert.True(leadResult.Skipped);
        Assert.Contains("fetched", leadResult.SkipReason ?? "", StringComparison.OrdinalIgnoreCase);

        // Next iteration replanned and executed band-490 msfrc.
        var msfResult = Assert.Single(report.Actions, a => a.Action.Tool == "msfrc");
        Assert.Equal(cve, msfResult.Action.CveId);
        Assert.Equal(490, msfResult.Action.Priority);
        Assert.True(msfResult.Action.Priority > leadResult.Action.Priority,
            "band-490 msfrc must outrank band-250 cve-lead");
        Assert.NotEmpty(proc.Calls);
    }

    [Fact]
    public async Task CveLead_Audits_Unfetchable_When_No_Source_Has_Artifact()
    {
        const string cve = "CVE-9999-99999";
        var scope = ScopeLoader.Parse("10.129.0.0/16");
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecPocs: true);

        // Stub returns no refs at all — the lead is genuinely dead.
        var stub = new StubSource("metasploit",
            (_, _) => Array.Empty<PocRef>());

        var aggregator = new PocAggregator(new IPocSource[] { stub }, audit);
        var planner = new ExploitationPlanner(audit, _outDir);
        var creds = new CredentialStore(audit);
        var flagEx = new FlagExtractor(audit);

        var autopilot = new AutopilotRunner(
            scope, audit, perms, planner, creds, flagEx, _outDir,
            pocAggregator: aggregator,
            fetchPoc: true,
            maxIterations: 3);

        var findings = new[] { HostWithCveLead("10.129.238.35", 9419, cve) };
        var report = await autopilot.RunAsync(findings);

        Assert.Equal(1, stub.CallCount);
        var lead = Assert.Single(report.Actions, a => a.Action.Tool == "cve-lead");
        Assert.False(lead.Succeeded);
        Assert.True(lead.Skipped);
        Assert.Contains("no source had artifact", lead.SkipReason ?? "", StringComparison.OrdinalIgnoreCase);

        // Audit contains a cve.lead.unfetchable event.
        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("cve.lead.unfetchable", auditText);
        Assert.Contains(cve, auditText);
    }

    [Fact]
    public async Task CveLead_Fetches_Only_Once_Per_RunAsync_Across_Iterations()
    {
        const string cve = "CVE-2026-12345";
        var scope = ScopeLoader.Parse("10.129.0.0/16");
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecPocs: true);

        // Stub returns nothing — keeps the lead in the plan across iters.
        var stub = new StubSource("metasploit", (_, _) => Array.Empty<PocRef>());
        var aggregator = new PocAggregator(new IPocSource[] { stub }, audit);
        var planner = new ExploitationPlanner(audit, _outDir);
        var creds = new CredentialStore(audit);
        var flagEx = new FlagExtractor(audit);

        var autopilot = new AutopilotRunner(
            scope, audit, perms, planner, creds, flagEx, _outDir,
            pocAggregator: aggregator,
            fetchPoc: true,
            maxIterations: 5);

        // Two findings on the same host emit two cve-leads for the same
        // CVE. Even though they're distinct actions (different StableId
        // for different ports), the loop guard should prevent the second
        // from re-querying the source.
        var findings = new[]
        {
            HostWithCveLead("10.129.238.35", 9419, cve),
            HostWithCveLead("10.129.238.35", 9420, cve),
        };
        var report = await autopilot.RunAsync(findings);

        // Exactly one fetch despite two cve-lead actions.
        Assert.Equal(1, stub.CallCount);
        var leads = report.Actions.Where(a => a.Action.Tool == "cve-lead").ToList();
        Assert.True(leads.Count >= 2);
    }

    [Fact]
    public async Task CveLead_Honors_NoFetchPoc_Flag_And_Skips_Without_Querying_Sources()
    {
        const string cve = "CVE-2026-27944";
        var scope = ScopeLoader.Parse("10.129.0.0/16");
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecPocs: true);

        var stub = new StubSource("metasploit", (_, _) =>
            throw new InvalidOperationException("source must NOT be queried"));
        var aggregator = new PocAggregator(new IPocSource[] { stub }, audit);
        var planner = new ExploitationPlanner(audit, _outDir);
        var creds = new CredentialStore(audit);
        var flagEx = new FlagExtractor(audit);

        var autopilot = new AutopilotRunner(
            scope, audit, perms, planner, creds, flagEx, _outDir,
            pocAggregator: aggregator,
            fetchPoc: false, // --no-fetch-poc
            maxIterations: 1);

        var findings = new[] { HostWithCveLead("10.129.238.35", 9419, cve) };
        var report = await autopilot.RunAsync(findings);

        Assert.Equal(0, stub.CallCount);
        var lead = Assert.Single(report.Actions, a => a.Action.Tool == "cve-lead");
        Assert.True(lead.Skipped);
        Assert.Contains("fetch disabled", lead.SkipReason ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CveLead_Refuses_Out_Of_Scope_Target_Without_Fetching()
    {
        const string cve = "CVE-2026-27944";
        var scope = ScopeLoader.Parse("10.129.0.0/16");
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecPocs: true);

        var stub = new StubSource("metasploit", (_, _) =>
            throw new InvalidOperationException("source must NOT be queried for OOS target"));
        var aggregator = new PocAggregator(new IPocSource[] { stub }, audit);
        var planner = new ExploitationPlanner(audit, _outDir);
        var creds = new CredentialStore(audit);
        var flagEx = new FlagExtractor(audit);

        var autopilot = new AutopilotRunner(
            scope, audit, perms, planner, creds, flagEx, _outDir,
            pocAggregator: aggregator,
            fetchPoc: true,
            maxIterations: 1);

        // 8.8.8.8 is out of scope. The runner's belt-and-braces
        // _scope.Require check fires before RunCveLeadAsync ever runs.
        var findings = new[] { HostWithCveLead("8.8.8.8", 80, cve) };
        var report = await autopilot.RunAsync(findings);

        Assert.Equal(0, stub.CallCount);
        Assert.Contains(report.Actions, a =>
            a.Action.Tool == "cve-lead"
            && a.Skipped
            && (a.SkipReason ?? "").Contains("scope", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CveLead_Without_Aggregator_Skips_Cleanly_For_Backwards_Compat()
    {
        const string cve = "CVE-2026-27944";
        var scope = ScopeLoader.Parse("10.129.0.0/16");
        using var audit = new AuditLog(_auditPath);
        var perms = new RunPermissions(allowExecPocs: true);

        var planner = new ExploitationPlanner(audit, _outDir);
        var creds = new CredentialStore(audit);
        var flagEx = new FlagExtractor(audit);

        // No aggregator wired — exactly the regression the existing
        // AutopilotRunnerTests rely on: cve-lead remains a clean skip.
        var autopilot = new AutopilotRunner(
            scope, audit, perms, planner, creds, flagEx, _outDir,
            pocAggregator: null,
            fetchPoc: true,
            maxIterations: 1);

        var findings = new[] { HostWithCveLead("10.129.238.35", 9419, cve) };
        var report = await autopilot.RunAsync(findings);

        var lead = Assert.Single(report.Actions, a => a.Action.Tool == "cve-lead");
        Assert.True(lead.Skipped);
        Assert.False(lead.Succeeded);
        Assert.Contains("aggregator not registered", lead.SkipReason ?? "", StringComparison.OrdinalIgnoreCase);
    }

    private sealed class CannedProcessRunner : IProcessRunner
    {
        public int ExitCode { get; set; } = 0;
        public string Stdout { get; set; } = "";
        public string Stderr { get; set; } = "";
        public List<(string Bin, string Args)> Calls { get; } = new();
        public (int, string, string) Run(string f, string a, int t) { Calls.Add((f, a)); return (ExitCode, Stdout, Stderr); }
        public (int, string, string) RunShell(string c, int t) => throw new NotSupportedException();
    }
}
