using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Doctor;
using Drederick.Exploit;
using Drederick.Recon;
using Drederick.Reporting;
using Drederick.Scope;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Autopilot;

public class AutopilotRunnerTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"autopilot-{Guid.NewGuid():N}.jsonl");

    private static string NewOutDir() =>
        Path.Combine(Path.GetTempPath(), $"autopilot-run-{Guid.NewGuid():N}");

    private sealed class CannedRunner : IProcessRunner
    {
        public int ExitCode { get; set; } = 0;
        public string Stdout { get; set; } = "";
        public string Stderr { get; set; } = "";
        public List<(string Bin, string Args)> Calls { get; } = new();
        public (int, string, string) Run(string f, string a, int t) { Calls.Add((f, a)); return (ExitCode, Stdout, Stderr); }
        public (int, string, string) RunShell(string c, int t) => throw new NotSupportedException();
    }

    private static void InsertServiceCveFinding(string outDir, string target, int port, string cveId)
    {
        using var conn = new SqliteConnection($"Data Source={Path.Combine(outDir, "findings.db")}");
        conn.Open();
        long hostId;
        long serviceId;
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT id FROM hosts WHERE address=$target;";
            cmd.Parameters.AddWithValue("$target", target);
            hostId = Convert.ToInt64(cmd.ExecuteScalar());
        }
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
SELECT s.id
FROM services s
JOIN hosts h ON h.id = s.host_id
WHERE h.address=$target AND s.port=$port;";
            cmd.Parameters.AddWithValue("$target", target);
            cmd.Parameters.AddWithValue("$port", port);
            serviceId = Convert.ToInt64(cmd.ExecuteScalar());
        }
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
INSERT INTO findings(host_id, service_id, kind, data_json, created_at)
VALUES($host, $service, 'cve', $data, $created);";
            cmd.Parameters.AddWithValue("$host", hostId);
            cmd.Parameters.AddWithValue("$service", serviceId);
            cmd.Parameters.AddWithValue("$data", $$"""{"cve_id":"{{cveId}}","cvss":9.8}""");
            cmd.Parameters.AddWithValue("$created", DateTimeOffset.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        }
    }

    [Fact]
    public async Task Refuses_To_Execute_Actions_Against_Out_Of_Scope_Target()
    {
        using var audit = new AuditLog(NewAuditPath());
        var outDir = NewOutDir();
        Directory.CreateDirectory(outDir);
        try
        {
            var scope = ScopeLoader.Parse("10.10.10.0/24");
            var perms = new RunPermissions(allowCredAttacks: true, acknowledgeLockoutRisk: true);
            var proc = new CannedRunner();
            var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
            var spray = new PasswordSprayTool(scope, audit, perms, exploitRunner, netexecPath: "/bin/true");
            var creds = new CredentialStore(audit);
            creds.Add("admin", "admin");

            var planner = new ExploitationPlanner(audit, outDir);
            var flagEx = new FlagExtractor(audit);
            var autopilot = new AutopilotRunner(scope, audit, perms, planner, creds, flagEx, outDir,
                nuclei: null, spray: spray, maxIterations: 1);

            // Out-of-scope host embedded in findings; planner emits actions
            // against its target, runner + underlying tool must both refuse.
            var findings = new[]
            {
                new HostFinding
                {
                    Target = "8.8.8.8",
                    Nmap = new NmapResult { OpenPorts = new List<NmapPort>
                        { new() { Port = 445, Service = "microsoft-ds" } } },
                },
            };
            var report = await autopilot.RunAsync(findings);
            Assert.All(report.Actions, a => Assert.False(a.Succeeded));
            Assert.Empty(proc.Calls); // no netexec spawn whatsoever
        }
        finally { if (Directory.Exists(outDir)) Directory.Delete(outDir, true); }
    }

    [Fact]
    public async Task Skips_Spray_When_Permission_Not_Granted()
    {
        using var audit = new AuditLog(NewAuditPath());
        var outDir = NewOutDir();
        Directory.CreateDirectory(outDir);
        try
        {
            var scope = ScopeLoader.Parse("10.10.10.0/24");
            var perms = RunPermissions.None;
            PasswordSprayTool.ResetThrottleForTests();
            var proc = new CannedRunner();
            var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
            var spray = new PasswordSprayTool(scope, audit, perms, exploitRunner, netexecPath: "/bin/true");
            var creds = new CredentialStore(audit);
            creds.Add("admin", "admin");

            var planner = new ExploitationPlanner(audit, outDir);
            var flagEx = new FlagExtractor(audit);
            var autopilot = new AutopilotRunner(scope, audit, perms, planner, creds, flagEx, outDir,
                nuclei: null, spray: spray, maxIterations: 1);

            var findings = new[]
            {
                new HostFinding
                {
                    Target = "10.10.10.5",
                    Nmap = new NmapResult { OpenPorts = new List<NmapPort>
                        { new() { Port = 445, Service = "microsoft-ds" } } },
                },
            };
            var report = await autopilot.RunAsync(findings);
            Assert.NotEmpty(report.Actions);
            Assert.All(report.Actions, a => Assert.True(a.Skipped));
            Assert.Empty(proc.Calls);
        }
        finally { if (Directory.Exists(outDir)) Directory.Delete(outDir, true); }
    }

    [Fact]
    public async Task Captures_Flags_From_Captured_Stdout()
    {
        using var audit = new AuditLog(NewAuditPath());
        var outDir = NewOutDir();
        Directory.CreateDirectory(outDir);
        try
        {
            var scope = ScopeLoader.Parse("10.10.10.0/24");
            var perms = new RunPermissions(allowCredAttacks: true, acknowledgeLockoutRisk: true);
            PasswordSprayTool.ResetThrottleForTests();
            // netexec success output contains a [+] + a staged flag.
            var proc = new CannedRunner
            {
                Stdout = "[+] CORP\\admin:admin (Pwn3d!)  loot: HTB{knockout_round_one}\n",
            };
            var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
            var spray = new PasswordSprayTool(scope, audit, perms, exploitRunner, netexecPath: "/bin/true");
            var creds = new CredentialStore(audit);
            creds.Add("admin", "admin");

            var planner = new ExploitationPlanner(audit, outDir);
            var flagEx = new FlagExtractor(audit);
            var autopilot = new AutopilotRunner(scope, audit, perms, planner, creds, flagEx, outDir,
                nuclei: null, spray: spray, maxIterations: 1);

            var findings = new[]
            {
                new HostFinding
                {
                    Target = "10.10.10.5",
                    Nmap = new NmapResult { OpenPorts = new List<NmapPort>
                        { new() { Port = 445, Service = "microsoft-ds" } } },
                },
            };
            var report = await autopilot.RunAsync(findings);
            Assert.Contains(report.Actions, a => a.Succeeded);
            Assert.Contains(report.Flags, f => f.Value == "HTB{knockout_round_one}");
        }
        finally { if (Directory.Exists(outDir)) Directory.Delete(outDir, true); }
    }

    [Fact]
    public async Task Iteration_Does_Not_Repeat_Same_Action()
    {
        using var audit = new AuditLog(NewAuditPath());
        var outDir = NewOutDir();
        Directory.CreateDirectory(outDir);
        try
        {
            var scope = ScopeLoader.Parse("10.10.10.0/24");
            var perms = new RunPermissions(allowCredAttacks: true, acknowledgeLockoutRisk: true);
            PasswordSprayTool.ResetThrottleForTests();
            var proc = new CannedRunner { Stdout = "[-] failed" };
            var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
            var spray = new PasswordSprayTool(scope, audit, perms, exploitRunner, netexecPath: "/bin/true");
            var creds = new CredentialStore(audit);
            creds.Add("admin", "admin");

            var planner = new ExploitationPlanner(audit, outDir);
            var flagEx = new FlagExtractor(audit);
            var autopilot = new AutopilotRunner(scope, audit, perms, planner, creds, flagEx, outDir,
                nuclei: null, spray: spray, maxIterations: 3);

            var findings = new[]
            {
                new HostFinding
                {
                    Target = "10.10.10.5",
                    Nmap = new NmapResult { OpenPorts = new List<NmapPort>
                        { new() { Port = 445, Service = "microsoft-ds" } } },
                },
            };
            var report = await autopilot.RunAsync(findings);
            // planner emits one spray per (host, proto, cred) — once attempted
            // and recorded, subsequent iterations skip. So at most 1 call.
            Assert.Single(proc.Calls);
            Assert.Single(report.Actions);
        }
        finally { if (Directory.Exists(outDir)) Directory.Delete(outDir, true); }
    }

    [Fact]
    public void Planner_Prioritizes_Cve_Poc_Actions_Ahead_Of_Sprays()
    {
        using var audit = new AuditLog(NewAuditPath());
        var outDir = NewOutDir();
        Directory.CreateDirectory(outDir);
        try
        {
            var templatePath = Path.Combine(outDir, "poc_cache", "nuclei", "cves", "2024", "CVE-2024-29849.yaml");
            Directory.CreateDirectory(Path.GetDirectoryName(templatePath)!);
            File.WriteAllText(templatePath, "id: CVE-2024-29849\n");

            var findings = new[]
            {
                new HostFinding
                {
                    Target = "10.10.10.5",
                    Nmap = new NmapResult { OpenPorts = new List<NmapPort>
                        { new() { Port = 80, Service = "http", Product = "Microsoft HTTPAPI" } } },
                },
            };

            var sqlite = new SqliteReport(outDir);
            sqlite.WriteReport(findings);
            sqlite.UpsertCve("CVE-2024-29849", 9.8, "Veeam Enterprise Manager auth bypass", "2024-05-21");
            sqlite.UpsertPocRef("CVE-2024-29849", "nuclei", externalId: "CVE-2024-29849", localPath: templatePath);
            sqlite.UpsertPocRef("CVE-2024-29849", "metasploit", externalId: "auxiliary/scanner/http/title");
            InsertServiceCveFinding(outDir, "10.10.10.5", 80, "CVE-2024-29849");

            var creds = new CredentialStore(audit);
            creds.Add("admin", "admin");
            var planner = new ExploitationPlanner(audit, outDir);
            var plan = planner.Plan(findings, creds, new RunPermissions(allowExecPocs: true, allowCredAttacks: true));

            Assert.Contains(plan, a => a.Tool == "nuclei" && a.CveId == "CVE-2024-29849" && a.Priority == 500);
            Assert.Contains(plan, a => a.Tool == "msfrc"
                                       && a.CveId == "CVE-2024-29849"
                                       && a.Module == "auxiliary/scanner/http/title"
                                       && a.Options["RHOSTS"] == "10.10.10.5"
                                       && a.Options["RPORT"] == "80");
            var lowestCvePriority = plan.Where(a => !string.IsNullOrWhiteSpace(a.CveId)).Min(a => a.Priority);
            var sprayPriority = plan.Where(a => a.Tool == "password-spray").DefaultIfEmpty(new ExploitAction { Priority = 0 }).Max(a => a.Priority);
            Assert.True(lowestCvePriority > sprayPriority);
        }
        finally { if (Directory.Exists(outDir)) Directory.Delete(outDir, true); }
    }

    [Fact]
    public async Task Cve_Nuclei_Actions_Are_Not_Repeated_Across_Iterations()
    {
        using var audit = new AuditLog(NewAuditPath());
        var outDir = NewOutDir();
        Directory.CreateDirectory(outDir);
        try
        {
            var templatePath = Path.Combine(outDir, "poc_cache", "nuclei", "cves", "2024", "CVE-2024-29849.yaml");
            Directory.CreateDirectory(Path.GetDirectoryName(templatePath)!);
            File.WriteAllText(templatePath, "id: CVE-2024-29849\n");

            var scope = ScopeLoader.Parse("10.10.10.0/24");
            var perms = new RunPermissions(allowExecPocs: true);
            var proc = new CannedRunner();
            var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
            var nuclei = new NucleiRunner(scope, audit, perms, exploitRunner, nucleiPath: "/bin/true");
            var creds = new CredentialStore(audit);

            var planner = new ExploitationPlanner(audit, outDir);
            var flagEx = new FlagExtractor(audit);
            var autopilot = new AutopilotRunner(scope, audit, perms, planner, creds, flagEx, outDir,
                nuclei: nuclei, spray: null, maxIterations: 3);

            var findings = new[]
            {
                new HostFinding
                {
                    Target = "10.10.10.5",
                    Nmap = new NmapResult { OpenPorts = new List<NmapPort>
                    {
                        new()
                        {
                            Port = 80,
                            Service = "http",
                            Product = "Microsoft HTTPAPI",
                            Scripts = new List<NmapScript>
                            {
                                new() { Id = "vulners", Output = "candidate: CVE-2024-29849" },
                            },
                        },
                    } },
                },
            };

            var report = await autopilot.RunAsync(findings);
            Assert.Single(proc.Calls);
            Assert.Single(report.Actions);
            Assert.Equal("nuclei", report.Actions[0].Action.Tool);
            Assert.Equal("CVE-2024-29849", report.Actions[0].Action.CveId);
        }
        finally { if (Directory.Exists(outDir)) Directory.Delete(outDir, true); }
    }

    [Fact]
    public async Task Executes_MsfRc_Actions_From_Cve_Poc_Refs()
    {
        using var audit = new AuditLog(NewAuditPath());
        var outDir = NewOutDir();
        Directory.CreateDirectory(outDir);
        try
        {
            var findings = new[]
            {
                new HostFinding
                {
                    Target = "10.10.10.5",
                    Nmap = new NmapResult { OpenPorts = new List<NmapPort>
                        { new() { Port = 80, Service = "http", Product = "Microsoft HTTPAPI" } } },
                },
            };

            var sqlite = new SqliteReport(outDir);
            sqlite.WriteReport(findings);
            sqlite.UpsertCve("CVE-2024-29849", 9.8, "Veeam Enterprise Manager auth bypass", "2024-05-21");
            sqlite.UpsertPocRef("CVE-2024-29849", "metasploit", externalId: "auxiliary/scanner/http/title");
            InsertServiceCveFinding(outDir, "10.10.10.5", 80, "CVE-2024-29849");

            var scope = ScopeLoader.Parse("10.10.10.0/24");
            var perms = new RunPermissions(allowExecPocs: true);
            var proc = new CannedRunner { Stdout = "msf auxiliary completed\n" };
            var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
            var msf = new MsfRcRunner(scope, audit, perms, exploitRunner, msfconsolePath: "/bin/true");

            var planner = new ExploitationPlanner(audit, outDir);
            var flagEx = new FlagExtractor(audit);
            var autopilot = new AutopilotRunner(scope, audit, perms, planner, new CredentialStore(audit), flagEx, outDir,
                nuclei: null, spray: null, msf: msf, maxIterations: 2);

            var report = await autopilot.RunAsync(findings);
            Assert.Single(proc.Calls);
            Assert.Single(report.Actions);
            Assert.Contains("-r", proc.Calls[0].Args);
            Assert.Equal("msfrc", report.Actions[0].Action.Tool);
            Assert.True(report.Actions[0].Succeeded);
        }
        finally { if (Directory.Exists(outDir)) Directory.Delete(outDir, true); }
    }
}
