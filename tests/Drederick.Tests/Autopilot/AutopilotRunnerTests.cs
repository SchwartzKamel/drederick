using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Doctor;
using Drederick.Exploit;
using Drederick.Recon;
using Drederick.Scope;
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
}
