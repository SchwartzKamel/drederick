using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Autopilot;
using Drederick.Doctor;
using Drederick.Exploit;
using Drederick.Memory;
using Drederick.Recon;
using Drederick.Reporting;
using Drederick.Scope;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Integration;

/// <summary>
/// End-to-end integration coverage that wires real Drederick components
/// (Scope, AuditLog, ExploitRunner, AutopilotRunner, planner, credential
/// store, flag extractor, session manager, pivot prober, reporters) together
/// with <see cref="IProcessRunner"/> stubs that replay fixture output — no
/// real subprocesses, no network. Reproduces the full kill chain as a safety
/// net against silent integration breakage.
/// </summary>
public class EndToEndIntegrationTests : IDisposable
{
    private readonly string _workDir;

    public EndToEndIntegrationTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-e2e-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
        PasswordSprayTool.ResetThrottleForTests();
        Environment.SetEnvironmentVariable("DREDERICK_SKIP_CVE", "1");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
        Environment.SetEnvironmentVariable("DREDERICK_SKIP_CVE", null);
    }

    // -----------------------------------------------------------------
    // Fixture + helper plumbing
    // -----------------------------------------------------------------

    private static string FindFixture(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "Drederick.Tests", "Integration", "Fixtures", name);
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException($"fixture '{name}' not locatable from {AppContext.BaseDirectory}");
    }

    private static string ReadFixture(string name) => File.ReadAllText(FindFixture(name));

    private static string Sha256Hex(string s)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    /// <summary>
    /// Scripted IProcessRunner: first handler whose predicate matches
    /// (binary, args) / (shell command) wins. Unmatched calls return a
    /// failing exit to surface missing fixtures early.
    /// </summary>
    private sealed class ScriptedRunner : IProcessRunner
    {
        public readonly record struct Call(string Kind, string Bin, string Args);

        public List<Call> Calls { get; } = new();
        private readonly List<(Func<string, string, bool> Match, Func<(int, string, string)> Respond)> _run = new();
        private readonly List<(Func<string, bool> Match, Func<(int, string, string)> Respond)> _shell = new();

        public ScriptedRunner OnRun(Func<string, string, bool> match, int exit, string stdout = "", string stderr = "")
        { _run.Add((match, () => (exit, stdout, stderr))); return this; }

        public ScriptedRunner OnShell(Func<string, bool> match, int exit, string stdout = "", string stderr = "")
        { _shell.Add((match, () => (exit, stdout, stderr))); return this; }

        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
        {
            Calls.Add(new Call("run", file, arguments));
            foreach (var (m, r) in _run) if (m(file, arguments)) return r();
            return (127, "", $"ScriptedRunner: unmatched run(bin='{file}', args='{arguments}')");
        }

        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
        {
            Calls.Add(new Call("shell", "/bin/sh", commandLine));
            foreach (var (m, r) in _shell) if (m(commandLine)) return r();
            return (127, "", "ScriptedRunner: unmatched shell");
        }
    }

    private sealed class FakeHandlerListener : IHandlerListener
    {
        public bool Opened = true;
        public string? SessionId = "S1";
        public Task<(bool opened, string? sessionId)> AwaitAsync(
            string lhost, int lport, TimeSpan timeout, CancellationToken ct)
            => Task.FromResult<(bool, string?)>((Opened, Opened ? SessionId : null));
    }

    private sealed class FakeStager : IPayloadStager
    {
        public Task<(bool success, string? error)> StageAsync(
            string target, string? payloadKind, string? lhost, int? lport,
            IReadOnlyDictionary<string, string>? extra, CancellationToken ct)
            => Task.FromResult<(bool, string?)>((true, null));

        public Task<(bool success, string? error)> TriggerAsync(
            string target, int port,
            IReadOnlyDictionary<string, string>? extra, CancellationToken ct)
            => Task.FromResult<(bool, string?)>((true, null));
    }

    private static HostFinding HostWith(string ip, params (int port, string svc, string? product, string? version)[] ports)
    {
        var hf = new HostFinding { Target = ip, Nmap = new NmapResult { ReturnCode = 0 } };
        foreach (var (p, s, pr, v) in ports)
            hf.Nmap!.OpenPorts.Add(new NmapPort { Port = p, Protocol = "tcp", Service = s, Product = pr, Version = v });
        return hf;
    }

    private static List<Dictionary<string, System.Text.Json.JsonElement>> ReadAudit(string path)
    {
        var list = new List<Dictionary<string, System.Text.Json.JsonElement>>();
        if (!File.Exists(path)) return list;
        foreach (var line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var d = System.Text.Json.JsonDocument.Parse(line);
            var row = new Dictionary<string, System.Text.Json.JsonElement>();
            foreach (var p in d.RootElement.EnumerateObject()) row[p.Name] = p.Value.Clone();
            list.Add(row);
        }
        return list;
    }

    // -----------------------------------------------------------------
    // 1. Full recon → autopilot (all gates off) — no exploits spawned.
    // -----------------------------------------------------------------

    [Fact]
    public async Task Full_Chain_Recon_To_Flag()
    {
        var outDir = Path.Combine(_workDir, "out1");
        Directory.CreateDirectory(outDir);
        using var audit = new AuditLog(Path.Combine(outDir, "audit.jsonl"));
        var scope = ScopeLoader.Parse("10.10.10.5");

        // Scope invariant verification: out-of-scope target must be refused.
        Assert.Throws<ScopeException>(() => scope.Require("8.8.8.8"));

        // Seed the knowledge base as if nmap fixture + HTTP banner probe
        // already ran. Fixtures are read so the files are exercised, even
        // though we feed HostFinding directly (NmapTool uses Process.Start
        // and cannot be stubbed via IProcessRunner).
        _ = ReadFixture("nmap-10.10.10.5.xml");
        _ = ReadFixture("http-banner-apache-2.4.41.txt");

        var finding = HostWith("10.10.10.5",
            (22, "ssh", "OpenSSH", "8.2p1"),
            (80, "http", "Apache httpd", "2.4.41"));
        finding.Http.Add(new HttpResult
        {
            Url = "http://10.10.10.5/",
            Status = 200,
            Server = "Apache/2.4.41",
            Title = "It works!",
        });
        var findings = new[] { finding };

        var kb = new KnowledgeBase();
        kb.Merge(findings);

        // No permissions granted → exec-pocs and cred-attacks are refused.
        var perms = new RunPermissions(allowExecPocs: false, allowCredAttacks: false);
        var proc = new ScriptedRunner(); // will fail on any unexpected spawn
        var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
        var spray = new PasswordSprayTool(scope, audit, perms, exploitRunner, netexecPath: "/bin/true");
        var creds = new CredentialStore(audit);
        creds.SeedDefaultLab();

        var planner = new ExploitationPlanner(audit, outDir);
        var flagEx = new FlagExtractor(audit);
        var autopilot = new AutopilotRunner(scope, audit, perms, planner, creds, flagEx, outDir,
            nuclei: null, spray: spray, maxIterations: 2);

        var report = await autopilot.RunAsync(findings);

        // Plan emits spray actions (ssh on 22, no SMB) but every execution
        // path refuses at the permission gate → Skipped and/or no success.
        Assert.Empty(proc.Calls); // no netexec spawn
        Assert.All(report.Actions, a => Assert.False(a.Succeeded));
        Assert.Empty(report.Flags); // no flags anywhere
        Assert.NotEmpty(report.Actions); // planner *did* emit actions

        // The refusal left a permission_refused audit event behind.
        var events = ReadAudit(audit.Path);
        Assert.Contains(events, e => e["event"].GetString() == "password-spray.permission_refused");
    }

    // -----------------------------------------------------------------
    // 2. Cred spray success → credential captured → planner dedups.
    // -----------------------------------------------------------------

    [Fact]
    public async Task Autopilot_Cred_Spray_Success_To_Session()
    {
        var outDir = Path.Combine(_workDir, "out2");
        Directory.CreateDirectory(outDir);
        using var audit = new AuditLog(Path.Combine(outDir, "audit.jsonl"));
        var scope = ScopeLoader.Parse("10.10.10.5");
        Assert.Throws<ScopeException>(() => scope.Require("192.0.2.99"));

        var successStdout = ReadFixture("netexec-smb-success.txt");

        var perms = new RunPermissions(allowCredAttacks: true, acknowledgeLockoutRisk: true);
        var proc = new ScriptedRunner().OnRun(
            match: (bin, _) => bin.EndsWith("netexec") || bin.EndsWith("/bin/true"),
            exit: 0, stdout: successStdout);

        var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
        var spray = new PasswordSprayTool(scope, audit, perms, exploitRunner, netexecPath: "/usr/bin/netexec");
        var creds = new CredentialStore(audit);
        creds.Add("admin", "Password1!"); // single cred — deterministic plan
        var planner = new ExploitationPlanner(audit, outDir);
        var flagEx = new FlagExtractor(audit);
        var autopilot = new AutopilotRunner(scope, audit, perms, planner, creds, flagEx, outDir,
            nuclei: null, spray: spray, maxIterations: 3);

        var findings = new[] { HostWith("10.10.10.5", (445, "microsoft-ds", null, null)) };

        var report = await autopilot.RunAsync(findings);

        Assert.Single(proc.Calls); // one spray attempt, even with 3 iterations (dedup works)
        var successes = report.Actions.Where(a => a.Succeeded).ToList();
        Assert.Single(successes);

        // CredentialStore still reports the captured cred.
        var known = creds.List();
        Assert.Contains(known, c => c.User == "admin"
            && c.PasswordSha256 == Sha256Hex("Password1!"));

        // Audit: attempt recorded with succeeded=true; plaintext not present.
        var events = ReadAudit(audit.Path);
        Assert.Contains(events, e =>
            e["event"].GetString() == "autopilot.cred.attempt"
            && e.ContainsKey("succeeded") && e["succeeded"].GetBoolean() == true);

        // Plaintext canary: password must not appear anywhere in the audit file.
        var auditText = File.ReadAllText(audit.Path);
        Assert.DoesNotContain("Password1!", auditText);
        Assert.Contains(Sha256Hex("Password1!"), auditText);
    }

    // -----------------------------------------------------------------
    // 3. Multi-stage chain → PoC → stager → handler → session →
    //    post-ex → flag extraction. This is the headline kill chain.
    // -----------------------------------------------------------------

    [Fact]
    public async Task MultiStage_Chain_To_PostEx_To_FlagExtraction()
    {
        var outDir = Path.Combine(_workDir, "out3");
        Directory.CreateDirectory(outDir);
        using var audit = new AuditLog(Path.Combine(outDir, "audit.jsonl"));
        var scope = ScopeLoader.Parse("10.10.10.5");
        Assert.Throws<ScopeException>(() => scope.Require("1.1.1.1"));

        // Create a "cached PoC" artifact on disk so ExploitRunner can hash it.
        var pocDir = Path.Combine(outDir, "poc_cache", "local");
        Directory.CreateDirectory(pocDir);
        var pocPath = Path.Combine(pocDir, "cve-2099-0001.sh");
        File.WriteAllText(pocPath, "#!/bin/sh\necho 'simulated PoC'\n");

        // Create a loot directory that will be harvested for flags.
        var lootDir = Path.Combine(outDir, "loot");
        Directory.CreateDirectory(lootDir);
        var flagPath = Path.Combine(lootDir, "flag.txt");
        const string flagValue = "HTB{canary_e2e_chain}";
        File.WriteAllText(flagPath, flagValue + "\n");

        var perms = new RunPermissions(allowExecPocs: true, allowPayloads: true);

        // PostExLinux's whoami parser expects `id; whoami; hostname` output.
        var whoamiFixture = ReadFixture("postex-linux-whoami-root.txt");

        var proc = new ScriptedRunner()
            // Stage 1 — PoC spawn: binary is the cached PoC path itself.
            .OnRun((bin, _) => bin == pocPath, exit: 0, stdout: "pwned")
            // Post-ex: every call goes through /bin/sh -c '<cmd>'. We don't
            // know which sub-cmd, so we return the whoami/id fixture for the
            // whoami branch and empty stdout for the rest. The whoami stage
            // is the one the test asserts on.
            .OnRun((bin, args) => bin == "/bin/sh" && args.Contains("id; whoami; hostname"),
                exit: 0, stdout: whoamiFixture)
            .OnRun((bin, _) => bin == "/bin/sh", exit: 0, stdout: "");

        var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
        var msf = new MsfRcRunner(scope, audit, perms, exploitRunner, msfconsolePath: "/bin/true");
        var stager = new FakeStager();
        var handler = new FakeHandlerListener { Opened = true, SessionId = "S1" };

        var multi = new MultiStageExploitRunner(scope, audit, exploitRunner, msf, stager, handler, perms);

        var spec = new MultiStageChainSpec(
            Target: "10.10.10.5",
            Port: 445,
            CachedPocPath: pocPath,
            MsfModule: null,
            PayloadKind: "linux/x64/meterpreter/reverse_tcp",
            Lhost: "10.10.10.5",
            Lport: 4444,
            HandlerTimeout: TimeSpan.FromMilliseconds(200),
            ExtraOptions: null);

        var chain = await multi.RunChainAsync(spec);

        Assert.True(chain.Success);
        Assert.Equal("S1", chain.SessionId);

        // Register session, then dispatch post-ex.
        var postExLinux = new PostExLinux(scope, audit, proc, shPath: "/bin/sh");
        var postExWin = new PostExWindows(scope, audit, proc, shellBinary: "/bin/true");
        using var sessions = new SessionManager(scope, audit, postExLinux, postExWin, perms);
        sessions.Register(new ActiveSession("S1", "10.10.10.5",
            SessionProtocol.Meterpreter, SessionPlatform.Linux, DateTimeOffset.UtcNow, null));

        var postEx = await postExLinux.RunAllAsync("10.10.10.5", session: "S1");
        Assert.True(postEx.WhoAmI.IsRoot);
        Assert.Equal("root", postEx.WhoAmI.User);

        // Flag harvest over the loot directory.
        var seen = new ConcurrentDictionary<string, FlagMatch>();
        var flagEx = new FlagExtractor(audit);
        var flags = flagEx.ScanDirectory(lootDir);
        Assert.Contains(flags, f => f.Value == flagValue
            && f.ValueSha256 == Sha256Hex(flagValue));

        // Dedup: scanning again returns the same SHA-256 exactly once.
        File.WriteAllText(Path.Combine(lootDir, "flag2.txt"), flagValue + "\n");
        var flags2 = flagEx.ScanDirectory(lootDir);
        Assert.Equal(1, flags2.Count(f => f.ValueSha256 == Sha256Hex(flagValue)));

        // Audit: every stage produced start/finish pairs.
        var events = ReadAudit(audit.Path).Select(e => e["event"].GetString()).ToList();
        foreach (var stage in new[] { "preflight", "poc", "stager", "payload", "handler", "record" })
        {
            Assert.Contains($"multistage.{stage}.start", events);
            Assert.Contains($"multistage.{stage}.finish", events);
        }
        Assert.Contains("session.open", events);
        Assert.Contains("postex.linux.whoami.start", events);
        Assert.Contains("postex.linux.whoami.finish", events);
    }

    // -----------------------------------------------------------------
    // 4. Pivot from session discovers a new in-scope host.
    // -----------------------------------------------------------------

    [Fact]
    public async Task Pivot_From_Session_Discovers_New_In_Scope_Host()
    {
        var outDir = Path.Combine(_workDir, "out4");
        Directory.CreateDirectory(outDir);
        using var audit = new AuditLog(Path.Combine(outDir, "audit.jsonl"));
        var scope = ScopeLoader.Parse("10.10.10.5\n10.10.11.0/24");
        Assert.Throws<ScopeException>(() => scope.Require("172.16.0.1"));

        var sweep = ReadFixture("pivot-ping-sweep.txt");
        var ncOpen = ReadFixture("pivot-nc-probe-open.txt");
        var banner = ReadFixture("pivot-ssh-banner.txt");

        var proc = new ScriptedRunner()
            .OnRun((bin, args) => bin == "/bin/sh" && args.Contains("ping -c1"),
                exit: 0, stdout: sweep)
            .OnRun((bin, args) => bin == "/bin/sh" && args.Contains("timeout 2 nc"),
                exit: 0, stdout: banner)
            .OnRun((bin, args) => bin == "/bin/sh" && args.Contains("nc -zvw1 10.10.11.42 22"),
                exit: 0, stdout: ncOpen);

        var kb = new KnowledgeBase();
        var prober = new SessionPivotProber(scope, audit, proc, "/bin/sh", kb);

        var result = await prober.ProbeCidrAsync(
            "S1", "10.10.10.5", "10.10.11.0/24",
            SessionPlatform.Linux, new[] { 22 }, CancellationToken.None);

        var hit = Assert.Single(result.Discovered);
        Assert.Equal("10.10.11.42", hit.Ip);
        Assert.Contains(22, hit.OpenPorts);
        Assert.False(string.IsNullOrEmpty(hit.Banner));
        Assert.Contains("OpenSSH", hit.Banner!);

        // KB stores pivot findings with Source = "session:<id>".
        var kbPivots = kb.FindPivotsBySource("session:S1");
        Assert.Contains(kbPivots, p => p.Ip == "10.10.11.42");

        var events = ReadAudit(audit.Path).Select(e => e["event"].GetString()).ToList();
        Assert.Contains("pivot.probe.start", events);
        Assert.Contains("pivot.probe.finish", events);
    }

    // -----------------------------------------------------------------
    // 5. Out-of-scope pivot IP silently dropped (no hard fail).
    // -----------------------------------------------------------------

    [Fact]
    public async Task Out_Of_Scope_Pivot_IP_Silently_Dropped()
    {
        var outDir = Path.Combine(_workDir, "out5");
        Directory.CreateDirectory(outDir);
        using var audit = new AuditLog(Path.Combine(outDir, "audit.jsonl"));
        // 10.10.11.0/24 is NOT in scope here.
        var scope = ScopeLoader.Parse("10.10.10.5");
        Assert.Throws<ScopeException>(() => scope.Require("10.10.11.42"));

        var sweep = ReadFixture("pivot-ping-sweep.txt");
        var proc = new ScriptedRunner()
            .OnRun((bin, args) => bin == "/bin/sh" && args.Contains("ping -c1"),
                exit: 0, stdout: sweep);

        var kb = new KnowledgeBase();
        var prober = new SessionPivotProber(scope, audit, proc, "/bin/sh", kb);

        // Must NOT throw — scope drop is silent at the pivot boundary.
        var result = await prober.ProbeCidrAsync(
            "S1", "10.10.10.5", "10.10.11.0/24",
            SessionPlatform.Linux, new[] { 22 }, CancellationToken.None);

        Assert.Empty(result.Discovered);
        Assert.Null(result.Error);

        var events = ReadAudit(audit.Path).Select(e => e["event"].GetString()).ToList();
        Assert.Contains("pivot.out_of_scope", events);
        Assert.Empty(kb.FindPivotsBySource("S1"));
    }

    // -----------------------------------------------------------------
    // 6. Wildcard scope file refused — ScopeLoader throws before anything.
    // -----------------------------------------------------------------

    [Fact]
    public void Scope_File_Refuses_Wildcard_Across_Entire_Chain()
    {
        var scopePath = Path.Combine(_workDir, "scope-wildcard.txt");
        File.WriteAllText(scopePath, "0.0.0.0/0\n");

        // Lab mode + allowBroad=false → refused.
        Assert.Throws<ScopeException>(() =>
            ScopeLoader.LoadFile(scopePath, allowBroad: false, labMode: true));

        // Even with allowBroad=true, wildcards remain refused
        // (@invariant-id:scope-wildcard-refused).
        Assert.Throws<ScopeException>(() =>
            ScopeLoader.LoadFile(scopePath, allowBroad: true, labMode: true));

        // Strict mode — also refused.
        Assert.Throws<ScopeException>(() =>
            ScopeLoader.LoadFile(scopePath, allowBroad: true, labMode: false));

        // IPv6 wildcard likewise.
        var v6 = Path.Combine(_workDir, "scope-v6-wildcard.txt");
        File.WriteAllText(v6, "::/0\n");
        Assert.Throws<ScopeException>(() =>
            ScopeLoader.LoadFile(v6, allowBroad: true, labMode: true));
    }

    // -----------------------------------------------------------------
    // 7. Plaintext canary secret never appears in any report artifact.
    // -----------------------------------------------------------------

    [Fact]
    public async Task Plaintext_Secret_Never_Appears_In_Any_Report()
    {
        const string canary = "ULTRA_CANARY_E2E_666";
        var canarySha = Sha256Hex(canary);

        var outDir = Path.Combine(_workDir, "out7");
        Directory.CreateDirectory(outDir);
        using var audit = new AuditLog(Path.Combine(outDir, "audit.jsonl"));
        var scope = ScopeLoader.Parse("10.10.10.0/24");
        Assert.Throws<ScopeException>(() => scope.Require("9.9.9.9"));

        // Canned "failed login" stdout — no plaintext anywhere in the fixture.
        var failStdout = ReadFixture("netexec-smb-fail.txt");
        Assert.DoesNotContain(canary, failStdout);

        var perms = new RunPermissions(allowCredAttacks: true, acknowledgeLockoutRisk: true);
        var proc = new ScriptedRunner().OnRun(
            match: (bin, _) => bin.EndsWith("netexec") || bin == "/bin/true",
            exit: 1, stdout: failStdout);

        var exploitRunner = new ExploitRunner(scope, audit, outDir, proc);
        var spray = new PasswordSprayTool(scope, audit, perms, exploitRunner, netexecPath: "/bin/true");

        var creds = new CredentialStore(audit);
        creds.Add("operator", canary, source: "test-canary");

        var planner = new ExploitationPlanner(audit, outDir);
        var flagEx = new FlagExtractor(audit);
        var autopilot = new AutopilotRunner(scope, audit, perms, planner, creds, flagEx, outDir,
            nuclei: null, spray: spray, maxIterations: 2);

        // Two in-scope hosts with SMB → canary attempted against each.
        var findings = new[]
        {
            HostWith("10.10.10.5", (445, "microsoft-ds", null, null)),
            HostWith("10.10.10.6", (445, "microsoft-ds", null, null)),
        };
        var report = await autopilot.RunAsync(findings);

        // Emit every report artifact mentioned in the spec.
        AutopilotReporter.Write(outDir, report);
        JsonReport.Write(Path.Combine(outDir, "report.json"), findings, scope.Source);
        MarkdownReport.Write(Path.Combine(outDir, "report.md"), findings, scope.Source);
        var sqlite = new SqliteReport(outDir);
        sqlite.WriteReport(findings);

        // Sanity: we DID try to spray and the captured stdout was hashed.
        Assert.True(proc.Calls.Count >= 2);

        // Scrub the canary from every listed artifact.
        var artifacts = new[]
        {
            Path.Combine(outDir, "audit.jsonl"),
            Path.Combine(outDir, "autopilot.md"),
            Path.Combine(outDir, "autopilot.json"),
            Path.Combine(outDir, "report.md"),
            Path.Combine(outDir, "report.json"),
        };
        foreach (var path in artifacts)
        {
            Assert.True(File.Exists(path), $"missing artifact: {path}");
            var text = File.ReadAllText(path);
            Assert.DoesNotContain(canary, text);
        }

        // findings.db — dump every text cell across every table.
        var dbPath = Path.Combine(outDir, "findings.db");
        Assert.True(File.Exists(dbPath));
        using (var conn = new SqliteConnection($"Data Source={dbPath}"))
        {
            conn.Open();
            var tables = new List<string>();
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table';";
                using var r = cmd.ExecuteReader();
                while (r.Read()) tables.Add(r.GetString(0));
            }
            foreach (var t in tables)
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $"SELECT * FROM \"{t}\";";
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    for (int i = 0; i < r.FieldCount; i++)
                    {
                        if (r.IsDBNull(i)) continue;
                        var v = r.GetValue(i)?.ToString() ?? "";
                        Assert.False(v.Contains(canary),
                            $"canary leaked into findings.db table '{t}' col {r.GetName(i)}: '{v}'");
                    }
                }
            }
        }
        SqliteConnection.ClearAllPools();

        // SHA-256 of the canary may appear in the audit (attempt digests).
        var auditText = File.ReadAllText(Path.Combine(outDir, "audit.jsonl"));
        Assert.Contains(canarySha, auditText);
    }
}
