using System.Text.Json;
using Drederick.Audit;
using Drederick.Cli;
using Drederick.Exploit;
using Drederick.Scope;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests.Cli;

// --- htb-zerologon-direct ---
/// <summary>
/// Unit tests for <see cref="ZerologonCommand"/>. The command is wired
/// to take an <see cref="IZerologonExecutor"/> fake so tests never touch
/// the network, never spawn impacket, and never build the real
/// <c>ZeroLogonTool</c> dependency graph. Closes GAP-021.
/// </summary>
public sealed class ZerologonCommandTests : IDisposable
{
    private readonly string _outDir;
    private readonly string _auditPath;

    public ZerologonCommandTests()
    {
        _outDir = Path.Combine(Path.GetTempPath(), $"zerologon-cli-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_outDir);
        _auditPath = Path.Combine(_outDir, "audit.jsonl");
    }

    public void Dispose()
    {
        try { Directory.Delete(_outDir, recursive: true); } catch { /* best-effort */ }
    }

    private sealed class FakeExecutor : IZerologonExecutor
    {
        public ZeroLogonResult NextResult { get; set; } = new();
        public bool LastReset;
        public bool LastDumpSecrets;
        public string? LastTarget;
        public string? LastDcName;
        public int CallCount;

        public Task<ZeroLogonResult> RunAsync(
            string target, string dcName, bool resetMachinePassword,
            bool dumpSecrets, CancellationToken ct)
        {
            CallCount++;
            LastTarget = target;
            LastDcName = dcName;
            LastReset = resetMachinePassword;
            LastDumpSecrets = dumpSecrets;
            // Carry over mutable fields onto a fresh result with the
            // canonical target/dc_name (init-only on the result type).
            var src = NextResult;
            return Task.FromResult(new ZeroLogonResult
            {
                Target = target,
                DcName = dcName,
                Domain = src.Domain,
                Success = src.Success,
                AttemptsNeeded = src.AttemptsNeeded,
                PasswordSetToEmpty = src.PasswordSetToEmpty,
                SecretsDumped = src.SecretsDumped,
                SecretsDigest = src.SecretsDigest,
                SecretsCount = src.SecretsCount,
                Error = src.Error,
            });
        }
    }

    private (ZerologonCommand cmd, StringWriter stdout, StringWriter stderr, FakeExecutor fake, AuditLog audit)
        Build(string scopeSpec, FakeExecutor? executor = null)
    {
        var scope = ScopeLoader.Parse(scopeSpec);
        var audit = new AuditLog(_auditPath);
        var fake = executor ?? new FakeExecutor();
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var cmd = new ZerologonCommand(stdout, stderr, fake, scope, audit);
        return (cmd, stdout, stderr, fake, audit);
    }

    private CommandLineOptions DefaultOpts() => new()
    {
        ZerologonSubcommand = true,
        OutputDir = _outDir,
        Targets = { "10.10.10.50" },
        ZerologonDcName = "DC01",
        LabMode = true,
    };

    [Fact]
    public async Task ProbeMode_NotVulnerable_ExitCode1()
    {
        var (cmd, _, _, fake, audit) = Build("10.10.10.0/24");
        fake.NextResult = new ZeroLogonResult { Success = false, AttemptsNeeded = 2000 };
        var opts = DefaultOpts();

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(1, rc);
        Assert.False(fake.LastReset);
        audit.Dispose();
        Assert.Contains("\"zerologon.probe\"", File.ReadAllText(_auditPath));
    }

    [Fact]
    public async Task ProbeMode_Vulnerable_ExitCode0()
    {
        var (cmd, _, _, fake, audit) = Build("10.10.10.0/24");
        fake.NextResult = new ZeroLogonResult
        {
            Success = true,
            AttemptsNeeded = 137,
            PasswordSetToEmpty = false,
        };
        var opts = DefaultOpts();

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(0, rc);
        Assert.False(fake.LastReset);
        audit.Dispose();
        var auditText = File.ReadAllText(_auditPath);
        Assert.Contains("\"zerologon.probe\"", auditText);
        Assert.Contains("\"vulnerable\":true", auditText);
    }

    [Fact]
    public async Task ResetWithoutLabMode_RequiresDestructiveFlag()
    {
        var (cmd, _, stderr, fake, _) = Build("10.10.10.0/24");
        var opts = DefaultOpts();
        opts.LabMode = false;
        opts.ZerologonResetMachinePw = true;
        // No --allow-destructive / --allow-cred-attacks

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(2, rc);
        Assert.Equal(0, fake.CallCount);
        var msg = stderr.ToString();
        Assert.Contains("--allow-destructive", msg);
        Assert.Contains("--allow-cred-attacks", msg);
    }

    [Theory]
    [InlineData("dc with space")]
    [InlineData("dc01;rm")]
    [InlineData("THIS-NETBIOS-NAME-IS-WAY-TOO-LONG")]
    [InlineData("")]
    public async Task DcName_Shape_Validation_Rejects(string dcName)
    {
        var (cmd, _, stderr, fake, _) = Build("10.10.10.0/24");
        var opts = DefaultOpts();
        opts.ZerologonDcName = dcName;

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(2, rc);
        Assert.Equal(0, fake.CallCount);
        Assert.Contains("dc-name", stderr.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OutOfScopeTarget_ExitCode2()
    {
        var (cmd, _, stderr, fake, _) = Build("10.10.10.0/24");
        var opts = DefaultOpts();
        opts.Targets.Clear();
        opts.Targets.Add("192.168.99.99");

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(2, rc);
        Assert.Equal(0, fake.CallCount);
        Assert.Contains("scope", stderr.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task JsonOutput_Mode_ProducesParseableJson()
    {
        var (cmd, stdout, _, fake, _) = Build("10.10.10.0/24");
        fake.NextResult = new ZeroLogonResult { Success = true, AttemptsNeeded = 42 };
        var opts = DefaultOpts();
        opts.ZerologonJson = true;

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(0, rc);
        // --json mode emits *only* JSON (no human-readable preamble).
        using var doc = JsonDocument.Parse(stdout.ToString());
        Assert.Equal("zerologon", doc.RootElement.GetProperty("tool").GetString());
        Assert.Equal("10.10.10.50", doc.RootElement.GetProperty("target").GetString());
        Assert.Equal("DC01", doc.RootElement.GetProperty("dc_name").GetString());
        Assert.True(doc.RootElement.GetProperty("vulnerable").GetBoolean());
    }

    [Fact]
    public async Task SecretsDump_ImpliesResetMachinePw()
    {
        var (cmd, _, _, fake, _) = Build("10.10.10.0/24");
        fake.NextResult = new ZeroLogonResult
        {
            Success = true,
            PasswordSetToEmpty = true,
            AttemptsNeeded = 200,
            SecretsDumped = true,
            SecretsCount = 5,
            SecretsDigest = "0000000000000000000000000000000000000000000000000000000000000000",
        };
        var opts = DefaultOpts();
        opts.ZerologonResetMachinePw = false;
        opts.ZerologonDumpSecrets = true;

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(0, rc);
        Assert.True(fake.LastReset, "--dump-secrets must auto-enable reset");
        Assert.True(fake.LastDumpSecrets);
    }

    [Fact]
    public async Task Audit_NeverLogs_PlaintextHashes()
    {
        const string canaryHash = "aad3b435b51404eeaad3b435b51404ee";
        const string canaryDigest = "deadbeefcafe00000000000000000000000000000000000000000000aabbccdd";

        var (cmd, _, _, fake, audit) = Build("10.10.10.0/24");
        fake.NextResult = new ZeroLogonResult
        {
            Success = true,
            PasswordSetToEmpty = true,
            AttemptsNeeded = 200,
            SecretsDumped = true,
            SecretsCount = 3,
            // The result carries ONLY a SHA-256 digest of the secretsdump
            // output; the plaintext hash never appears anywhere.
            SecretsDigest = canaryDigest,
        };
        var opts = DefaultOpts();
        opts.ZerologonResetMachinePw = true;
        opts.ZerologonDumpSecrets = true;

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(0, rc);
        audit.Dispose();
        var auditText = File.ReadAllText(_auditPath);
        Assert.DoesNotContain(canaryHash, auditText);
        Assert.Contains(canaryDigest, auditText);
        Assert.Contains("\"zerologon.secretsdump\"", auditText);
        Assert.Contains("\"hash_count\":3", auditText);
    }

    [Fact]
    public async Task RecordsExploitRun_InSqlite()
    {
        var (cmd, _, _, fake, _) = Build("10.10.10.0/24");
        fake.NextResult = new ZeroLogonResult { Success = true, AttemptsNeeded = 88 };
        var opts = DefaultOpts();

        var rc = await cmd.ExecuteAsync(opts);
        Assert.Equal(0, rc);

        var dbPath = Path.Combine(_outDir, "findings.db");
        Assert.True(File.Exists(dbPath));
        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();
        using var sqliteCmd = conn.CreateCommand();
        sqliteCmd.CommandText =
            "SELECT tool, target, exit_code, argv_digest FROM exploit_runs WHERE tool = 'zerologon';";
        using var reader = sqliteCmd.ExecuteReader();
        Assert.True(reader.Read());
        Assert.Equal("zerologon", reader.GetString(0));
        Assert.Equal("10.10.10.50", reader.GetString(1));
        Assert.Equal(0, reader.GetInt32(2));
        Assert.False(string.IsNullOrEmpty(reader.GetString(3)));
    }

    [Fact]
    public async Task MissingTarget_ExitCode2()
    {
        var (cmd, _, stderr, fake, _) = Build("10.10.10.0/24");
        var opts = DefaultOpts();
        opts.Targets.Clear();

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(2, rc);
        Assert.Equal(0, fake.CallCount);
        Assert.Contains("--target", stderr.ToString());
    }
}
// --- end htb-zerologon-direct ---
