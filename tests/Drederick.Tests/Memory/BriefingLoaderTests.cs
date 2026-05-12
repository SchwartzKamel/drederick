using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Memory;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Memory;

public class BriefingLoaderTests
{
    private static string FixturePath(string name, [CallerFilePath] string thisFile = "")
    {
        // tests/Drederick.Tests/Memory/BriefingLoaderTests.cs
        //   -> tests/fixtures/briefing/<name>
        var memoryDir = Path.GetDirectoryName(thisFile)!;
        var testsDir = Path.GetDirectoryName(memoryDir)!;
        var root = Path.GetDirectoryName(testsDir)!;
        return Path.Combine(root, "fixtures", "briefing", name);
    }

    private static AuditLog NewAudit(out string path)
    {
        path = Path.Combine(Path.GetTempPath(), $"drederick-briefing-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(path);
    }

    private static Scope.Scope LabScope() =>
        ScopeLoader.Parse("10.10.10.0/24");

    private static string Sha256Hex(string s)
    {
        var h = SHA256.HashData(Encoding.UTF8.GetBytes(s));
        return Convert.ToHexString(h).ToLowerInvariant();
    }

    [Fact]
    public void ExampleBox_Parses_All_Sections()
    {
        var scope = LabScope();
        using var audit = NewAudit(out var auditPath);
        var seed = BriefingLoader.Load(FixturePath("example_box.md"), scope, audit);

        Assert.False(seed.Malformed);
        // 4 raw targets — one out of scope (192.168.99.42) — 3 kept.
        Assert.Equal(3, seed.Targets.Count);
        Assert.Contains("10.10.10.5", seed.Targets);
        Assert.Contains("10.10.10.6", seed.Targets);
        Assert.Contains("10.10.10.99", seed.Targets);
        Assert.DoesNotContain("192.168.99.42", seed.Targets);

        Assert.Equal(new[] { "alice", "bob", "svc_sql" }, seed.Users);

        Assert.Equal(3, seed.Credentials.Count);
        var alice = seed.Credentials.Single(c => c.Username == "alice");
        Assert.Equal("password", alice.Kind);
        // Plaintext password hashed: sha256("p@ssw0rd") stored.
        Assert.Equal(Sha256Hex("p@ssw0rd"), alice.SecretSha256);

        var bob = seed.Credentials.Single(c => c.Username == "bob");
        Assert.Equal("ntlm", bob.Kind);
        Assert.Equal("31d6cfe0d16ae931b73c59d7e0c089c0", bob.SecretSha256);

        Assert.Contains("no DoS", seed.Constraints);
        Assert.NotNull(seed.Notes);
        Assert.Contains("Foothold", seed.Notes!);
    }

    [Fact]
    public void OutOfScope_Target_Recorded_But_Not_Granted()
    {
        var scope = LabScope();
        using var audit = NewAudit(out var auditPath);
        var seed = BriefingLoader.Load(FixturePath("example_box.md"), scope, audit);
        audit.Dispose();

        Assert.DoesNotContain("192.168.99.42", seed.Targets);

        var log = File.ReadAllText(auditPath);
        Assert.Contains("\"briefing.target.out_of_scope\"", log);
        Assert.Contains("192.168.99.42", log);
        // Loader must throw via Scope.Require if anyone tries to use it
        // — out-of-scope strings never get authorized.
        Assert.Throws<ScopeException>(() => scope.Require("192.168.99.42"));
    }

    [Fact]
    public void Plaintext_Password_Never_Appears_In_Kb_Serialization()
    {
        // Canary: p@ssw0rd must not survive into KnowledgeBase JSON.
        const string canary = "p@ssw0rd";
        var scope = LabScope();
        using var audit = NewAudit(out _);
        var seed = BriefingLoader.Load(FixturePath("example_box.md"), scope, audit);

        var kb = new KnowledgeBase();
        kb.MergeFromBriefing(seed);
        var json = JsonSerializer.Serialize(kb, new JsonSerializerOptions { WriteIndented = true });

        Assert.DoesNotContain(canary, json);
        Assert.DoesNotContain("hunter2", json); // belt-and-suspenders
        // The SHA of the plaintext must be present though.
        Assert.Contains(Sha256Hex(canary), json);
    }

    [Fact]
    public void Empty_Briefing_Parses_To_Empty_Seed()
    {
        var scope = LabScope();
        using var audit = NewAudit(out _);
        var seed = BriefingLoader.Load(FixturePath("empty.md"), scope, audit);

        Assert.False(seed.Malformed);
        Assert.Empty(seed.Targets);
        Assert.Empty(seed.Users);
        Assert.Empty(seed.Credentials);
        Assert.Empty(seed.Constraints);
        Assert.Null(seed.Notes);
    }

    [Fact]
    public void Malformed_Briefing_Produces_Best_Effort_Partial_Parse()
    {
        var scope = LabScope();
        using var audit = NewAudit(out var auditPath);
        var seed = BriefingLoader.Load(FixturePath("malformed.md"), scope, audit);
        audit.Dispose();

        // Best-effort: we still get the in-scope target and at least
        // one credential out of the table.
        Assert.Contains("10.10.10.5", seed.Targets);
        Assert.NotEmpty(seed.Credentials);
        Assert.Contains(seed.Credentials, c => c.Username == "alice");
        Assert.Contains(seed.Credentials, c => c.Username == "bob");

        var bob = seed.Credentials.Single(c => c.Username == "bob");
        Assert.Equal("ntlm", bob.Kind);
        // NTLM hash stored verbatim (not re-hashed).
        Assert.Equal("aad3b435b51404eeaad3b435b51404ee", bob.SecretSha256);

        // Notes still parsed even after a non-canonical section.
        Assert.NotNull(seed.Notes);

        var log = File.ReadAllText(auditPath);
        Assert.Contains("\"briefing.loaded\"", log);
        Assert.Contains("\"briefing.parsed\"", log);
    }

    [Fact]
    public void Audit_Records_Loaded_And_Parsed_Events()
    {
        var scope = LabScope();
        using var audit = NewAudit(out var auditPath);
        var seed = BriefingLoader.Load(FixturePath("example_box.md"), scope, audit);
        audit.Dispose();

        var log = File.ReadAllText(auditPath);
        Assert.Contains("\"briefing.loaded\"", log);
        Assert.Contains("\"briefing.parsed\"", log);
        Assert.Contains("\"sha256\"", log);
        Assert.Contains(seed.Sha256, log);
        Assert.Contains("plaintext_passwords_sha256", log);
    }

    [Fact]
    public void Path_With_Null_Byte_Is_Rejected()
    {
        var scope = LabScope();
        using var audit = NewAudit(out var auditPath);
        var seed = BriefingLoader.Load("/tmp/foo\0bar.md", scope, audit);
        audit.Dispose();

        Assert.Empty(seed.Targets);
        Assert.Empty(seed.Credentials);
        var log = File.ReadAllText(auditPath);
        Assert.Contains("\"briefing.error\"", log);
        Assert.Contains("path_rejected", log);
    }

    [Fact]
    public void Path_With_Newline_Is_Rejected()
    {
        var scope = LabScope();
        using var audit = NewAudit(out var auditPath);
        var seed = BriefingLoader.Load("foo\n.md", scope, audit);
        audit.Dispose();

        Assert.Empty(seed.Targets);
        var log = File.ReadAllText(auditPath);
        Assert.Contains("path_rejected", log);
    }

    [Fact]
    public void Missing_File_Records_Not_Found()
    {
        var scope = LabScope();
        using var audit = NewAudit(out var auditPath);
        var ghost = Path.Combine(Path.GetTempPath(), $"drederick-briefing-ghost-{Guid.NewGuid():N}.md");
        var seed = BriefingLoader.Load(ghost, scope, audit);
        audit.Dispose();

        Assert.Empty(seed.Targets);
        var log = File.ReadAllText(auditPath);
        Assert.Contains("\"briefing.error\"", log);
        Assert.Contains("not_found", log);
    }

    [Fact]
    public void Merge_From_Briefing_Populates_Globals()
    {
        var scope = LabScope();
        using var audit = NewAudit(out _);
        var seed = BriefingLoader.Load(FixturePath("example_box.md"), scope, audit);

        var kb = new KnowledgeBase();
        kb.MergeFromBriefing(seed);

        Assert.Equal(seed.Sha256, kb.Globals["briefing.sha256"]);
        Assert.Equal("3", kb.Globals["briefing.user_count"]);
        Assert.Equal("alice", kb.Globals["briefing.users.0"]);
        Assert.Contains("no DoS", kb.Globals.Values);
        Assert.Same(seed, kb.Briefing);
    }
}
