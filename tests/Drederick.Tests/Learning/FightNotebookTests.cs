using Drederick.Audit;
using Drederick.Learning;
using Xunit;

namespace Drederick.Tests.Learning;

public sealed class FightNotebookTests : IDisposable
{
    private readonly string _root;

    public FightNotebookTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "fight-notebook-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }
        catch { /* best-effort */ }
    }

    private string RunPath() => Path.Combine(_root, "fight-notes.jsonl");
    private string AggPath() => Path.Combine(_root, "agg.jsonl");

    [Fact]
    public async Task TakeNoteAsync_AppendsToBothSinks_AndComputesSha()
    {
        await using var nb = new FightNotebook(RunPath(), AggPath(), audit: null, enabled: true);

        var n = await nb.TakeNoteAsync(
            FightNoteCategory.WinningMove,
            "Used SeImpersonatePrivilege via PrintSpoofer for SYSTEM.",
            tags: new[] { "winpe", "GAP-048" },
            fightId: "test-fight-1",
            targetHost: "10.10.10.5",
            source: "llm");

        Assert.True(File.Exists(RunPath()));
        Assert.True(File.Exists(AggPath()));
        Assert.Equal("winning_move", n.Category);
        Assert.Equal(64, n.BodySha256.Length);
        Assert.Equal(2, n.Tags.Count);
        // Private host redacted to /24.
        Assert.Equal("10.10.10.0/24", n.TargetHost);

        var runLines = File.ReadAllLines(RunPath());
        var aggLines = File.ReadAllLines(AggPath());
        Assert.Single(runLines);
        Assert.Single(aggLines);
    }

    [Fact]
    public async Task TakeNoteAsync_RedactsPasswordsAndKeysBeforeWrite()
    {
        await using var nb = new FightNotebook(RunPath(), aggregatePath: null, audit: null, enabled: true);

        var n = await nb.TakeNoteAsync(
            FightNoteCategory.Mistake,
            "Tried password=Hunter2! against svc, got locked out. " +
            "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature " +
            "lmhash:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            source: "llm");

        Assert.DoesNotContain("Hunter2!", n.Body);
        Assert.Contains("[REDACTED:password]", n.Body);
        Assert.Contains("[REDACTED:jwt]", n.Body);
        Assert.Contains("[REDACTED:lm:nt-hash]", n.Body);

        var disk = File.ReadAllText(RunPath());
        Assert.DoesNotContain("Hunter2!", disk);
    }

    [Fact]
    public async Task TakeNoteAsync_RedactsPemPrivateKey()
    {
        await using var nb = new FightNotebook(RunPath(), aggregatePath: null, audit: null, enabled: true);

        var body =
            "Captured ssh key from /home/svc/.ssh/id_rsa:\n" +
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQ\nfakekeydata\n" +
            "-----END OPENSSH PRIVATE KEY-----\n" +
            "use it for lateral.";

        var n = await nb.TakeNoteAsync(FightNoteCategory.Tactic, body);

        Assert.DoesNotContain("AAAAB3NzaC1yc2E", n.Body);
        Assert.Contains("[REDACTED:private-key]", n.Body);
    }

    [Fact]
    public async Task TakeNoteAsync_RecordsAuditWithoutBody()
    {
        var auditPath = Path.Combine(_root, "audit.jsonl");
        var audit = new AuditLog(auditPath);
        await using var nb = new FightNotebook(RunPath(), aggregatePath: null, audit: audit, enabled: true);

        await nb.TakeNoteAsync(
            FightNoteCategory.Lesson,
            "SeImpersonate => PrintSpoofer is the win path on srv2019.",
            tags: new[] { "windows", "winpe" });

        var auditText = File.ReadAllText(auditPath);
        Assert.Contains("notebook.take_note", auditText);
        Assert.Contains("body_sha256", auditText);
        Assert.DoesNotContain("PrintSpoofer", auditText);
    }

    [Fact]
    public async Task TakeNoteAsync_DisabledNotebook_DoesNotWriteToDisk()
    {
        await using var nb = new FightNotebook(RunPath(), aggregatePath: null, audit: null, enabled: false);

        var n = await nb.TakeNoteAsync(FightNoteCategory.Observation, "telemetry off");

        Assert.False(File.Exists(RunPath()));
        Assert.NotEmpty(n.BodySha256);
    }

    [Fact]
    public async Task ReadAsync_FiltersByCategoryAndTag_NewestFirst()
    {
        await using var nb = new FightNotebook(RunPath(), AggPath(), audit: null, enabled: true);
        await nb.TakeNoteAsync(FightNoteCategory.Observation, "first observation", tags: new[] { "smb" });
        await Task.Delay(15);
        await nb.TakeNoteAsync(FightNoteCategory.Tactic, "tactic on smb", tags: new[] { "smb", "ad" });
        await Task.Delay(15);
        await nb.TakeNoteAsync(FightNoteCategory.Tactic, "tactic on web", tags: new[] { "web" });

        var smb = await nb.ReadAsync(includeAggregate: false, anyTags: new[] { "smb" });
        Assert.Equal(2, smb.Count);
        // newest first
        Assert.Equal("tactic on smb", smb[0].Body);

        var tactics = await nb.ReadAsync(includeAggregate: false, category: "tactic");
        Assert.Equal(2, tactics.Count);
        Assert.All(tactics, t => Assert.Equal("tactic", t.Category));
    }

    [Fact]
    public async Task ReadAsync_DeduplicatesAcrossRunAndAggregate()
    {
        await using var nb = new FightNotebook(RunPath(), AggPath(), audit: null, enabled: true);
        await nb.TakeNoteAsync(FightNoteCategory.WinningMove, "the winning move");

        // Run + aggregate both contain the same line. ReadAsync must dedup.
        var notes = await nb.ReadAsync(includeAggregate: true);
        Assert.Single(notes);
    }

    [Fact]
    public void RedactSecrets_HandlesAuthorizationHeaderAndUserPassUrl()
    {
        var s = FightNotebook.RedactSecrets(
            "Authorization: Bearer abc123XYZ.token  http://admin:s3cret@10.0.0.5/api");
        Assert.Contains("[REDACTED:authz]", s);
        Assert.Contains("[REDACTED:basic-auth]", s);
        Assert.DoesNotContain("s3cret", s);
    }

    [Fact]
    public void RedactSecrets_HighEntropyHexBlobMasked()
    {
        var s = FightNotebook.RedactSecrets("hash=" + new string('a', 40));
        Assert.Contains("[REDACTED:hash]", s);
    }

    [Fact]
    public async Task TakeNoteAsync_NullBody_Throws()
    {
        await using var nb = new FightNotebook(RunPath(), aggregatePath: null, audit: null, enabled: true);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            nb.TakeNoteAsync(FightNoteCategory.Tactic, ""));
    }

    [Fact]
    public async Task TakeNoteAsync_PublicHost_NotRedacted()
    {
        await using var nb = new FightNotebook(RunPath(), aggregatePath: null, audit: null, enabled: true);
        var n = await nb.TakeNoteAsync(FightNoteCategory.Observation, "external recon", targetHost: "8.8.8.8");
        Assert.Equal("8.8.8.8", n.TargetHost);
    }
}
