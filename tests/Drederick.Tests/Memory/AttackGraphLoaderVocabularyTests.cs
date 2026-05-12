using Drederick.Audit;
using Drederick.Memory;
using Xunit;

namespace Drederick.Tests.Memory;

public class AttackGraphLoaderVocabularyTests
{
    private static string TempAuditPath()
    {
        var d = Path.Combine(Path.GetTempPath(), $"drederick-vocab-{Guid.NewGuid():N}");
        Directory.CreateDirectory(d);
        return Path.Combine(d, "audit.jsonl");
    }

    [Fact]
    public void Technique_Maps_To_Tactic()
    {
        var p = TempAuditPath();
        try
        {
            using var audit = new AuditLog(p);
            var vocab = new AttackGraphLoaderVocabulary();
            var r = vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind,
                "technique", AttackGraphLoaderVocabulary.Mode.Lab, "n1", audit);
            Assert.Equal("tactic", r.Canonical);
            Assert.True(r.Mapped);
            Assert.False(r.Rejected);
            Assert.Equal("technique", r.OriginalTerm);
        }
        finally { Directory.Delete(Path.GetDirectoryName(p)!, true); }
    }

    [Fact]
    public void Multiple_Aliases_Recognized()
    {
        var vocab = new AttackGraphLoaderVocabulary();
        var mode = AttackGraphLoaderVocabulary.Mode.Lab;

        Assert.Equal("credential",
            vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind, "loot", mode, "x", null).Canonical);
        Assert.Equal("privilege",
            vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind, "access", mode, "x", null).Canonical);
        Assert.Equal("stale",
            vocab.Resolve(AttackGraphLoaderVocabulary.Field.State, "invalidated", mode, "x", null).Canonical);
        Assert.Equal("owned",
            vocab.Resolve(AttackGraphLoaderVocabulary.Field.State, "pwned", mode, "x", null).Canonical);
        Assert.Equal("host",
            vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind, "machine", mode, "x", null).Canonical);
    }

    [Fact]
    public void Unknown_Vocab_In_Strict_Mode_Is_Rejected()
    {
        var vocab = new AttackGraphLoaderVocabulary();
        var r = vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind,
            "zorglub", AttackGraphLoaderVocabulary.Mode.Strict, "n1", null);
        Assert.True(r.Rejected);
        Assert.False(r.Mapped);
        Assert.Equal(string.Empty, r.Canonical);
        Assert.Equal("zorglub", r.OriginalTerm);
    }

    [Fact]
    public void Lab_Mode_Warns_And_Accepts_Unknown_Vocab()
    {
        var p = TempAuditPath();
        try
        {
            using (var audit = new AuditLog(p))
            {
                var vocab = new AttackGraphLoaderVocabulary();
                var r = vocab.Resolve(AttackGraphLoaderVocabulary.Field.State,
                    "weirdstate", AttackGraphLoaderVocabulary.Mode.Lab, "n7", audit);
                Assert.False(r.Rejected);
                Assert.False(r.Mapped);
                Assert.Equal("weirdstate", r.Canonical);
            }

            var text = File.ReadAllText(p);
            Assert.Contains("attack_graph.vocab.unknown", text);
            Assert.Contains("weirdstate", text);
            Assert.Contains("\"n7\"", text);
        }
        finally { Directory.Delete(Path.GetDirectoryName(p)!, true); }
    }

    [Fact]
    public void Audit_Event_Records_Source_And_Target_Terms()
    {
        var p = TempAuditPath();
        try
        {
            using (var audit = new AuditLog(p))
            {
                var vocab = new AttackGraphLoaderVocabulary();
                vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind,
                    "loot", AttackGraphLoaderVocabulary.Mode.Lab, "node-42", audit);
            }

            var text = File.ReadAllText(p);
            Assert.Contains("attack_graph.deprecated_vocab", text);
            Assert.Contains("\"old_term\":\"loot\"", text);
            Assert.Contains("\"new_term\":\"credential\"", text);
            Assert.Contains("\"node_id\":\"node-42\"", text);
            Assert.Contains("\"field\":\"kind\"", text);
        }
        finally { Directory.Delete(Path.GetDirectoryName(p)!, true); }
    }

    [Fact]
    public void Matching_Is_Case_Insensitive()
    {
        var vocab = new AttackGraphLoaderVocabulary();
        var mode = AttackGraphLoaderVocabulary.Mode.Lab;

        var upper = vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind, "TECHNIQUE", mode, "x", null);
        Assert.Equal("tactic", upper.Canonical);
        Assert.True(upper.Mapped);

        var mixed = vocab.Resolve(AttackGraphLoaderVocabulary.Field.State, "InValidated", mode, "x", null);
        Assert.Equal("stale", mixed.Canonical);
        Assert.True(mixed.Mapped);

        var canonical = vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind, "HOST", mode, "x", null);
        Assert.Equal("host", canonical.Canonical);
        Assert.False(canonical.Mapped);
    }

    [Fact]
    public void Canonical_Term_Is_Not_Marked_As_Mapped()
    {
        var p = TempAuditPath();
        try
        {
            using (var audit = new AuditLog(p))
            {
                var vocab = new AttackGraphLoaderVocabulary();
                var r = vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind,
                    "credential", AttackGraphLoaderVocabulary.Mode.Strict, "n1", audit);
                Assert.Equal("credential", r.Canonical);
                Assert.False(r.Mapped);
                Assert.False(r.Rejected);
            }
            var text = File.Exists(p) ? File.ReadAllText(p) : string.Empty;
            Assert.DoesNotContain("attack_graph.deprecated_vocab", text);
            Assert.DoesNotContain("attack_graph.vocab.unknown", text);
        }
        finally { Directory.Delete(Path.GetDirectoryName(p)!, true); }
    }

    [Fact]
    public void Strict_Mode_Still_Maps_Known_Aliases()
    {
        var p = TempAuditPath();
        try
        {
            using (var audit = new AuditLog(p))
            {
                var vocab = new AttackGraphLoaderVocabulary();
                var r = vocab.Resolve(AttackGraphLoaderVocabulary.Field.Kind,
                    "loot", AttackGraphLoaderVocabulary.Mode.Strict, "n1", audit);
                Assert.Equal("credential", r.Canonical);
                Assert.True(r.Mapped);
                Assert.False(r.Rejected);
            }
            var text = File.ReadAllText(p);
            Assert.Contains("attack_graph.deprecated_vocab", text);
            Assert.Contains("\"mode\":\"strict\"", text);
        }
        finally { Directory.Delete(Path.GetDirectoryName(p)!, true); }
    }
}
