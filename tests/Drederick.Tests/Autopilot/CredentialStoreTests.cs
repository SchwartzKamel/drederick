using Drederick.Audit;
using Drederick.Autopilot;
using Xunit;

namespace Drederick.Tests.Autopilot;

public class CredentialStoreTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"cred-store-{Guid.NewGuid():N}.jsonl");

    [Fact]
    public void Add_And_List_Credentials()
    {
        using var audit = new AuditLog(NewAuditPath());
        var store = new CredentialStore(audit);

        Assert.True(store.Add("alice", "Hunter2", "CORP"));
        Assert.True(store.Add("bob", "letmein"));
        // Idempotent: same tuple doesn't double.
        Assert.False(store.Add("alice", "Hunter2", "CORP"));

        var list = store.List();
        Assert.Equal(2, list.Count);
        // Realms are lowercased during normalization for case-insensitive dedup.
        Assert.Contains(list, c => c.User == "alice" && c.Realm == "corp");
        Assert.Contains(list, c => c.User == "bob" && c.Realm is null);
    }

    [Fact]
    public void TryGetSecret_Validates_Hash()
    {
        using var audit = new AuditLog(NewAuditPath());
        var store = new CredentialStore(audit);
        store.Add("root", "toor");

        var goodRef = new CredentialRef
        {
            User = "root", PasswordSha256 = CredentialStore.Sha256Hex("toor"),
        };
        var badRef = new CredentialRef
        {
            User = "root", PasswordSha256 = CredentialStore.Sha256Hex("different"),
        };
        Assert.Equal("toor", store.TryGetSecret(goodRef));
        Assert.Null(store.TryGetSecret(badRef));
    }

    [Fact]
    public void Attempt_Matrix_Tracks_Duplicates()
    {
        using var audit = new AuditLog(NewAuditPath());
        var store = new CredentialStore(audit);
        store.Add("admin", "admin");
        var cred = store.List()[0];

        Assert.False(store.HasAttempted("10.10.10.5", "smb", cred));
        store.RecordAttempt("10.10.10.5", "smb", cred, succeeded: false);
        Assert.True(store.HasAttempted("10.10.10.5", "smb", cred));
        // Different host → not yet attempted.
        Assert.False(store.HasAttempted("10.10.10.6", "smb", cred));
        // Different service → not yet attempted.
        Assert.False(store.HasAttempted("10.10.10.5", "ssh", cred));
    }

    [Fact]
    public void Seed_Default_Lab_Adds_Known_Pairs()
    {
        using var audit = new AuditLog(NewAuditPath());
        var store = new CredentialStore(audit);
        var added = store.SeedDefaultLab();
        Assert.True(added >= 4);
        Assert.True(store.Count >= 4);
        Assert.Contains(store.List(), c => c.User == "root");
        Assert.Contains(store.List(), c => c.User == "admin");
    }

    [Fact]
    public void Plaintext_Never_Logged_In_Audit()
    {
        var path = NewAuditPath();
        try
        {
            using (var audit = new AuditLog(path))
            {
                var store = new CredentialStore(audit);
                store.Add("alice", "SuperSecretCanary42", "CORP");
                var r = store.List()[0];
                _ = store.TryGetSecret(r);
                store.RecordAttempt("10.10.10.5", "smb", r, succeeded: true);
            }
            var text = File.ReadAllText(path);
            Assert.DoesNotContain("SuperSecretCanary42", text);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }
}
