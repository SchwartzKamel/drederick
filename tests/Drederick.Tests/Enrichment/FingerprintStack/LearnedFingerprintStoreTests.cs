using System.Text.Json;
using Drederick.Enrichment.FingerprintStack;
using Xunit;

namespace Drederick.Tests.Enrichment.FingerprintStack;

public class LearnedFingerprintStoreTests
{
    private static string NewOutRoot()
    {
        var p = Path.Combine(Path.GetTempPath(), "drederick-lfp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(p);
        return p;
    }

    private static LearnedFingerprint MakeEntry(string kind, string value, string fight, int port = 80)
    {
        var now = DateTimeOffset.UtcNow.ToString("o");
        return new LearnedFingerprint(
            Id: LearnedFingerprintStore.ComputeId(kind, value),
            SignalKind: kind,
            SignalValue: value,
            Vendor: "vendor",
            Product: "product",
            Version: "1.0",
            Port: port,
            Hits: 1,
            FirstSeen: now,
            LastSeen: now,
            EvidenceFights: new[] { fight });
    }

    [Fact]
    public async Task LoadAsync_MissingFile_ReturnsEmptyStore()
    {
        var root = NewOutRoot();
        try
        {
            var store = new LearnedFingerprintStore(root);
            await store.LoadAsync();
            Assert.Equal(0, store.Count);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task UpsertSaveLoad_RoundTripsEntries()
    {
        var root = NewOutRoot();
        try
        {
            var store = new LearnedFingerprintStore(root);
            store.Upsert(MakeEntry("http_server", "Microsoft-HTTPAPI/2.0", "fight-a", 5985));
            await store.SaveAsync();

            var reloaded = new LearnedFingerprintStore(root);
            await reloaded.LoadAsync();
            Assert.Equal(1, reloaded.Count);
            Assert.True(reloaded.TryGetByValue("http_server", "Microsoft-HTTPAPI/2.0", out var fp));
            Assert.Equal(5985, fp.Port);
            Assert.Single(fp.EvidenceFights);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task SaveAsync_IsIdempotent_TwoCallsProduceSameEntries()
    {
        var root = NewOutRoot();
        try
        {
            var store = new LearnedFingerprintStore(root);
            store.Upsert(MakeEntry("http_server", "nginx/1.19", "fight-a"));
            await store.SaveAsync();
            var first = await File.ReadAllTextAsync(store.Path);
            await store.SaveAsync();
            var second = await File.ReadAllTextAsync(store.Path);

            // The "updated" timestamp differs between saves; entries must not.
            using var d1 = JsonDocument.Parse(first);
            using var d2 = JsonDocument.Parse(second);
            var e1 = d1.RootElement.GetProperty("entries").GetRawText();
            var e2 = d2.RootElement.GetProperty("entries").GetRawText();
            Assert.Equal(e1, e2);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void Upsert_SameId_IncrementsHits_AndDedupsEvidenceFights()
    {
        var root = NewOutRoot();
        try
        {
            var store = new LearnedFingerprintStore(root);
            store.Upsert(MakeEntry("http_server", "Apache/2.4.41", "fight-a"));
            store.Upsert(MakeEntry("http_server", "Apache/2.4.41", "fight-b"));
            store.Upsert(MakeEntry("http_server", "Apache/2.4.41", "fight-a")); // dup fight id

            Assert.True(store.TryGetByValue("http_server", "Apache/2.4.41", out var fp));
            Assert.Equal(3, fp.Hits);
            Assert.Equal(2, fp.EvidenceFights.Count);
            Assert.Contains("fight-a", fp.EvidenceFights);
            Assert.Contains("fight-b", fp.EvidenceFights);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void TryGetByValue_MissingEntry_ReturnsFalse()
    {
        var root = NewOutRoot();
        try
        {
            var store = new LearnedFingerprintStore(root);
            Assert.False(store.TryGetByValue("http_server", "absent", out _));
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void ComputeId_DifferentKindsOrValues_ProduceDifferentIds()
    {
        var a = LearnedFingerprintStore.ComputeId("http_server", "Apache/2.4.41");
        var b = LearnedFingerprintStore.ComputeId("ssh_banner", "Apache/2.4.41");
        var c = LearnedFingerprintStore.ComputeId("http_server", "nginx/1.19");
        Assert.NotEqual(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal(a, LearnedFingerprintStore.ComputeId("http_server", "Apache/2.4.41"));
    }

    [Fact]
    public void Upsert_FromManyThreads_NoLostUpdates()
    {
        var root = NewOutRoot();
        try
        {
            var store = new LearnedFingerprintStore(root);
            const int threads = 16;
            const int perThread = 50;
            var tasks = new Task[threads];
            for (var t = 0; t < threads; t++)
            {
                var fight = $"fight-{t}";
                tasks[t] = Task.Run(() =>
                {
                    for (var i = 0; i < perThread; i++)
                    {
                        store.Upsert(MakeEntry("http_server", "Microsoft-HTTPAPI/2.0", fight, 5985));
                    }
                });
            }
            Task.WaitAll(tasks);

            Assert.True(store.TryGetByValue("http_server", "Microsoft-HTTPAPI/2.0", out var fp));
            Assert.Equal(threads * perThread, fp.Hits);
            Assert.Equal(threads, fp.EvidenceFights.Count);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task LoadAsync_CorruptFile_ReturnsEmptyStore()
    {
        var root = NewOutRoot();
        try
        {
            var path = Path.Combine(root, "memory", "learned-fingerprints.json");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, "{ this is not json");
            var store = new LearnedFingerprintStore(root);
            await store.LoadAsync();
            Assert.Equal(0, store.Count);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task SaveAsync_PersistsToCorrectPath()
    {
        var root = NewOutRoot();
        try
        {
            var store = new LearnedFingerprintStore(root);
            store.Upsert(MakeEntry("http_server", "nginx/1.19", "fight-a"));
            await store.SaveAsync();
            Assert.True(File.Exists(Path.Combine(root, "memory", "learned-fingerprints.json")));
        }
        finally { Directory.Delete(root, true); }
    }
}
