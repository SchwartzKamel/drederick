using System.Reflection;
using System.Text.Json;

namespace Drederick.Enrichment.FingerprintStack.Signals;

/// <summary>
/// Loads the embedded favicon SHA-256 corpus (favicon-corpus.json) and
/// exposes a fast hash → (vendor, product) lookup. The default singleton
/// loads the resource shipped with the assembly; tests may construct a
/// corpus directly with <see cref="FaviconCorpus(IDictionary{string, FaviconCorpusEntry})"/>.
/// </summary>
public sealed class FaviconCorpus
{
    private readonly Dictionary<string, FaviconCorpusEntry> _byHash;

    public FaviconCorpus(IDictionary<string, FaviconCorpusEntry> entries)
    {
        _byHash = new Dictionary<string, FaviconCorpusEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in entries)
        {
            _byHash[k.Trim().ToLowerInvariant()] = v;
        }
    }

    public int Count => _byHash.Count;

    public bool TryLookup(string sha256Hex, out FaviconCorpusEntry entry)
        => _byHash.TryGetValue(sha256Hex.Trim().ToLowerInvariant(), out entry!);

    public static FaviconCorpus LoadEmbedded()
    {
        var asm = typeof(FaviconCorpus).Assembly;
        var name = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("favicon-corpus.json", StringComparison.OrdinalIgnoreCase));
        if (name is null)
            return new FaviconCorpus(new Dictionary<string, FaviconCorpusEntry>());

        using var stream = asm.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException("Failed to open favicon-corpus.json resource stream.");
        using var doc = JsonDocument.Parse(stream);
        var root = doc.RootElement;
        var entries = new Dictionary<string, FaviconCorpusEntry>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("entries", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var e in arr.EnumerateArray())
            {
                if (!e.TryGetProperty("sha256", out var sh)) continue;
                var hash = sh.GetString();
                if (string.IsNullOrWhiteSpace(hash)) continue;
                var vendor = e.TryGetProperty("vendor", out var v) ? v.GetString() ?? "" : "";
                var product = e.TryGetProperty("product", out var p) ? p.GetString() ?? "" : "";
                var version = e.TryGetProperty("version", out var ver) ? ver.GetString() : null;
                entries[hash] = new FaviconCorpusEntry(vendor, product, version);
            }
        }
        return new FaviconCorpus(entries);
    }
}

public sealed record FaviconCorpusEntry(string Vendor, string Product, string? Version);
