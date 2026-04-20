using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Drederick.Doctor;

namespace Drederick.Enrichment;

/// <summary>
/// Queries the local <c>searchsploit</c> CLI (Exploit-DB mirror) for PoC
/// entries matching a CVE id. Gracefully no-ops when <c>searchsploit</c> is
/// not on PATH. When caching is enabled, mirrors each matching entry into
/// <c>&lt;cache&gt;/exploit-db/&lt;edb-id&gt;/&lt;filename&gt;</c> verbatim —
/// SHA-256 is recorded against the raw bytes of the source file (no
/// neutralisation, no re-encoding).
/// </summary>
public sealed class SearchsploitSource : IPocSource
{
    public const string SourceName = "exploit-db";
    private const int TimeoutSeconds = 30;

    private readonly IProcessRunner _runner;
    private readonly IFileSystem _fs;

    public SearchsploitSource(IProcessRunner? runner = null, IFileSystem? fs = null)
    {
        _runner = runner ?? new DefaultProcessRunner();
        _fs = fs ?? new RealFileSystem();
    }

    public string Name => SourceName;

    public Task<IReadOnlyList<PocRef>> QueryAsync(string cveId, PocQueryContext ctx, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);
        ArgumentNullException.ThrowIfNull(ctx);

        IReadOnlyList<PocRef> empty = Array.Empty<PocRef>();

        (int code, string stdout, string stderr) res;
        try
        {
            res = _runner.Run("searchsploit", $"--json {ShellArg(cveId)}", TimeoutSeconds);
        }
        catch (Win32Exception)
        {
            // searchsploit not on PATH — silent no-op, as spec requires.
            return Task.FromResult(empty);
        }
        catch (InvalidOperationException)
        {
            return Task.FromResult(empty);
        }
        catch (TimeoutException)
        {
            return Task.FromResult(empty);
        }

        if (res.code != 0 || string.IsNullOrWhiteSpace(res.stdout))
        {
            return Task.FromResult(empty);
        }

        List<ParsedEntry> entries;
        try { entries = ParseEntries(res.stdout); }
        catch (JsonException) { return Task.FromResult(empty); }

        var refs = new List<PocRef>(entries.Count);
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.EdbId)) continue;
            var url = $"https://www.exploit-db.com/exploits/{entry.EdbId}";
            string? localPath = null;

            if (ctx.FetchPoc)
            {
                try
                {
                    localPath = MirrorEntry(entry, ctx);
                }
                catch (Win32Exception) { /* searchsploit vanished mid-run */ }
                catch (InvalidOperationException) { }
                catch (TimeoutException) { }
                catch (IOException) { }
            }

            refs.Add(new PocRef(Name, Url: url, ExternalId: entry.EdbId, LocalPath: localPath));
        }

        return Task.FromResult<IReadOnlyList<PocRef>>(refs);
    }

    private string? MirrorEntry(ParsedEntry entry, PocQueryContext ctx)
    {
        // The `searchsploit --json` output carries `Path`: an absolute path to
        // the source file inside the local exploit-db mirror. That file is our
        // "source of truth" — we copy it verbatim into the cache directory so
        // the SHA-256 matches whatever searchsploit would have shipped.
        var sourcePath = entry.Path;
        if (string.IsNullOrWhiteSpace(sourcePath) || !_fs.FileExists(sourcePath))
        {
            // Fall back to `searchsploit -m` which mirrors into CWD. We run it
            // in a dedicated staging dir to capture the single copied file.
            var staging = Path.Combine(ctx.CacheRoot, Name, entry.EdbId!, ".staging");
            _fs.CreateDirectory(staging);
            var shellCmd = $"cd {ShellArg(staging)} && searchsploit -m {ShellArg(entry.EdbId!)}";
            try { _ = _runner.RunShell(shellCmd, TimeoutSeconds); }
            catch (Win32Exception) { return null; }
            catch (InvalidOperationException) { return null; }
            catch (TimeoutException) { return null; }
            var staged = _fs.EnumerateFiles(staging).FirstOrDefault();
            if (staged is null) return null;
            sourcePath = staged;
        }

        var dir = Path.Combine(ctx.CacheRoot, Name, entry.EdbId!);
        _fs.CreateDirectory(dir);
        var fileName = Path.GetFileName(sourcePath);
        if (string.IsNullOrWhiteSpace(fileName)) fileName = $"{entry.EdbId}.bin";
        var dest = Path.Combine(dir, fileName);

        // Verbatim copy — no content rewrite. SHA-256 is of the raw bytes.
        var bytes = _fs.ReadAllBytes(sourcePath);
        _fs.WriteAllBytes(dest, bytes);
        var sha = Sha256Hex(bytes);

        ctx.Report.UpsertPocSource(
            source: Name,
            externalId: entry.EdbId!,
            sha256: sha,
            path: dest,
            fetchedAt: DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture),
            sourceUrl: $"https://www.exploit-db.com/exploits/{entry.EdbId}");
        return dest;
    }

    internal sealed record ParsedEntry(string? EdbId, string? Title, string? Path);

    internal static List<ParsedEntry> ParseEntries(string json)
    {
        var list = new List<ParsedEntry>();
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("RESULTS_EXPLOIT", out var arr)
            || arr.ValueKind != JsonValueKind.Array) return list;
        foreach (var el in arr.EnumerateArray())
        {
            string? edb = GetString(el, "EDB-ID") ?? GetString(el, "Edb-Id") ?? GetString(el, "edb_id");
            string? title = GetString(el, "Title");
            string? path = GetString(el, "Path");
            list.Add(new ParsedEntry(edb, title, path));
        }
        return list;
    }

    private static string? GetString(JsonElement el, string prop)
    {
        if (el.ValueKind != JsonValueKind.Object) return null;
        if (!el.TryGetProperty(prop, out var v)) return null;
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.ToString(),
            _ => null,
        };
    }

    private static string Sha256Hex(byte[] bytes)
    {
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string ShellArg(string s)
    {
        // Single-quote wrap with embedded-quote escape. Our callers only pass
        // numeric EDB ids, CVE ids, and whitelisted paths, but be explicit.
        return "'" + s.Replace("'", "'\\''") + "'";
    }
}

/// <summary>Small filesystem abstraction so tests can avoid disk I/O.</summary>
public interface IFileSystem
{
    bool FileExists(string path);
    byte[] ReadAllBytes(string path);
    void WriteAllBytes(string path, byte[] bytes);
    void CreateDirectory(string path);
    IEnumerable<string> EnumerateFiles(string path);
}

internal sealed class RealFileSystem : IFileSystem
{
    public bool FileExists(string path) => File.Exists(path);
    public byte[] ReadAllBytes(string path) => File.ReadAllBytes(path);
    public void WriteAllBytes(string path, byte[] bytes) => File.WriteAllBytes(path, bytes);
    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
    public IEnumerable<string> EnumerateFiles(string path)
        => Directory.Exists(path) ? Directory.EnumerateFiles(path) : Enumerable.Empty<string>();
}
