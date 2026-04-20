using System.ComponentModel;
using System.Security.Cryptography;
using Drederick.Enrichment;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

public class SearchsploitSourceTests : IDisposable
{
    private readonly string _workDir;

    public SearchsploitSourceTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "drederick-ss-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workDir, recursive: true); } catch { }
    }

    private static string LoadFixture(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "fixtures", name);
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException($"fixture not found: {name}");
    }

    [Fact]
    public async Task Returns_empty_when_searchsploit_missing()
    {
        var runner = new RecordingProcessRunner();
        runner.OnRunThrow((f, _) => f == "searchsploit", new Win32Exception(2, "no such file"));

        var src = new SearchsploitSource(runner);
        var outDir = _workDir;
        var report = new SqliteReport(outDir);
        var ctx = new PocQueryContext(Path.Combine(outDir, "poc_cache"), fetchPoc: true, report);

        var refs = await src.QueryAsync("CVE-2011-2523", ctx, CancellationToken.None);
        Assert.Empty(refs);
    }

    [Fact]
    public async Task Parses_json_into_refs_without_caching_when_fetch_off()
    {
        var runner = new RecordingProcessRunner();
        var json = LoadFixture("searchsploit-sample.json");
        runner.OnRun((f, a) => f == "searchsploit" && a.Contains("--json"), 0, stdout: json);

        var src = new SearchsploitSource(runner);
        var outDir = _workDir;
        var report = new SqliteReport(outDir);
        var ctx = new PocQueryContext(Path.Combine(outDir, "poc_cache"), fetchPoc: false, report);

        var refs = await src.QueryAsync("CVE-2011-2523", ctx, CancellationToken.None);

        Assert.Equal(2, refs.Count);
        Assert.All(refs, r => Assert.Equal("exploit-db", r.Source));
        Assert.Contains(refs, r => r.ExternalId == "17491" && r.Url == "https://www.exploit-db.com/exploits/17491");
        Assert.All(refs, r => Assert.Null(r.LocalPath));
        // No shell / mirror invocation when fetchPoc is off.
        Assert.DoesNotContain(runner.Calls, c => c.Kind == "shell");
    }

    [Fact]
    public async Task Caches_source_verbatim_with_matching_sha256_when_fetch_on()
    {
        // Put a fake exploit source file on disk where `Path` in the JSON points.
        var exploitDir = Path.Combine(_workDir, "edb", "exploits", "unix", "remote");
        Directory.CreateDirectory(exploitDir);
        var srcFile17491 = Path.Combine(exploitDir, "17491.rb");
        var body17491 = System.Text.Encoding.UTF8.GetBytes("# vsftpd 2.3.4 backdoor module — verbatim bytes\n");
        File.WriteAllBytes(srcFile17491, body17491);
        var srcFile49757 = Path.Combine(exploitDir, "49757.py");
        var body49757 = System.Text.Encoding.UTF8.GetBytes("# py version\nprint('non-executed')\n");
        File.WriteAllBytes(srcFile49757, body49757);

        var rewritten = LoadFixture("searchsploit-sample.json")
            .Replace("/usr/share/exploitdb/exploits/unix/remote/17491.rb", srcFile17491)
            .Replace("/usr/share/exploitdb/exploits/unix/remote/49757.py", srcFile49757);

        var runner = new RecordingProcessRunner();
        runner.OnRun((f, a) => f == "searchsploit" && a.Contains("--json"), 0, stdout: rewritten);

        var outDir = _workDir;
        var cacheRoot = Path.Combine(outDir, "poc_cache");
        var report = new SqliteReport(outDir);
        var ctx = new PocQueryContext(cacheRoot, fetchPoc: true, report);

        var src = new SearchsploitSource(runner);
        var refs = await src.QueryAsync("CVE-2011-2523", ctx, CancellationToken.None);

        Assert.Equal(2, refs.Count);
        var r17491 = refs.Single(r => r.ExternalId == "17491");
        Assert.NotNull(r17491.LocalPath);
        Assert.True(File.Exists(r17491.LocalPath));
        var cachedBytes = File.ReadAllBytes(r17491.LocalPath!);
        // Verbatim: cached bytes must equal the source file bytes.
        Assert.Equal(body17491, cachedBytes);

        // poc_sources row must record the same SHA-256 we compute off-disk.
        var sha = Convert.ToHexString(SHA256.HashData(body17491)).ToLowerInvariant();
        using var conn = new SqliteConnection($"Data Source={report.DatabasePath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sha256, path, source_url FROM poc_sources WHERE source='exploit-db' AND external_id='17491';";
        using var reader = cmd.ExecuteReader();
        Assert.True(reader.Read());
        Assert.Equal(sha, reader.GetString(0));
        Assert.Equal(r17491.LocalPath, reader.GetString(1));
        Assert.Equal("https://www.exploit-db.com/exploits/17491", reader.GetString(2));
    }

    [Fact]
    public async Task Parse_handles_missing_array()
    {
        // No RESULTS_EXPLOIT array -> empty refs, no throw.
        var runner = new RecordingProcessRunner();
        runner.OnRun((f, a) => f == "searchsploit", 0, stdout: "{}");
        var src = new SearchsploitSource(runner);
        var report = new SqliteReport(_workDir);
        var ctx = new PocQueryContext(Path.Combine(_workDir, "cache"), false, report);
        Assert.Empty(await src.QueryAsync("CVE-2011-2523", ctx, CancellationToken.None));
    }
}
