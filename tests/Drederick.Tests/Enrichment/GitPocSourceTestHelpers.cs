using System.Collections.Concurrent;
using Drederick.Audit;
using Drederick.Enrichment;

namespace Drederick.Tests.Enrichment;

/// <summary>
/// In-memory <see cref="IGitClient"/> that materialises a fake repo on disk
/// when <see cref="CloneSparseAsync"/> is called. Tests script the
/// resulting tree via <see cref="Layout"/> (relative path → file content).
/// Records every clone for assertions; refuses any URL not on the
/// hard-coded allowlist.
/// </summary>
internal sealed class FakeGitClient : IGitClient
{
    public sealed record CloneCall(string Url, string Dest, IReadOnlyList<string> SparsePaths);

    public List<CloneCall> Clones { get; } = new();
    public Dictionary<string, byte[]> Layout { get; } = new();
    public bool ForceFail { get; set; }
    public int FailExitCode { get; set; } = 128;
    public string FailStderr { get; set; } = "fatal: unable to access repository";
    public string FailStage { get; set; } = "clone";
    public string GitVersion { get; set; } = "git version 2.43.0 (fake)";
    public bool EgressOk { get; set; } = true;
    public string EgressStderr { get; set; } = string.Empty;
    public ConcurrentBag<string> CachedDirs { get; } = new();

    public bool IsCached(string repoDir) => CachedDirs.Contains(repoDir);

    public Task<GitCloneResult> CloneSparseAsync(
        string repoUrl,
        string destDir,
        IReadOnlyList<string> sparsePaths,
        CancellationToken ct)
    {
        Clones.Add(new CloneCall(repoUrl, destDir, sparsePaths.ToArray()));
        if (!GitPocAllowlist.IsAllowed(repoUrl))
            return Task.FromResult(new GitCloneResult(false, -1, "url not on allowlist", "url-not-allowed"));
        if (ForceFail)
            return Task.FromResult(new GitCloneResult(false, FailExitCode, FailStderr, FailStage));
        Directory.CreateDirectory(Path.Combine(destDir, ".git"));
        foreach (var (rel, body) in Layout)
        {
            var full = Path.Combine(destDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllBytes(full, body);
        }
        CachedDirs.Add(destDir);
        return Task.FromResult(new GitCloneResult(true, 0, string.Empty, "ok"));
    }

    public Task<GitEgressResult> ProbeEgressAsync(CancellationToken ct)
        => Task.FromResult(new GitEgressResult(EgressOk, EgressOk ? 0 : 128, EgressStderr, "git ls-remote (fake)"));
}

/// <summary>
/// In-memory <see cref="IGitHubHttpClient"/> for <see cref="PocInGitHubSource"/>
/// tests. Maps URL → response; supports a 429 stub for rate-limit tests.
/// Records every request including auth header for the GITHUB_TOKEN test.
/// </summary>
internal sealed class FakeGitHubHttpClient : IGitHubHttpClient
{
    public List<string> RequestedUrls { get; } = new();
    public Dictionary<string, GitHubFetchResult> Responses { get; } = new(StringComparer.Ordinal);
    public GitHubFetchResult? DefaultResponse { get; set; }
    public Func<string, Task<GitHubFetchResult>>? Handler { get; set; }

    public Task<GitHubFetchResult> GetAsync(string url, CancellationToken ct)
    {
        RequestedUrls.Add(url);
        if (Handler is not null) return Handler(url);
        if (Responses.TryGetValue(url, out var r)) return Task.FromResult(r);
        return Task.FromResult(DefaultResponse ?? new GitHubFetchResult(404, null, null, null));
    }
}

internal static class TestEnv
{
    public static (string WorkDir, AuditLog Audit, Drederick.Reporting.SqliteReport Report) Make(string prefix)
    {
        var work = Path.Combine(Path.GetTempPath(), $"drederick-{prefix}-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        var audit = new AuditLog(Path.Combine(work, "audit.jsonl"));
        var report = new Drederick.Reporting.SqliteReport(work);
        return (work, audit, report);
    }

    public static PocQueryContext Ctx(string workDir, AuditLog audit, Drederick.Reporting.SqliteReport report, bool fetch = true)
        => new(Path.Combine(workDir, "poc_cache"), fetch, report, audit);

    public static IReadOnlyList<string> ReadAuditEvents(string workDir)
    {
        var path = Path.Combine(workDir, "audit.jsonl");
        if (!File.Exists(path)) return Array.Empty<string>();
        return File.ReadAllLines(path);
    }
}
