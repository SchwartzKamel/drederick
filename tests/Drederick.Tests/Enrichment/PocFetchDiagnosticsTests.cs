using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Enrichment;
using Xunit;

namespace Drederick.Tests.Enrichment;

/// <summary>
/// GAP-053 — tests for <see cref="PocFetchDiagnostics"/>. Verifies the
/// new <c>poc.fetch.error.diagnosed</c> audit event contains git
/// presence + DNS + HTTPS-reachability classification, and that auth
/// tokens are stripped from both <c>target_url</c> and stderr.
/// </summary>
public sealed class PocFetchDiagnosticsTests
{
    // --- test doubles ----------------------------------------------------

    private sealed class StubGitClient : IGitClient
    {
        public string GitVersion { get; set; } = "git version 2.43.0";
        public GitCloneResult Result { get; set; } = new(false, 128, "fatal: could not resolve host: github.com", "clone");
        public bool IsCached(string repoDir) => false;
        public Task<GitCloneResult> CloneSparseAsync(string repoUrl, string destDir, IReadOnlyList<string> sparsePaths, CancellationToken ct)
            => Task.FromResult(Result);
        public Task<GitEgressResult> ProbeEgressAsync(CancellationToken ct)
            => Task.FromResult(new GitEgressResult(false, 128, string.Empty, "fake-probe"));
    }

    private sealed class StubDns : IDnsResolver
    {
        public DnsProbeResult Result { get; set; } = new(true, new[] { "140.82.114.4" }, null);
        public List<string> Hosts { get; } = new();
        public Task<DnsProbeResult> ResolveAsync(string host, CancellationToken ct)
        {
            Hosts.Add(host);
            return Task.FromResult(Result);
        }
    }

    private sealed class StubHttp : IHttpReachabilityProbe
    {
        public HttpProbeResult Result { get; set; } = new(true, 200, null);
        public List<string> Urls { get; } = new();
        public Task<HttpProbeResult> HeadAsync(string url, CancellationToken ct)
        {
            Urls.Add(url);
            return Task.FromResult(Result);
        }
    }

    private static (string work, AuditLog audit) NewAudit(string suffix)
    {
        var work = Path.Combine(Path.GetTempPath(), $"drederick-pocdiag-{suffix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(work);
        return (work, new AuditLog(Path.Combine(work, "audit.jsonl")));
    }

    private static IReadOnlyList<JsonElement> ReadEvents(string work, string evt)
    {
        var path = Path.Combine(work, "audit.jsonl");
        if (!File.Exists(path)) return Array.Empty<JsonElement>();
        var list = new List<JsonElement>();
        foreach (var line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement.Clone();
            if (root.GetProperty("event").GetString() == evt) list.Add(root);
        }
        return list;
    }

    // --- success path: no diagnostic event ------------------------------

    [Fact]
    public async Task WrapAsync_returns_result_without_audit_when_operation_succeeds()
    {
        var (work, audit) = NewAudit("ok");
        try
        {
            var git = new StubGitClient { Result = new GitCloneResult(true, 0, string.Empty, "ok") };
            var diag = new PocFetchDiagnostics(git, new StubDns(), new StubHttp());

            var r = await diag.WrapAsync(audit, "metasploit-git", "CVE-2024-1",
                "https://github.com/rapid7/metasploit-framework",
                _ => Task.FromResult(git.Result), CancellationToken.None);

            Assert.True(r.Success);
            audit.Dispose();
            Assert.Empty(ReadEvents(work, "poc.fetch.error.diagnosed"));
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    // --- captures git --version when present -----------------------------

    [Fact]
    public async Task WrapAsync_captures_git_version_and_present_true()
    {
        var (work, audit) = NewAudit("gitver");
        try
        {
            var git = new StubGitClient { GitVersion = "git version 2.44.1 (test)" };
            var diag = new PocFetchDiagnostics(git, new StubDns(), new StubHttp());

            await diag.WrapAsync(audit, "metasploit-git", "CVE-2024-1",
                "https://github.com/rapid7/metasploit-framework",
                _ => Task.FromResult(git.Result), CancellationToken.None);
            audit.Dispose();

            var evts = ReadEvents(work, "poc.fetch.error.diagnosed");
            var e = Assert.Single(evts);
            Assert.True(e.GetProperty("git_present").GetBoolean());
            Assert.Equal("git version 2.44.1 (test)", e.GetProperty("git_version").GetString());
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    [Fact]
    public async Task WrapAsync_reports_git_present_false_when_binary_missing()
    {
        var (work, audit) = NewAudit("nogit");
        try
        {
            var git = new StubGitClient { GitVersion = "git not available: No such file or directory" };
            var diag = new PocFetchDiagnostics(git, new StubDns(), new StubHttp());

            await diag.WrapAsync(audit, "nuclei-git", "CVE-2024-2",
                "https://github.com/projectdiscovery/nuclei-templates",
                _ => Task.FromResult(git.Result), CancellationToken.None);
            audit.Dispose();

            var e = Assert.Single(ReadEvents(work, "poc.fetch.error.diagnosed"));
            Assert.False(e.GetProperty("git_present").GetBoolean());
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    // --- classifies DNS vs HTTPS failure --------------------------------

    [Fact]
    public async Task WrapAsync_classifies_dns_failure_with_dns_ok_false()
    {
        var (work, audit) = NewAudit("dnsfail");
        try
        {
            var git = new StubGitClient();
            var dns = new StubDns { Result = new DnsProbeResult(false, Array.Empty<string>(), "HostNotFound") };
            var diag = new PocFetchDiagnostics(git, dns, new StubHttp { Result = new HttpProbeResult(false, null, "Timeout") });

            await diag.WrapAsync(audit, "metasploit-git", "CVE-2024-1",
                "https://github.com/rapid7/metasploit-framework",
                _ => Task.FromResult(git.Result), CancellationToken.None);
            audit.Dispose();

            var e = Assert.Single(ReadEvents(work, "poc.fetch.error.diagnosed"));
            Assert.False(e.GetProperty("dns_ok").GetBoolean());
            Assert.Equal("HostNotFound", e.GetProperty("dns_error").GetString());
            Assert.False(e.GetProperty("https_reachable").GetBoolean());
            Assert.Equal("github.com", e.GetProperty("target_host").GetString());
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    [Fact]
    public async Task WrapAsync_classifies_https_reachable_but_clone_failed()
    {
        var (work, audit) = NewAudit("clonefail");
        try
        {
            // DNS resolves, HTTPS HEAD returns 200, but the clone still failed
            // (e.g. auth required / partial clone unsupported on a corporate proxy).
            var git = new StubGitClient
            {
                Result = new GitCloneResult(false, 128, "fatal: Authentication failed", "clone"),
            };
            var dns = new StubDns { Result = new DnsProbeResult(true, new[] { "140.82.114.4" }, null) };
            var http = new StubHttp { Result = new HttpProbeResult(true, 200, null) };
            var diag = new PocFetchDiagnostics(git, dns, http);

            await diag.WrapAsync(audit, "poc-in-github", "CVE-2024-3",
                "https://github.com/nomi-sec/PoC-in-GitHub",
                _ => Task.FromResult(git.Result), CancellationToken.None);
            audit.Dispose();

            var e = Assert.Single(ReadEvents(work, "poc.fetch.error.diagnosed"));
            Assert.True(e.GetProperty("dns_ok").GetBoolean());
            Assert.True(e.GetProperty("https_reachable").GetBoolean());
            Assert.Equal(200, e.GetProperty("https_status").GetInt32());
            Assert.Equal(128, e.GetProperty("exit_code").GetInt32());
            Assert.Equal("clone", e.GetProperty("stage").GetString());
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    // --- required-field shape -------------------------------------------

    [Fact]
    public async Task WrapAsync_audit_event_contains_all_required_fields()
    {
        var (work, audit) = NewAudit("fields");
        try
        {
            var git = new StubGitClient();
            var diag = new PocFetchDiagnostics(git, new StubDns(), new StubHttp());

            await diag.WrapAsync(audit, "metasploit-git", "CVE-2024-1",
                "https://github.com/rapid7/metasploit-framework",
                _ => Task.FromResult(git.Result), CancellationToken.None);
            audit.Dispose();

            var e = Assert.Single(ReadEvents(work, "poc.fetch.error.diagnosed"));
            foreach (var field in new[]
            {
                "source", "cve_id", "target_url", "target_host",
                "git_present", "git_version", "dns_ok", "dns_addresses",
                "https_reachable", "exit_code", "stage",
                "stderr", "stderr_full_byte_size", "stderr_truncated", "stderr_sha256",
            })
            {
                Assert.True(e.TryGetProperty(field, out _), $"missing field: {field}");
            }
            Assert.Equal("metasploit-git", e.GetProperty("source").GetString());
            Assert.Equal("CVE-2024-1", e.GetProperty("cve_id").GetString());
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    // --- token redaction (canary) ---------------------------------------

    [Fact]
    public async Task WrapAsync_redacts_auth_token_in_url_and_stderr()
    {
        var (work, audit) = NewAudit("redact");
        try
        {
            const string TokenCanary = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            var stderrWithToken =
                "fatal: unable to access 'https://oauth2:" + TokenCanary + "@github.com/foo/bar': clone failed\n" +
                "Authorization: Bearer " + TokenCanary;
            var git = new StubGitClient
            {
                Result = new GitCloneResult(false, 128, stderrWithToken, "clone"),
            };
            var diag = new PocFetchDiagnostics(git, new StubDns(), new StubHttp());

            await diag.WrapAsync(audit, "poc-in-github", "CVE-2024-9",
                $"https://oauth2:{TokenCanary}@github.com/nomi-sec/PoC-in-GitHub",
                _ => Task.FromResult(git.Result), CancellationToken.None);
            audit.Dispose();

            var raw = File.ReadAllText(Path.Combine(work, "audit.jsonl"));
            Assert.DoesNotContain(TokenCanary, raw);

            var e = Assert.Single(ReadEvents(work, "poc.fetch.error.diagnosed"));
            var url = e.GetProperty("target_url").GetString() ?? string.Empty;
            Assert.DoesNotContain(TokenCanary, url);
            Assert.Equal("github.com", e.GetProperty("target_host").GetString());

            var stderr = e.GetProperty("stderr").GetString() ?? string.Empty;
            Assert.DoesNotContain(TokenCanary, stderr);
            Assert.Contains("REDACTED", stderr);
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }

    // --- stderr truncation pins to 4 KB ---------------------------------

    [Fact]
    public async Task WrapAsync_truncates_stderr_at_4kb_and_records_full_size()
    {
        var (work, audit) = NewAudit("trunc");
        try
        {
            var big = new string('x', 12_000);
            var git = new StubGitClient { Result = new GitCloneResult(false, 1, big, "clone") };
            var diag = new PocFetchDiagnostics(git, new StubDns(), new StubHttp());

            await diag.WrapAsync(audit, "metasploit-git", "CVE-2024-7",
                "https://github.com/rapid7/metasploit-framework",
                _ => Task.FromResult(git.Result), CancellationToken.None);
            audit.Dispose();

            var e = Assert.Single(ReadEvents(work, "poc.fetch.error.diagnosed"));
            var stderr = e.GetProperty("stderr").GetString() ?? string.Empty;
            Assert.True(Encoding.UTF8.GetByteCount(stderr) <= PocFetchDiagnostics.StderrTruncateBytes);
            Assert.Equal(12_000, e.GetProperty("stderr_full_byte_size").GetInt32());
            Assert.True(e.GetProperty("stderr_truncated").GetBoolean());
            var sha = e.GetProperty("stderr_sha256").GetString();
            Assert.Equal(64, sha!.Length);
        }
        finally { try { audit.Dispose(); } catch { } Directory.Delete(work, true); }
    }
}
