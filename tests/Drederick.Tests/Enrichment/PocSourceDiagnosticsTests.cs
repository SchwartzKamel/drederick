using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Enrichment;
using Xunit;

namespace Drederick.Tests.Enrichment;

/// <summary>
/// GAP-053 — verifies the diagnostics surface emitted by the git-clone PoC
/// sources when <c>git clone</c> fails. Before this change the only audit
/// breadcrumb was <c>poc.fetch.error</c> with the literal string
/// <c>"git clone failed"</c>; production failures were impossible to triage.
/// These tests pin the new <c>poc.fetch.diagnostics</c> event shape and the
/// enriched <c>poc.fetch.error</c> fields.
/// </summary>
public sealed class PocSourceDiagnosticsTests
{
    /// <summary>
    /// Scripted <see cref="IProcessRunner"/> that lets each test drive the
    /// exit code, stdout, and stderr returned for any <c>git …</c>
    /// invocation. Records every call so assertions can verify which step
    /// the source was on when it failed.
    /// </summary>
    private sealed class ScriptedRunner : IProcessRunner
    {
        public List<(string File, string Args)> Calls { get; } = new();
        public Func<string, string, (int, string, string)>? Handler { get; set; }
        public (int ExitCode, string StdOut, string StdErr) Default { get; set; } = (0, string.Empty, string.Empty);

        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
        {
            Calls.Add((file, arguments));
            return Handler is null ? Default : Handler(file, arguments);
        }

        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
            => throw new NotSupportedException();
    }

    private static List<JsonElement> ReadAuditEvents(string workDir, string eventName)
    {
        var path = Path.Combine(workDir, "audit.jsonl");
        var matches = new List<JsonElement>();
        if (!File.Exists(path)) return matches;
        foreach (var line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.TryGetProperty("event", out var ev) &&
                string.Equals(ev.GetString(), eventName, StringComparison.Ordinal))
            {
                // Clone the element so it survives the using-Dispose.
                matches.Add(JsonDocument.Parse(line).RootElement.Clone());
            }
        }
        return matches;
    }

    [Fact]
    public async Task ClientCapturesGitVersionAndStderrOnCloneFailure()
    {
        var runner = new ScriptedRunner
        {
            Handler = (file, args) =>
            {
                if (args == "--version") return (0, "git version 2.43.0 (test)\n", string.Empty);
                if (args.StartsWith("clone ", StringComparison.Ordinal))
                {
                    var stderr = "fatal: unable to access 'https://example/': Could not resolve host\n";
                    return (128, string.Empty, stderr);
                }
                return (0, string.Empty, string.Empty);
            },
        };
        var client = new ProcessGitClient(runner);

        Assert.Equal("git version 2.43.0 (test)", client.GitVersion);

        var dest = Path.Combine(Path.GetTempPath(), $"drederick-poc-diag-{Guid.NewGuid():N}");
        try
        {
            var result = await client.CloneSparseAsync(
                GitPocAllowlist.NucleiTemplates,
                dest,
                new[] { "http" },
                CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal(128, result.ExitCode);
            Assert.Equal("clone", result.Stage);
            Assert.Contains("Could not resolve host", result.Stderr);
        }
        finally
        {
            if (Directory.Exists(dest)) Directory.Delete(dest, recursive: true);
        }
    }

    [Fact]
    public async Task NucleiSourceEmitsDiagnosticsAuditOnCloneFailure()
    {
        var fake = new FakeGitClient
        {
            ForceFail = true,
            FailExitCode = 128,
            FailStderr = "fatal: unable to access 'https://github.com/projectdiscovery/nuclei-templates/': dial tcp: lookup github.com: no such host\n",
            FailStage = "clone",
            GitVersion = "git version 2.43.0 (fake)",
            EgressOk = false,
            EgressStderr = "fatal: unable to access github.com canary",
        };
        var (work, audit, report) = TestEnv.Make("nuclei-diag");
        try
        {
            var src = new NucleiTemplatesGitSource(git: fake);
            var refs = await src.QueryAsync("CVE-2023-12345", TestEnv.Ctx(work, audit, report), CancellationToken.None);
            Assert.Empty(refs);
            audit.Dispose();

            var diags = ReadAuditEvents(work, "poc.fetch.diagnostics");
            var diag = Assert.Single(diags);
            var f = diag;
            Assert.Equal("nuclei-git", f.GetProperty("source").GetString());
            Assert.Equal("CVE-2023-12345", f.GetProperty("cve_id").GetString());
            Assert.Equal("git version 2.43.0 (fake)", f.GetProperty("git_version").GetString());
            Assert.Equal(128, f.GetProperty("exit_code").GetInt32());
            Assert.Equal("clone", f.GetProperty("stage").GetString());
            Assert.Contains("no such host", f.GetProperty("stderr").GetString());
            Assert.False(f.GetProperty("egress_ok").GetBoolean());
            Assert.Equal(GitPocAllowlist.NucleiTemplates, f.GetProperty("repo_url").GetString());

            var errors = ReadAuditEvents(work, "poc.fetch.error");
            var err = Assert.Single(errors);
            var ef = err;
            Assert.Equal("git clone failed", ef.GetProperty("error").GetString());
            Assert.Equal(128, ef.GetProperty("exit_code").GetInt32());
            Assert.Equal("git version 2.43.0 (fake)", ef.GetProperty("git_version").GetString());
            Assert.False(ef.GetProperty("egress_ok").GetBoolean());
            Assert.Contains("no such host", ef.GetProperty("stderr_first_512_bytes").GetString());
        }
        finally
        {
            report.Dispose();
            try { Directory.Delete(work, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task MetasploitSourceEmitsDiagnosticsAuditOnCloneFailure()
    {
        var fake = new FakeGitClient
        {
            ForceFail = true,
            FailExitCode = 1,
            FailStderr = "fatal: refusing to clone into existing dir",
            FailStage = "sparse-checkout",
        };
        var (work, audit, report) = TestEnv.Make("msf-diag");
        try
        {
            var src = new MetasploitGitSource(git: fake);
            var refs = await src.QueryAsync("CVE-2024-11111", TestEnv.Ctx(work, audit, report), CancellationToken.None);
            Assert.Empty(refs);
            audit.Dispose();

            var diag = Assert.Single(ReadAuditEvents(work, "poc.fetch.diagnostics"));
            var f = diag;
            Assert.Equal("metasploit-git", f.GetProperty("source").GetString());
            Assert.Equal(1, f.GetProperty("exit_code").GetInt32());
            Assert.Equal("sparse-checkout", f.GetProperty("stage").GetString());
            Assert.Equal(GitPocAllowlist.MetasploitFramework, f.GetProperty("repo_url").GetString());
        }
        finally
        {
            report.Dispose();
            try { Directory.Delete(work, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task PocInGitHubSourceEmitsDiagnosticsAuditOnCloneFailure()
    {
        var fake = new FakeGitClient
        {
            ForceFail = true,
            FailExitCode = 128,
            FailStderr = "fatal: connection timed out",
            FailStage = "clone",
        };
        var (work, audit, report) = TestEnv.Make("pig-diag");
        try
        {
            var src = new PocInGitHubSource(git: fake);
            var refs = await src.QueryAsync("CVE-2022-99999", TestEnv.Ctx(work, audit, report), CancellationToken.None);
            Assert.Empty(refs);
            audit.Dispose();

            var diag = Assert.Single(ReadAuditEvents(work, "poc.fetch.diagnostics"));
            var f = diag;
            Assert.Equal("poc-in-github", f.GetProperty("source").GetString());
            Assert.Equal(GitPocAllowlist.PocInGitHub, f.GetProperty("repo_url").GetString());
            Assert.Contains("connection timed out", f.GetProperty("stderr").GetString());
        }
        finally
        {
            report.Dispose();
            try { Directory.Delete(work, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task DiagnosticsTruncatesStderrAtTwoKilobytesAndRecordsSha256()
    {
        // Build a >2 KB stderr blob so the truncation path is exercised.
        var line = "fatal: padding-line-with-some-bulk-to-blow-past-the-2kb-truncation-threshold-for-stderr-diagnostics\n";
        var sb = new StringBuilder(8192);
        while (sb.Length < 8 * 1024) sb.Append(line);
        var bigStderr = sb.ToString();
        var fullByteSize = Encoding.UTF8.GetByteCount(bigStderr);
        Assert.True(fullByteSize > GitPocDiagnostics.StderrTruncateBytes);

        var fake = new FakeGitClient
        {
            ForceFail = true,
            FailExitCode = 128,
            FailStderr = bigStderr,
            FailStage = "clone",
        };
        var (work, audit, report) = TestEnv.Make("trunc-diag");
        try
        {
            var src = new NucleiTemplatesGitSource(git: fake);
            await src.QueryAsync("CVE-2025-55555", TestEnv.Ctx(work, audit, report), CancellationToken.None);
            audit.Dispose();

            var diag = Assert.Single(ReadAuditEvents(work, "poc.fetch.diagnostics"));
            var f = diag;

            var stderr = f.GetProperty("stderr").GetString()!;
            Assert.True(Encoding.UTF8.GetByteCount(stderr) <= GitPocDiagnostics.StderrTruncateBytes,
                $"truncated stderr should be <= 2 KB, was {Encoding.UTF8.GetByteCount(stderr)}");
            Assert.Equal(fullByteSize, f.GetProperty("stderr_full_byte_size").GetInt32());
            Assert.True(f.GetProperty("stderr_truncated").GetBoolean());

            // sha256 of full stderr must be present (and lowercase hex, 64 chars).
            var sha = f.GetProperty("stderr_sha256").GetString()!;
            Assert.Equal(64, sha.Length);
            Assert.Matches("^[0-9a-f]{64}$", sha);

            // The error event preview is bounded at 512 bytes — strictly tighter.
            var err = Assert.Single(ReadAuditEvents(work, "poc.fetch.error"));
            var preview = err.GetProperty("stderr_first_512_bytes").GetString()!;
            Assert.True(Encoding.UTF8.GetByteCount(preview) <= GitPocDiagnostics.StderrErrorPreviewBytes);
        }
        finally
        {
            report.Dispose();
            try { Directory.Delete(work, recursive: true); } catch { }
        }
    }

    [Fact]
    public void Utf8TruncationDoesNotSplitMultiByteRunes()
    {
        // 4-byte UTF-8 runes; cap at 5 bytes must yield a clean 1-rune string,
        // not a corrupt half-rune.
        var s = "𝄞𝄞𝄞𝄞"; // four U+1D11E, each 4 bytes UTF-8 = 16 bytes total
        var truncated = GitPocDiagnostics.TruncateUtf8(s, 5);
        Assert.Equal("𝄞", truncated);
        Assert.Equal(4, Encoding.UTF8.GetByteCount(truncated));
    }
}
