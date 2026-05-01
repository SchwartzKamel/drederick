using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Drederick.Learning;
using Xunit;

namespace Drederick.Tests.Learning;

public class FightCorpusTests
{
    private const string SyntheticV1Yaml = """
        schema_version: 1
        fights:
          - id: alpha-2026-01-01
            box: alpha
            date: "2026-01-01"
            target_ip: 10.10.10.1
            difficulty: Easy
            outcome: loss
            rematch_of: null
            gaps_addressed: []
            services_found:
              - port: 22
                service: ssh
                version: "OpenSSH 8.0"
            vulns_identified:
              - CVE-2020-0001
            exploits_attempted:
              - tool: ssh-spray
                target: "10.10.10.1:22"
                result: miss
          - id: alpha-2026-01-02-rematch
            box: alpha
            date: "2026-01-02"
            target_ip: 10.10.10.1
            difficulty: Easy
            outcome: win
            rematch_of: alpha-2026-01-01
            gaps_addressed:
              - GAP-001  # ssh user enumeration
              - GAP-002
            services_found: []
            vulns_identified: []
            exploits_attempted: []
          - id: bravo-2026-02-01
            box: bravo
            date: "2026-02-01"
            target_ip: 10.10.10.2
            difficulty: Hard
            outcome: loss
            services_found: []
            vulns_identified: []
            exploits_attempted: []
        """;

    [Fact]
    public void Parse_synthetic_v1_returns_three_fights_with_query_helpers()
    {
        var log = FightCorpus.Parse(SyntheticV1Yaml);
        Assert.Equal(1, log.SchemaVersion);
        Assert.Equal(3, log.Fights.Count);

        var ids = log.Fights.Select(f => f.Id).ToList();
        Assert.Contains("alpha-2026-01-01", ids);
        Assert.Contains("alpha-2026-01-02-rematch", ids);

        var rematch = log.Fights.Single(f => f.Id == "alpha-2026-01-02-rematch");
        Assert.Equal("alpha-2026-01-01", rematch.RematchOf);
        Assert.Equal(2, rematch.GapsAddressed.Count);

        var first = log.Fights.Single(f => f.Id == "alpha-2026-01-01");
        Assert.Single(first.ServicesFound);
        Assert.Equal(22, first.ServicesFound[0].Port);
        Assert.Single(first.ExploitsAttempted);
        // result→Outcome mapping
        Assert.Equal("miss", first.ExploitsAttempted[0].Outcome);
    }

    [Fact]
    public async Task Query_helpers_filter_correctly_on_synthetic_fixture()
    {
        using var dir = TempDir.New();
        var path = Path.Combine(dir.Path, "fight-log.yaml");
        File.WriteAllText(path, SyntheticV1Yaml);
        var corpus = new FightCorpus(path);
        await corpus.LoadAsync();

        Assert.Equal(2, corpus.ByBox("alpha").Count());
        Assert.Equal(2, corpus.ByBox("ALPHA").Count()); // case-insensitive
        Assert.Single(corpus.ByBox("bravo"));

        var rematches = corpus.Rematches("alpha-2026-01-01").ToList();
        Assert.Single(rematches);
        Assert.Equal("alpha-2026-01-02-rematch", rematches[0].Id);

        var addressing = corpus.AddressingGap("GAP-001").ToList();
        Assert.Single(addressing);
        Assert.Equal("alpha-2026-01-02-rematch", addressing[0].Id);

        // Recent: 200-year window covers everything
        Assert.Equal(3, corpus.Recent(TimeSpan.FromDays(365 * 200)).Count());
        // Far-future cutoff: nothing.
        Assert.Empty(corpus.Recent(TimeSpan.Zero));
    }

    [Fact]
    public void Schema_version_mismatch_throws_FightCorpusSchemaException()
    {
        var v2 = "schema_version: 2\nfights: []\n";
        var ex = Assert.Throws<FightCorpusSchemaException>(() => FightCorpus.Parse(v2, "synthetic.yaml"));
        Assert.Equal(2, ex.FoundVersion);
        Assert.Equal(1, ex.ExpectedVersion);
        Assert.Contains("schema_version=2", ex.Message);
        Assert.Contains("synthetic.yaml", ex.Message);
    }

    [Fact]
    public async Task Missing_corpus_returns_empty_log_gracefully()
    {
        // Force an explicit non-existent --fight-corpus override AND clear env
        // AND point HOME at an empty directory so default discovery misses too.
        using var dir = TempDir.New();
        var corpus = new FightCorpus(
            cliPath: null,
            envOverride: new Dictionary<string, string?> { [FightCorpus.EnvVar] = null },
            homeOverride: dir.Path);

        Assert.False(corpus.HasCorpus);
        var log = await corpus.LoadAsync();
        Assert.Equal(1, log.SchemaVersion);
        Assert.Empty(log.Fights);
    }

    [Fact]
    public async Task EnvVar_override_is_honored()
    {
        using var dir = TempDir.New();
        var path = Path.Combine(dir.Path, "via-env.yaml");
        File.WriteAllText(path, SyntheticV1Yaml);

        var corpus = new FightCorpus(
            cliPath: null,
            envOverride: new Dictionary<string, string?> { [FightCorpus.EnvVar] = path },
            homeOverride: "/nonexistent-home-dir-for-test");

        Assert.Equal(Path.GetFullPath(path), corpus.ResolvedPath);
        var log = await corpus.LoadAsync();
        Assert.Equal(3, log.Fights.Count);
    }

    [Fact]
    public async Task Cli_override_takes_precedence_over_env_and_default()
    {
        using var dir = TempDir.New();
        var cliPath = Path.Combine(dir.Path, "cli.yaml");
        var envPath = Path.Combine(dir.Path, "env.yaml");
        File.WriteAllText(cliPath, SyntheticV1Yaml);
        // env points at a file with mismatched schema — if env wins, parse throws.
        File.WriteAllText(envPath, "schema_version: 99\nfights: []\n");

        var corpus = new FightCorpus(
            cliPath: cliPath,
            envOverride: new Dictionary<string, string?> { [FightCorpus.EnvVar] = envPath },
            homeOverride: dir.Path);

        Assert.Equal(Path.GetFullPath(cliPath), corpus.ResolvedPath);
        var log = await corpus.LoadAsync();
        Assert.Equal(3, log.Fights.Count);
    }

    [Fact]
    public async Task Real_corpus_parses_with_three_or_more_fights_when_present()
    {
        var home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home))
        {
            return;
        }
        var realPath = Path.Combine(home, "HTB", "fight-log.yaml");
        if (!File.Exists(realPath))
        {
            // Graceful skip: tests must pass even when ~/HTB/ doesn't exist.
            return;
        }

        var corpus = new FightCorpus(realPath);
        var log = await corpus.LoadAsync();
        Assert.Equal(1, log.SchemaVersion);
        Assert.True(log.Fights.Count >= 3, $"expected >=3 fights, got {log.Fights.Count}");

        var ids = log.Fights.Select(f => f.Id).ToList();
        Assert.Contains("lame-2026-04-30", ids);
        Assert.Contains("lame-2026-04-30-rematch", ids);
        Assert.Contains("jobtwo-2026-05-01", ids);

        var rematch = log.Fights.Single(f => f.Id == "lame-2026-04-30-rematch");
        Assert.Equal("lame-2026-04-30", rematch.RematchOf);
        Assert.Equal("win", rematch.Outcome);
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; }
        private TempDir(string p) { Path = p; }
        public static TempDir New()
        {
            var p = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                "drederick-fightcorpus-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(p);
            return new TempDir(p);
        }
        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch { }
        }
    }
}
