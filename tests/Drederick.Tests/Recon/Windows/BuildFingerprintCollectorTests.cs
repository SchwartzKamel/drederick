using Drederick.Enrichment;
using Drederick.Recon;
using Drederick.Recon.Windows;
using Xunit;

namespace Drederick.Tests.Recon.Windows;

/// <summary>
/// Tests for the slice-C Windows build fingerprint feeder
/// (htb-windows-vulns-fingerprint-feeder / PingPong writeup #3).
///
/// The collector is a passive join over <see cref="HostFinding"/>; the
/// matcher is a pure data filter against the embedded
/// <c>data/windows-build-fingerprints.json</c> corpus. Neither touches
/// the network, calls <c>_scope.Require</c>, or logs secrets.
/// </summary>
public class BuildFingerprintCollectorTests
{
    private static readonly BuildFingerprintCollector Collector = new();

    [Fact]
    public void ExtractsCurrentBuild_FromSmbNegotiate()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.5",
            Smb = new List<SmbResult>
            {
                new()
                {
                    Port = 445,
                    Os = "Windows Server 2019 Standard 17763",
                    Protocols = new List<string> { "SMB 3.1.1" },
                },
            },
        };

        var fp = Collector.Build(host);

        Assert.NotNull(fp.Product);
        Assert.Contains("2019", fp.Product!);
        Assert.Equal("17763", fp.CurrentBuild);
        Assert.Equal("3.1.1", fp.SmbDialect);
        Assert.Contains("WinSrv-2019", fp.ProductTags());
    }

    [Fact]
    public void ExtractsUbr_FromNmapScriptOutput()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.6",
            Nmap = new NmapResult
            {
                ReturnCode = 0,
                OpenPorts = new List<NmapPort>
                {
                    new()
                    {
                        Port = 445,
                        Service = "microsoft-ds",
                        Scripts = new List<NmapScript>
                        {
                            new()
                            {
                                Id = "smb-os-discovery",
                                Output = "OS: Windows Server 2019 Standard (build 17763.4252)\nComputer name: DC01",
                            },
                        },
                    },
                },
            },
        };

        var fp = Collector.Build(host);

        Assert.Equal("17763", fp.CurrentBuild);
        Assert.Equal("4252", fp.Ubr);
    }

    [Fact]
    public void ParsesInstalledKbs_FromFindingsBag()
    {
        // The chain-template `findings` dictionary is the bridge between
        // a WinRM-based hotfix harvester and the analyzer — operators
        // (or a future probe) drop `windows.installed_kbs` here.
        var host = new HostFinding
        {
            Target = "10.10.10.7",
            Findings = new Dictionary<string, string>
            {
                ["windows.installed_kbs"] = "KB5005565, KB5028171, kb-5025221",
                ["windows.current_build"] = "17763",
                ["windows.ubr"] = "4252",
                ["windows.product"] = "Windows Server 2019",
            },
        };

        var fp = Collector.Build(host);

        Assert.Contains("KB5005565", fp.InstalledKbs);
        Assert.Contains("KB5028171", fp.InstalledKbs);
        Assert.Contains("KB5025221", fp.InstalledKbs);
        Assert.Equal("17763", fp.CurrentBuild);
        Assert.Equal("4252", fp.Ubr);
    }

    [Fact]
    public void EmptyFindings_ReturnsEmptyResult()
    {
        var host = new HostFinding { Target = "10.10.10.99" };
        var fp = Collector.Build(host);
        Assert.Same(WindowsBuildFingerprint.Empty, fp);
        Assert.Empty(fp.InstalledKbs);
        Assert.Null(fp.Product);
    }

    [Fact]
    public void DetectsSmbv1Feature_FromNtLmDialect()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.5",
            Smb = new List<SmbResult>
            {
                new()
                {
                    Port = 445,
                    Os = "Windows Server 2016",
                    Protocols = new List<string> { "NT LM 0.12", "SMB 2.1" },
                },
            },
        };

        var fp = Collector.Build(host);
        Assert.Contains("smbv1", fp.EnabledFeatures);
    }
}

public class FingerprintMatcherTests
{
    private static readonly FingerprintMatcher Matcher = FingerprintMatcher.LoadEmbedded();

    [Fact]
    public void Corpus_LoadsAtLeast20Entries()
    {
        Assert.True(Matcher.Count >= 20,
            $"corpus only has {Matcher.Count} entries, expected >= 20");
    }

    [Fact]
    public void Corpus_WellFormed()
    {
        foreach (var e in Matcher.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(e.Kb), "kb required");
            Assert.NotNull(e.Fixes);
            Assert.NotEmpty(e.Fixes!);
            Assert.NotNull(e.Products);
            Assert.NotEmpty(e.Products!);
        }
    }

    [Fact]
    public void FilterSuppressesPatchedPrintNightmare()
    {
        var fp = new WindowsBuildFingerprint(
            Product: "Windows Server 2019 Standard",
            CurrentBuild: "17763",
            Ubr: "2090",
            ReleaseId: "1809",
            FeaturePack: null,
            InstalledKbs: new[] { "KB5004945" },
            EnabledFeatures: new[] { "spooler" },
            SmbDialect: "3.1.1",
            AdSchemaVersion: null,
            ServiceVersions: new Dictionary<string, string>());

        var hits = Matcher.MatchWindowsBuild(fp);
        Assert.DoesNotContain(hits, h => h.Cve == "CVE-2021-34527");
        Assert.DoesNotContain(hits, h => h.Cve == "CVE-2021-1675");
    }

    [Fact]
    public void FilterEmitsUnpatchedZerologon_OnDomainController()
    {
        var fp = new WindowsBuildFingerprint(
            Product: "Windows Server 2019 Standard",
            CurrentBuild: "17763",
            Ubr: "1100",
            ReleaseId: "1809",
            FeaturePack: null,
            InstalledKbs: new[] { "KB4012598" },
            EnabledFeatures: new[] { "domain-controller" },
            SmbDialect: "3.1.1",
            AdSchemaVersion: "88",
            ServiceVersions: new Dictionary<string, string>());

        var hits = Matcher.MatchWindowsBuild(fp);
        var zl = hits.FirstOrDefault(h => h.Cve == "CVE-2020-1472");
        Assert.NotNull(zl);
        Assert.Equal(FingerprintMatchConfidence.High, zl!.Confidence);
        Assert.Equal("red", zl.Severity);
    }

    [Fact]
    public void LowBuildRevision_EmitsMediumConfidence_WhenKbListUnknown()
    {
        var fp = new WindowsBuildFingerprint(
            Product: "Windows Server 2019 Standard",
            CurrentBuild: "17763",
            Ubr: "100",
            ReleaseId: null,
            FeaturePack: null,
            InstalledKbs: Array.Empty<string>(),
            EnabledFeatures: Array.Empty<string>(),
            SmbDialect: null,
            AdSchemaVersion: null,
            ServiceVersions: new Dictionary<string, string>());

        var hits = Matcher.MatchWindowsBuild(fp);
        Assert.NotEmpty(hits);
        Assert.Contains(hits, h => h.Confidence == FingerprintMatchConfidence.Medium);
    }

    [Fact]
    public void MissingFingerprintData_FallsBackToLowConfidence()
    {
        // No build, no KBs, no features — only banner-derived product tag.
        var fp = new WindowsBuildFingerprint(
            Product: "Windows Server 2019",
            CurrentBuild: null,
            Ubr: null,
            ReleaseId: null,
            FeaturePack: null,
            InstalledKbs: Array.Empty<string>(),
            EnabledFeatures: Array.Empty<string>(),
            SmbDialect: null,
            AdSchemaVersion: null,
            ServiceVersions: new Dictionary<string, string>());

        var hits = Matcher.MatchWindowsBuild(fp);
        Assert.NotEmpty(hits);
        Assert.All(hits, h => Assert.Equal(FingerprintMatchConfidence.Low, h.Confidence));
    }

    [Fact]
    public void EmptyFingerprint_ProducesCandidates_WhenUnconstrained()
    {
        // Empty fingerprint => no product tags => every entry is a soft
        // pass on product, low-confidence band. This is the
        // "prefer false positives over false negatives" stance.
        var hits = Matcher.MatchWindowsBuild(WindowsBuildFingerprint.Empty);
        Assert.NotEmpty(hits);
        Assert.All(hits, h => Assert.Equal(FingerprintMatchConfidence.Low, h.Confidence));
    }

    [Fact]
    public void FeatureGate_FiltersWhenFeatureKnownAbsent()
    {
        // Box advertises features but spooler is NOT in the list — the
        // matcher should drop spooler-gated CVEs.
        var fp = new WindowsBuildFingerprint(
            Product: "Windows Server 2019 Standard",
            CurrentBuild: "17763",
            Ubr: "100",
            ReleaseId: null,
            FeaturePack: null,
            InstalledKbs: Array.Empty<string>(),
            EnabledFeatures: new[] { "iis" }, // spooler intentionally absent
            SmbDialect: null,
            AdSchemaVersion: null,
            ServiceVersions: new Dictionary<string, string>());

        var hits = Matcher.MatchWindowsBuild(fp);
        // PrintNightmare requires spooler — should NOT appear.
        Assert.DoesNotContain(hits, h => h.Cve == "CVE-2021-34527");
    }

    [Fact]
    public void SupersededKb_AlsoSatisfiesPatch()
    {
        // Operator has KB5005565 (an older PrintNightmare patch that was
        // later superseded by KB5004945). The corpus declares KB5005565
        // in `supersedes` so installing it should still suppress.
        var fp = new WindowsBuildFingerprint(
            Product: "Windows Server 2019 Standard",
            CurrentBuild: "17763",
            Ubr: "2090",
            ReleaseId: null,
            FeaturePack: null,
            InstalledKbs: new[] { "KB5005565" },
            EnabledFeatures: new[] { "spooler" },
            SmbDialect: null,
            AdSchemaVersion: null,
            ServiceVersions: new Dictionary<string, string>());

        var hits = Matcher.MatchWindowsBuild(fp);
        Assert.DoesNotContain(hits, h => h.Cve == "CVE-2021-34527");
    }
}
