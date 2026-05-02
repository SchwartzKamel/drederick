using Drederick.Enrichment.FingerprintStack;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests.Enrichment.FingerprintStack;

public class FingerprintLearnerTests
{
    private static string NewOutRoot()
    {
        var p = Path.Combine(Path.GetTempPath(), "drederick-fpl-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(p);
        return p;
    }

    [Fact]
    public void ParseServerHeader_MicrosoftHttpapi_SplitsVendorProductVersion()
    {
        var (vendor, product, version) = FingerprintLearner.ParseServerHeader("Microsoft-HTTPAPI/2.0");
        Assert.Equal("Microsoft", vendor);
        Assert.Equal("HTTPAPI", product);
        Assert.Equal("2.0", version);
    }

    [Fact]
    public void ParseServerHeader_ApacheUbuntu_DropsTrailingAnnotation()
    {
        var (vendor, product, version) = FingerprintLearner.ParseServerHeader("Apache/2.4.41 (Ubuntu)");
        Assert.Equal("Apache", vendor);
        Assert.Equal("Apache", product);
        Assert.Equal("2.4.41", version);
    }

    [Fact]
    public void ParseServerHeader_NoSlash_ReturnsBareName()
    {
        var (vendor, product, version) = FingerprintLearner.ParseServerHeader("nginx");
        Assert.Equal("nginx", vendor);
        Assert.Equal("nginx", product);
        Assert.Null(version);
    }

    [Fact]
    public void LearnFromFinding_JobTwoR4_TeachesMicrosoftHttpapiOn5985()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.123",
            Http =
            {
                new HttpResult
                {
                    Url = "http://10.10.10.123:5985/wsman",
                    Status = 404,
                    Server = "Microsoft-HTTPAPI/2.0",
                },
            },
        };
        var store = new LearnedFingerprintStore(NewOutRoot());

        var n = FingerprintLearner.LearnFromFinding(host, "jobtwo-r4", store);

        Assert.Equal(1, n);
        Assert.True(store.TryGetByValue("http_server", "Microsoft-HTTPAPI/2.0", out var fp));
        Assert.Equal("microsoft", fp.Vendor);
        Assert.Equal("wsman", fp.Product);
        Assert.Equal("2.0", fp.Version);
        Assert.Equal(5985, fp.Port);
        Assert.Contains("jobtwo-r4", fp.EvidenceFights);
    }

    [Fact]
    public void LearnFromFinding_NonWsmanPort_KeepsRawVendorProduct()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.50",
            Http =
            {
                new HttpResult { Url = "http://10.10.10.50/", Server = "Apache/2.4.41 (Ubuntu)" },
            },
        };
        var store = new LearnedFingerprintStore(NewOutRoot());

        FingerprintLearner.LearnFromFinding(host, "fight-x", store);

        Assert.True(store.TryGetByValue("http_server", "Apache/2.4.41 (Ubuntu)", out var fp));
        Assert.Equal("Apache", fp.Vendor);
        Assert.Equal("Apache", fp.Product);
        Assert.Equal("2.4.41", fp.Version);
        Assert.Equal(80, fp.Port);
    }

    [Fact]
    public void LearnFromFinding_TlsSubject_LearnedAsTlsSubjectDn()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.99",
            Tls =
            {
                new TlsResult { Port = 443, Subject = "CN=corp.example.com,O=Example Corp" },
            },
        };
        var store = new LearnedFingerprintStore(NewOutRoot());

        FingerprintLearner.LearnFromFinding(host, "fight-tls", store);

        Assert.True(store.TryGetByValue("tls_subject_dn", "CN=corp.example.com,O=Example Corp", out var fp));
        Assert.Equal(443, fp.Port);
    }

    [Fact]
    public void LearnFromFinding_SshBanner_ParsesOpenSshVendor()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.7",
            Ssh =
            {
                new SshResult { Port = 22, Banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" },
            },
        };
        var store = new LearnedFingerprintStore(NewOutRoot());

        FingerprintLearner.LearnFromFinding(host, "fight-ssh", store);

        Assert.True(store.TryGetByValue("ssh_banner", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", out var fp));
        Assert.Equal("openbsd", fp.Vendor);
        Assert.Equal("openssh", fp.Product);
        Assert.Equal("8.2p1", fp.Version);
        Assert.Equal(22, fp.Port);
    }

    [Fact]
    public void LearnFromFinding_SmbOs_LearnedAsSmbOs()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.4",
            Smb =
            {
                new SmbResult { Port = 445, Os = "Windows Server 2008 R2 Enterprise 7601 Service Pack 1" },
            },
        };
        var store = new LearnedFingerprintStore(NewOutRoot());

        FingerprintLearner.LearnFromFinding(host, "fight-smb", store);

        Assert.True(store.TryGetByValue("smb_os", "Windows Server 2008 R2 Enterprise 7601 Service Pack 1", out var fp));
        Assert.Equal("microsoft", fp.Vendor);
        Assert.Equal("windows", fp.Product);
        Assert.Equal(445, fp.Port);
    }

    [Fact]
    public void LearnFromFinding_StackCandidate_LearnedAsConfirmed()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.123",
            Fingerprint =
            {
                new FingerprintReport
                {
                    Port = 5985,
                    Candidates =
                    {
                        new FingerprintCandidate
                        {
                            Vendor = "microsoft",
                            Product = "wsman",
                            Version = "2.0",
                            Confidence = 0.9,
                            Cpe = "cpe:2.3:a:microsoft:wsman:2.0:*:*:*:*:*:*:*",
                        },
                    },
                },
            },
        };
        var store = new LearnedFingerprintStore(NewOutRoot());

        FingerprintLearner.LearnFromFinding(host, "fight-stack", store);

        Assert.True(store.TryGetByValue("stack_candidate", "cpe:2.3:a:microsoft:wsman:2.0:*:*:*:*:*:*:*", out var fp));
        Assert.Equal("microsoft", fp.Vendor);
        Assert.Equal("wsman", fp.Product);
        Assert.Equal(5985, fp.Port);
    }

    [Fact]
    public void LearnFromFinding_TwoFightsSameSignal_AccumulatesHits()
    {
        var store = new LearnedFingerprintStore(NewOutRoot());
        var host = new HostFinding
        {
            Target = "10.10.10.123",
            Http = { new HttpResult { Url = "http://10.10.10.123:5985/", Server = "Microsoft-HTTPAPI/2.0" } },
        };
        FingerprintLearner.LearnFromFinding(host, "jobtwo-r4", store);
        FingerprintLearner.LearnFromFinding(host, "jobtwo-r5", store);

        Assert.True(store.TryGetByValue("http_server", "Microsoft-HTTPAPI/2.0", out var fp));
        Assert.Equal(2, fp.Hits);
        Assert.Equal(2, fp.EvidenceFights.Count);
    }

    [Fact]
    public void LearnFromFinding_EmptyServer_SkipsEntry()
    {
        var store = new LearnedFingerprintStore(NewOutRoot());
        var host = new HostFinding
        {
            Target = "10.10.10.1",
            Http = { new HttpResult { Url = "http://10.10.10.1/", Server = null } },
        };
        var n = FingerprintLearner.LearnFromFinding(host, "fight-empty", store);
        Assert.Equal(0, n);
        Assert.Equal(0, store.Count);
    }
}
