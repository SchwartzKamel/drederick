using Drederick.Learning;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests.Learning;

public class ArchetypeClassifierTests
{
    private static HostFinding EmptyHost(string target = "10.10.10.1") => new() { Target = target };

    [Fact]
    public void Returns_Unknown_When_No_Signals()
    {
        var classifier = new ArchetypeClassifier();

        var result = classifier.Classify(EmptyHost());

        Assert.Equal(TargetArchetype.Unknown, result.Primary);
        Assert.Null(result.Secondary);
        Assert.Equal(0.0, result.Confidence);
        Assert.Empty(result.Signals);
    }

    [Fact]
    public void Classifies_JobTwoR4_Shape_As_WindowsAdEdge()
    {
        // JobTwo r4 fingerprint: nmap returned no ports, native HTTP/TLS
        // probes succeeded on 80/443/5985 (HTTP) and 443/10001/10002 (TLS).
        // Microsoft-HTTPAPI/2.0 banner. No SMB visible.
        var host = new HostFinding
        {
            Target = "10.10.10.99",
            Nmap = new NmapResult { OpenPorts = new List<NmapPort>() },
            Http = new List<HttpResult>
            {
                new() { Url = "http://10.10.10.99:80/", Server = "Microsoft-HTTPAPI/2.0", Status = 404 },
                new() { Url = "https://10.10.10.99:443/", Server = "Microsoft-HTTPAPI/2.0", Status = 404 },
                new() { Url = "http://10.10.10.99:5985/", Server = "Microsoft-HTTPAPI/2.0", Status = 404 },
            },
            Tls = new List<TlsResult>
            {
                new() { Port = 443, Subject = "CN=jobtwo" },
                new() { Port = 10001, Subject = "CN=jobtwo" },
                new() { Port = 10002, Subject = "CN=jobtwo" },
            },
        };

        var classifier = new ArchetypeClassifier();
        var result = classifier.Classify(host);

        Assert.Equal(TargetArchetype.WindowsAdEdge, result.Primary);
        Assert.True(result.Confidence > 0.5, $"expected high confidence, got {result.Confidence}");
        Assert.True(result.Confidence <= 0.95, "confidence must be capped at 0.95");
        Assert.Contains(result.Signals, s => s.Contains("Microsoft-HTTPAPI"));
        Assert.Contains(result.Signals, s => s.Contains("WinRM"));
    }

    [Fact]
    public void Classifies_Lame_Shape_As_LinuxSambaClassic()
    {
        // Lame fingerprint: ports 21/22/139/445 + OpenSSH banner + Samba SMB OS.
        var host = new HostFinding
        {
            Target = "10.10.10.3",
            Nmap = new NmapResult
            {
                OpenPorts = new List<NmapPort>
                {
                    new() { Port = 21, Service = "ftp", Product = "vsftpd" },
                    new() { Port = 22, Service = "ssh", Product = "OpenSSH" },
                    new() { Port = 139, Service = "netbios-ssn" },
                    new() { Port = 445, Service = "microsoft-ds" },
                },
            },
            Ssh = new List<SshResult>
            {
                new() { Port = 22, Banner = "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1" },
            },
            Smb = new List<SmbResult>
            {
                new() { Port = 445, Os = "Unix (Samba 3.0.20-Debian)", ComputerName = "lame" },
            },
            Ftp = new List<FtpResult>
            {
                new() { Port = 21, Banner = "220 (vsFTPd 2.3.4)" },
            },
        };

        var classifier = new ArchetypeClassifier();
        var result = classifier.Classify(host);

        Assert.Equal(TargetArchetype.LinuxClassic, result.Primary);
        Assert.True(result.Confidence > 0.7, $"expected high confidence, got {result.Confidence}");
        Assert.Contains(result.Signals, s => s.Contains("Samba", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Signals, s => s.Contains("OpenSSH"));
    }

    [Fact]
    public void Confidence_Reflects_Signal_Count()
    {
        // Partial WindowsAdEdge: Microsoft-HTTPAPI on a single port, no
        // WinRM, no second TLS endpoint, no 80+443 dual stack. Should
        // still classify as WindowsAdEdge but with reduced confidence.
        var partial = new HostFinding
        {
            Target = "10.10.10.50",
            Http = new List<HttpResult>
            {
                new() { Url = "http://10.10.10.50:80/", Server = "Microsoft-HTTPAPI/2.0" },
            },
            Tls = new List<TlsResult>
            {
                new() { Port = 443, Subject = "CN=x" },
            },
        };

        // Full WindowsAdEdge — all four positive checks fire.
        var full = new HostFinding
        {
            Target = "10.10.10.51",
            Http = new List<HttpResult>
            {
                new() { Url = "http://10.10.10.51:80/", Server = "Microsoft-HTTPAPI/2.0" },
                new() { Url = "https://10.10.10.51:443/", Server = "Microsoft-HTTPAPI/2.0" },
                new() { Url = "http://10.10.10.51:5985/", Server = "Microsoft-HTTPAPI/2.0" },
            },
            Tls = new List<TlsResult>
            {
                new() { Port = 443 },
                new() { Port = 10001 },
            },
        };

        var classifier = new ArchetypeClassifier();
        var partialResult = classifier.Classify(partial);
        var fullResult = classifier.Classify(full);

        Assert.Equal(TargetArchetype.WindowsAdEdge, partialResult.Primary);
        Assert.Equal(TargetArchetype.WindowsAdEdge, fullResult.Primary);
        Assert.True(
            fullResult.Confidence > partialResult.Confidence,
            $"full ({fullResult.Confidence}) must exceed partial ({partialResult.Confidence})");
        Assert.True(partialResult.Confidence < 0.95, "partial match must not hit cap");
        Assert.Equal(0.95, fullResult.Confidence, precision: 2);
    }

    [Fact]
    public void Classifies_Pure_WebStack_When_Only_Http_Visible()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.7",
            Http = new List<HttpResult>
            {
                new() { Url = "http://10.10.10.7:80/", Server = "nginx/1.18.0", Status = 200 },
            },
            Tls = new List<TlsResult>
            {
                new() { Port = 443, Subject = "CN=web" },
            },
        };

        var classifier = new ArchetypeClassifier();
        var result = classifier.Classify(host);

        Assert.Equal(TargetArchetype.WebStack, result.Primary);
        Assert.True(result.Confidence > 0.0);
    }

    [Fact]
    public void Classifies_Honeypot_When_Too_Many_Ports_Open()
    {
        var ports = new List<NmapPort>();
        for (int p = 1; p <= 60; p++)
        {
            ports.Add(new NmapPort { Port = p, Service = "unknown" });
        }
        var host = new HostFinding
        {
            Target = "10.10.10.250",
            Nmap = new NmapResult { OpenPorts = ports },
        };

        var classifier = new ArchetypeClassifier();
        var result = classifier.Classify(host);

        Assert.Equal(TargetArchetype.Honeypot, result.Primary);
        Assert.Contains(result.Signals, s => s.Contains("ports", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Classifies_DC_Shape_As_WindowsDcCandidate()
    {
        var host = new HostFinding
        {
            Target = "10.10.10.40",
            Nmap = new NmapResult
            {
                OpenPorts = new List<NmapPort>
                {
                    new() { Port = 88, Service = "kerberos-sec" },
                    new() { Port = 135, Service = "msrpc" },
                    new() { Port = 389, Service = "ldap" },
                    new() { Port = 445, Service = "microsoft-ds" },
                    new() { Port = 464, Service = "kpasswd5" },
                    new() { Port = 636, Service = "ldapssl" },
                    new() { Port = 3268, Service = "globalcatLDAP" },
                    new() { Port = 3269, Service = "globalcatLDAPssl" },
                },
            },
            Kerberos = new List<KerberosResult>
            {
                new() { Port = 88, Realm = "CORP.LOCAL" },
            },
        };

        var classifier = new ArchetypeClassifier();
        var result = classifier.Classify(host);

        Assert.Equal(TargetArchetype.WindowsDcCandidate, result.Primary);
        Assert.Contains(result.Signals, s => s.Contains("Kerberos", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Throws_On_Null_Host()
    {
        var classifier = new ArchetypeClassifier();
        Assert.Throws<ArgumentNullException>(() => classifier.Classify(null!));
    }
}
