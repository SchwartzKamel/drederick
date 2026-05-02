using Drederick.Ops;
using Xunit;

namespace Drederick.Tests;

public class TenableScanImporterTests
{
    private static readonly string FixtureDir = Path.Combine(
        Path.GetDirectoryName(typeof(TenableScanImporterTests).Assembly.Location)!,
        "..", "..", "..", "..", "fixtures", "tenable");

    // -------------------------------------------------------------------------
    // Nessus XML tests
    // -------------------------------------------------------------------------

    [Fact]
    public void ParseNessusXml_ExtractsBothHosts()
    {
        var xml = File.ReadAllText(Path.Combine(FixtureDir, "sample.nessus"));
        var result = TenableScanImporter.ParseNessusXml(xml, "sample.nessus");
        Assert.Equal("nessus-xml", result.Format);
        Assert.Contains("10.10.10.5", result.Hosts);
        Assert.Contains("10.10.10.6", result.Hosts);
        Assert.Equal(2, result.Hosts.Count); // notanip.local is skipped
    }

    [Fact]
    public void ParseNessusXml_SkipsNonIpHostName()
    {
        var xml = File.ReadAllText(Path.Combine(FixtureDir, "sample.nessus"));
        var result = TenableScanImporter.ParseNessusXml(xml, "sample.nessus");
        Assert.DoesNotContain("notanip.local", result.Hosts);
    }

    [Fact]
    public void ParseNessusXml_ExtractsServicesForFirstHost()
    {
        var xml = File.ReadAllText(Path.Combine(FixtureDir, "sample.nessus"));
        var result = TenableScanImporter.ParseNessusXml(xml, "sample.nessus");
        var host = result.HostScans.First(h => h.IpAddress == "10.10.10.5");
        var ports = host.Services.Select(s => s.Port).ToHashSet();
        Assert.Contains(22, ports);
        Assert.Contains(80, ports);
        Assert.Contains(443, ports);
    }

    [Fact]
    public void ParseNessusXml_ExtractsCves()
    {
        var xml = File.ReadAllText(Path.Combine(FixtureDir, "sample.nessus"));
        var result = TenableScanImporter.ParseNessusXml(xml, "sample.nessus");
        var host = result.HostScans.First(h => h.IpAddress == "10.10.10.5");
        var svc443 = host.Services.First(s => s.Port == 443);
        Assert.Contains("CVE-2021-1234", svc443.Cves);
        Assert.Contains("CVE-2021-5678", svc443.Cves);
    }

    [Fact]
    public void ParseNessusXml_ExtractsFqdnAndOs()
    {
        var xml = File.ReadAllText(Path.Combine(FixtureDir, "sample.nessus"));
        var result = TenableScanImporter.ParseNessusXml(xml, "sample.nessus");
        var host = result.HostScans.First(h => h.IpAddress == "10.10.10.5");
        Assert.Equal("target.htb", host.Fqdn);
        Assert.Contains("Linux", host.Os);
    }

    [Fact]
    public void ParseNessusXml_ExtractsSeverity()
    {
        var xml = File.ReadAllText(Path.Combine(FixtureDir, "sample.nessus"));
        var result = TenableScanImporter.ParseNessusXml(xml, "sample.nessus");
        var host = result.HostScans.First(h => h.IpAddress == "10.10.10.5");
        var svc443 = host.Services.First(s => s.Port == 443);
        Assert.Equal(3, svc443.Severity); // high
    }

    [Fact]
    public void ParseNessusXml_UsesHostIpTagOverNameAttribute()
    {
        const string xml = """
            <?xml version="1.0" ?>
            <NessusClientData_v2>
              <Report name="Test">
                <ReportHost name="hostname.example.com">
                  <HostProperties>
                    <tag name="host-ip">10.10.10.20</tag>
                  </HostProperties>
                  <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0" pluginID="10267" pluginName="SSH Info" pluginFamily="x">
                  </ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
            """;
        var result = TenableScanImporter.ParseNessusXml(xml, "<inline>");
        Assert.Contains("10.10.10.20", result.Hosts);
        Assert.DoesNotContain("hostname.example.com", result.Hosts);
    }

    [Fact]
    public void ParseNessusXml_ThrowsOnMalformedXml()
    {
        Assert.Throws<InvalidOperationException>(() =>
            TenableScanImporter.ParseNessusXml("<unclosed>", "<test>"));
    }

    // -------------------------------------------------------------------------
    // CSV tests
    // -------------------------------------------------------------------------

    [Fact]
    public void ParseCsv_ExtractsBothHosts()
    {
        var csv = File.ReadAllText(Path.Combine(FixtureDir, "sample.csv"));
        var result = TenableScanImporter.ParseCsv(csv, "sample.csv");
        Assert.Equal("csv", result.Format);
        Assert.Contains("10.10.10.5", result.Hosts);
        Assert.Contains("10.10.10.6", result.Hosts);
    }

    [Fact]
    public void ParseCsv_ExtractsCve()
    {
        var csv = File.ReadAllText(Path.Combine(FixtureDir, "sample.csv"));
        var result = TenableScanImporter.ParseCsv(csv, "sample.csv");
        var host = result.HostScans.First(h => h.IpAddress == "10.10.10.5");
        var svc443 = host.Services.First(s => s.Port == 443);
        Assert.Contains("CVE-2021-1234", svc443.Cves);
    }

    [Fact]
    public void ParseCsv_MapsSeverityFromRiskLabel()
    {
        var csv = File.ReadAllText(Path.Combine(FixtureDir, "sample.csv"));
        var result = TenableScanImporter.ParseCsv(csv, "sample.csv");
        var host = result.HostScans.First(h => h.IpAddress == "10.10.10.5");
        var svc443 = host.Services.First(s => s.Port == 443);
        Assert.Equal(2, svc443.Severity); // "Medium" → 2
    }

    [Fact]
    public void ParseCsv_ThrowsWhenHostColumnMissing()
    {
        const string csv = "Plugin ID,Port,Risk\n10267,22,None\n";
        Assert.Throws<InvalidOperationException>(() =>
            TenableScanImporter.ParseCsv(csv, "<test>"));
    }

    [Fact]
    public void ParseCsv_ReturnsEmptyForEmptyContent()
    {
        var result = TenableScanImporter.ParseCsv("", "<empty>");
        Assert.Empty(result.Hosts);
    }

    // -------------------------------------------------------------------------
    // Auto-detection tests
    // -------------------------------------------------------------------------

    [Fact]
    public void ParseContent_AutoDetectsNessusXml()
    {
        var xml = File.ReadAllText(Path.Combine(FixtureDir, "sample.nessus"));
        var result = TenableScanImporter.ParseContent(xml, "sample.nessus");
        Assert.Equal("nessus-xml", result.Format);
    }

    [Fact]
    public void ParseContent_AutoDetectsCsv()
    {
        var csv = File.ReadAllText(Path.Combine(FixtureDir, "sample.csv"));
        var result = TenableScanImporter.ParseContent(csv, "sample.csv");
        Assert.Equal("csv", result.Format);
    }

    [Fact]
    public void ParseContent_ThrowsOnUnrecognizedFormat()
    {
        Assert.Throws<InvalidOperationException>(() =>
            TenableScanImporter.ParseContent("not tenable data", "<test>"));
    }

    // -------------------------------------------------------------------------
    // Parse(filePath) tests
    // -------------------------------------------------------------------------

    [Fact]
    public void Parse_ThrowsFileNotFoundForMissingFile()
    {
        Assert.Throws<FileNotFoundException>(() =>
            TenableScanImporter.Parse("/nonexistent/path/scan.nessus"));
    }

    [Fact]
    public void Parse_ReadsNessusFileFromDisk()
    {
        var path = Path.Combine(FixtureDir, "sample.nessus");
        var result = TenableScanImporter.Parse(path);
        Assert.Equal(2, result.Hosts.Count);
    }

    [Fact]
    public void Parse_ReadsCsvFileFromDisk()
    {
        var path = Path.Combine(FixtureDir, "sample.csv");
        var result = TenableScanImporter.Parse(path);
        Assert.Equal(2, result.Hosts.Count);
    }

    // -------------------------------------------------------------------------
    // ToHostFindings conversion tests
    // -------------------------------------------------------------------------

    [Fact]
    public void ToHostFindings_PopulatesNmapPorts()
    {
        var xml = File.ReadAllText(Path.Combine(FixtureDir, "sample.nessus"));
        var result = TenableScanImporter.ParseNessusXml(xml, "sample.nessus");
        var findings = TenableScanImporter.ToHostFindings(result);

        var host = findings.First(f => f.Target == "10.10.10.5");
        Assert.NotNull(host.Nmap);
        var ports = host.Nmap!.OpenPorts.Select(p => p.Port).ToHashSet();
        Assert.Contains(22, ports);
        Assert.Contains(80, ports);
        Assert.Contains(443, ports);
    }

    [Fact]
    public void ToHostFindings_DeduplicatesPortProtocolPairs()
    {
        const string xml = """
            <?xml version="1.0" ?>
            <NessusClientData_v2>
              <Report name="Test">
                <ReportHost name="10.10.10.7">
                  <HostProperties>
                    <tag name="host-ip">10.10.10.7</tag>
                  </HostProperties>
                  <ReportItem port="80" svc_name="www" protocol="tcp" severity="0" pluginID="1" pluginName="A" pluginFamily="x"></ReportItem>
                  <ReportItem port="80" svc_name="www" protocol="tcp" severity="1" pluginID="2" pluginName="B" pluginFamily="x"></ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
            """;
        var result = TenableScanImporter.ParseNessusXml(xml, "<inline>");
        var findings = TenableScanImporter.ToHostFindings(result);
        var host = findings.First(f => f.Target == "10.10.10.7");
        Assert.NotNull(host.Nmap);
        // Port 80/tcp appears twice in the scan but should produce exactly one NmapPort.
        Assert.Single(host.Nmap!.OpenPorts, p => p.Port == 80 && p.Protocol == "tcp");
    }

    [Fact]
    public void ToHostFindings_HostWithNoServicesHasNullNmap()
    {
        const string xml = """
            <?xml version="1.0" ?>
            <NessusClientData_v2>
              <Report name="Test">
                <ReportHost name="10.10.10.8">
                  <HostProperties>
                    <tag name="host-ip">10.10.10.8</tag>
                  </HostProperties>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
            """;
        var result = TenableScanImporter.ParseNessusXml(xml, "<inline>");
        var findings = TenableScanImporter.ToHostFindings(result);
        var host = findings.First(f => f.Target == "10.10.10.8");
        Assert.Null(host.Nmap);
    }

    // -------------------------------------------------------------------------
    // CSV splitter tests
    // -------------------------------------------------------------------------

    [Fact]
    public void SplitCsvLine_HandlesUnquotedFields()
    {
        var fields = TenableScanImporter.SplitCsvLine("a,b,c");
        Assert.Equal(new[] { "a", "b", "c" }, fields);
    }

    [Fact]
    public void SplitCsvLine_HandlesQuotedFieldWithComma()
    {
        var fields = TenableScanImporter.SplitCsvLine("\"hello, world\",b,c");
        Assert.Equal(new[] { "hello, world", "b", "c" }, fields);
    }

    [Fact]
    public void SplitCsvLine_HandlesEscapedDoubleQuote()
    {
        var fields = TenableScanImporter.SplitCsvLine("\"he said \"\"hi\"\"\",b");
        Assert.Equal(new[] { "he said \"hi\"", "b" }, fields);
    }

    [Fact]
    public void SplitCsvLine_HandlesSingleEmptyField()
    {
        var fields = TenableScanImporter.SplitCsvLine("a,,c");
        Assert.Equal(new[] { "a", "", "c" }, fields);
    }
}
