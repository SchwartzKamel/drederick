namespace Drederick.Enrichment.FingerprintStack.Signals;

/// <summary>
/// Inspects TLS certificate Subject / SAN / Issuer for product keywords
/// (Plesk, vSphere, vCenter, ESXi, GitLab, Confluence, Jenkins, Splunk,
/// SonarQube, Grafana, Kibana, Elasticsearch, etc). Subject/SAN keyword
/// hits score 0.6; issuer-only hits score 0.4.
/// </summary>
public sealed class TlsCertSignal : IFingerprintSignal
{
    public string Name => "tls-cert";

    private const double SubjectKeywordWeight = 0.6;
    private const double IssuerOnlyWeight = 0.4;

    private sealed record Keyword(string Token, string Vendor, string Product);

    private static readonly Keyword[] _corpus =
    {
        new("plesk",        "plesk",            "plesk"),
        new("vsphere",      "vmware",           "vsphere"),
        new("vcenter",      "vmware",           "vcenter"),
        new("esxi",         "vmware",           "esxi"),
        new("vmware",       "vmware",           "vmware"),
        new("gitlab",       "gitlab",           "gitlab"),
        new("confluence",   "atlassian",        "confluence"),
        new("jira",         "atlassian",        "jira"),
        new("bitbucket",    "atlassian",        "bitbucket"),
        new("jenkins",      "jenkins",          "jenkins"),
        new("splunk",       "splunk",           "splunk"),
        new("sonarqube",    "sonarsource",      "sonarqube"),
        new("grafana",      "grafana",          "grafana"),
        new("kibana",       "elastic",          "kibana"),
        new("elasticsearch","elastic",          "elasticsearch"),
        new("logstash",     "elastic",          "logstash"),
        new("rabbitmq",     "pivotal",          "rabbitmq"),
        new("nextcloud",    "nextcloud",        "nextcloud"),
        new("owncloud",     "owncloud",         "owncloud"),
        new("zimbra",       "zimbra",           "zimbra"),
        new("exchange",     "microsoft",        "exchange"),
        new("rdweb",        "microsoft",        "remote_desktop_web"),
        new("citrix",       "citrix",           "netscaler"),
        new("fortigate",    "fortinet",         "fortigate"),
        new("pulse",        "ivanti",           "connect_secure"),
        new("ssl-vpn",      "fortinet",         "fortigate_ssl_vpn"),
    };

    public IReadOnlyList<FingerprintSignalHit> Extract(FingerprintInput input)
    {
        var hits = new List<FingerprintSignalHit>();

        var subjectHay = string.Join(" ", new[] { input.TlsSubject ?? "" }
            .Concat(input.TlsSubjectAltNames ?? Array.Empty<string>()));
        var issuerHay = input.TlsIssuer ?? "";
        if (subjectHay.Length == 0 && issuerHay.Length == 0) return hits;

        var subjectLower = subjectHay.ToLowerInvariant();
        var issuerLower = issuerHay.ToLowerInvariant();

        foreach (var kw in _corpus)
        {
            if (subjectLower.Contains(kw.Token, StringComparison.Ordinal))
            {
                hits.Add(new FingerprintSignalHit(
                    Name, kw.Vendor, kw.Product, null, SubjectKeywordWeight,
                    $"subject/SAN contains '{kw.Token}'"));
            }
            else if (issuerLower.Contains(kw.Token, StringComparison.Ordinal))
            {
                hits.Add(new FingerprintSignalHit(
                    Name, kw.Vendor, kw.Product, null, IssuerOnlyWeight,
                    $"issuer contains '{kw.Token}'"));
            }
        }

        return hits;
    }
}
