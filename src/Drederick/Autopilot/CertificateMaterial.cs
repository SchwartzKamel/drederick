using System.Text.Json.Serialization;

namespace Drederick.Autopilot;

/// <summary>
/// GAP-014 — Result of a <see cref="PfxCertScanner"/> pass over a harvested
/// loot/postex directory. Pure data record; no behaviour.
/// </summary>
public sealed class PfxCertScanResult
{
    [JsonPropertyName("certificates")]
    public List<CertificateMaterial> Certificates { get; set; } = new();

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

/// <summary>
/// GAP-014 — Single piece of certificate / key / Kerberos material recovered
/// from disk by <see cref="PfxCertScanner"/>.
///
/// Plaintext discipline: the recovered PFX password (if any) is recorded
/// out-of-band in a sibling file with mode 0600. Only the SHA-256 of the
/// recovered password is captured here.
/// </summary>
public sealed class CertificateMaterial
{
    [JsonPropertyName("path")]
    public string Path { get; set; } = "";

    /// <summary>"pfx" | "p12" | "key" | "pem" | "crt" | "cer" | "ccache" | "keytab".</summary>
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";

    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }

    [JsonPropertyName("sans")]
    public List<string> Sans { get; set; } = new();

    [JsonPropertyName("eku")]
    public List<string> ExtendedKeyUsage { get; set; } = new();

    [JsonPropertyName("not_before")]
    public DateTime? NotBefore { get; set; }

    [JsonPropertyName("not_after")]
    public DateTime? NotAfter { get; set; }

    [JsonPropertyName("encrypted")]
    public bool Encrypted { get; set; }

    /// <summary>SHA-256 of a recovered password, if the bundle was opened.</summary>
    [JsonPropertyName("password_recovered_sha256")]
    public string? PasswordRecoveredSha256 { get; set; }

    /// <summary>SAN contains a likely-DC hostname AND EKU contains Client Authentication.</summary>
    [JsonPropertyName("pkinit_capable")]
    public bool PkinitCapable { get; set; }

    /// <summary>ccache contains a TGT for the krbtgt principal.</summary>
    [JsonPropertyName("golden_ticket_indicator")]
    public bool GoldenTicketIndicator { get; set; }

    /// <summary>EKU contains TLS Client Authentication (1.3.6.1.5.5.7.3.2).</summary>
    [JsonPropertyName("client_auth_capable")]
    public bool ClientAuthCapable { get; set; }

    /// <summary>Kerberos principal extracted from ccache/keytab.</summary>
    [JsonPropertyName("principal")]
    public string? Principal { get; set; }

    /// <summary>Kerberos realm extracted from ccache/keytab.</summary>
    [JsonPropertyName("realm")]
    public string? Realm { get; set; }

    /// <summary>SHA-256 of the certificate DER body (or raw file bytes for ccache/keytab/PEM-only).</summary>
    [JsonPropertyName("fingerprint_sha256")]
    public string Fingerprint { get; set; } = "";
}
