using Drederick.Recon;

namespace Drederick.Enrichment.FingerprintStack;

/// <summary>
/// Harvests fingerprint signatures from a completed <see cref="HostFinding"/>
/// and persists them into a <see cref="LearnedFingerprintStore"/>. Each
/// invocation tags the new evidence with a <c>fightId</c> so cross-run
/// convergence is visible to the operator and the LLM planner.
/// </summary>
public static class FingerprintLearner
{
    /// <summary>
    /// Walks every observable signal on <paramref name="host"/> and upserts a
    /// <see cref="LearnedFingerprint"/> for each. After JobTwo r4 the store
    /// permanently knows that <c>Microsoft-HTTPAPI/2.0</c> on port 5985
    /// belongs to the WinRM (microsoft/wsman) family.
    /// </summary>
    public static int LearnFromFinding(HostFinding host, string fightId, LearnedFingerprintStore store)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentException.ThrowIfNullOrEmpty(fightId);
        ArgumentNullException.ThrowIfNull(store);

        var now = DateTimeOffset.UtcNow.ToString("o");
        var learned = 0;

        foreach (var http in host.Http)
        {
            if (string.IsNullOrWhiteSpace(http.Server)) continue;
            var (vendor, product, version) = ParseServerHeader(http.Server!);
            var port = ExtractPort(http.Url) ?? 0;
            // WinRM heuristic: Microsoft HTTPAPI on the canonical WSMan ports.
            if (vendor.Equals("Microsoft", StringComparison.OrdinalIgnoreCase)
                && product.Contains("HTTPAPI", StringComparison.OrdinalIgnoreCase)
                && (port == 5985 || port == 5986))
            {
                vendor = "microsoft";
                product = "wsman";
            }
            UpsertSignal(store, "http_server", http.Server!.Trim(), vendor, product, version, port, fightId, now);
            learned++;
        }

        foreach (var tls in host.Tls)
        {
            if (string.IsNullOrWhiteSpace(tls.Subject)) continue;
            UpsertSignal(store, "tls_subject_dn", tls.Subject!.Trim(), "", "", null, tls.Port, fightId, now);
            learned++;
        }

        foreach (var ssh in host.Ssh)
        {
            if (string.IsNullOrWhiteSpace(ssh.Banner)) continue;
            var (vendor, product, version) = ParseSshBanner(ssh.Banner!);
            UpsertSignal(store, "ssh_banner", ssh.Banner!.Trim(), vendor, product, version, ssh.Port, fightId, now);
            learned++;
        }

        foreach (var sshk in host.SshHostkey)
        {
            if (string.IsNullOrWhiteSpace(sshk.Banner)) continue;
            var (vendor, product, version) = ParseSshBanner(sshk.Banner!);
            UpsertSignal(store, "ssh_banner", sshk.Banner!.Trim(), vendor, product, version, sshk.Port, fightId, now);
            learned++;
        }

        foreach (var smb in host.Smb)
        {
            if (string.IsNullOrWhiteSpace(smb.Os)) continue;
            UpsertSignal(store, "smb_os", smb.Os!.Trim(), "microsoft", "windows", null, smb.Port, fightId, now);
            learned++;
        }

        foreach (var fp in host.Fingerprint)
        {
            foreach (var c in fp.Candidates)
            {
                if (string.IsNullOrEmpty(c.Vendor) || string.IsNullOrEmpty(c.Product)) continue;
                // Use the existing-stack candidate as a high-confidence
                // confirmation. Key by the CPE string when present so the
                // entry is dedup-stable across runs.
                var value = string.IsNullOrEmpty(c.Cpe) ? $"{c.Vendor}/{c.Product}/{c.Version}" : c.Cpe;
                UpsertSignal(store, "stack_candidate", value, c.Vendor, c.Product, c.Version, fp.Port ?? 0, fightId, now);
                learned++;
            }
        }

        return learned;
    }

    /// <summary>
    /// Parses an HTTP <c>Server</c> header into a best-guess
    /// (vendor, product, version) tuple. Splits on '/' and takes the first
    /// trailing token as the version.
    /// </summary>
    /// <example>
    /// <c>Microsoft-HTTPAPI/2.0</c> → (Microsoft, HTTPAPI, 2.0).
    /// <c>Apache/2.4.41 (Ubuntu)</c> → (Apache, Apache, 2.4.41).
    /// <c>nginx</c> → (nginx, nginx, null).
    /// </example>
    public static (string Vendor, string Product, string? Version) ParseServerHeader(string server)
    {
        ArgumentNullException.ThrowIfNull(server);
        var trimmed = server.Trim();
        if (trimmed.Length == 0) return ("", "", null);

        // Take only the first whitespace-delimited token to drop trailing
        // "(Ubuntu)" / "PHP/7.x" annotations.
        var space = trimmed.IndexOf(' ');
        var head = space > 0 ? trimmed.Substring(0, space) : trimmed;

        var slash = head.IndexOf('/');
        if (slash < 0) return (head, head, null);

        var name = head.Substring(0, slash);
        var version = head.Substring(slash + 1);
        if (string.IsNullOrEmpty(version)) version = null;

        // Hyphenated names like "Microsoft-HTTPAPI" → vendor=Microsoft, product=HTTPAPI.
        var dash = name.IndexOf('-');
        if (dash > 0 && dash < name.Length - 1)
        {
            var vendor = name.Substring(0, dash);
            var product = name.Substring(dash + 1);
            return (vendor, product, version);
        }
        return (name, name, version);
    }

    private static (string Vendor, string Product, string? Version) ParseSshBanner(string banner)
    {
        // "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" → softwareversion is the
        // token between the second '-' and the first whitespace.
        var trimmed = banner.Trim();
        var first = trimmed.IndexOf('-');
        if (first < 0) return ("", "ssh", null);
        var second = trimmed.IndexOf('-', first + 1);
        if (second < 0) return ("", "ssh", null);
        var tail = trimmed.Substring(second + 1);
        var space = tail.IndexOf(' ');
        if (space > 0) tail = tail.Substring(0, space);
        var underscore = tail.IndexOf('_');
        if (underscore <= 0) return ("", tail.ToLowerInvariant(), null);
        var product = tail.Substring(0, underscore);
        var version = tail.Substring(underscore + 1);
        var vendor = product.Equals("OpenSSH", StringComparison.OrdinalIgnoreCase) ? "openbsd" : "";
        return (vendor, product.ToLowerInvariant(), string.IsNullOrEmpty(version) ? null : version);
    }

    private static int? ExtractPort(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return null;
        if (uri.IsDefaultPort)
        {
            return uri.Scheme switch
            {
                "http" => 80,
                "https" => 443,
                _ => uri.Port,
            };
        }
        return uri.Port;
    }

    private static void UpsertSignal(
        LearnedFingerprintStore store,
        string kind,
        string value,
        string vendor,
        string product,
        string? version,
        int port,
        string fightId,
        string now)
    {
        var id = LearnedFingerprintStore.ComputeId(kind, value);
        var entry = new LearnedFingerprint(
            Id: id,
            SignalKind: kind,
            SignalValue: value,
            Vendor: vendor,
            Product: product,
            Version: version,
            Port: port,
            Hits: 1,
            FirstSeen: now,
            LastSeen: now,
            EvidenceFights: new[] { fightId });
        store.Upsert(entry);
    }
}
