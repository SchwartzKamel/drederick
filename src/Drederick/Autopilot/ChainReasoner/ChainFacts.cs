using Drederick.Memory;
using Drederick.Recon;

namespace Drederick.Autopilot.ChainReasoner;

/// <summary>
/// Predicate set extracted from the <see cref="KnowledgeBase"/>, the
/// <see cref="CredentialStore"/>, and the live session registry. The chain
/// reasoner matches each <see cref="ChainTemplate.Requires"/> entry against
/// this set; a chain whose predicates aren't all satisfied is pruned.
///
/// Predicate vocabulary (string-keyed, case-sensitive):
///   • <c>service.&lt;name&gt;</c>          — at least one host advertises the named service
///   • <c>service.&lt;name&gt;@&lt;host&gt;</c> — host-scoped variant
///   • <c>port.&lt;n&gt;@&lt;host&gt;</c>      — host has the numeric port open
///   • <c>smb.anon-read=true</c>             — at least one SMB target permits null-session listing
///   • <c>smb.signing.required=false</c>     — at least one target advertises signing not required
///   • <c>ftp.anon=true</c>                   — anonymous FTP allowed somewhere
///   • <c>ldap.anon-bind=true</c>             — anonymous LDAP bind succeeded
///   • <c>snmp.community.public</c>           — community 'public' answered
///   • <c>kerberos.realm.&lt;realm&gt;</c>     — Kerberos realm seen
///   • <c>kerberos.spns&gt;0</c>              — at least one SPN observed (kerberoast feasibility)
///   • <c>http.target</c> / <c>http.500</c>   — HTTP service exists / 5xx seen
///   • <c>cred.any</c>                         — at least one credential in the store
///   • <c>cred.user.&lt;user&gt;</c>          — specific user known
///   • <c>session.open=true</c>                — at least one post-ex session live
/// </summary>
public sealed class ChainFacts
{
    public HashSet<string> Predicates { get; } = new(StringComparer.Ordinal);
    public List<string> Targets { get; } = new();
    public IReadOnlyList<string> OpenSessionIds { get; init; } = Array.Empty<string>();
    public int CredentialCount { get; init; }

    public bool Has(string predicate) => Predicates.Contains(predicate);

    public static ChainFacts From(
        KnowledgeBase kb,
        CredentialStore? creds,
        IReadOnlyList<string>? openSessionIds)
    {
        ArgumentNullException.ThrowIfNull(kb);
        var sessions = openSessionIds ?? Array.Empty<string>();
        var f = new ChainFacts
        {
            OpenSessionIds = sessions,
            CredentialCount = creds?.Count ?? 0,
        };

        if (sessions.Count > 0) f.Predicates.Add("session.open=true");

        if (creds != null && creds.Count > 0)
        {
            f.Predicates.Add("cred.any");
            foreach (var c in creds.List())
            {
                if (!string.IsNullOrEmpty(c.User))
                    f.Predicates.Add($"cred.user.{c.User.ToLowerInvariant()}");
            }
        }

        foreach (var (host, hf) in kb.Hosts)
        {
            f.Targets.Add(host);
            ExtractFromHost(host, hf, f);
        }

        return f;
    }

    private static void ExtractFromHost(string host, HostFinding hf, ChainFacts f)
    {
        if (hf.Nmap?.OpenPorts is { Count: > 0 } ports)
        {
            foreach (var p in ports)
            {
                f.Predicates.Add($"port.{p.Port}@{host}");
                if (!string.IsNullOrEmpty(p.Service))
                {
                    var svc = p.Service.ToLowerInvariant();
                    f.Predicates.Add($"service.{svc}");
                    f.Predicates.Add($"service.{svc}@{host}");
                }
            }
        }

        foreach (var s in hf.Smb)
        {
            f.Predicates.Add("service.smb");
            f.Predicates.Add($"service.smb@{host}");
            if (s.SigningRequired == false)
                f.Predicates.Add("smb.signing.required=false");
            // Anon listing: shares present without auth implies null-session worked.
            if (s.Shares.Count > 0)
                f.Predicates.Add("smb.anon-read=true");
        }

        foreach (var ftp in hf.Ftp)
        {
            f.Predicates.Add("service.ftp");
            f.Predicates.Add($"service.ftp@{host}");
            if (ftp.AnonymousAllowed) f.Predicates.Add("ftp.anon=true");
        }

        foreach (var ldap in hf.Ldap)
        {
            f.Predicates.Add("service.ldap");
            f.Predicates.Add($"service.ldap@{host}");
            if (ldap.AnonymousBind) f.Predicates.Add("ldap.anon-bind=true");
        }

        foreach (var snmp in hf.Snmp)
        {
            f.Predicates.Add("service.snmp");
            f.Predicates.Add($"service.snmp@{host}");
            if (snmp.Reachable && string.Equals(snmp.Community, "public", StringComparison.OrdinalIgnoreCase))
                f.Predicates.Add("snmp.community.public");
        }

        foreach (var k in hf.Kerberos)
        {
            f.Predicates.Add("service.kerberos");
            f.Predicates.Add($"service.kerberos@{host}");
            if (!string.IsNullOrEmpty(k.Realm))
                f.Predicates.Add($"kerberos.realm.{k.Realm.ToLowerInvariant()}");
            if (k.Spns.Count > 0)
                f.Predicates.Add("kerberos.spns>0");
        }

        if (hf.Http.Count > 0) f.Predicates.Add("http.target");
        foreach (var h in hf.Http)
        {
            if (h.Status is >= 500 and < 600) f.Predicates.Add("http.500");
        }
    }
}
