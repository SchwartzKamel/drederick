using Drederick.Audit;


namespace Drederick.Recon
{

    /// <summary>
    /// Kerberos realm / SPN discovery via LDAP against a Domain Controller.
    /// This tool deliberately DOES NOT speak the Kerberos protocol itself:
    /// it performs no <c>KRB_AS_REQ</c> probes, no AS-REP roasting, no
    /// Kerberoasting (<c>TGS-REQ</c> for SPN tickets), no user enumeration
    /// through PA-ENC-TIMESTAMP timing differences, and it never shells out to
    /// offensive helpers like <c>krb5-enum-users</c> or <c>GetNPUsers.py</c>.
    /// SPN discovery is performed exclusively through an LDAP subtree search for
    /// <c>(servicePrincipalName=*)</c>, which is a passive directory read and not
    /// a Kerberos packet exchange.
    ///
    /// Scope gate runs first; then an anonymous LDAP bind is attempted unless
    /// explicit credentials were supplied, in which case a simple bind with
    /// those creds is used. Result cardinality is capped at
    /// <see cref="MaxSpnEntries"/> to keep output bounded on large directories.
    /// </summary>
    public sealed class KerberosTool : IReconTool
    {
        public string Name => "kerberos";

        public string Description =>
            "Discover the Kerberos realm and service principal names (SPNs) for a " +
            "Domain Controller via LDAP. Performs an anonymous bind by default, " +
            "or a simple bind when explicit credentials are supplied. Does not " +
            "speak the Kerberos protocol itself (no AS-REP roasting, no " +
            "Kerberoasting, no user enumeration via timing).";

        internal const int MaxSpnEntries = 500;

        private readonly Scope.Scope _scope;
        private readonly AuditLog _audit;
        private readonly Func<string, int, string?, string?, Kerberos.ILdapClient> _connectFactory;

        public KerberosTool(
            Scope.Scope scope,
            AuditLog audit,
            Func<string, int, string?, string?, Kerberos.ILdapClient>? connectFactory = null)
        {
            _scope = scope;
            _audit = audit;
            _connectFactory = connectFactory ?? DefaultConnect;
        }

        private static Kerberos.ILdapClient DefaultConnect(string host, int port, string? user, string? password)
            => new Kerberos.DefaultLdapClient(host, port);

        public Task<KerberosResult> ProbeAsync(
            string target,
            int port = 389,
            string? bindUser = null,
            string? bindPassword = null,
            CancellationToken ct = default)
        {
            _scope.Require(target);

            _audit.Record("kerberos.start", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["authenticated"] = !string.IsNullOrEmpty(bindUser),
            });

            var result = new KerberosResult { Port = port };

            Kerberos.ILdapClient? client = null;
            try
            {
                client = _connectFactory(target, port, bindUser, bindPassword);

                try
                {
                    client.Bind(bindUser, bindPassword);
                }
                catch (Exception ex)
                {
                    result.Error = string.IsNullOrEmpty(bindUser)
                        ? $"anonymous bind refused: {Tail(ex.Message, 300)}"
                        : $"bind failed: {Tail(ex.Message, 300)}";
                    RecordFinish(target, port, result);
                    return Task.FromResult(result);
                }

                ct.ThrowIfCancellationRequested();

                string? baseDn = null;
                try
                {
                    baseDn = client.GetDefaultNamingContext();
                }
                catch (Exception ex)
                {
                    result.Error = $"rootDSE read failed: {Tail(ex.Message, 300)}";
                    RecordFinish(target, port, result);
                    return Task.FromResult(result);
                }

                if (string.IsNullOrWhiteSpace(baseDn))
                {
                    result.Error = "no defaultNamingContext on rootDSE";
                    result.Realm = RealmFromHostname(target);
                    RecordFinish(target, port, result);
                    return Task.FromResult(result);
                }

                result.Realm = RealmFromNamingContext(baseDn) ?? RealmFromHostname(target);

                IEnumerable<Kerberos.LdapEntry> entries;
                try
                {
                    entries = client.Search(
                        baseDn,
                        "(servicePrincipalName=*)",
                        new[] { "servicePrincipalName", "sAMAccountName" },
                        MaxSpnEntries);
                }
                catch (Exception ex)
                {
                    result.Error = $"spn search failed: {Tail(ex.Message, 300)}";
                    RecordFinish(target, port, result);
                    return Task.FromResult(result);
                }

                int count = 0;
                foreach (var entry in entries)
                {
                    if (count >= MaxSpnEntries) break;
                    count++;
                    if (!entry.Attributes.TryGetValue("servicePrincipalName", out var spns)) continue;
                    foreach (var spn in spns)
                    {
                        if (string.IsNullOrWhiteSpace(spn)) continue;
                        result.Spns.Add(spn);
                        if (result.Spns.Count >= MaxSpnEntries) break;
                    }
                    if (result.Spns.Count >= MaxSpnEntries) break;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                result.Error = Tail(ex.Message, 500);
            }
            finally
            {
                try { client?.Dispose(); } catch { /* best-effort */ }
            }

            RecordFinish(target, port, result);
            return Task.FromResult(result);
        }

        private void RecordFinish(string target, int port, KerberosResult result)
        {
            _audit.Record("kerberos.finish", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["realm"] = result.Realm,
                ["spn_count"] = result.Spns.Count,
                ["error"] = result.Error,
            });
        }

        internal static string? RealmFromNamingContext(string dn)
        {
            // "DC=corp,DC=example,DC=com" -> "CORP.EXAMPLE.COM"
            var parts = dn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var dcs = new List<string>();
            foreach (var p in parts)
            {
                if (p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    dcs.Add(p[3..]);
            }
            if (dcs.Count == 0) return null;
            return string.Join('.', dcs).ToUpperInvariant();
        }

        internal static string? RealmFromHostname(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return null;
            var dot = host.IndexOf('.');
            if (dot <= 0 || dot == host.Length - 1) return null;
            return host[(dot + 1)..].ToUpperInvariant();
        }

        private static string Tail(string s, int max) =>
            string.IsNullOrEmpty(s) ? string.Empty : (s.Length <= max ? s : s[^max..]);
    }

} // namespace Drederick.Recon

namespace Drederick.Recon.Kerberos
{
    /// <summary>
    /// Minimal LDAP client surface used by <see cref="KerberosTool"/>. Lives in
    /// the <c>Drederick.Recon.Kerberos</c> sub-namespace so it cannot collide
    /// with an <c>ILdapClient</c> defined at <c>Drederick.Recon</c> scope by
    /// the parallel <c>ldap-tool</c> agent; a later registration pass can
    /// unify both if the shapes converge.
    /// </summary>
    public interface ILdapClient : IDisposable
    {
        /// <summary>
        /// Bind to the directory. Null/empty user means anonymous simple bind.
        /// Throws if the server refuses the bind.
        /// </summary>
        void Bind(string? user, string? password);

        /// <summary>
        /// Return <c>defaultNamingContext</c> from rootDSE, or null if the
        /// server does not expose one.
        /// </summary>
        string? GetDefaultNamingContext();

        /// <summary>
        /// Subtree search. Implementations must cap results at
        /// <paramref name="sizeLimit"/>.
        /// </summary>
        IEnumerable<LdapEntry> Search(string baseDn, string filter, string[] attributes, int sizeLimit);
    }

    public sealed class LdapEntry
    {
        public string DistinguishedName { get; set; } = "";
        public Dictionary<string, List<string>> Attributes { get; } =
            new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Default implementation backed by <c>System.DirectoryServices.Protocols</c>.
    /// Only exercised by runtime callers; tests inject a fake via the
    /// <see cref="KerberosTool"/> constructor factory.
    /// </summary>
    internal sealed class DefaultLdapClient : ILdapClient
    {
        private readonly string _host;
        private readonly int _port;
        private System.DirectoryServices.Protocols.LdapConnection? _conn;

        public DefaultLdapClient(string host, int port)
        {
            _host = host;
            _port = port;
        }

        public void Bind(string? user, string? password)
        {
            var id = new System.DirectoryServices.Protocols.LdapDirectoryIdentifier(_host, _port);
            var conn = new System.DirectoryServices.Protocols.LdapConnection(id)
            {
                AuthType = string.IsNullOrEmpty(user)
                    ? System.DirectoryServices.Protocols.AuthType.Anonymous
                    : System.DirectoryServices.Protocols.AuthType.Basic,
                Timeout = TimeSpan.FromSeconds(10),
            };
            conn.SessionOptions.ProtocolVersion = 3;

            if (string.IsNullOrEmpty(user))
            {
                conn.Bind();
            }
            else
            {
                conn.Bind(new System.Net.NetworkCredential(user, password ?? string.Empty));
            }
            _conn = conn;
        }

        public string? GetDefaultNamingContext()
        {
            if (_conn is null) return null;
            var req = new System.DirectoryServices.Protocols.SearchRequest(
                distinguishedName: string.Empty,
                ldapFilter: "(objectClass=*)",
                searchScope: System.DirectoryServices.Protocols.SearchScope.Base,
                attributeList: new[] { "defaultNamingContext" });
            var resp = (System.DirectoryServices.Protocols.SearchResponse)_conn.SendRequest(req);
            foreach (System.DirectoryServices.Protocols.SearchResultEntry e in resp.Entries)
            {
                if (e.Attributes.Contains("defaultNamingContext"))
                {
                    var attr = e.Attributes["defaultNamingContext"];
                    if (attr.Count > 0) return attr[0]?.ToString();
                }
            }
            return null;
        }

        public IEnumerable<LdapEntry> Search(string baseDn, string filter, string[] attributes, int sizeLimit)
        {
            if (_conn is null) yield break;
            var req = new System.DirectoryServices.Protocols.SearchRequest(
                distinguishedName: baseDn,
                ldapFilter: filter,
                searchScope: System.DirectoryServices.Protocols.SearchScope.Subtree,
                attributeList: attributes);
            req.SizeLimit = sizeLimit;
            var resp = (System.DirectoryServices.Protocols.SearchResponse)_conn.SendRequest(req);
            foreach (System.DirectoryServices.Protocols.SearchResultEntry e in resp.Entries)
            {
                var entry = new LdapEntry { DistinguishedName = e.DistinguishedName };
                foreach (string a in e.Attributes.AttributeNames)
                {
                    var values = new List<string>();
                    var attr = e.Attributes[a];
                    for (int i = 0; i < attr.Count; i++)
                    {
                        var v = attr[i];
                        if (v is string s) values.Add(s);
                        else if (v is byte[] b) values.Add(System.Text.Encoding.UTF8.GetString(b));
                        else if (v != null) values.Add(v.ToString() ?? string.Empty);
                    }
                    entry.Attributes[a] = values;
                }
                yield return entry;
            }
        }

        public void Dispose() => _conn?.Dispose();
    }
}
