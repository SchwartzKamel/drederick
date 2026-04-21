using System.DirectoryServices.Protocols;
using Drederick.Audit;
using Drederick.Recon.Shared;

namespace Drederick.Recon
{

    /// <summary>
    /// Passive, read-only LDAP probe. Connects to a target on the given port,
    /// attempts an <b>anonymous</b> bind only, and — on success — reads the
    /// server's rootDSE for the capability attributes <c>namingContexts</c>,
    /// <c>supportedControl</c>, <c>supportedLDAPVersion</c> and
    /// <c>supportedSASLMechanisms</c>. Never attempts a credentialed bind, never
    /// enumerates subtrees/users/computers, never performs active SASL
    /// negotiation beyond reading the server-advertised mechanisms list.
    ///
    /// The injectable client interface <see cref="ILdapClient"/> lives in the
    /// shared <c>Drederick.Recon.Shared</c> namespace and is consumed by both
    /// this tool and the Kerberos probe.
    /// </summary>
    public sealed class LdapTool : IReconTool
    {
        public string Name => "ldap";

        public string Description =>
            "Probe LDAP on a target: attempt an anonymous bind and, if accepted, " +
            "read rootDSE capability attributes (namingContexts, supportedControl, " +
            "supportedLDAPVersion, supportedSASLMechanisms). Read-only; no " +
            "credentialed binds, no directory enumeration, no SASL negotiation.";

        private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan BindTimeout = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);

        private static readonly string[] RootDseAttributes =
        [
            "namingContexts",
        "supportedControl",
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
    ];

        private readonly Scope.Scope _scope;
        private readonly AuditLog _audit;
        private readonly Func<string, int, ILdapClient> _connectFactory;

        public LdapTool(
            Scope.Scope scope,
            AuditLog audit,
            Func<string, int, ILdapClient>? connectFactory = null)
        {
            _scope = scope;
            _audit = audit;
            _connectFactory = connectFactory ?? DefaultFactory;
        }

        private static ILdapClient DefaultFactory(string host, int port)
        {
            var id = new LdapDirectoryIdentifier(host, port);
            var conn = new LdapConnection(id)
            {
                AuthType = AuthType.Anonymous,
                Timeout = ConnectTimeout,
            };
            conn.SessionOptions.ProtocolVersion = 3;
            return new LdapConnectionAdapter(conn);
        }

        public Task<LdapResult> ProbeAsync(string target, int port = 389, CancellationToken ct = default)
        {
            _scope.Require(target);

            _audit.Record("ldap.start", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
            });

            var result = new LdapResult { Port = port };
            ILdapClient? client = null;
            try
            {
                client = _connectFactory(target, port);

                try
                {
                    client.BindAnonymous(BindTimeout);
                    result.AnonymousBind = true;
                }
                catch (LdapAnonymousRefusedException)
                {
                    // Server explicitly refused anonymous bind. Not an error, it's
                    // a finding: the service is reachable but requires auth.
                    result.AnonymousBind = false;
                }

                if (result.AnonymousBind)
                {
                    var dse = client.QueryRootDse(RootDseAttributes, QueryTimeout);
                    result.NamingContexts = dse.NamingContexts;
                    result.SupportedControls = dse.SupportedControls;
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            finally
            {
                if (client is not null)
                {
                    try { client.Dispose(); } catch { /* best-effort close */ }
                }
            }

            _audit.Record("ldap.finish", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["anonymous_bind"] = result.AnonymousBind,
                ["naming_contexts"] = result.NamingContexts.Count,
                ["supported_controls"] = result.SupportedControls.Count,
                ["error"] = result.Error,
            });

            return Task.FromResult(result);
        }
    }

}

namespace Drederick.Recon.Shared
{
    internal sealed class LdapConnectionAdapter : ILdapClient
    {
        private readonly LdapConnection _conn;

        public LdapConnectionAdapter(LdapConnection conn) => _conn = conn;

        public void BindAnonymous(TimeSpan timeout)
        {
            _conn.Timeout = timeout;
            try
            {
                _conn.Bind();
            }
            catch (LdapException ex) when (IsAnonymousRefused(ex.ErrorCode))
            {
                throw new LdapAnonymousRefusedException("anonymous bind refused by server", ex);
            }
        }

        private static bool IsAnonymousRefused(int code) => code switch
        {
            8 => true,   // strongAuthRequired
            48 => true,  // inappropriateAuthentication
            49 => true,  // invalidCredentials
            50 => true,  // insufficientAccessRights
            53 => true,  // unwillingToPerform
            _ => false,
        };

        public LdapRootDse QueryRootDse(string[] attributes, TimeSpan timeout)
        {
            var req = new SearchRequest(
                distinguishedName: "",
                ldapFilter: "(objectClass=*)",
                searchScope: SearchScope.Base,
                attributeList: attributes);

            var resp = (SearchResponse)_conn.SendRequest(req, timeout);
            var dse = new LdapRootDse();
            if (resp.Entries.Count == 0) return dse;

            var entry = resp.Entries[0];
            dse.NamingContexts = ReadAttr(entry, "namingContexts");
            dse.SupportedControls = ReadAttr(entry, "supportedControl");
            dse.SupportedLdapVersions = ReadAttr(entry, "supportedLDAPVersion");
            dse.SupportedSaslMechanisms = ReadAttr(entry, "supportedSASLMechanisms");
            return dse;
        }

        private static List<string> ReadAttr(SearchResultEntry entry, string name)
        {
            var list = new List<string>();
            if (!entry.Attributes.Contains(name)) return list;
            var values = entry.Attributes[name].GetValues(typeof(string));
            foreach (var v in values)
            {
                var s = v as string ?? v?.ToString();
                if (!string.IsNullOrEmpty(s)) list.Add(s);
            }
            return list;
        }

        public void Dispose()
        {
            try { _conn.Dispose(); } catch { /* best-effort close */ }
        }
    }
}
