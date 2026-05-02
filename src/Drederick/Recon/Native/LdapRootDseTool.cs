// Original NSE script: ldap-rootdse.nse
// Source: https://nmap.org/nsedoc/scripts/ldap-rootdse.html
// Author: Patrik Karlsson
// License: NPSL
//
// Native C# port: anonymous-bind to an LDAP server and read the
// rootDSE (namingContexts, supportedControl, supportedLDAPVersion,
// supportedSASLMechanisms). Reuses the shared ILdapClient contract
// from Drederick.Recon.Shared so unit tests can stub the directory
// without standing up an actual LDAP server.
using Drederick.Audit;
using Drederick.Recon.Shared;

namespace Drederick.Recon.Native;

public sealed class LdapRootDseTool : IReconTool
{
    public string Name => "ldap-rootdse";
    public string Description =>
        "Native port of nmap's ldap-rootdse.nse: anonymous-bind and dump the " +
        "rootDSE (naming contexts / supported controls / SASL mechanisms). " +
        "Target must be in scope.";

    private static readonly TimeSpan BindTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(8);
    private static readonly string[] RequestedAttributes =
    {
        "namingContexts", "supportedControl",
        "supportedLDAPVersion", "supportedSASLMechanisms",
    };

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, int, ILdapClient> _factory;

    public LdapRootDseTool(
        Scope.Scope scope,
        AuditLog audit,
        Func<string, int, ILdapClient>? factory = null)
    {
        _scope = scope;
        _audit = audit;
        _factory = factory ?? DefaultFactory;
    }

    public async Task<LdapRootDseResult> ProbeAsync(string target, int port = 389, CancellationToken ct = default)
    {
        _scope.Require(target);
        _audit.Record("ldap-rootdse.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
        });

        var result = new LdapRootDseResult { Port = port };
        try
        {
            await Task.Yield();
            ct.ThrowIfCancellationRequested();
            using var client = _factory(target, port);
            try
            {
                client.BindAnonymous(BindTimeout);
                result.AnonymousBind = true;
            }
            catch (LdapAnonymousRefusedException ex)
            {
                result.AnonymousBind = false;
                result.Error = ex.Message;
                goto finish;
            }
            var dse = client.QueryRootDse(RequestedAttributes, QueryTimeout);
            result.NamingContexts.AddRange(dse.NamingContexts);
            result.SupportedControls.AddRange(dse.SupportedControls);
            result.SupportedLdapVersions.AddRange(dse.SupportedLdapVersions);
            result.SupportedSaslMechanisms.AddRange(dse.SupportedSaslMechanisms);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { result.Error = ex.Message; }

    finish:
        _audit.Record("ldap-rootdse.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["port"] = port,
            ["anonymous_bind"] = result.AnonymousBind,
            ["naming_contexts"] = result.NamingContexts.Count,
            ["error"] = result.Error,
        });
        return result;
    }

    private static ILdapClient DefaultFactory(string host, int port) =>
        new DefaultAnonymousAdapter(host, port);

    /// <summary>
    /// Default ILdapClient backed by System.DirectoryServices.Protocols.
    /// Anonymous-bind only; raises LdapAnonymousRefusedException on the
    /// strongAuthRequired / inappropriateAuth status codes.
    /// </summary>
    private sealed class DefaultAnonymousAdapter : ILdapClient
    {
        private readonly System.DirectoryServices.Protocols.LdapConnection _conn;

        public DefaultAnonymousAdapter(string host, int port)
        {
            var id = new System.DirectoryServices.Protocols.LdapDirectoryIdentifier(host, port);
            _conn = new System.DirectoryServices.Protocols.LdapConnection(id)
            {
                AuthType = System.DirectoryServices.Protocols.AuthType.Anonymous,
            };
            _conn.SessionOptions.ProtocolVersion = 3;
        }

        public void BindAnonymous(TimeSpan timeout)
        {
            _conn.Timeout = timeout;
            try { _conn.Bind(); }
            catch (System.DirectoryServices.Protocols.LdapException ex)
                when (ex.ErrorCode is 8 or 50)
            { throw new LdapAnonymousRefusedException(ex.Message, ex); }
        }

        public LdapRootDse QueryRootDse(string[] attributes, TimeSpan timeout)
        {
            _conn.Timeout = timeout;
            var req = new System.DirectoryServices.Protocols.SearchRequest(
                "", "(objectClass=*)",
                System.DirectoryServices.Protocols.SearchScope.Base, attributes);
            var resp = (System.DirectoryServices.Protocols.SearchResponse)_conn.SendRequest(req);
            var dse = new LdapRootDse();
            if (resp.Entries.Count > 0)
            {
                var e = resp.Entries[0];
                Pull(e, "namingContexts", dse.NamingContexts);
                Pull(e, "supportedControl", dse.SupportedControls);
                Pull(e, "supportedLDAPVersion", dse.SupportedLdapVersions);
                Pull(e, "supportedSASLMechanisms", dse.SupportedSaslMechanisms);
            }
            return dse;
        }

        private static void Pull(System.DirectoryServices.Protocols.SearchResultEntry e,
            string name, List<string> bucket)
        {
            if (!e.Attributes.Contains(name)) return;
            foreach (var v in e.Attributes[name].GetValues(typeof(string)))
                if (v is string s) bucket.Add(s);
        }

        public void Dispose() => _conn.Dispose();
    }
}
