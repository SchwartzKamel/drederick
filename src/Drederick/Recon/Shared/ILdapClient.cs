namespace Drederick.Recon.Shared;

/// <summary>
/// Unified, passive LDAP client contract shared by the recon LDAP and
/// Kerberos tools. Lives in the <c>Drederick.Recon.Shared</c> namespace
/// after the prior split between <c>Drederick.Recon.Ldap.ILdapClient</c>
/// (anonymous-only rootDSE read) and <c>Drederick.Recon.Kerberos.ILdapClient</c>
/// (anonymous or simple-bind SPN subtree search) was consolidated.
///
/// The interface surface is the union of the two historical shapes. All
/// methods are defined as default interface methods that throw
/// <see cref="NotSupportedException"/> so adapter implementations only
/// override the operations they actually need. In particular, the LDAP
/// adapter never exposes credentialed bind behaviour even though
/// <see cref="Bind"/> is part of the shared contract — its
/// <see cref="LdapTool"/> caller only invokes <see cref="BindAnonymous"/>.
/// </summary>
public interface ILdapClient : IDisposable
{
    // --- Anonymous rootDSE read surface (used by LdapTool) ---

    /// <summary>Attempt an anonymous LDAP bind. Throw
    /// <see cref="LdapAnonymousRefusedException"/> if the server
    /// explicitly refuses anonymous binds; any other exception is
    /// treated as a hard error by the caller.</summary>
    void BindAnonymous(TimeSpan timeout) => throw new NotSupportedException();

    /// <summary>Issue a base-scope search of the empty DN
    /// (<c>(objectClass=*)</c>) requesting only the given
    /// attributes.</summary>
    LdapRootDse QueryRootDse(string[] attributes, TimeSpan timeout) => throw new NotSupportedException();

    // --- Bind-and-search surface (used by KerberosTool) ---

    /// <summary>
    /// Bind to the directory. Null/empty user means anonymous simple bind.
    /// Throws if the server refuses the bind.
    /// </summary>
    void Bind(string? user, string? password) => throw new NotSupportedException();

    /// <summary>
    /// Return <c>defaultNamingContext</c> from rootDSE, or null if the
    /// server does not expose one.
    /// </summary>
    string? GetDefaultNamingContext() => throw new NotSupportedException();

    /// <summary>
    /// Subtree search. Implementations must cap results at
    /// <paramref name="sizeLimit"/>.
    /// </summary>
    IEnumerable<LdapEntry> Search(string baseDn, string filter, string[] attributes, int sizeLimit)
        => throw new NotSupportedException();
}

public sealed class LdapRootDse
{
    public List<string> NamingContexts { get; set; } = new();
    public List<string> SupportedControls { get; set; } = new();
    public List<string> SupportedLdapVersions { get; set; } = new();
    public List<string> SupportedSaslMechanisms { get; set; } = new();
}

public sealed class LdapEntry
{
    public string DistinguishedName { get; set; } = "";
    public Dictionary<string, List<string>> Attributes { get; } =
        new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Signals that an anonymous bind was refused by the remote server (as
/// opposed to a transport or protocol error). Caller records
/// <c>AnonymousBind=false</c> without populating <c>Error</c>.
/// </summary>
public sealed class LdapAnonymousRefusedException : Exception
{
    public LdapAnonymousRefusedException(string message) : base(message) { }
    public LdapAnonymousRefusedException(string message, Exception inner) : base(message, inner) { }
}
