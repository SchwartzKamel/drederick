using System.Net;
using System.Net.Sockets;

namespace Drederick.Scope;

/// <summary>
/// Loads a scope file. Format: one CIDR, IP, or comment per line. '#' begins a
/// comment. Blank lines are ignored. IPv4 and IPv6 are both supported.
/// </summary>
public static class ScopeLoader
{
    private const int MaxV4Prefix = 16;
    private const int MaxV6Prefix = 48;

    public static Scope LoadFile(string path, bool allowBroad = false)
    {
        if (!File.Exists(path))
            throw new ScopeException($"Scope file not found: {path}");
        return Parse(File.ReadAllText(path), path, allowBroad);
    }

    public static Scope Parse(string text, string source = "<memory>", bool allowBroad = false)
    {
        var entries = new List<ScopeEntry>();
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine;
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            if (line.Length == 0) continue;
            entries.Add(ParseEntry(line));
        }
        Validate(entries, allowBroad);
        return new Scope(entries, source);
    }

    private static ScopeEntry ParseEntry(string line)
    {
        string addrPart;
        int prefix;
        var slash = line.IndexOf('/');
        if (slash >= 0)
        {
            addrPart = line[..slash];
            if (!int.TryParse(line[(slash + 1)..], out prefix))
                throw new ScopeException($"Invalid prefix in scope entry '{line}'.");
        }
        else
        {
            addrPart = line;
            prefix = -1;
        }
        if (!IPAddress.TryParse(addrPart, out var ip))
            throw new ScopeException($"Invalid address in scope entry '{line}'.");
        if (prefix < 0)
            prefix = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        return new ScopeEntry(ip, prefix);
    }

    private static void Validate(IReadOnlyList<ScopeEntry> entries, bool allowBroad)
    {
        if (entries.Count == 0)
            throw new ScopeException("Scope is empty. Add at least one authorized network.");
        foreach (var e in entries)
        {
            if (e.PrefixLength == 0)
                throw new ScopeException($"Refusing wildcard scope entry {e}.");
            if (allowBroad) continue;
            if (e.Family == AddressFamily.InterNetwork && e.PrefixLength < MaxV4Prefix)
                throw new ScopeException(
                    $"Scope entry {e} is broader than /{MaxV4Prefix}. " +
                    "Pass --allow-broad to override.");
            if (e.Family == AddressFamily.InterNetworkV6 && e.PrefixLength < MaxV6Prefix)
                throw new ScopeException(
                    $"Scope entry {e} is broader than /{MaxV6Prefix}. " +
                    "Pass --allow-broad to override.");
        }
    }
}
