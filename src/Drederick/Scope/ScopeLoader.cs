using System.Net;
using System.Net.Sockets;

namespace Drederick.Scope;

/// <summary>
/// Loads a scope file. Format: one CIDR, IP, or comment per line. '#' begins a
/// comment. Blank lines are ignored. IPv4 and IPv6 are both supported.
/// </summary>
public static class ScopeLoader
{
    // Strict (production / non-lab) caps.
    private const int MaxV4PrefixStrict = 16;
    private const int MaxV6PrefixStrict = 48;

    // Lab/CTF caps. Looser, because HTB/TryHackMe ranges can legitimately be
    // as large as a /8, but still refuses 0.0.0.0/0 and wide-open IPv6.
    private const int MaxV4PrefixLab = 8;
    private const int MaxV6PrefixLab = 32;

    public static Scope LoadFile(string path, bool allowBroad = false, bool labMode = true)
    {
        if (!File.Exists(path))
            throw new ScopeException($"Scope file not found: {path}");
        return Parse(File.ReadAllText(path), path, allowBroad, labMode);
    }

    public static Scope Parse(
        string text,
        string source = "<memory>",
        bool allowBroad = false,
        bool labMode = true)
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
        Validate(entries, allowBroad, labMode);
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

    private static void Validate(IReadOnlyList<ScopeEntry> entries, bool allowBroad, bool labMode)
    {
        if (entries.Count == 0)
            throw new ScopeException("Scope is empty. Add at least one authorized network.");
        var v4Cap = labMode ? MaxV4PrefixLab : MaxV4PrefixStrict;
        var v6Cap = labMode ? MaxV6PrefixLab : MaxV6PrefixStrict;
        foreach (var e in entries)
        {
            if (e.PrefixLength == 0)
                throw new ScopeException($"Refusing wildcard scope entry {e}.");
            if (allowBroad) continue;
            if (e.Family == AddressFamily.InterNetwork && e.PrefixLength < v4Cap)
                throw new ScopeException(
                    $"Scope entry {e} is broader than /{v4Cap} " +
                    $"({(labMode ? "lab" : "strict")} cap). Pass --allow-broad to override.");
            if (e.Family == AddressFamily.InterNetworkV6 && e.PrefixLength < v6Cap)
                throw new ScopeException(
                    $"Scope entry {e} is broader than /{v6Cap} " +
                    $"({(labMode ? "lab" : "strict")} cap). Pass --allow-broad to override.");
        }
    }
}
