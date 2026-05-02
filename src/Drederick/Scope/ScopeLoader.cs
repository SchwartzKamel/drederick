using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using YamlDotNet.RepresentationModel;

namespace Drederick.Scope;

/// <summary>
/// Loads a scope file. Two formats are accepted, auto-detected:
/// <list type="bullet">
///   <item><description>
///     Legacy line-based: one CIDR, IP, hostname, or comment per line.
///     '#' begins a comment. Blank lines are ignored.
///   </description></item>
///   <item><description>
///     YAML mapping with <c>include:</c> and optional <c>exclude:</c> lists.
///     Targets matching an include rule but ALSO matching an exclude rule
///     are denied (deny wins). The <c>exclude:</c> list is sourced
///     <strong>only</strong> from the scope file — never from CLI flags,
///     env vars, or LLM input.
///   </description></item>
/// </list>
/// IPv4 and IPv6 are both supported. Wildcards (<c>0.0.0.0/0</c>, <c>::/0</c>)
/// are refused in both <c>include</c> and <c>exclude</c> regardless of
/// <c>--allow-broad</c>.
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

    private static readonly Regex YamlKeyProbe = new(
        @"^[\t ]*(include|exclude|allow_broad)[\t ]*:",
        RegexOptions.Multiline | RegexOptions.Compiled);

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
        var (includes, excludes) = LooksLikeYaml(text)
            ? ParseYaml(text)
            : ParseLegacy(text);

        Validate(includes, allowBroad, labMode, role: "include");
        // Excludes are validated for shape (no wildcards, valid prefix) but are
        // NOT subject to the allow-broad prefix cap — a deny rule covering a
        // large CIDR is operationally useful and never broadens authorization.
        Validate(excludes, allowBroad: true, labMode, role: "exclude");

        return new Scope(includes, excludes, source);
    }

    private static bool LooksLikeYaml(string text) => YamlKeyProbe.IsMatch(text);

    private static (List<ScopeEntry> includes, List<ScopeEntry> excludes) ParseLegacy(string text)
    {
        var entries = new List<ScopeEntry>();
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine;
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            if (line.Length == 0) continue;
            entries.AddRange(ParseEntry(line));
        }
        return (entries, new List<ScopeEntry>());
    }

    private static (List<ScopeEntry> includes, List<ScopeEntry> excludes) ParseYaml(string text)
    {
        var stream = new YamlStream();
        try
        {
            stream.Load(new StringReader(text));
        }
        catch (Exception ex)
        {
            throw new ScopeException($"Invalid YAML in scope file: {ex.Message}");
        }
        if (stream.Documents.Count == 0)
            throw new ScopeException("Scope YAML document is empty.");
        if (stream.Documents[0].RootNode is not YamlMappingNode root)
            throw new ScopeException("Scope YAML root must be a mapping with 'include:' and optional 'exclude:'.");

        var includes = ReadList(root, "include");
        var excludes = ReadList(root, "exclude");
        return (includes, excludes);
    }

    private static List<ScopeEntry> ReadList(YamlMappingNode root, string key)
    {
        var entries = new List<ScopeEntry>();
        if (!root.Children.TryGetValue(new YamlScalarNode(key), out var node))
            return entries;
        if (node is YamlScalarNode scalar && string.IsNullOrWhiteSpace(scalar.Value))
            return entries;
        if (node is not YamlSequenceNode seq)
            throw new ScopeException($"Scope YAML '{key}:' must be a list.");
        foreach (var item in seq.Children)
        {
            if (item is not YamlScalarNode s || string.IsNullOrWhiteSpace(s.Value))
                throw new ScopeException($"Scope YAML '{key}:' contains a non-string entry.");
            entries.AddRange(ParseEntry(s.Value!.Trim()));
        }
        return entries;
    }

    /// <summary>
    /// Parses a single scope-file line into one or more <see cref="ScopeEntry"/>
    /// records. CIDRs and bare IPs produce a single entry. Hostnames are
    /// resolved via DNS at parse time and produce one entry per resolved
    /// address; the original hostname is preserved on <see cref="ScopeEntry.OriginLabel"/>
    /// so deny messages can name the operator-supplied rule.
    /// </summary>
    private static IEnumerable<ScopeEntry> ParseEntry(string line)
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

        if (IPAddress.TryParse(addrPart, out var ip))
        {
            if (prefix < 0)
                prefix = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            return new[] { new ScopeEntry(ip, prefix) };
        }

        // Not an IP — treat as hostname and resolve via DNS. A prefix on a
        // hostname is meaningless (which resolved address would it apply to?)
        // so refuse it.
        if (slash >= 0)
            throw new ScopeException(
                $"Hostnames may not carry a CIDR prefix in scope entry '{line}'.");

        if (!LooksLikeHostname(addrPart))
            throw new ScopeException($"Invalid address in scope entry '{line}'.");

        IPAddress[] resolved;
        try
        {
            resolved = Dns.GetHostAddresses(addrPart);
        }
        catch (Exception ex)
        {
            throw new ScopeException(
                $"Failed to resolve hostname '{addrPart}' in scope entry: {ex.Message}");
        }
        if (resolved.Length == 0)
            throw new ScopeException($"Hostname '{addrPart}' did not resolve to any address.");

        var list = new List<ScopeEntry>(resolved.Length);
        foreach (var addr in resolved)
        {
            var p = addr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            list.Add(new ScopeEntry(addr, p, addrPart));
        }
        return list;
    }

    private static bool LooksLikeHostname(string s)
    {
        if (string.IsNullOrEmpty(s) || s.Length > 253) return false;
        foreach (var ch in s)
        {
            if (!(char.IsLetterOrDigit(ch) || ch == '-' || ch == '.' || ch == '_'))
                return false;
        }
        return true;
    }

    private static void Validate(
        IReadOnlyList<ScopeEntry> entries,
        bool allowBroad,
        bool labMode,
        string role = "include")
    {
        if (role == "include" && entries.Count == 0)
            throw new ScopeException("Scope is empty. Add at least one authorized network.");
        var v4Cap = labMode ? MaxV4PrefixLab : MaxV4PrefixStrict;
        var v6Cap = labMode ? MaxV6PrefixLab : MaxV6PrefixStrict;
        foreach (var e in entries)
        {
            // Wildcard is refused in BOTH include and exclude — excluding
            // 0.0.0.0/0 is meaningless and ambiguous.
            if (e.PrefixLength == 0)
                throw new ScopeException($"Refusing wildcard scope entry {e.Display} in '{role}' list.");
            if (allowBroad) continue;
            if (e.Family == AddressFamily.InterNetwork && e.PrefixLength < v4Cap)
                throw new ScopeException(
                    $"Scope entry {e.Display} is broader than /{v4Cap} " +
                    $"({(labMode ? "lab" : "strict")} cap). Pass --allow-broad to override.");
            if (e.Family == AddressFamily.InterNetworkV6 && e.PrefixLength < v6Cap)
                throw new ScopeException(
                    $"Scope entry {e.Display} is broader than /{v6Cap} " +
                    $"({(labMode ? "lab" : "strict")} cap). Pass --allow-broad to override.");
        }
    }
}
