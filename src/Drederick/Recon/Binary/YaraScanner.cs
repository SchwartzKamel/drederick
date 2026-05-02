// YaraScanner.cs — pure-C# minimal YARA-rule subset matcher.
//
// Why pure C#? The libyara native engine is platform-fragile (libyara.so /
// libyara.dll / libyara.dylib version coupling) and contradicts Drederick's
// self-sufficiency stance: bundled community rules ARE the value, the engine
// is replaceable. We embed a curated rule corpus + this minimal matcher so
// `dotnet build` produces a single artifact that classifies binaries on any
// platform without needing libyara installed.
//
// Supported YARA grammar subset:
//   rule <name> [: <tag> ...] { ... }
//   meta:        key = "value"
//   strings:
//     $a = "literal"   [nocase] [wide] [ascii] [fullword]
//     $b = { AA BB ?? CC }     -- hex with ?? wildcards
//   condition:
//     any of them | all of them | N of them
//     $a and $b | $a or $b | not $a
//     parentheses
//
// NOT supported: regex strings, hex jumps `[2-4]`, hex alternation `(AA|BB)`,
// filesize, hash, math, modules, for..of expressions.
//
// Provenance of bundled rules (BUNDLED_RULES below):
//   - Florian Roth's signature-base (Apache-2.0) — packer/malware idioms.
//   - Public-domain offensive corpus (mimikatz, meterpreter, cobalt strike).
// All rules below are re-authored for Drederick's minimal subset.

using System.Globalization;
using System.Reflection;
using System.Text;
using Drederick.Audit;

namespace Drederick.Recon.Binary;

/// <summary>Single rule match against a buffer.</summary>
public sealed record YaraMatch(
    string RuleName,
    IReadOnlyDictionary<string, string> Meta,
    IReadOnlyList<string> Tags,
    YaraStringMatch[] StringMatches);

/// <summary>Single string hit inside a buffer.</summary>
public sealed record YaraStringMatch(string Identifier, long Offset, int Length);

/// <summary>
/// Pure-C# minimal YARA matcher. Loads bundled rules, embedded resources
/// (Recon/Binary/Rules/*.yar) when present, plus an optional overlay at
/// ~/.drederick/yara/*.yar.
/// </summary>
public sealed class YaraScanner
{
    private readonly AuditLog _audit;
    private readonly List<YaraRule> _rules;

    public int RuleCount => _rules.Count;
    public IReadOnlyList<string> RuleNames => _rules.Select(r => r.Name).ToList();

    public YaraScanner(AuditLog audit)
        : this(audit, LoadDefaultRules(audit))
    {
    }

    internal YaraScanner(AuditLog audit, IReadOnlyList<YaraRule> rules)
    {
        _audit = audit;
        _rules = new List<YaraRule>(rules);
    }

    public IReadOnlyList<YaraMatch> Scan(ReadOnlySpan<byte> data)
    {
        var results = new List<YaraMatch>();
        if (_rules.Count == 0) return results;
        foreach (var rule in _rules)
        {
            var matches = new Dictionary<string, List<YaraStringMatch>>(StringComparer.Ordinal);
            foreach (var s in rule.Strings)
                matches[s.Identifier] = FindAll(data, s);
            if (rule.Condition.Evaluate(matches))
            {
                var flat = matches.Values.SelectMany(v => v).ToArray();
                results.Add(new YaraMatch(rule.Name, rule.Meta, rule.Tags, flat));
            }
        }
        return results;
    }

    private static List<YaraStringMatch> FindAll(ReadOnlySpan<byte> data, YaraString s)
    {
        var hits = new List<YaraStringMatch>();
        if (s is HexYaraString hx)
        {
            var pat = hx.Bytes; var mask = hx.Mask;
            if (pat.Length == 0 || pat.Length > data.Length) return hits;
            for (int i = 0; i + pat.Length <= data.Length; i++)
            {
                bool ok = true;
                for (int k = 0; k < pat.Length; k++)
                {
                    if (mask[k] != 0xFF) continue;
                    if (data[i + k] != pat[k]) { ok = false; break; }
                }
                if (ok) hits.Add(new YaraStringMatch(s.Identifier, i, pat.Length));
            }
            return hits;
        }
        if (s is TextYaraString tx)
        {
            if (tx.Ascii) ScanText(data, s.Identifier, tx, hits, wide: false);
            if (tx.Wide)  ScanText(data, s.Identifier, tx, hits, wide: true);
        }
        return hits;
    }

    private static void ScanText(ReadOnlySpan<byte> data, string id, TextYaraString tx,
        List<YaraStringMatch> hits, bool wide)
    {
        var pat = wide ? Encode(tx.Literal, true) : Encoding.ASCII.GetBytes(tx.Literal);
        if (pat.Length == 0 || pat.Length > data.Length) return;
        bool nocase = tx.NoCase;
        for (int i = 0; i + pat.Length <= data.Length; i++)
        {
            bool ok = true;
            for (int k = 0; k < pat.Length; k++)
            {
                byte a = data[i + k]; byte b = pat[k];
                if (nocase)
                {
                    if (a >= (byte)'A' && a <= (byte)'Z') a = (byte)(a + 32);
                    if (b >= (byte)'A' && b <= (byte)'Z') b = (byte)(b + 32);
                }
                if (a != b) { ok = false; break; }
            }
            if (ok && tx.FullWord && !IsWordBoundary(data, i, pat.Length)) ok = false;
            if (ok) hits.Add(new YaraStringMatch(id, i, pat.Length));
        }
    }

    private static byte[] Encode(string s, bool wide)
    {
        if (!wide) return Encoding.ASCII.GetBytes(s);
        var b = new byte[s.Length * 2];
        for (int i = 0; i < s.Length; i++) { b[i * 2] = (byte)s[i]; b[i * 2 + 1] = 0; }
        return b;
    }

    private static bool IsWordBoundary(ReadOnlySpan<byte> data, int start, int len)
    {
        bool L = (start == 0) || !IsWordByte(data[start - 1]);
        int end = start + len;
        bool R = (end >= data.Length) || !IsWordByte(data[end]);
        return L && R;
    }

    private static bool IsWordByte(byte c) =>
        (c >= (byte)'a' && c <= (byte)'z') ||
        (c >= (byte)'A' && c <= (byte)'Z') ||
        (c >= (byte)'0' && c <= (byte)'9') || c == (byte)'_';

    private static IReadOnlyList<YaraRule> LoadDefaultRules(AuditLog audit)
    {
        var bag = new List<YaraRule>();
        // Bundled corpus is always loaded.
        try
        {
            var parsed = YaraRuleParser.ParseAll(BundledRules);
            bag.AddRange(parsed);
            audit.Record("yara.load", new Dictionary<string, object?>
            {
                ["source"] = "bundled",
                ["rules"] = parsed.Count,
            });
        }
        catch (Exception ex)
        {
            audit.Record("yara.load_error", new Dictionary<string, object?>
            {
                ["source"] = "bundled",
                ["error"] = ex.Message,
            });
        }

        // Embedded *.yar resources (overlay if present).
        try
        {
            var asm = typeof(YaraScanner).Assembly;
            foreach (var name in asm.GetManifestResourceNames())
            {
                if (!name.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) &&
                    !name.EndsWith(".yara", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    using var s = asm.GetManifestResourceStream(name);
                    if (s is null) continue;
                    using var r = new StreamReader(s);
                    var src = r.ReadToEnd();
                    var parsed = YaraRuleParser.ParseAll(src);
                    bag.AddRange(parsed);
                    audit.Record("yara.load", new Dictionary<string, object?>
                    {
                        ["source"] = name,
                        ["rules"] = parsed.Count,
                    });
                }
                catch (Exception ex)
                {
                    audit.Record("yara.load_error", new Dictionary<string, object?>
                    {
                        ["source"] = name,
                        ["error"] = ex.Message,
                    });
                }
            }
        }
        catch { /* never fail the scanner because of resource loading */ }

        // Optional filesystem overlay.
        try
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var dir = Path.Combine(home, ".drederick", "yara");
            if (Directory.Exists(dir))
            {
                foreach (var f in Directory.EnumerateFiles(dir, "*.yar*"))
                {
                    try
                    {
                        var src = File.ReadAllText(f);
                        var parsed = YaraRuleParser.ParseAll(src);
                        bag.AddRange(parsed);
                        audit.Record("yara.load", new Dictionary<string, object?>
                        {
                            ["source"] = f,
                            ["rules"] = parsed.Count,
                        });
                    }
                    catch (Exception ex)
                    {
                        audit.Record("yara.load_error", new Dictionary<string, object?>
                        {
                            ["source"] = f,
                            ["error"] = ex.Message,
                        });
                    }
                }
            }
        }
        catch { /* never fail */ }

        return bag;
    }

    // ---------------- bundled corpus (20 curated rules) ----------------
    private const string BundledRules = @"
rule packer_upx {
    meta: category = ""packer"" description = ""UPX packer signature""
    strings: $a = ""UPX0"" ascii  $b = ""UPX1"" ascii  $c = ""UPX!"" ascii
    condition: 2 of them
}
rule packer_aspack {
    meta: category = ""packer"" description = ""ASPack signature""
    strings: $a = "".aspack"" ascii  $b = "".adata"" ascii
    condition: any of them
}
rule packer_fsg {
    meta: category = ""packer"" description = ""FSG packer signature""
    strings: $a = ""FSG!"" ascii
    condition: any of them
}
rule packer_themida {
    meta: category = ""packer"" description = ""Themida / WinLicense signature""
    strings: $a = "".themida"" ascii  $b = ""WinLicen"" ascii
    condition: any of them
}
rule packer_mpress {
    meta: category = ""packer"" description = ""MPRESS packer signature""
    strings: $a = "".MPRESS1"" ascii  $b = "".MPRESS2"" ascii
    condition: any of them
}
rule suspicious_create_remote_thread {
    meta: category = ""suspicious-imports"" description = ""Remote thread creation API present""
    strings: $a = ""CreateRemoteThread"" ascii  $b = ""CreateRemoteThreadEx"" ascii
    condition: any of them
}
rule suspicious_virtual_alloc_ex {
    meta: category = ""suspicious-imports"" description = ""Cross-process memory allocation API""
    strings: $a = ""VirtualAllocEx"" ascii  $b = ""WriteProcessMemory"" ascii
    condition: all of them
}
rule suspicious_process_hollowing {
    meta: category = ""suspicious-imports"" description = ""Process hollowing primitive""
    strings: $a = ""ZwUnmapViewOfSection"" ascii  $b = ""WriteProcessMemory"" ascii  $c = ""SetThreadContext"" ascii
    condition: 2 of them
}
rule suspicious_credential_access {
    meta: category = ""suspicious-imports"" description = ""Credential-access APIs (LSA / SAM)""
    strings: $a = ""LsaEnumerateLogonSessions"" ascii  $b = ""SamConnect"" ascii  $c = ""LsaRetrievePrivateData"" ascii
    condition: any of them
}
rule suspicious_persistence_run {
    meta: category = ""suspicious-imports"" description = ""Run-key / Run-Once persistence strings""
    strings:
        $a = ""Software\\Microsoft\\Windows\\CurrentVersion\\Run"" ascii nocase
        $b = ""Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"" ascii nocase
    condition: any of them
}
rule suspicious_powershell_cradle {
    meta: category = ""suspicious-imports"" description = ""PowerShell download cradle idioms""
    strings:
        $a = ""DownloadString"" ascii
        $b = ""IEX("" ascii nocase
        $c = ""Invoke-Expression"" ascii nocase
        $d = ""FromBase64String"" ascii
    condition: 2 of them
}
rule malware_mimikatz_strings {
    meta: category = ""malware-family"" description = ""Mimikatz banner / module strings""
    strings:
        $a = ""mimikatz"" ascii nocase
        $b = ""sekurlsa::logonpasswords"" ascii nocase
        $c = ""kerberos::list"" ascii nocase
        $d = ""gentilkiwi"" ascii nocase
    condition: any of them
}
rule malware_cobaltstrike_beacon {
    meta: category = ""malware-family"" description = ""Cobalt Strike beacon idioms""
    strings:
        $a = ""beacon.dll"" ascii nocase
        $b = ""ReflectiveLoader"" ascii
        $c = ""%s (admin)"" ascii
    condition: 2 of them
}
rule malware_meterpreter_strings {
    meta: category = ""malware-family"" description = ""Metasploit Meterpreter idioms""
    strings:
        $a = ""metsrv.dll"" ascii nocase
        $b = ""stdapi_sys_config"" ascii
        $c = ""stdapi_fs_ls"" ascii
        $d = ""PAYLOAD_UUID"" ascii
    condition: any of them
}
rule shellcode_x86_jmp_call_pop {
    meta: category = ""shellcode"" description = ""x86 JMP/CALL/POP get-EIP idiom""
    strings: $h = { EB 05 E8 ?? ?? ?? ?? 58 }
    condition: $h
}
rule shellcode_fnstenv {
    meta: category = ""shellcode"" description = ""FNSTENV get-EIP idiom (FPU-based)""
    strings: $h = { D9 EE D9 74 24 F4 }
    condition: $h
}
rule shellcode_egghunter {
    meta: category = ""shellcode"" description = ""Classic egg-hunter idiom""
    strings: $h = { 66 81 CA FF 0F 42 }
    condition: $h
}
rule shellcode_peb_walk {
    meta: category = ""shellcode"" description = ""x86 fs:[0x30] PEB walk""
    strings: $h = { 64 A1 30 00 00 00 }
    condition: $h
}
rule shellcode_msf_xor_decoder {
    meta: category = ""shellcode"" description = ""Metasploit shikata-style XOR decoder prologue""
    strings: $h = { BB ?? ?? ?? ?? D9 74 24 F4 }
    condition: $h
}
rule metadata_pdb_path_leak {
    meta: category = ""metadata"" description = ""PDB path leak (developer workstation breadcrumb)""
    strings:
        $a = "".pdb"" ascii
        $b = ""C:\\Users\\"" ascii nocase
        $c = ""\\Debug\\"" ascii nocase
        $d = ""\\Release\\"" ascii nocase
    condition: 2 of them
}
";
}

// ---------------- internal rule model ----------------

internal abstract class YaraString
{
    public required string Identifier { get; init; }
}

internal sealed class TextYaraString : YaraString
{
    public required string Literal { get; init; }
    public bool NoCase { get; init; }
    public bool Wide { get; init; }
    public bool Ascii { get; init; } = true;
    public bool FullWord { get; init; }
}

internal sealed class HexYaraString : YaraString
{
    public required byte[] Bytes { get; init; }
    public required byte[] Mask { get; init; }
}

internal interface IYaraCondition
{
    bool Evaluate(IReadOnlyDictionary<string, List<YaraStringMatch>> matches);
}

internal sealed class StringRefCond : IYaraCondition
{
    public required string Id { get; init; }
    public bool Evaluate(IReadOnlyDictionary<string, List<YaraStringMatch>> m)
        => m.TryGetValue(Id, out var l) && l.Count > 0;
}

internal sealed class NotCond : IYaraCondition
{
    public required IYaraCondition Inner { get; init; }
    public bool Evaluate(IReadOnlyDictionary<string, List<YaraStringMatch>> m) => !Inner.Evaluate(m);
}

internal sealed class AndCond : IYaraCondition
{
    public required IYaraCondition Left { get; init; }
    public required IYaraCondition Right { get; init; }
    public bool Evaluate(IReadOnlyDictionary<string, List<YaraStringMatch>> m)
        => Left.Evaluate(m) && Right.Evaluate(m);
}

internal sealed class OrCond : IYaraCondition
{
    public required IYaraCondition Left { get; init; }
    public required IYaraCondition Right { get; init; }
    public bool Evaluate(IReadOnlyDictionary<string, List<YaraStringMatch>> m)
        => Left.Evaluate(m) || Right.Evaluate(m);
}

internal sealed class OfThemCond : IYaraCondition
{
    public required int Threshold { get; init; }
    public bool Evaluate(IReadOnlyDictionary<string, List<YaraStringMatch>> m)
    {
        int hit = m.Values.Count(l => l.Count > 0);
        if (Threshold < 0) return hit == m.Count;
        return hit >= Threshold;
    }
}

internal sealed class YaraRule
{
    public required string Name { get; init; }
    public required IReadOnlyList<string> Tags { get; init; }
    public required IReadOnlyDictionary<string, string> Meta { get; init; }
    public required IReadOnlyList<YaraString> Strings { get; init; }
    public required IYaraCondition Condition { get; init; }
}

internal static class YaraRuleParser
{
    public static IReadOnlyList<YaraRule> ParseAll(string src)
    {
        src = StripComments(src);
        var rules = new List<YaraRule>();
        int i = 0;
        while (i < src.Length)
        {
            while (i < src.Length && char.IsWhiteSpace(src[i])) i++;
            if (i >= src.Length) break;
            int kw = src.IndexOf("rule", i, StringComparison.Ordinal);
            if (kw < 0) break;
            // require token boundary on left
            if (kw > 0 && (char.IsLetterOrDigit(src[kw - 1]) || src[kw - 1] == '_'))
            { i = kw + 1; continue; }
            i = kw + 4;
            while (i < src.Length && char.IsWhiteSpace(src[i])) i++;
            int ns = i;
            while (i < src.Length && (char.IsLetterOrDigit(src[i]) || src[i] == '_')) i++;
            string name = src.Substring(ns, i - ns);
            if (name.Length == 0) break;
            var tags = new List<string>();
            while (i < src.Length && src[i] != '{')
            {
                if (src[i] == ':') { i++; continue; }
                if (char.IsWhiteSpace(src[i])) { i++; continue; }
                int ts = i;
                while (i < src.Length && (char.IsLetterOrDigit(src[i]) || src[i] == '_')) i++;
                if (i > ts) tags.Add(src.Substring(ts, i - ts));
                else i++;
            }
            int open = src.IndexOf('{', i);
            int close = FindMatchingBrace(src, open);
            if (open < 0 || close < 0) break;
            string body = src.Substring(open + 1, close - open - 1);
            i = close + 1;
            try { rules.Add(ParseRule(name, tags, body)); }
            catch { /* skip malformed rule */ }
        }
        return rules;
    }

    private static int FindMatchingBrace(string s, int open)
    {
        if (open < 0 || open >= s.Length) return -1;
        int depth = 0; bool inStr = false;
        for (int i = open; i < s.Length; i++)
        {
            char c = s[i];
            if (inStr)
            {
                if (c == '\\' && i + 1 < s.Length) { i++; continue; }
                if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { inStr = true; continue; }
            if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    private static string StripComments(string src)
    {
        var sb = new StringBuilder(src.Length);
        int i = 0; bool inStr = false;
        while (i < src.Length)
        {
            char c = src[i];
            if (inStr)
            {
                sb.Append(c);
                if (c == '\\' && i + 1 < src.Length) { sb.Append(src[i + 1]); i += 2; continue; }
                if (c == '"') inStr = false;
                i++; continue;
            }
            if (c == '"') { inStr = true; sb.Append(c); i++; continue; }
            if (c == '/' && i + 1 < src.Length && src[i + 1] == '/')
            {
                while (i < src.Length && src[i] != '\n') i++;
                continue;
            }
            if (c == '/' && i + 1 < src.Length && src[i + 1] == '*')
            {
                i += 2;
                while (i + 1 < src.Length && !(src[i] == '*' && src[i + 1] == '/')) i++;
                i += 2; continue;
            }
            sb.Append(c); i++;
        }
        return sb.ToString();
    }

    private static YaraRule ParseRule(string name, List<string> tags, string body)
    {
        var meta = new Dictionary<string, string>(StringComparer.Ordinal);
        var strs = new List<YaraString>();
        IYaraCondition? cond = null;
        var sections = SplitSections(body);
        if (sections.TryGetValue("meta", out var metaSrc)) ParseMeta(metaSrc, meta);
        if (sections.TryGetValue("strings", out var stringsSrc)) ParseStrings(stringsSrc, strs);
        if (sections.TryGetValue("condition", out var condSrc))
            cond = ConditionParser.Parse(condSrc);
        if (cond is null) throw new FormatException("missing condition");
        return new YaraRule
        {
            Name = name,
            Tags = tags,
            Meta = meta,
            Strings = strs,
            Condition = cond,
        };
    }

    private static Dictionary<string, string> SplitSections(string body)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        string[] keys = { "meta", "strings", "condition" };
        var positions = new List<(string key, int start, int afterColon)>();
        foreach (var k in keys)
        {
            int idx = 0;
            while (true)
            {
                int p = body.IndexOf(k, idx, StringComparison.Ordinal);
                if (p < 0) break;
                if (p > 0 && (char.IsLetterOrDigit(body[p - 1]) || body[p - 1] == '_'))
                { idx = p + 1; continue; }
                int j = p + k.Length;
                while (j < body.Length && char.IsWhiteSpace(body[j])) j++;
                if (j < body.Length && body[j] == ':')
                {
                    positions.Add((k, p, j + 1));
                    break;
                }
                idx = p + 1;
            }
        }
        positions.Sort((a, b) => a.start.CompareTo(b.start));
        for (int n = 0; n < positions.Count; n++)
        {
            int s = positions[n].afterColon;
            int e = (n + 1 < positions.Count) ? positions[n + 1].start : body.Length;
            dict[positions[n].key] = body.Substring(s, e - s);
        }
        return dict;
    }

    private static void ParseMeta(string src, Dictionary<string, string> meta)
    {
        // Parse `key = "value"` pairs separated by whitespace.
        int i = 0;
        while (i < src.Length)
        {
            while (i < src.Length && (char.IsWhiteSpace(src[i]) || src[i] == ',')) i++;
            if (i >= src.Length) break;
            int ks = i;
            while (i < src.Length && (char.IsLetterOrDigit(src[i]) || src[i] == '_')) i++;
            if (i == ks) { i++; continue; }
            string key = src.Substring(ks, i - ks);
            while (i < src.Length && (src[i] == ' ' || src[i] == '\t' || src[i] == '=')) i++;
            if (i >= src.Length) break;
            string val;
            if (src[i] == '"')
            {
                int e = i + 1;
                var sb = new StringBuilder();
                while (e < src.Length && src[e] != '"')
                {
                    if (src[e] == '\\' && e + 1 < src.Length) { sb.Append(src[e + 1]); e += 2; continue; }
                    sb.Append(src[e]); e++;
                }
                val = sb.ToString();
                i = e + 1;
            }
            else
            {
                int vs = i;
                while (i < src.Length && !char.IsWhiteSpace(src[i])) i++;
                val = src.Substring(vs, i - vs);
            }
            meta[key] = val;
        }
    }

    private static void ParseStrings(string src, List<YaraString> strs)
    {
        int i = 0;
        while (i < src.Length)
        {
            while (i < src.Length && src[i] != '$') i++;
            if (i >= src.Length) break;
            i++;
            int idStart = i;
            while (i < src.Length && (char.IsLetterOrDigit(src[i]) || src[i] == '_')) i++;
            string id = "$" + src.Substring(idStart, i - idStart);
            while (i < src.Length && (src[i] == ' ' || src[i] == '\t' || src[i] == '=')) i++;
            if (i >= src.Length) break;
            if (src[i] == '"')
            {
                int e = i + 1;
                var sb = new StringBuilder();
                while (e < src.Length && src[e] != '"')
                {
                    if (src[e] == '\\' && e + 1 < src.Length)
                    {
                        char esc = src[e + 1];
                        sb.Append(esc switch
                        {
                            'n' => '\n', 'r' => '\r', 't' => '\t',
                            '\\' => '\\', '"' => '"', '0' => '\0',
                            _ => esc,
                        });
                        e += 2;
                    }
                    else { sb.Append(src[e]); e++; }
                }
                int afterQuote = e + 1;
                int modEnd = afterQuote;
                while (modEnd < src.Length && src[modEnd] != '\n' && src[modEnd] != '$') modEnd++;
                var mods = src.Substring(afterQuote, modEnd - afterQuote);
                bool nocase = ContainsToken(mods, "nocase");
                bool wide = ContainsToken(mods, "wide");
                bool ascii = ContainsToken(mods, "ascii") || !wide;
                bool fullword = ContainsToken(mods, "fullword");
                strs.Add(new TextYaraString
                {
                    Identifier = id,
                    Literal = sb.ToString(),
                    NoCase = nocase,
                    Wide = wide,
                    Ascii = ascii,
                    FullWord = fullword,
                });
                i = modEnd;
            }
            else if (src[i] == '{')
            {
                int e = src.IndexOf('}', i);
                if (e < 0) break;
                var hex = src.Substring(i + 1, e - i - 1);
                var (bytes, mask) = ParseHex(hex);
                strs.Add(new HexYaraString
                {
                    Identifier = id,
                    Bytes = bytes,
                    Mask = mask,
                });
                i = e + 1;
            }
            else
            {
                while (i < src.Length && src[i] != '\n' && src[i] != '$') i++;
            }
        }
    }

    private static bool ContainsToken(string s, string token)
    {
        int idx = 0;
        while (true)
        {
            int p = s.IndexOf(token, idx, StringComparison.Ordinal);
            if (p < 0) return false;
            bool L = (p == 0) || !char.IsLetterOrDigit(s[p - 1]);
            int after = p + token.Length;
            bool R = (after >= s.Length) || !char.IsLetterOrDigit(s[after]);
            if (L && R) return true;
            idx = p + 1;
        }
    }

    private static (byte[] bytes, byte[] mask) ParseHex(string src)
    {
        var b = new List<byte>();
        var m = new List<byte>();
        int i = 0;
        while (i < src.Length)
        {
            while (i < src.Length && char.IsWhiteSpace(src[i])) i++;
            if (i + 1 >= src.Length) break;
            char c1 = src[i], c2 = src[i + 1];
            byte hi, lo, hm = 0xF0, lm = 0x0F;
            if (c1 == '?') { hi = 0; hm = 0; } else hi = (byte)Hex(c1);
            if (c2 == '?') { lo = 0; lm = 0; } else lo = (byte)Hex(c2);
            byte val = (byte)((hi << 4) | lo);
            byte mask = (byte)(hm | lm);
            if (mask != 0xFF) mask = 0x00;
            b.Add(val); m.Add(mask);
            i += 2;
        }
        return (b.ToArray(), m.ToArray());
    }

    private static int Hex(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => 0,
    };
}

internal static class ConditionParser
{
    public static IYaraCondition Parse(string src)
    {
        var toks = Tokenize(src);
        int i = 0;
        return ParseOr(toks, ref i);
    }

    private static List<string> Tokenize(string s)
    {
        var t = new List<string>();
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (char.IsWhiteSpace(c) || c == ',') { i++; continue; }
            if (c == '(' || c == ')') { t.Add(c.ToString()); i++; continue; }
            if (c == '$')
            {
                int s0 = i; i++;
                while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] == '_')) i++;
                t.Add(s.Substring(s0, i - s0));
                continue;
            }
            if (char.IsDigit(c))
            {
                int s0 = i; while (i < s.Length && char.IsDigit(s[i])) i++;
                t.Add(s.Substring(s0, i - s0)); continue;
            }
            if (char.IsLetter(c) || c == '_')
            {
                int s0 = i; while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] == '_')) i++;
                t.Add(s.Substring(s0, i - s0)); continue;
            }
            i++;
        }
        return t;
    }

    private static IYaraCondition ParseOr(List<string> t, ref int i)
    {
        var left = ParseAnd(t, ref i);
        while (i < t.Count && string.Equals(t[i], "or", StringComparison.OrdinalIgnoreCase))
        {
            i++;
            var right = ParseAnd(t, ref i);
            left = new OrCond { Left = left, Right = right };
        }
        return left;
    }

    private static IYaraCondition ParseAnd(List<string> t, ref int i)
    {
        var left = ParseNot(t, ref i);
        while (i < t.Count && string.Equals(t[i], "and", StringComparison.OrdinalIgnoreCase))
        {
            i++;
            var right = ParseNot(t, ref i);
            left = new AndCond { Left = left, Right = right };
        }
        return left;
    }

    private static IYaraCondition ParseNot(List<string> t, ref int i)
    {
        if (i < t.Count && string.Equals(t[i], "not", StringComparison.OrdinalIgnoreCase))
        {
            i++;
            return new NotCond { Inner = ParseNot(t, ref i) };
        }
        return ParsePrimary(t, ref i);
    }

    private static IYaraCondition ParsePrimary(List<string> t, ref int i)
    {
        if (i >= t.Count) throw new FormatException("unexpected end of condition");
        var tok = t[i];
        if (tok == "(")
        {
            i++;
            var c = ParseOr(t, ref i);
            if (i < t.Count && t[i] == ")") i++;
            return c;
        }
        if (tok.StartsWith("$", StringComparison.Ordinal))
        {
            i++;
            return new StringRefCond { Id = tok };
        }
        if (string.Equals(tok, "any", StringComparison.OrdinalIgnoreCase))
        {
            i++;
            ExpectKeyword(t, ref i, "of");
            ExpectKeyword(t, ref i, "them");
            return new OfThemCond { Threshold = 1 };
        }
        if (string.Equals(tok, "all", StringComparison.OrdinalIgnoreCase))
        {
            i++;
            ExpectKeyword(t, ref i, "of");
            ExpectKeyword(t, ref i, "them");
            return new OfThemCond { Threshold = -1 };
        }
        if (int.TryParse(tok, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n))
        {
            i++;
            ExpectKeyword(t, ref i, "of");
            ExpectKeyword(t, ref i, "them");
            return new OfThemCond { Threshold = n };
        }
        i++;
        return new AlwaysTrue();
    }

    private static void ExpectKeyword(List<string> t, ref int i, string kw)
    {
        if (i < t.Count && string.Equals(t[i], kw, StringComparison.OrdinalIgnoreCase)) i++;
    }

    private sealed class AlwaysTrue : IYaraCondition
    {
        public bool Evaluate(IReadOnlyDictionary<string, List<YaraStringMatch>> m) => true;
    }
}
