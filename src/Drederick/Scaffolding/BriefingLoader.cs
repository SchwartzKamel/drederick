using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Scaffolding;

/// <summary>
/// Discovers and parses <c>briefing.md</c> per
/// <c>machines/SCAFFOLDING/LOADER_SPEC.md</c> §2 + §3.1. Emits
/// <c>briefing.discovered</c>, <c>briefing.ingested</c>,
/// <c>briefing.skipped</c>, and <c>briefing.absent</c> audit events.
/// Parser is intentionally permissive: unknown sections are preserved
/// in <see cref="BriefingDocument.RawMarkdown"/>; only known H2 sections
/// are structured.
/// </summary>
public static class BriefingLoader
{
    private static readonly string[] KnownSections =
    {
        "topology",
        "assumed-breach material",
        "known / suspected attack paths",
        "known/suspected attack paths",
        "cornerman directives",
        "out-of-scope reminders",
    };

    public static BriefingDocument? LoadOrAbsent(
        string? overridePath,
        string scopeDir,
        AuditLog audit)
    {
        var searched = new List<string>();
        string? path = null;

        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            searched.Add(overridePath);
            if (File.Exists(overridePath)) path = overridePath;
        }
        if (path is null)
        {
            var candidate = Path.Combine(scopeDir, "briefing.md");
            searched.Add(candidate);
            if (File.Exists(candidate)) path = candidate;
        }

        if (path is null)
        {
            audit.Record("briefing.absent", new Dictionary<string, object?>
            {
                ["searched_paths"] = searched,
            });
            return null;
        }

        string text;
        try { text = File.ReadAllText(path); }
        catch (Exception ex)
        {
            audit.Record("briefing.skipped", new Dictionary<string, object?>
            {
                ["path"] = path,
                ["reason"] = "missing",
                ["error"] = ex.Message,
            });
            return null;
        }

        var sha = Sha256(text);
        var lineCount = text.Split('\n').Length;
        var (frontmatter, body) = SplitFrontmatter(text);

        audit.Record("briefing.discovered", new Dictionary<string, object?>
        {
            ["path"] = path,
            ["sha256"] = sha,
            ["lines"] = lineCount,
            ["frontmatter_keys"] = frontmatter.Keys.ToList(),
        });

        BriefingDocument doc;
        try
        {
            doc = Parse(path, sha, lineCount, frontmatter, body, text);
        }
        catch (Exception ex)
        {
            audit.Record("briefing.skipped", new Dictionary<string, object?>
            {
                ["path"] = path,
                ["reason"] = "invalid",
                ["error"] = ex.Message,
            });
            return null;
        }

        audit.Record("briefing.ingested", new Dictionary<string, object?>
        {
            ["path"] = path,
            ["sha256"] = sha,
            ["sections_parsed"] = doc.SectionsParsed,
            ["assumed_breach_artifact_count"] = doc.AssumedBreach.Count,
        });
        return doc;
    }

    internal static BriefingDocument Parse(
        string path,
        string sha,
        int lineCount,
        IReadOnlyDictionary<string, string?> frontmatter,
        string body,
        string raw)
    {
        var sections = SplitH2Sections(body);
        var sectionsParsed = new List<string>();

        string? topology = null;
        var artifacts = new List<AssumedBreachArtifact>();
        var paths = new List<string>();
        var cornermanDo = new List<string>();
        var cornermanDont = new List<string>();
        string? oos = null;

        foreach (var (heading, content) in sections)
        {
            var key = NormalizeHeading(heading);
            switch (key)
            {
                case "topology":
                    topology = content.Trim();
                    sectionsParsed.Add("Topology");
                    break;
                case "assumed-breach material":
                    artifacts.AddRange(ParseAssumedBreachTable(content));
                    sectionsParsed.Add("Assumed-Breach Material");
                    break;
                case "known / suspected attack paths":
                case "known/suspected attack paths":
                    paths.AddRange(ParseOrderedList(content));
                    sectionsParsed.Add("Known / Suspected Attack Paths");
                    break;
                case "cornerman directives":
                    ParseDoDont(content, cornermanDo, cornermanDont);
                    sectionsParsed.Add("Cornerman Directives");
                    break;
                case "out-of-scope reminders":
                    oos = content.Trim();
                    sectionsParsed.Add("Out-of-Scope Reminders");
                    break;
            }
        }

        return new BriefingDocument(
            path, sha, lineCount, frontmatter,
            topology, artifacts, paths, cornermanDo, cornermanDont, oos,
            sectionsParsed, raw);
    }

    private static string NormalizeHeading(string h)
    {
        var s = h.Trim().ToLowerInvariant();
        s = Regex.Replace(s, @"^\d+[.)]\s*", "");
        return s;
    }

    private static (Dictionary<string, string?> fm, string body) SplitFrontmatter(string text)
    {
        var fm = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (!text.StartsWith("---")) return (fm, text);
        var end = text.IndexOf("\n---", 3, StringComparison.Ordinal);
        if (end < 0) return (fm, text);
        var fmBlock = text.Substring(3, end - 3);
        foreach (var line in fmBlock.Split('\n'))
        {
            var l = line.Trim();
            if (l.Length == 0) continue;
            var c = l.IndexOf(':');
            if (c <= 0) continue;
            var k = l[..c].Trim();
            var v = l[(c + 1)..].Trim().Trim('"');
            fm[k] = string.IsNullOrEmpty(v) ? null : v;
        }
        var bodyStart = end + 4;
        if (bodyStart > text.Length) bodyStart = text.Length;
        return (fm, text[bodyStart..]);
    }

    private static IEnumerable<(string heading, string body)> SplitH2Sections(string body)
    {
        var matches = Regex.Matches(body, @"^##\s+(.+?)\s*$", RegexOptions.Multiline);
        for (var i = 0; i < matches.Count; i++)
        {
            var m = matches[i];
            var start = m.Index + m.Length;
            var end = (i + 1 < matches.Count) ? matches[i + 1].Index : body.Length;
            yield return (m.Groups[1].Value, body[start..end]);
        }
    }

    internal static IEnumerable<AssumedBreachArtifact> ParseAssumedBreachTable(string content)
    {
        var lines = content.Split('\n');
        string[]? headers = null;
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (!line.StartsWith("|")) continue;
            if (Regex.IsMatch(line, @"^\|[\s\-:|]+\|$")) continue;
            var cells = line.Trim('|').Split('|').Select(c => c.Trim()).ToArray();
            if (headers is null)
            {
                headers = cells.Select(c => c.ToLowerInvariant()).ToArray();
                continue;
            }
            string Get(params string[] keys)
            {
                foreach (var k in keys)
                {
                    var idx = Array.FindIndex(headers, h => h.Contains(k, StringComparison.Ordinal));
                    if (idx >= 0 && idx < cells.Length) return cells[idx];
                }
                return string.Empty;
            }
            var path = Get("path", "artifact", "file");
            if (string.IsNullOrEmpty(path)) continue;
            var kind = Get("kind", "type");
            var identity = Get("identity", "user", "subject");
            var useFor = Get("use_for", "use for", "purpose", "use");
            yield return new AssumedBreachArtifact(
                Strip(path),
                Strip(kind),
                NullIfEmpty(Strip(identity)),
                NullIfEmpty(Strip(useFor)));
        }
    }

    private static string Strip(string s) => s.Trim().Trim('`').Trim();
    private static string? NullIfEmpty(string s) => string.IsNullOrEmpty(s) ? null : s;

    private static IEnumerable<string> ParseOrderedList(string content)
    {
        foreach (var raw in content.Split('\n'))
        {
            var l = raw.TrimEnd();
            var m = Regex.Match(l, @"^\s*(?:\d+[.)]|[-*])\s+(.+)$");
            if (m.Success) yield return m.Groups[1].Value.Trim();
        }
    }

    private static void ParseDoDont(string content, List<string> doList, List<string> dontList)
    {
        var current = (List<string>?)null;
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.TrimEnd();
            var lower = line.Trim().ToLowerInvariant().TrimEnd(':');
            if (Regex.IsMatch(lower, @"^#{1,6}\s*do$") || lower == "do" || lower.EndsWith(" do"))
            { current = doList; continue; }
            if (Regex.IsMatch(lower, @"^#{1,6}\s*don'?t$") || lower == "don't" || lower == "dont" || lower.EndsWith(" don't"))
            { current = dontList; continue; }
            var m = Regex.Match(line, @"^\s*(?:[-*]|\d+[.)])\s+(.+)$");
            if (m.Success && current is not null) current.Add(m.Groups[1].Value.Trim());
        }
    }

    public static string Sha256(string text)
    {
        var b = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        var sb = new StringBuilder(b.Length * 2);
        foreach (var x in b) sb.Append(x.ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }
}
