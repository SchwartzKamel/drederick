using System.Text.RegularExpressions;

namespace Drederick.Memory;

/// <summary>
/// Per-section extractors for the operator-supplied briefing markdown
/// format (the cornerman / HTB <c>~/arenas/htb/&lt;box&gt;/briefing.md</c>
/// convention). Pure functions over a slice of section lines so they can
/// be unit-tested independently of file I/O.
///
/// The parser is permissive on shape: each extractor walks the section's
/// lines and pulls bullet items (<c>-</c>, <c>*</c>, <c>•</c>) and/or
/// markdown table rows, ignoring header rows and separator rows.
/// </summary>
public static class BriefingMarkdownExtractors
{
    // A "raw" credential before hashing — the loader hashes
    // plaintext passwords into the typed BriefingCredential. Tests
    // assert this intermediate shape directly.
    public sealed record RawCredential(string Username, string Kind, string Secret);

    private static readonly Regex BulletLine = new(
        @"^\s*(?:[-*•+]|\d+\.)\s+(?<body>.+)$",
        RegexOptions.Compiled);

    private static readonly Regex TableSeparator = new(
        @"^\s*\|?\s*:?-{2,}.*$",
        RegexOptions.Compiled);

    private static readonly Regex CredentialRow = new(
        @"^(?<user>[^\s:|]+)(?:\s+(?<kind>NTLM|LM|AES256|AES128|SHA1|SHA256|KRB|TGT|TGS|HASH))?\s*:\s*(?<secret>\S.*)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>Pull bullet items from a section. Header/blank rows are skipped.</summary>
    public static IReadOnlyList<string> ExtractBulletList(IEnumerable<string> sectionLines)
    {
        var result = new List<string>();
        foreach (var raw in sectionLines)
        {
            var line = raw.TrimEnd();
            if (line.Length == 0) continue;
            var m = BulletLine.Match(line);
            if (!m.Success) continue;
            var body = m.Groups["body"].Value.Trim();
            if (body.Length > 0) result.Add(body);
        }
        return result;
    }

    /// <summary>
    /// Pull target hints (host / IP / CIDR strings) from the
    /// <c>## Targets</c> section. Inline trailing comments (after
    /// <c>#</c>) and trailing parentheticals are stripped so
    /// <c>10.10.10.5 (web)</c> becomes <c>10.10.10.5</c>. Inline
    /// "host - description" bullets are split on the first <c> - </c>.
    /// </summary>
    public static IReadOnlyList<string> ExtractTargets(IEnumerable<string> sectionLines)
    {
        var result = new List<string>();
        foreach (var item in ExtractBulletList(sectionLines))
        {
            var cleaned = StripTrailingComment(item);
            var firstToken = SplitFirstToken(cleaned);
            if (firstToken.Length > 0) result.Add(firstToken);
        }
        return result;
    }

    /// <summary>
    /// Pull usernames from the <c>## Users</c> section. Same bullet
    /// shape as <see cref="ExtractTargets"/>; trailing parentheticals
    /// and comments are stripped.
    /// </summary>
    public static IReadOnlyList<string> ExtractUsers(IEnumerable<string> sectionLines)
    {
        var result = new List<string>();
        foreach (var item in ExtractBulletList(sectionLines))
        {
            var cleaned = StripTrailingComment(item);
            var firstToken = SplitFirstToken(cleaned);
            if (firstToken.Length > 0) result.Add(firstToken);
        }
        return result;
    }

    /// <summary>
    /// Pull credential rows from the <c>## Credentials</c> section.
    /// Accepts bullet items (<c>- alice:hunter2</c>,
    /// <c>- bob NTLM:31d6cfe0...</c>) and markdown table rows
    /// (<c>| alice | hunter2 |</c>). Returns RAW secrets — the
    /// loader is responsible for hashing plaintext passwords before
    /// they leave this function's caller frame.
    /// </summary>
    public static IReadOnlyList<RawCredential> ExtractCredentials(IEnumerable<string> sectionLines)
    {
        var result = new List<RawCredential>();
        foreach (var raw in sectionLines)
        {
            var line = raw.TrimEnd();
            if (line.Length == 0) continue;
            if (TableSeparator.IsMatch(line)) continue;

            string body;
            var bm = BulletLine.Match(line);
            if (bm.Success)
            {
                body = bm.Groups["body"].Value.Trim();
            }
            else if (line.TrimStart().StartsWith("|"))
            {
                // Markdown table row. Skip header row (which contains
                // "user" or "username" as a heading word).
                var cols = line.Trim().Trim('|')
                    .Split('|', StringSplitOptions.TrimEntries)
                    .Where(c => c.Length > 0).ToList();
                if (cols.Count < 2) continue;
                var heading = cols[0].ToLowerInvariant();
                if (heading is "user" or "username" or "account" or "principal") continue;

                if (cols.Count >= 3 && IsKindToken(cols[1]))
                {
                    result.Add(new RawCredential(cols[0], NormalizeKind(cols[1]), cols[2]));
                }
                else
                {
                    result.Add(new RawCredential(cols[0], "password", cols[1]));
                }
                continue;
            }
            else
            {
                continue;
            }

            var cm = CredentialRow.Match(body);
            if (!cm.Success) continue;
            var user = cm.Groups["user"].Value.Trim();
            var kind = cm.Groups["kind"].Success
                ? NormalizeKind(cm.Groups["kind"].Value)
                : "password";
            var secret = cm.Groups["secret"].Value.Trim();
            if (user.Length == 0 || secret.Length == 0) continue;
            result.Add(new RawCredential(user, kind, secret));
        }
        return result;
    }

    /// <summary>
    /// Pull free-form constraints from the <c>## Constraints</c> section.
    /// Each bullet item is one constraint string; preserved verbatim
    /// for the LLM planner.
    /// </summary>
    public static IReadOnlyList<string> ExtractConstraints(IEnumerable<string> sectionLines) =>
        ExtractBulletList(sectionLines);

    /// <summary>
    /// Join the <c>## Notes</c> section into a single trimmed string.
    /// Empty / whitespace-only sections return <c>null</c>.
    /// </summary>
    public static string? ExtractNotes(IEnumerable<string> sectionLines)
    {
        var joined = string.Join("\n", sectionLines).Trim();
        return joined.Length == 0 ? null : joined;
    }

    /// <summary>
    /// Split the full markdown body into <c>## H2</c>-keyed sections.
    /// The dictionary key is the lowercased section title (without the
    /// leading <c>## </c>); the value is the slice of lines between
    /// that header and the next <c>## </c> header (exclusive on both
    /// ends).
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> SplitSections(string markdown)
    {
        var sections = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(markdown)) return sections;
        var lines = markdown.Replace("\r\n", "\n").Split('\n');
        string? current = null;
        List<string> buffer = new();
        foreach (var line in lines)
        {
            if (line.StartsWith("## ", StringComparison.Ordinal))
            {
                if (current is not null) sections[current] = buffer;
                current = line[3..].Trim();
                buffer = new List<string>();
            }
            else
            {
                buffer.Add(line);
            }
        }
        if (current is not null) sections[current] = buffer;
        return sections;
    }

    private static bool IsKindToken(string s) =>
        s.Equals("NTLM", StringComparison.OrdinalIgnoreCase) ||
        s.Equals("LM", StringComparison.OrdinalIgnoreCase) ||
        s.Equals("AES256", StringComparison.OrdinalIgnoreCase) ||
        s.Equals("AES128", StringComparison.OrdinalIgnoreCase) ||
        s.Equals("SHA1", StringComparison.OrdinalIgnoreCase) ||
        s.Equals("SHA256", StringComparison.OrdinalIgnoreCase) ||
        s.Equals("password", StringComparison.OrdinalIgnoreCase) ||
        s.Equals("hash", StringComparison.OrdinalIgnoreCase);

    private static string NormalizeKind(string s) => s.ToLowerInvariant();

    private static string StripTrailingComment(string s)
    {
        var hash = s.IndexOf('#');
        if (hash >= 0) s = s[..hash];
        return s.Trim();
    }

    private static string SplitFirstToken(string s)
    {
        // Take the first whitespace-delimited token, then strip trailing
        // punctuation like "," and ")".
        var t = s.Trim();
        var space = t.IndexOfAny(new[] { ' ', '\t', '(' });
        if (space > 0) t = t[..space];
        return t.TrimEnd(',', ')', '.', ';');
    }
}
