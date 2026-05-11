using System.Text.RegularExpressions;

namespace Drederick.Reporting;

/// <summary>
/// Context-aware flag detector. Closes GAP-008 / GAP-009: the legacy
/// extractor caught any 32-hex string and confidently surfaced URL path
/// segments, JSON keys, Vulners IDs, ETags, and GUIDs as "flags".
///
/// Detection rules:
/// <list type="bullet">
///   <item>Strong markers (<c>HTB{…}</c>, <c>flag{…}</c>, <c>CTF{…}</c>,
///   <c>picoCTF{…}</c>, <c>THM{…}</c>) are always accepted at high
///   confidence regardless of source.</item>
///   <item>Bare 32-hex candidates are filtered: rejected when surrounded by
///   URL/base64 punctuation, when a JSON-key shape is detected, when a
///   GUID literal is in scope, or when preceded by a noise prefix
///   (vulners:, sha256:, ETag:, etc.).</item>
///   <item>Confidence for accepted bare-hex scales by <see cref="FlagSource"/>:
///   shell-output of a known flag file is ~0.9, generic file content 0.55,
///   network response 0.35, scan metadata 0.15.</item>
/// </list>
///
/// Pure-text; no I/O, no network. Does not call <c>_scope.Require</c> by design.
/// </summary>
public sealed class FlagDetector
{
    /// <summary>Single detection result; <see cref="Rejection"/> is non-null
    /// when the candidate was filtered as a false positive.</summary>
    public sealed record DetectedFlag(
        string Value,
        FlagSource Source,
        string Origin,
        double Confidence,
        string? Rejection);

    // --- htb-flag-filter --- strong markers, always accepted.
    private static readonly Regex[] StrongMarkers =
    {
        new(@"HTB\{[^}\r\n]{4,128}\}", RegexOptions.Compiled),
        new(@"flag\{[^}\r\n]{4,128}\}", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"CTF\{[^}\r\n]{4,128}\}", RegexOptions.Compiled),
        new(@"picoCTF\{[^}\r\n]{4,128}\}", RegexOptions.Compiled),
        new(@"THM\{[^}\r\n]{4,128}\}", RegexOptions.Compiled),
    };

    private static readonly Regex HexCandidate =
        new(@"\b[0-9a-fA-F]{32}\b", RegexOptions.Compiled);

    private static readonly Regex AlnumCandidate =
        new(@"\b[A-Za-z0-9]{32}\b", RegexOptions.Compiled);

    private static readonly Regex FlagFilePath =
        new(@"(?:^|/)(?:root/root\.txt|home/[^/]+/user\.txt)$", RegexOptions.Compiled);

    private static readonly string[] NoisePrefixes =
    {
        "vulners:", "cve-", "sha256:", "sha1:", "md5:",
        "etag:", "if-none-match:", "boundary=", "nonce=", "csrf",
    };
    // --- end htb-flag-filter ---

    /// <summary>Return every candidate in <paramref name="content"/> as a
    /// <see cref="DetectedFlag"/> — including rejected ones, so callers can
    /// audit why something didn't surface.</summary>
    public IReadOnlyList<DetectedFlag> Detect(string? content, FlagSource source, string origin)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return Array.Empty<DetectedFlag>();
        }
        origin ??= string.Empty;

        var results = new List<DetectedFlag>();
        var seen = new HashSet<(string value, int start)>();

        // Collect all strong-marker matches, then suppress overlaps from
        // shortest → longest (picoCTF{x} contains CTF{x}; only the outer
        // is the real flag).
        var markerHits = new List<Match>();
        foreach (var marker in StrongMarkers)
        {
            foreach (Match m in marker.Matches(content))
            {
                markerHits.Add(m);
            }
        }
        markerHits.Sort((a, b) => b.Length.CompareTo(a.Length));
        var coveredRanges = new List<(int start, int end)>();
        foreach (var m in markerHits)
        {
            if (!seen.Add((m.Value, m.Index))) continue;
            if (coveredRanges.Any(r =>
                    m.Index < r.end && m.Index + m.Length > r.start))
            {
                continue;
            }
            coveredRanges.Add((m.Index, m.Index + m.Length));
            results.Add(new DetectedFlag(
                m.Value, FlagSource.ExplicitFlagMarker, origin, 0.98, null));
        }

        var originLooksLikeUrl = LooksLikeUrl(origin);
        var originIsFlagFile = FlagFilePath.IsMatch(origin);

        foreach (Match m in HexCandidate.Matches(content))
        {
            if (!seen.Add((m.Value, m.Index))) continue;
            var rejection = ClassifyHexCandidate(content, m, source, origin,
                originLooksLikeUrl, originIsFlagFile);
            var confidence = rejection is null
                ? ConfidenceFor(source, originIsFlagFile)
                : 0.0;
            results.Add(new DetectedFlag(m.Value, source, origin, confidence, rejection));
        }

        // Length-32 alphanumeric (not pure-hex) only meaningful from a
        // ShellCommandOutput reading a *.txt flag file. Everywhere else
        // it's session tokens, CSRF, etc.
        if (source == FlagSource.ShellCommandOutput &&
            origin.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
        {
            foreach (Match m in AlnumCandidate.Matches(content))
            {
                if (HexCandidate.IsMatch(m.Value)) continue;
                if (!seen.Add((m.Value, m.Index))) continue;
                var rejection = ClassifyHexCandidate(content, m, source, origin,
                    originLooksLikeUrl, originIsFlagFile);
                var confidence = rejection is null
                    ? Math.Max(0.5, ConfidenceFor(source, originIsFlagFile) - 0.1)
                    : 0.0;
                results.Add(new DetectedFlag(m.Value, source, origin, confidence, rejection));
            }
        }

        return results;
    }

    /// <summary>Convenience: highest-confidence accepted detection, or null.</summary>
    public DetectedFlag? DetectBest(string? content, FlagSource source, string origin)
    {
        DetectedFlag? best = null;
        foreach (var d in Detect(content, source, origin))
        {
            if (d.Rejection is not null) continue;
            if (best is null || d.Confidence > best.Confidence) best = d;
        }
        return best;
    }

    private static string? ClassifyHexCandidate(
        string content, Match m, FlagSource source, string origin,
        bool originLooksLikeUrl, bool originIsFlagFile)
    {
        var start = m.Index;
        var end = m.Index + m.Length;

        if (originLooksLikeUrl && !originIsFlagFile)
        {
            return "origin-looks-like-url";
        }

        var before = start > 0 ? content[start - 1] : '\0';
        var after = end < content.Length ? content[end] : '\0';

        if (before == '/' || after == '/') return "url-path-segment";
        if (before == '=' || after == '=') return "base64-or-query-segment";

        // JSON key: "<hex>": ...   →  preceded by " and "<hex>": within
        // 40 chars after start.
        if (before == '"')
        {
            var tail = content.Substring(end, Math.Min(40, content.Length - end));
            if (tail.StartsWith("\":") || tail.StartsWith("\" :"))
            {
                return "json-key-shape";
            }
        }

        // GUID braces: {<hex>} → preceded by '{' one char before.
        if (before == '{') return "guid-brace-literal";

        // Dashed GUID continuation (rare for 32-hex \b match — but the spec
        // calls it out explicitly).
        var look = start >= 4 ? content.Substring(start - 4, 4) : string.Empty;
        if (look.Contains('-') && look.Any(IsHex)) return "guid-dashed-fragment";

        // Line-prefix noise: scan back to start-of-line up to 100 chars.
        var lineStart = start;
        var floor = Math.Max(0, start - 100);
        while (lineStart > floor && content[lineStart - 1] != '\n') lineStart--;
        var prefix = content.Substring(lineStart, start - lineStart).ToLowerInvariant();
        foreach (var bad in NoisePrefixes)
        {
            if (prefix.Contains(bad, StringComparison.Ordinal)) return $"noise-prefix:{bad}";
        }
        // CVE id earlier on same line ⇒ Vulners-style reference.
        if (Regex.IsMatch(prefix, @"cve-\d{4}-\d{4,}", RegexOptions.IgnoreCase))
        {
            return "cve-reference-line";
        }

        // ScanMetadata is so noisy we only accept when the surrounding text
        // explicitly looks like flag content (handled by confidence floor),
        // but bare-hex from a banner is still allowed at very low conf.

        _ = source;
        return null;
    }

    private static double ConfidenceFor(FlagSource source, bool originIsFlagFile)
    {
        // Flag-file path elevates confidence regardless of how the content
        // was captured.
        if (originIsFlagFile)
        {
            return source switch
            {
                FlagSource.ShellCommandOutput => 0.90,
                FlagSource.UserHomeFile => 0.85,
                FlagSource.FileSystemContent => 0.85,
                _ => 0.80,
            };
        }
        return source switch
        {
            FlagSource.ExplicitFlagMarker => 0.98,
            FlagSource.UserHomeFile => 0.85,
            FlagSource.ShellCommandOutput => 0.70,
            FlagSource.FileSystemContent => 0.55,
            FlagSource.NetworkServiceResponse => 0.35,
            FlagSource.ScanMetadata => 0.15,
            _ => 0.30,
        };
    }

    private static bool LooksLikeUrl(string origin)
    {
        if (string.IsNullOrEmpty(origin)) return false;
        if (origin.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return true;
        if (origin.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return true;
        if (origin.Contains("/api/", StringComparison.OrdinalIgnoreCase)) return true;
        if (origin.Contains('?') || origin.Contains('=')) return true;
        return false;
    }

    private static bool IsHex(char c) =>
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
