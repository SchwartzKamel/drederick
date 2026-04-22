using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Autopilot;

/// <summary>
/// Scans loot / captured stdout / report artefacts for CTF-style flag
/// patterns — the scoring judge, looking for knockouts. Purely local: reads
/// files under <c>out/</c>, never touches the network, never validates flags
/// against a remote service.
///
/// Patterns are liberal by design — we'd rather surface a false positive the
/// operator can discard than drop a real flag. All matches are deduplicated
/// by SHA-256 so repeating content in multiple files doesn't pad the
/// scorecard.
/// </summary>
public sealed class FlagExtractor
{
    private readonly AuditLog _audit;
    private readonly IReadOnlyList<Regex> _patterns;
    private readonly long _maxFileBytes;

    /// <summary>Built-in patterns covering the common CTF/lab formats.</summary>
    public static IReadOnlyList<Regex> DefaultPatterns { get; } = new[]
    {
        // generic CTF flag: flag{...} / FLAG{...} / ctf{...}
        new Regex(@"\b(?i:flag|ctf|pwn|key)\{[^}\r\n]{1,200}\}", RegexOptions.Compiled),
        // HackTheBox: HTB{...}
        new Regex(@"\bHTB\{[^}\r\n]{1,200}\}", RegexOptions.Compiled),
        // TryHackMe: THM{...}
        new Regex(@"\bTHM\{[^}\r\n]{1,200}\}", RegexOptions.Compiled),
        // pwn.college / picoCTF: picoCTF{...}
        new Regex(@"\bpicoCTF\{[^}\r\n]{1,200}\}", RegexOptions.Compiled),
        // root.txt / user.txt style: 32-hex flag (HTB historical)
        new Regex(@"\b[a-fA-F0-9]{32}\b", RegexOptions.Compiled),
    };

    public FlagExtractor(AuditLog audit, IReadOnlyList<Regex>? patterns = null, long? maxFileBytes = null)
    {
        _audit = audit;
        _patterns = patterns ?? DefaultPatterns;
        _maxFileBytes = maxFileBytes ?? (5L * 1024 * 1024);
    }

    /// <summary>
    /// Recursively scan <paramref name="root"/> for flag-shaped strings.
    /// Returns one <see cref="FlagMatch"/> per unique (pattern, value)
    /// deduplicated by SHA-256 of the matched string.
    /// </summary>
    public IReadOnlyList<FlagMatch> ScanDirectory(string root)
    {
        var seen = new ConcurrentDictionary<string, FlagMatch>();
        if (!Directory.Exists(root)) return Array.Empty<FlagMatch>();

        int filesScanned = 0;
        int filesSkipped = 0;
        foreach (var file in SafeEnumerate(root))
        {
            if (IsBoringExtension(file)) { filesSkipped++; continue; }
            FileInfo fi;
            try { fi = new FileInfo(file); }
            catch { filesSkipped++; continue; }
            if (!fi.Exists || fi.Length == 0) { filesSkipped++; continue; }
            if (fi.Length > _maxFileBytes) { filesSkipped++; continue; }

            try
            {
                var text = ReadTextSafe(file);
                if (text is null) { filesSkipped++; continue; }
                filesScanned++;
                ScanText(text, file, seen);
            }
            catch (IOException) { filesSkipped++; }
            catch (UnauthorizedAccessException) { filesSkipped++; }
        }

        var result = seen.Values
            .OrderByDescending(m => m.Pattern.Length) // stable-ish
            .ToList();

        _audit.Record("autopilot.flags.scanned", new Dictionary<string, object?>
        {
            ["root"] = root,
            ["files_scanned"] = filesScanned,
            ["files_skipped"] = filesSkipped,
            ["matches"] = result.Count,
        });
        return result;
    }

    /// <summary>Scan an in-memory blob (typically captured subprocess stdout)
    /// and merge matches into <paramref name="seen"/>. Exposed for autopilot
    /// to harvest flags directly from exploit output without a file hop.</summary>
    public void ScanText(string text, string source, ConcurrentDictionary<string, FlagMatch> seen)
    {
        if (string.IsNullOrEmpty(text)) return;
        foreach (var pattern in _patterns)
        {
            foreach (Match m in pattern.Matches(text))
            {
                if (m.Length < 4) continue;
                var value = m.Value;
                var digest = Sha256Hex(value);
                seen.TryAdd(digest, new FlagMatch(
                    Value: value,
                    ValueSha256: digest,
                    Pattern: pattern.ToString(),
                    Source: source));
            }
        }
    }

    private static IEnumerable<string> SafeEnumerate(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            string[] files;
            string[] dirs;
            try
            {
                files = Directory.GetFiles(dir);
                dirs = Directory.GetDirectories(dir);
            }
            catch { continue; }
            foreach (var f in files) yield return f;
            foreach (var d in dirs) stack.Push(d);
        }
    }

    private static bool IsBoringExtension(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".db" or ".db-shm" or ".db-wal" or ".png" or ".jpg" or ".jpeg"
            or ".gif" or ".ico" or ".so" or ".dll" or ".exe" or ".pdb" or ".zip" or ".gz"
            or ".tar" or ".7z" or ".bz2";
    }

    private static string? ReadTextSafe(string path)
    {
        try
        {
            // Heuristic: sample first 1KB to reject binaries early.
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            Span<byte> head = stackalloc byte[Math.Min(1024, (int)Math.Min(fs.Length, 1024))];
            var n = fs.Read(head);
            for (int i = 0; i < n; i++)
            {
                if (head[i] == 0) return null; // NUL byte ⇒ treat as binary.
            }
            fs.Position = 0;
            using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return sr.ReadToEnd();
        }
        catch { return null; }
    }

    public static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? ""));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

/// <summary>Single captured flag match. Values are stored verbatim — it's
/// the operator's loot. Never transmitted off-box.</summary>
public sealed record FlagMatch(string Value, string ValueSha256, string Pattern, string Source);
