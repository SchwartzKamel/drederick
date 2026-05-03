using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Telemetry;

namespace Drederick.Learning;

/// <summary>
/// Append-only JSONL fight notebook. The LLM (and operator) drop short
/// structured notes during and between fights; the notebook is the
/// long-term memory that <c>drederick review</c> reads back, and that
/// the planner / archetype layer feeds into future engagements.
///
/// <para><b>Two sinks per note (both append-only, neither overwrites):</b>
/// <list type="bullet">
///   <item><c>&lt;outputRoot&gt;/fight-notes.jsonl</c> — per-fight notes
///   alongside <c>report.json</c> / <c>audit.jsonl</c>.</item>
///   <item><c>~/.drederick/fight-notebook.jsonl</c> — cross-fight
///   aggregate so reviews and the LLM system prompt can pull recent
///   lessons regardless of which run produced them.</item>
/// </list>
/// </para>
///
/// <para><b>Privacy invariants (mirrors <see cref="TelemetryRecorder"/>):</b>
/// <list type="number">
///   <item>Bodies are passed through <see cref="RedactSecrets"/> before
///   write — passwords, hashes, NT/LM, private keys, bearer tokens, JWT,
///   and high-entropy hex blobs are replaced with <c>[REDACTED:&lt;kind&gt;]</c>
///   markers. Plaintext secrets do not reach disk.</item>
///   <item>Target hosts are reduced to <c>/24</c> (v4) / <c>/48</c> (v6)
///   for RFC1918 / loopback / link-local addresses by re-using
///   <see cref="TelemetryRecorder.RedactHost"/>.</item>
///   <item>Audit log records <c>notebook.take_note</c> with
///   <c>body_sha256</c> only — never the body itself.</item>
/// </list>
/// </para>
///
/// <para><b>Thread safety.</b> Writes serialize behind a
/// <see cref="SemaphoreSlim"/>(1). Reads open their own stream and may
/// run concurrently with writes; the JSONL append shape tolerates a
/// concurrent reader at end-of-file.</para>
/// </summary>
public sealed class FightNotebook : IAsyncDisposable, IDisposable
{
    private readonly string _runPath;
    private readonly string? _aggregatePath;
    private readonly AuditLog? _audit;
    private readonly bool _enabled;
    private readonly SemaphoreSlim _writeGate = new(1, 1);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public string RunPath => _runPath;
    public string? AggregatePath => _aggregatePath;
    public bool Enabled => _enabled;

    /// <summary>
    /// Construct a notebook. <paramref name="aggregatePath"/> is
    /// optional; when null, only the per-run JSONL is written.
    /// <paramref name="audit"/> is optional but recommended — every
    /// note take is recorded with <c>body_sha256</c> only.
    /// </summary>
    public FightNotebook(
        string runPath,
        string? aggregatePath = null,
        AuditLog? audit = null,
        bool enabled = true)
    {
        if (string.IsNullOrWhiteSpace(runPath))
            throw new ArgumentException("runPath is required", nameof(runPath));
        _runPath = runPath;
        _aggregatePath = aggregatePath;
        _audit = audit;
        _enabled = enabled;
    }

    /// <summary>
    /// Default cross-fight aggregate path: <c>~/.drederick/fight-notebook.jsonl</c>.
    /// </summary>
    public static string DefaultAggregatePath()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".drederick", "fight-notebook.jsonl");
    }

    /// <summary>
    /// Persist a note. Returns the persisted record (with body redacted
    /// and SHA-256 filled in). When the notebook is disabled, returns
    /// the redacted record without touching disk.
    /// </summary>
    public async Task<FightNote> TakeNoteAsync(
        string category,
        string body,
        IEnumerable<string>? tags = null,
        string? fightId = null,
        string? targetHost = null,
        string? targetArchetype = null,
        string source = "llm",
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(category))
            throw new ArgumentException("category is required", nameof(category));
        if (string.IsNullOrWhiteSpace(body))
            throw new ArgumentException("body is required", nameof(body));

        var redactedBody = RedactSecrets(body);
        var redactedHost = TelemetryRecorder.RedactHost(targetHost);
        var sha = Sha256Hex(redactedBody);
        var note = new FightNote
        {
            Timestamp = DateTimeOffset.UtcNow.ToString("o"),
            FightId = fightId,
            Category = category.Trim().ToLowerInvariant(),
            Body = redactedBody,
            BodySha256 = sha,
            Tags = (tags ?? Array.Empty<string>())
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Select(t => t.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            TargetHost = redactedHost,
            TargetArchetype = targetArchetype,
            Source = string.IsNullOrWhiteSpace(source) ? "llm" : source,
        };

        if (_enabled)
        {
            await _writeGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                EnsureDir(_runPath);
                var line = JsonSerializer.Serialize(note, JsonOpts) + "\n";
                await File.AppendAllTextAsync(_runPath, line, Encoding.UTF8, ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(_aggregatePath))
                {
                    EnsureDir(_aggregatePath);
                    await File.AppendAllTextAsync(_aggregatePath, line, Encoding.UTF8, ct).ConfigureAwait(false);
                }
            }
            finally
            {
                _writeGate.Release();
            }
        }

        _audit?.Record("notebook.take_note", new Dictionary<string, object?>
        {
            ["category"] = note.Category,
            ["body_sha256"] = note.BodySha256,
            ["body_len"] = note.Body.Length,
            ["tag_count"] = note.Tags.Count,
            ["fight_id"] = note.FightId,
            ["target_host"] = note.TargetHost,
            ["target_archetype"] = note.TargetArchetype,
            ["source"] = note.Source,
        });

        return note;
    }

    /// <summary>
    /// Read all notes from the per-run JSONL plus (optionally) the
    /// aggregate, with optional category / tag / since filtering.
    /// Newest-first.
    /// </summary>
    public async Task<IReadOnlyList<FightNote>> ReadAsync(
        bool includeAggregate = true,
        string? category = null,
        IEnumerable<string>? anyTags = null,
        DateTimeOffset? since = null,
        int limit = 200,
        CancellationToken ct = default)
    {
        var paths = new List<string> { _runPath };
        if (includeAggregate && !string.IsNullOrEmpty(_aggregatePath))
            paths.Add(_aggregatePath);

        var tagFilter = (anyTags ?? Array.Empty<string>())
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.Trim())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var notes = new List<FightNote>();
        foreach (var path in paths)
        {
            if (!File.Exists(path)) continue;
            await foreach (var n in StreamNotesAsync(path, ct).ConfigureAwait(false))
            {
                if (!seen.Add(NoteKey(n))) continue;
                if (category is not null &&
                    !string.Equals(n.Category, category, StringComparison.OrdinalIgnoreCase)) continue;
                if (tagFilter.Count > 0 && !n.Tags.Any(tagFilter.Contains)) continue;
                if (since is not null &&
                    DateTimeOffset.TryParse(n.Timestamp, out var ts) && ts < since) continue;
                notes.Add(n);
            }
        }

        return notes
            .OrderByDescending(n => n.Timestamp, StringComparer.Ordinal)
            .Take(Math.Max(0, limit))
            .ToArray();
    }

    private static string NoteKey(FightNote n) =>
        $"{n.Timestamp}|{n.BodySha256}|{n.FightId}";

    private static async IAsyncEnumerable<FightNote> StreamNotesAsync(
        string path,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sr = new StreamReader(fs, Encoding.UTF8);
        string? line;
        while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            if (line.Length == 0) continue;
            FightNote? n;
            try { n = JsonSerializer.Deserialize<FightNote>(line, JsonOpts); }
            catch (JsonException) { continue; }
            if (n is not null) yield return n;
        }
    }

    /// <summary>
    /// Redact obvious secrets out of free-form note bodies before they
    /// hit disk. Conservative: prefer marking <c>[REDACTED:kind]</c>
    /// over leaking. Operators are encouraged to write notes about
    /// <i>technique</i>, not credentials — but if a credential slips
    /// in, it is masked.
    /// </summary>
    public static string RedactSecrets(string body)
    {
        if (string.IsNullOrEmpty(body)) return body ?? "";
        var s = body;

        // PEM private keys (multi-line).
        s = Regex.Replace(
            s,
            @"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            "[REDACTED:private-key]",
            RegexOptions.Singleline);

        // password: foo / pass=foo / pwd: foo
        s = Regex.Replace(
            s,
            @"(?ix)\b(pass(?:word)?|pwd)\s*[:=]\s*[""']?([^\s""'\r\n]{3,})",
            "$1=[REDACTED:password]");

        // token=... / api[_-]?key=...
        s = Regex.Replace(
            s,
            @"(?ix)\b(api[_-]?key|token|secret|bearer)\s*[:=]\s*[""']?([A-Za-z0-9_\-\.~+/=]{8,})",
            "$1=[REDACTED:token]");

        // Authorization: Bearer eyJ...
        s = Regex.Replace(
            s,
            @"(?i)Authorization:\s*(Basic|Bearer)\s+[A-Za-z0-9_\-\.~+/=]+",
            "Authorization: $1 [REDACTED:authz]");

        // user:pass@host  (HTTP credentials).
        s = Regex.Replace(
            s,
            @"(?i)([a-z][a-z0-9+\-.]*://)([^/\s:@]+):([^/\s@]+)@",
            "$1$2:[REDACTED:basic-auth]@");

        // NT / LM hashes (often "user:rid:lmhash:nthash:::").
        s = Regex.Replace(
            s,
            @"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b",
            "[REDACTED:lm:nt-hash]");

        // JWT-shaped tokens.
        s = Regex.Replace(
            s,
            @"\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\b",
            "[REDACTED:jwt]");

        // Long high-entropy hex blobs (>= 40 chars) — likely hashes.
        s = Regex.Replace(
            s,
            @"\b[A-Fa-f0-9]{40,}\b",
            "[REDACTED:hash]");

        return s;
    }

    private static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s));
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    private static void EnsureDir(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }

    public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    public void Dispose() => _writeGate.Dispose();
}
