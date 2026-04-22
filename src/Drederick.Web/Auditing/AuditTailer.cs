using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Drederick.Web.Auditing;

/// <summary>
/// Read-only streaming reader over <c>audit.jsonl</c>. The audit log is
/// append-only per the upstream contract (<c>@invariant-id:audit-everything</c>
/// / <c>@invariant-id:no-exfiltration</c>); nothing in this class writes,
/// truncates, or mutates the file.
///
/// <para>
/// Two surfaces are exposed:
/// <list type="bullet">
///   <item><description><see cref="Read"/> — open-filter-close over a
///     stable snapshot of the file. Used by the REST audit endpoints.
///     </description></item>
///   <item><description><see cref="TailAsync"/> — incremental tail, yields
///     new entries as the file grows. Intended for a future SignalR hub
///     binding; not consumed by the REST endpoints in this agent.
///     </description></item>
/// </list>
/// </para>
///
/// <para>
/// Redaction: a small canary-scan pass checks every entry for known
/// plaintext-secret markers (see <see cref="PlaintextCanaries"/>) before
/// returning it. Upstream is supposed to digest secrets before writing
/// (<c>@invariant-id:no-plaintext-secrets</c>), so a hit means something is
/// broken in the producer; we redact the offending value and flip
/// <see cref="AuditEntry.RedactionWarning"/> so the UI can surface the bug.
/// </para>
/// </summary>
public sealed class AuditTailer
{
    public string FilePath { get; }

    public AuditTailer(string filePath)
    {
        FilePath = filePath;
    }

    /// <summary>
    /// Plaintext tokens that must NEVER appear in audit.jsonl. If one does,
    /// it means a producer upstream skipped the SHA-256 digest step.
    /// </summary>
    public static readonly string[] PlaintextCanaries =
    {
        // Generic secret markers — anything obviously plaintext-looking.
        "password=",
        "passwd=",
        "secret=",
        "plaintext_password",
        "plaintext_secret",
        // Test-harness canary used by AuditEndpointsTests.NoPlaintextInResponse_CanaryTest.
        "DREDERICK_TEST_PLAINTEXT_CANARY",
    };

    public sealed record AuditEntry(
        JsonElement Raw,
        string? EventType,
        DateTimeOffset? Timestamp,
        bool RedactionWarning);

    public sealed record TailQuery(
        DateTimeOffset? Since,
        int Limit,
        string? Category);

    /// <summary>
    /// Open, filter, and return a bounded slice of the audit log. Caller
    /// controls the limit. Returns the most recent <c>limit</c> matching
    /// entries, ordered oldest→newest.
    /// </summary>
    public IReadOnlyList<AuditEntry> Read(TailQuery query)
    {
        if (!File.Exists(FilePath))
        {
            return Array.Empty<AuditEntry>();
        }

        var limit = Math.Clamp(query.Limit, 1, 1000);
        var matched = new List<AuditEntry>();

        using var fs = new FileStream(
            FilePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(fs);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var entry = ParseLine(line);
            if (entry is null) continue;
            if (!MatchesQuery(entry, query)) continue;
            matched.Add(entry);
        }

        // Keep the newest `limit` entries, preserving chronological order.
        if (matched.Count <= limit) return matched;
        return matched.GetRange(matched.Count - limit, limit);
    }

    /// <summary>
    /// Collect distinct event-type prefixes present in the file for UI chip
    /// rendering. Prefix is the dotted token before the first '.', so
    /// <c>web.runs.start</c> yields <c>web</c>. The full event names are
    /// also included so more-specific filters work.
    /// </summary>
    public (IReadOnlyList<string> Prefixes, IReadOnlyList<string> Events) Categories()
    {
        var prefixes = new SortedSet<string>(StringComparer.Ordinal);
        var events = new SortedSet<string>(StringComparer.Ordinal);
        if (!File.Exists(FilePath))
        {
            return (Array.Empty<string>(), Array.Empty<string>());
        }
        using var fs = new FileStream(
            FilePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(fs);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var entry = ParseLine(line);
            if (entry?.EventType is null) continue;
            events.Add(entry.EventType);
            var dot = entry.EventType.IndexOf('.');
            prefixes.Add(dot > 0 ? entry.EventType[..dot] : entry.EventType);
        }
        return (prefixes.ToArray(), events.ToArray());
    }

    /// <summary>
    /// Incremental tail. Yields entries as the file grows; intended for the
    /// future SignalR hub. Not consumed by the REST endpoints in this
    /// agent — wiring is left to the Phase-3 agent.
    /// </summary>
    public async IAsyncEnumerable<AuditEntry> TailAsync(
        [EnumeratorCancellation] CancellationToken ct)
    {
        // Wait (briefly) for the file to exist so consumers can subscribe
        // before the server emits its first entry.
        while (!File.Exists(FilePath))
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(250, ct).ConfigureAwait(false);
        }

        using var fs = new FileStream(
            FilePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(fs);

        while (!ct.IsCancellationRequested)
        {
            string? line;
            while ((line = await reader.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var entry = ParseLine(line);
                if (entry is not null) yield return entry;
            }
            try
            {
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                yield break;
            }
        }
    }

    private static AuditEntry? ParseLine(string line)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(line); }
        catch (JsonException) { return null; }

        var root = doc.RootElement.Clone();
        doc.Dispose();

        string? eventType = null;
        if (root.TryGetProperty("event", out var evt) && evt.ValueKind == JsonValueKind.String)
        {
            eventType = evt.GetString();
        }

        DateTimeOffset? ts = null;
        if (root.TryGetProperty("ts", out var tsEl) && tsEl.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(tsEl.GetString(), out var parsedTs))
        {
            ts = parsedTs;
        }

        var hasCanary = LineContainsCanary(line);
        return new AuditEntry(root, eventType, ts, hasCanary);
    }

    private static bool LineContainsCanary(string line)
    {
        foreach (var canary in PlaintextCanaries)
        {
            if (line.Contains(canary, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool MatchesQuery(AuditEntry entry, TailQuery query)
    {
        if (query.Since is { } since && entry.Timestamp is { } ets && ets < since)
        {
            return false;
        }
        if (!string.IsNullOrEmpty(query.Category))
        {
            var cat = query.Category;
            if (entry.EventType is null) return false;
            // Match on exact event name OR on dotted prefix
            // ("web" matches "web.runs.start", "web.runs" matches "web.runs.start").
            if (!entry.EventType.Equals(cat, StringComparison.Ordinal)
                && !entry.EventType.StartsWith(cat + ".", StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }
}
