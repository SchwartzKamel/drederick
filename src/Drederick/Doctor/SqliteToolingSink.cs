using System.Reflection;

namespace Drederick.Doctor;

/// <summary>
/// Best-effort bridge to the findings.db tooling table created by the
/// parallel <c>findings-db-schema</c> work. At call-time we look for a type
/// named <c>Drederick.Reporting.SqliteReport</c> exposing a static
/// <c>UpsertTooling(string dbPath, IEnumerable&lt;ToolInfo&gt;)</c> (or a
/// per-row signature). If the type isn't present yet — because that wave
/// hasn't merged — we silently skip, leaving doctor output in audit.jsonl.
///
/// TODO(findings-db-schema): once SqliteReport.UpsertTooling lands, drop
/// the reflection lookup and call it directly.
/// </summary>
public static class SqliteToolingSink
{
    public static bool TryUpsert(string dbPath, IReadOnlyList<ToolInfo> tools)
    {
        try
        {
            var asm = typeof(ToolInfo).Assembly;
            var type = asm.GetType("Drederick.Reporting.SqliteReport");
            if (type is null) return false;

            // Preferred batch signature.
            var batch = type.GetMethod(
                "UpsertTooling",
                BindingFlags.Public | BindingFlags.Static,
                binder: null,
                types: new[] { typeof(string), typeof(IEnumerable<ToolInfo>) },
                modifiers: null);
            if (batch is not null)
            {
                batch.Invoke(null, new object?[] { dbPath, tools });
                return true;
            }

            // Per-row fallback: UpsertTooling(string, string name, string? version, string source, string? path, DateTimeOffset detectedAt)
            var row = type.GetMethod(
                "UpsertTooling",
                BindingFlags.Public | BindingFlags.Static,
                binder: null,
                types: new[]
                {
                    typeof(string), typeof(string), typeof(string), typeof(string),
                    typeof(string), typeof(DateTimeOffset),
                },
                modifiers: null);
            if (row is not null)
            {
                foreach (var t in tools)
                {
                    row.Invoke(null, new object?[]
                    {
                        dbPath, t.Name, t.Version, "doctor", t.Path, t.DetectedAt,
                    });
                }
                return true;
            }
        }
        catch
        {
            // If the other agent's signature differs in unexpected ways we
            // stay soft — tooling detection always lives in audit.jsonl too.
        }
        return false;
    }
}
