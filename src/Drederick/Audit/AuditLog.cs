using System.Text.Json;

namespace Drederick.Audit;

/// <summary>
/// Append-only JSONL audit log. Every scope decision and every subprocess or
/// network action is recorded with a UTC timestamp. Thread-safe.
/// </summary>
public sealed class AuditLog : IDisposable
{
    private readonly StreamWriter _writer;
    private readonly Lock _gate = new();
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
    };

    public string Path { get; }

    public AuditLog(string path)
    {
        Path = path;
        var dir = System.IO.Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
        };
    }

    public void Record(string @event, IReadOnlyDictionary<string, object?>? fields = null)
    {
        var entry = new Dictionary<string, object?>
        {
            ["ts"] = DateTimeOffset.UtcNow.ToString("o"),
            ["pid"] = Environment.ProcessId,
            ["event"] = @event,
        };
        if (fields is not null)
        {
            foreach (var kv in fields) entry[kv.Key] = kv.Value;
        }
        var line = JsonSerializer.Serialize(entry, JsonOpts);
        lock (_gate)
        {
            _writer.WriteLine(line);
        }
    }

    public void Dispose() => _writer.Dispose();
}
