using System.Text.Json;
using Drederick.Recon;

namespace Drederick.Reporting;

public static class JsonReport
{
    private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

    public static void Write(string path, IEnumerable<HostFinding> hosts, string scopeSource)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var payload = new
        {
            scope = scopeSource,
            generated = DateTimeOffset.UtcNow.ToString("o"),
            hosts = hosts.ToArray(),
        };
        File.WriteAllText(path, JsonSerializer.Serialize(payload, Opts));
    }
}
