namespace Drederick.Ops;

/// <summary>
/// Native PATH resolution — no subprocess, works on Linux/macOS/Windows.
/// </summary>
public static class PathResolver
{
    /// <summary>
    /// Returns the full path of <paramref name="binary"/> if it exists on PATH,
    /// otherwise null. Equivalent to <c>which binary</c> on POSIX systems.
    /// </summary>
    public static string? Which(string binary)
    {
        if (Path.IsPathRooted(binary) && File.Exists(binary))
            return binary;

        if (Path.IsPathRooted(binary))
            return null;

        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        var separator = Path.PathSeparator; // ':' on Linux/macOS, ';' on Windows

        foreach (var dir in pathVar.Split(separator, StringSplitOptions.RemoveEmptyEntries))
        {
            var fullPath = Path.Combine(dir, binary);
            if (File.Exists(fullPath))
                return fullPath;

            if (OperatingSystem.IsWindows())
            {
                var exePath = fullPath + ".exe";
                if (File.Exists(exePath))
                    return exePath;
            }
        }

        return null;
    }

    /// <summary>Returns true if <paramref name="binary"/> is available on PATH.</summary>
    public static bool IsAvailable(string binary) => Which(binary) is not null;
}
