namespace Drederick.Doctor;

/// <summary>
/// Resolves a bare executable name to an absolute path, or null if not found.
/// Tests inject a stub that searches a synthetic PATH directory.
/// </summary>
public interface IToolLocator
{
    string? Which(string name);
}

public sealed class PathToolLocator : IToolLocator
{
    private readonly string[] _dirs;

    public PathToolLocator(IEnumerable<string>? dirs = null)
    {
        if (dirs is not null)
        {
            _dirs = dirs.ToArray();
        }
        else
        {
            var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            var parts = path.Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
                .ToList();
            // Include Go's default bin dirs too — `go install` drops binaries
            // there even when the operator hasn't yet added them to PATH.
            // Without this, Which("nuclei") misses a nuclei that was just
            // installed via `go install`, and doctor thinks install failed.
            foreach (var d in GoBinFallbacks())
            {
                if (!parts.Contains(d)) parts.Add(d);
            }
            _dirs = parts.ToArray();
        }
    }

    private static IEnumerable<string> GoBinFallbacks()
    {
        var gobin = Environment.GetEnvironmentVariable("GOBIN");
        if (!string.IsNullOrEmpty(gobin)) yield return gobin;
        var gopath = Environment.GetEnvironmentVariable("GOPATH");
        if (!string.IsNullOrEmpty(gopath))
        {
            yield return System.IO.Path.Combine(gopath, "bin");
        }
        var home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(home))
        {
            yield return System.IO.Path.Combine(home, "go", "bin");
            yield return System.IO.Path.Combine(home, ".local", "bin");
        }
    }

    public string? Which(string name)
    {
        // On Windows executables need .exe/.cmd, but drederick targets Linux/macOS
        // operator workstations for CTF use; keep it simple.
        foreach (var d in _dirs)
        {
            var candidate = System.IO.Path.Combine(d, name);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}
