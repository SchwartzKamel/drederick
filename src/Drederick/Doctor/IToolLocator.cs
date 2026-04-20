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
            _dirs = path.Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
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
