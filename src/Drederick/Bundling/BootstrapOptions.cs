namespace Drederick.Bundling;

/// <summary>
/// Inputs to <see cref="DatasetteBootstrap.EnsureAsync"/>. Keeps the public
/// surface narrow: an operator-supplied explicit path, an auto-install gate,
/// a consent opt-out, and the cache root under which managed installs live.
/// </summary>
public sealed record BootstrapOptions(
    string? ExplicitPath,
    bool AutoInstall,
    bool AssumeYes,
    string CacheDir)
{
    /// <summary>
    /// Convenience default: auto-install on, assume-yes off, cache under
    /// <c>~/.drederick/</c>.
    /// </summary>
    public static BootstrapOptions Default()
    {
        var home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new BootstrapOptions(
            ExplicitPath: null,
            AutoInstall: true,
            AssumeYes: false,
            CacheDir: System.IO.Path.Combine(home, ".drederick"));
    }
}
