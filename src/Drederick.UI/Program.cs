using Avalonia;

namespace Drederick.UI;

/// <summary>
/// Entry point for the Drederick operator console. Uses the standard Avalonia
/// classic-desktop lifetime. Scanner invocation flows through
/// <see cref="Drederick.Host.DrederickHost"/> — this assembly never spawns
/// scanner subprocesses directly.
/// </summary>
internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        return BuildAvaloniaApp()
            .StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
