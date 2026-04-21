using Avalonia;
using Avalonia.Headless;
using Drederick.UI;

[assembly: AvaloniaTestApplication(typeof(Drederick.UI.Tests.TestAppBuilder))]

namespace Drederick.UI.Tests;

/// <summary>
/// Headless Avalonia test host. Mirrors bonsai's pattern: use the real
/// <see cref="App"/> but run under <see cref="AvaloniaHeadlessPlatform"/> so
/// there's no windowing dependency in CI.
/// </summary>
public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = true });
}
