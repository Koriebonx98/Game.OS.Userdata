using Avalonia;
using Avalonia.X11;
using System;

namespace GameOS.Desktop;

sealed class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args) => BuildAvaloniaApp()
        .StartWithClassicDesktopLifetime(args);

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
    {
        var builder = AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

        // When running under a virtual framebuffer (CI / screenshot mode) force the
        // software Skia renderer so that xwd/scrot can capture the rendered window.
        if (Environment.GetEnvironmentVariable("GAMEOS_SOFTWARE_RENDER") == "1")
        {
            builder = builder.With(new X11PlatformOptions
            {
                RenderingMode = new[] { X11RenderingMode.Software }
            });
        }

        return builder;
    }
}
