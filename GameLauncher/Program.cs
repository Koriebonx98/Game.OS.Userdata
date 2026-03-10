using Avalonia;
using Avalonia.Skia;
using System;

namespace GameLauncher;

internal sealed class Program
{
    [STAThread]
    public static void Main(string[] args) =>
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    public static AppBuilder BuildAvaloniaApp()
    {
        var builder = AppBuilder.Configure<App>()
                                .UsePlatformDetect()
                                .WithInterFont()
                                .LogToTrace();

        // When running under Xvfb (headless CI / Linux screenshot mode) force software
        // rendering so the app doesn't crash when it receives pointer events via xdotool.
        // GAMEOS_DISABLE_GPU=1  OR  LIBGL_ALWAYS_SOFTWARE=1 both activate this path.
        bool forceSwRenderer =
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GAMEOS_DISABLE_GPU")) ||
            Environment.GetEnvironmentVariable("LIBGL_ALWAYS_SOFTWARE") == "1" ||
            Environment.GetEnvironmentVariable("AVALONIA_USE_RASTER_RENDERER") == "1";

        if (forceSwRenderer)
        {
            builder = builder.With(new SkiaOptions { MaxGpuResourceSizeBytes = 0 });
        }

        return builder;
    }
}
