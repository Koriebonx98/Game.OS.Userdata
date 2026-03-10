using Avalonia;
using Avalonia.Skia;
using System;
using System.Runtime.InteropServices;

namespace GameLauncher;

internal sealed class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        DemoMode.DetectAndEnable(args);
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp()
    {
        // When running under Xvfb (headless CI / Linux screenshot mode) force software
        // rendering so the app doesn't crash when it receives pointer/keyboard events.
        // Set GAMEOS_DISABLE_GPU=1  OR  LIBGL_ALWAYS_SOFTWARE=1 to activate.
        bool forceSwRenderer =
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GAMEOS_DISABLE_GPU")) ||
            Environment.GetEnvironmentVariable("LIBGL_ALWAYS_SOFTWARE") == "1" ||
            Environment.GetEnvironmentVariable("AVALONIA_USE_RASTER_RENDERER") == "1";

        var builder = AppBuilder.Configure<App>()
                                .UsePlatformDetect()
                                .WithInterFont()
                                .LogToTrace();

        if (forceSwRenderer)
        {
            builder = builder
                .With(new SkiaOptions { MaxGpuResourceSizeBytes = 0 });

            // On Linux explicitly request the X11 software framebuffer path so
            // no EGL/GLX/Vulkan context is created — preventing the native crash
            // that Xvfb triggers when an OpenGL context is invalidated by input events.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                builder = builder.With(new X11PlatformOptions
                {
                    RenderingMode = new[] { X11RenderingMode.Software },
                });
            }
        }

        return builder;
    }
}
