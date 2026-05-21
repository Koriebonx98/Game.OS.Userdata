using System;

namespace GameLauncher;

/// <summary>
/// Global flag for demo / screenshot mode.
/// When enabled the launcher bypasses all network authentication and
/// pre-populates every page with rich static sample data so that
/// screenshots can be taken on any machine (CI, offline, etc.).
///
/// Activate via the <c>--demo</c> CLI argument or
/// <c>GAMEOS_DEMO_MODE=1</c> environment variable.
/// Pass <c>--screenshot &lt;path&gt;</c> to render a single frame to a PNG and exit.
/// </summary>
public static class DemoMode
{
    public static bool IsEnabled { get; private set; }

    /// <summary>When set, the app renders one frame to this path then exits.</summary>
    public static string? ScreenshotPath { get; private set; }

    /// <summary>
    /// Must be called before <see cref="Avalonia.AppBuilder.Build"/> so that
    /// the initial view-model wiring can use the flag.
    /// </summary>
    public static void DetectAndEnable(string[] args)
    {
        bool fromEnv = string.Equals(
            Environment.GetEnvironmentVariable("GAMEOS_DEMO_MODE"), "1",
            StringComparison.Ordinal);

        bool fromArg = Array.Exists(args, a =>
            string.Equals(a, "--demo", StringComparison.OrdinalIgnoreCase));

        IsEnabled = fromEnv || fromArg;

        // --screenshot <path>
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], "--screenshot", StringComparison.OrdinalIgnoreCase))
            {
                ScreenshotPath = args[i + 1];
                IsEnabled = true;   // screenshot implies demo mode
                break;
            }
        }

        if (IsEnabled)
            System.Diagnostics.Debug.WriteLine("[DemoMode] Demo/screenshot mode ENABLED");
    }
}
