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
/// </summary>
public static class DemoMode
{
    public static bool IsEnabled { get; private set; }

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

        if (IsEnabled)
            System.Diagnostics.Debug.WriteLine("[DemoMode] Demo/screenshot mode ENABLED");
    }
}
