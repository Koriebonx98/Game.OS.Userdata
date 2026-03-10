using Avalonia;
using System;

namespace GameLauncher;

internal sealed class Program
{
    /// <summary>
    /// Set by the <c>--demo</c> command-line flag.
    /// When true the app skips login and loads the static <see cref="GameCatalog"/>
    /// so all views can be seen without a live backend connection.
    /// </summary>
    internal static bool   DemoMode { get; private set; }

    /// <summary>
    /// Set by <c>--page=&lt;name&gt;</c>.  Determines which page is shown first
    /// in demo mode: dashboard · library · store · friends · profile · gamedetail.
    /// </summary>
    internal static string DemoPage { get; private set; } = "dashboard";

    [STAThread]
    public static void Main(string[] args)
    {
        foreach (var arg in args)
        {
            if (arg == "--demo")           DemoMode = true;
            if (arg.StartsWith("--page=")) DemoPage = arg[7..];
        }
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
                     .UsePlatformDetect()
                     .WithInterFont()
                     .LogToTrace();
}
