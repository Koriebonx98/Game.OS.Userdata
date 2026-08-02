using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace GameOS.Updater;

public class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // Parse command-line arguments passed by the launcher.
            // Expected: --zip <path> --target <dir> --launcher <launcherPath> [--username <name>]
            var args = desktop.Args ?? [];
            string? zipPath     = GetArg(args, "--zip");
            string? targetDir   = GetArg(args, "--target");
            string? launcherPath = GetArg(args, "--launcher");
            string? username    = GetArg(args, "--username");

            desktop.MainWindow = new UpdaterWindow(zipPath, targetDir, launcherPath, username);
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static string? GetArg(string[] args, string key)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], key, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        }
        return null;
    }
}
