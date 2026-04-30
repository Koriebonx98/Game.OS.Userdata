using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using GameLauncher.Services;
using GameLauncher.ViewModels;
using GameLauncher.Views;
using System.IO;

namespace GameLauncher;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var mainVm = new MainViewModel();
            if (DemoMode.IsEnabled)
                mainVm.LoadDemo();

            var settings = AppSettingsService.Load();

            // If an intro video is configured, play it fullscreen in-process
            // using the bundled LibVLC engine.  IntroWindow will swap itself
            // out for MainWindow once playback finishes (or on any failure).
            if (settings.ShowIntroVideo
                && !string.IsNullOrEmpty(settings.IntroVideoPath)
                && File.Exists(settings.IntroVideoPath))
            {
                desktop.MainWindow = new IntroWindow(mainVm, settings.IntroVideoPath);
            }
            else
            {
                desktop.MainWindow = new MainWindow { DataContext = mainVm };
            }
        }
        base.OnFrameworkInitializationCompleted();
    }
}
