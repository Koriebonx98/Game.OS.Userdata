using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using GameLauncher.ViewModels;
using GameLauncher.Views;

namespace GameLauncher;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var mainVm = new MainViewModel(Program.DemoMode, Program.DemoPage);
            var win = new MainWindow { DataContext = mainVm };
            // In demo mode use a taller window so more content is visible
            if (Program.DemoMode)
                win.Height = 1350;
            desktop.MainWindow = win;
        }
        base.OnFrameworkInitializationCompleted();
    }
}
