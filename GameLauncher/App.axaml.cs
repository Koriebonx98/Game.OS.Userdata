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
            var mainVm = new MainViewModel();
            desktop.MainWindow = new MainWindow { DataContext = mainVm };

            // In demo mode skip the login screen entirely and jump straight
            // to the dashboard with pre-populated data.
            if (DemoMode.IsEnabled)
                mainVm.LoadDemo();
        }
        base.OnFrameworkInitializationCompleted();
    }
}

