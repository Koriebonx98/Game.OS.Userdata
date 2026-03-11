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
            if (DemoMode.IsEnabled)
                mainVm.LoadDemo();
            desktop.MainWindow = new MainWindow { DataContext = mainVm };
        }
        base.OnFrameworkInitializationCompleted();
    }
}

