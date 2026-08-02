using Avalonia;
using GameOS.Updater;

AppBuilder.Configure<App>()
    .UsePlatformDetect()
    .WithInterFont()
    .StartWithClassicDesktopLifetime(args);
