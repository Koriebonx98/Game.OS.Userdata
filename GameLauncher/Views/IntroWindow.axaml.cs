using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;
using Avalonia.Threading;
using GameLauncher.Services;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace GameLauncher.Views;

public partial class IntroWindow : Window
{
    private DirectShowHost? _dsHost;
    private bool _finished;

    public IntroWindow()
    {
        InitializeComponent();
        Opened  += OnOpened;
        Closing += OnClosing;
    }

    private void OnOpened(object? sender, EventArgs e)
    {
        Opened -= OnOpened;

        var settings = AppSettingsService.Load();
        var path     = settings.IntroVideoPath;

        DevLogService.Log($"[IntroWindow] Opened. ShowIntroVideo={settings.ShowIntroVideo}  IntroVideoPath='{path}'");

        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            DevLogService.Log(string.IsNullOrEmpty(path)
                ? "[IntroWindow] IntroVideoPath is empty — finishing intro immediately."
                : $"[IntroWindow] Video file not found at '{path}' — finishing intro immediately.");
            FinishIntro();
            return;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Windows: use DirectShow (same codecs as WPF MediaElement, no VLC required).
            DevLogService.Log($"[IntroWindow] Windows — starting DirectShow playback for '{path}'.");

            _dsHost = new DirectShowHost
            {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment   = VerticalAlignment.Stretch,
            };
            _dsHost.PlaybackEnded  += () => Dispatcher.UIThread.Post(FinishIntro);
            _dsHost.PlaybackFailed += () => Dispatcher.UIThread.Post(FinishIntro);
            _dsHost.SetSource(path);

            VideoContainer.Children.Add(_dsHost);
        }
        else
        {
            // macOS / Linux support will be added in a future iteration.
            DevLogService.Log("[IntroWindow] Non-Windows platform — skipping intro video.");
            FinishIntro();
        }
    }

    // Prevent the user from closing the intro while it is playing.
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!_finished)
            e.Cancel = true;
    }

    private void FinishIntro()
    {
        if (_finished) return;
        _finished = true;

        DevLogService.Log("[IntroWindow] FinishIntro — stopping player and transitioning to main window.");

        _dsHost?.Stop();
        _dsHost = null;

        if (Application.Current?.ApplicationLifetime is
            IClassicDesktopStyleApplicationLifetime desktop &&
            desktop.MainWindow is { } main)
        {
            main.WindowState = WindowState.FullScreen;
            main.Show();
            main.Activate();
            DevLogService.Log("[IntroWindow] Main window shown fullscreen.");
        }

        Close();
    }
}
