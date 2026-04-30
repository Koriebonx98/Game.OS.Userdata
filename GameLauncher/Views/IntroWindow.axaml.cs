using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using LibVLCSharp.Shared;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace GameLauncher.Views;

public partial class IntroWindow : Window
{
    private LibVLC? _libVlc;
    private MediaPlayer? _mediaPlayer;
    private Media? _media;
    private bool _finished;

    public IntroWindow()
    {
        InitializeComponent();
        Opened  += OnOpened;
        Closing += OnClosing;
        Closed  += OnClosed;
    }

    private void OnOpened(object? sender, EventArgs e)
    {
        Opened -= OnOpened;

        var settings = Services.AppSettingsService.Load();
        var path     = settings.IntroVideoPath;

        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            FinishIntro();
            return;
        }

        try
        {
            // Provide the app directory so VLC can locate its native DLLs even
            // when the working directory differs from the executable's location.
            var appDir = AppContext.BaseDirectory;
            if (!string.IsNullOrEmpty(appDir) && Directory.Exists(appDir))
            {
                try { Core.Initialize(appDir); }
                catch { Core.Initialize(); }
            }
            else
            {
                Core.Initialize();
            }

            _libVlc      = new LibVLC(enableDebugLogs: false);
            _mediaPlayer = new MediaPlayer(_libVlc);

            _mediaPlayer.EndReached       += OnEndReached;
            _mediaPlayer.EncounteredError += OnEncounteredError;

            // Keep a reference to the Media so it isn't disposed before VLC
            // finishes reading it.
            _media = new Media(_libVlc, new Uri(path));

            // After the window is fully rendered, bind VLC to the native window
            // handle so it renders directly into the IntroWindow (no VideoView
            // needed – matching how PS5_OS drives playback via the OS media layer).
            Dispatcher.UIThread.Post(() =>
            {
                try
                {
                    var platformHandle = TryGetPlatformHandle();
                    if (platformHandle != null)
                    {
                        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                            _mediaPlayer.Hwnd = platformHandle.Handle;
                        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                            _mediaPlayer.XWindow = (uint)platformHandle.Handle;
                        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                            _mediaPlayer.NsObject = platformHandle.Handle;

                        _mediaPlayer.Play(_media);
                    }
                    else
                    {
                        FinishIntro();
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[IntroWindow] Failed to start playback: {ex.Message}");
                    FinishIntro();
                }
            }, DispatcherPriority.Loaded);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[IntroWindow] Failed to initialize VLC: {ex.Message}");
            FinishIntro();
        }
    }

    private void OnEndReached(object? sender, EventArgs e)
    {
        // VLC fires this on a background thread; marshal to the UI thread.
        Dispatcher.UIThread.Post(FinishIntro);
    }

    private void OnEncounteredError(object? sender, EventArgs e)
    {
        Dispatcher.UIThread.Post(FinishIntro);
    }

    // Prevent the user from closing the intro while it is playing.
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!_finished)
            e.Cancel = true;
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        DisposeVlc();
    }

    private void FinishIntro()
    {
        if (_finished) return;
        _finished = true;

        try { _mediaPlayer?.Stop(); }
        catch (ObjectDisposedException) { /* already cleaned up */ }

        DisposeVlc();

        // Show the main window fullscreen, then close the intro overlay.
        if (Application.Current?.ApplicationLifetime is
            IClassicDesktopStyleApplicationLifetime desktop &&
            desktop.MainWindow is { } main)
        {
            main.WindowState = WindowState.FullScreen;
            main.Show();
            main.Activate();
        }

        Close();
    }

    private void DisposeVlc()
    {
        if (_mediaPlayer != null)
        {
            _mediaPlayer.EndReached       -= OnEndReached;
            _mediaPlayer.EncounteredError -= OnEncounteredError;
            _mediaPlayer.Dispose();
            _mediaPlayer = null;
        }

        _media?.Dispose();
        _media = null;

        _libVlc?.Dispose();
        _libVlc = null;
    }
}
