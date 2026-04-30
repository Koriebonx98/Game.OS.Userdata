using System;
using System.ComponentModel;
using System.IO;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using GameLauncher.ViewModels;
using LibVLCSharp.Shared;

namespace GameLauncher.Views;

/// <summary>
/// Fullscreen intro video window that plays a video file using the bundled
/// LibVLC engine, then hands off to <see cref="MainWindow"/>.
/// </summary>
public partial class IntroWindow : Window
{
    private readonly string _videoPath;
    private readonly MainViewModel _mainVm;
    private LibVLC? _libVlc;
    private MediaPlayer? _mediaPlayer;
    private Media? _media;
    private bool _finished;

    // Parameterless constructor required by the Avalonia XAML loader / designer.
    public IntroWindow() : this(new MainViewModel(), string.Empty) { }

    public IntroWindow(MainViewModel mainVm, string videoPath)
    {
        InitializeComponent();

        _mainVm    = mainVm;
        _videoPath = videoPath;

        Opened  += OnOpened;
        Closing += OnClosing;
    }

    private void OnOpened(object? sender, EventArgs e)
    {
        Opened -= OnOpened;

        try
        {
            if (!File.Exists(_videoPath))
            {
                FinishAndShowMain();
                return;
            }

            Core.Initialize();
            _libVlc      = new LibVLC();
            _mediaPlayer = new MediaPlayer(_libVlc);

            VideoView.MediaPlayer = _mediaPlayer;

            _media = new Media(_libVlc, _videoPath, FromType.FromPath);
            _mediaPlayer.EndReached       += OnMediaEnded;
            _mediaPlayer.EncounteredError += OnMediaError;
            _mediaPlayer.Play(_media);
        }
        catch
        {
            FinishAndShowMain();
        }
    }

    private void OnMediaEnded(object? sender, EventArgs e)  => Dispatcher.UIThread.Post(FinishAndShowMain);
    private void OnMediaError(object? sender, EventArgs e)  => Dispatcher.UIThread.Post(FinishAndShowMain);

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        // Prevent the user closing the intro window while the video is playing.
        if (!_finished)
            e.Cancel = true;
    }

    private void FinishAndShowMain()
    {
        if (_finished) return;
        _finished = true;

        try { _mediaPlayer?.Stop(); } catch { /* ignore */ }
        DisposeVlc();

        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var mainWindow = new MainWindow { DataContext = _mainVm };
            // Replace the app's MainWindow so the lifetime doesn't exit when we close.
            desktop.MainWindow = mainWindow;
            mainWindow.Show();
        }

        Close();
    }

    private void DisposeVlc()
    {
        if (_mediaPlayer != null)
        {
            _mediaPlayer.EndReached       -= OnMediaEnded;
            _mediaPlayer.EncounteredError -= OnMediaError;
        }
        try { _mediaPlayer?.Dispose(); } catch { /* ignore */ }
        try { _media?.Dispose();       } catch { /* ignore */ }
        try { _libVlc?.Dispose();      } catch { /* ignore */ }
        _mediaPlayer = null;
        _media       = null;
        _libVlc      = null;
    }

    protected override void OnClosed(EventArgs e)
    {
        DisposeVlc();
        base.OnClosed(e);
    }
}
