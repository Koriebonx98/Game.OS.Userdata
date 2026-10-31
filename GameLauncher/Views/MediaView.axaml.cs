using Avalonia;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using System.Linq;
using GameLauncher.Services;
using GameLauncher.ViewModels;
using LibVLCSharp.Shared;
using System;
using System.IO;

namespace GameLauncher.Views;

public partial class MediaView : UserControl
{
    // ── VLC local file player state ───────────────────────────────────────────
    private LibVLC?      _libVlc;
    private MediaPlayer? _mediaPlayer;
    private Media?       _media;

    // ── Music player state (audio only, independent of the video overlay) ─────
    private LibVLC?      _audioVlc;
    private MediaPlayer? _audioPlayer;
    private Media?       _audioMedia;
    private readonly DispatcherTimer _audioTimer = new() { Interval = TimeSpan.FromMilliseconds(500) };

    private readonly DispatcherTimer _videoTimer = new() { Interval = TimeSpan.FromMilliseconds(500) };
    private bool _seekDragging;

    public MediaView()
    {
        _videoTimer.Tick += (_, _) =>
        {
            if (_mediaPlayer != null && DataContext is MediaViewModel v)
                v.UpdateVideoProgress(_mediaPlayer.Time, _mediaPlayer.Length);
        };
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Unloaded           += OnUnloaded;
        _audioTimer.Tick   += (_, _) => PublishAudioProgress();
    }

    private MediaViewModel? _subscribedVm;

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_subscribedVm != null) _subscribedVm.MediaFocusChanged -= ScrollFocusedIntoView;
        _subscribedVm = DataContext as MediaViewModel;
        if (_subscribedVm != null) _subscribedVm.MediaFocusChanged += ScrollFocusedIntoView;

        if (DataContext is MediaViewModel vm)
        {
            vm.PlayLocalVideoRequested = OnPlayLocalVideoRequested;
            vm.PlayMediaItemRequested = OnPlayMediaItemRequested;
            vm.PlayAudioRequested = StartAudio;
            vm.ToggleAudioPauseRequested = ToggleAudioPause;
            vm.StopAudioRequested = StopAudio;
            vm.StopVideoRequested = DisposeVlc;
            vm.ToggleVideoPauseRequested = ToggleVideoPause;
            vm.SeekByRequested = SeekBy;
            vm.SeekToRequested = SeekTo;
        }
    }

    // Keeps the controller highlight visible: scrolls every ScrollViewer around it (list and shelf) just enough.
    private void ScrollFocusedIntoView() =>
        Dispatcher.UIThread.Post(() =>
        {
            var btn = this.GetVisualDescendants().OfType<Button>()
                .FirstOrDefault(b => b.IsVisible && b.IsEffectivelyVisible && b.Classes.Contains("focused"));
            if (btn == null) return;
            foreach (var sv in btn.GetVisualAncestors().OfType<ScrollViewer>())
            {
                if (sv.Content is not Visual content) continue;
                var origin = btn.TranslatePoint(new Avalonia.Point(0, 0), content);
                if (origin == null) continue;
                var view = sv.Viewport;
                double x = sv.Offset.X, y = sv.Offset.Y;
                if (origin.Value.Y < y) y = origin.Value.Y - 8;
                else if (origin.Value.Y + btn.Bounds.Height > y + view.Height) y = origin.Value.Y + btn.Bounds.Height - view.Height + 8;
                if (origin.Value.X < x) x = origin.Value.X - 8;
                else if (origin.Value.X + btn.Bounds.Width > x + view.Width) x = origin.Value.X + btn.Bounds.Width - view.Width + 8;
                x = Math.Max(0, x); y = Math.Max(0, y);
                if (Math.Abs(x - sv.Offset.X) > 0.5 || Math.Abs(y - sv.Offset.Y) > 0.5)
                    sv.Offset = new Avalonia.Vector(x, y);
            }
            btn.BringIntoView();
        }, DispatcherPriority.Background);

    // ── Transport (video overlay and music) ──────────────────────────────────

    private void ToggleVideoPause()
    {
        if (_mediaPlayer == null || DataContext is not MediaViewModel vm) return;
        _mediaPlayer.Pause();
        vm.IsVideoPlaying = !vm.IsVideoPlaying;
    }

    private void SeekBy(bool video, long deltaMs)
    {
        var p = video ? _mediaPlayer : _audioPlayer;
        if (p == null || p.Length <= 0) return;
        p.Time = Math.Clamp(p.Time + deltaMs, 0, Math.Max(0, p.Length - 500));
        Publish(video);
    }

    private void SeekTo(bool video, double fraction)
    {
        var p = video ? _mediaPlayer : _audioPlayer;
        if (p == null || p.Length <= 0) return;
        p.Time = (long)(Math.Clamp(fraction, 0, 1) * p.Length);
        Publish(video);
    }

    private void Publish(bool video)
    {
        if (DataContext is not MediaViewModel vm) return;
        if (video && _mediaPlayer != null) vm.UpdateVideoProgress(_mediaPlayer.Time, _mediaPlayer.Length);
        else if (!video && _audioPlayer != null) vm.UpdateAudioProgress(_audioPlayer.Time, _audioPlayer.Length);
    }

    // Progress bars: click or drag to seek. Tag = "video" | "audio".
    private void OnSeekPressed(object? sender, Avalonia.Input.PointerPressedEventArgs e)
    {
        _seekDragging = true;
        e.Pointer.Capture(sender as Avalonia.Input.IInputElement);
        SeekFromPointer(sender, e);
    }

    private void OnSeekMoved(object? sender, Avalonia.Input.PointerEventArgs e)
    {
        if (_seekDragging) SeekFromPointer(sender, e);
    }

    private void OnSeekReleased(object? sender, Avalonia.Input.PointerReleasedEventArgs e)
    {
        if (!_seekDragging) return;
        SeekFromPointer(sender, e);
        _seekDragging = false;
        e.Pointer.Capture(null);
    }

    private void SeekFromPointer(object? sender, Avalonia.Input.PointerEventArgs e)
    {
        if (sender is not Control c || c.Bounds.Width <= 0 || DataContext is not MediaViewModel vm) return;
        double f = e.GetPosition(c).X / c.Bounds.Width;
        vm.SeekToRequested?.Invoke(string.Equals(c.Tag as string, "video"), f);
    }

    private void OnUnloaded(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        _videoTimer.Stop();
        (DataContext as MediaViewModel)?.EndAllSessions();
        DisposeVlc();
        StopAudio();
    }

    // ── Music player ─────────────────────────────────────────────────────────

    private static void InitVlcCore()
    {
        string? vlcDir = IntroWindow.FindBundledLibVlcDirectoryPublic();
        if (!string.IsNullOrEmpty(vlcDir)) Core.Initialize(vlcDir);
        else Core.Initialize();
    }

    private void StartAudio(string path)
    {
        if (DataContext is not MediaViewModel vm) return;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        StopAudio();
        try
        {
            InitVlcCore();
            _audioVlc    = new LibVLC(enableDebugLogs: false);
            _audioPlayer = new MediaPlayer(_audioVlc);
            _audioPlayer.EndReached       += OnAudioEnded;
            _audioPlayer.EncounteredError += OnAudioError;
            _audioMedia = new Media(_audioVlc, new Uri(path));
            _audioPlayer.Play(_audioMedia);
            vm.IsMusicPlaying = true;
            _audioTimer.Start();
        }
        catch (Exception ex)
        {
            DevLogService.Log($"[MediaView] Audio init failed: {ex.GetType().Name}: {ex.Message}");
            StopAudio();
            vm.IsMusicPlaying = false;
        }
    }

    private void ToggleAudioPause()
    {
        if (_audioPlayer == null || DataContext is not MediaViewModel vm) return;
        _audioPlayer.Pause();
        vm.IsMusicPlaying = !vm.IsMusicPlaying;
    }

    private void PublishAudioProgress()
    {
        if (_audioPlayer != null && DataContext is MediaViewModel vm)
            vm.UpdateAudioProgress(_audioPlayer.Time, _audioPlayer.Length);
    }

    // VLC raises these on its own thread, and the player must not be disposed from inside its callback.
    private void OnAudioEnded(object? sender, EventArgs e) =>
        System.Threading.Tasks.Task.Run(() => Dispatcher.UIThread.Post(() =>
        {
            if (DataContext is MediaViewModel vm) vm.OnAudioEnded();
        }));

    private void OnAudioError(object? sender, EventArgs e) =>
        System.Threading.Tasks.Task.Run(() => Dispatcher.UIThread.Post(() =>
        {
            StopAudio();
            if (DataContext is MediaViewModel vm) vm.IsMusicPlaying = false;
        }));

    private void StopAudio()
    {
        _audioTimer.Stop();
        if (_audioPlayer != null)
        {
            _audioPlayer.EndReached       -= OnAudioEnded;
            _audioPlayer.EncounteredError -= OnAudioError;
            try { _audioPlayer.Stop(); } catch (Exception ex) { DevLogService.Log($"[MediaView] Audio stop: {ex.Message}"); }
            _audioPlayer.Dispose();
            _audioPlayer = null;
        }
        _audioMedia?.Dispose();
        _audioMedia = null;
        _audioVlc?.Dispose();
        _audioVlc = null;
    }

    // ── VLC local file player ────────────────────────────────────────────────

    private async void OnPlayLocalVideoRequested()
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null) return;

        var files = await topLevel.StorageProvider.OpenFilePickerAsync(
            new FilePickerOpenOptions
            {
                Title         = "Select a media file to play",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Video / Audio files")
                    {
                        Patterns = new[]
                        {
                            "*.mp4", "*.mkv", "*.avi", "*.mov", "*.wmv",
                            "*.flv", "*.webm", "*.m4v", "*.ts", "*.m2ts",
                            "*.mp3", "*.flac", "*.aac", "*.ogg", "*.wav", "*.m4a",
                        },
                    },
                    FilePickerFileTypes.All,
                },
            });

        if (files.Count == 0) return;
        string path = files[0].Path.LocalPath;
        if (!File.Exists(path)) return;
        StartPlayback(path);
    }

    private void OnPlayMediaItemRequested(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        StartPlayback(path);
    }

    private void StartPlayback(string path)
    {
        if (DataContext is not MediaViewModel vm) return;

        // Stop any running playback before starting a new one.
        DisposeVlc();
        StopAudio();
        vm.IsMusicPlaying = false;

        try
        {
            string? vlcDir = IntroWindow.FindBundledLibVlcDirectoryPublic();
            if (!string.IsNullOrEmpty(vlcDir))
                Core.Initialize(vlcDir);
            else
                Core.Initialize();

            _libVlc      = new LibVLC(enableDebugLogs: false);
            _mediaPlayer = new MediaPlayer(_libVlc);
            _mediaPlayer.EndReached       += OnVlcEndReached;
            _mediaPlayer.EncounteredError += OnVlcError;
            _media = new Media(_libVlc, new Uri(path));

            vm.VlcMediaPath    = Path.GetFileName(path);
            vm.IsVideoPlaying  = true;
            vm.VideoProgressPercent = 0;
            vm.IsVlcPlayerOpen = true;
            _videoTimer.Start();

            // Attach to the VideoView AFTER the overlay is shown (next layout pass).
            Dispatcher.UIThread.Post(() =>
            {
                if (VlcOverlayVideoView != null)
                    VlcOverlayVideoView.MediaPlayer = _mediaPlayer;
                _mediaPlayer?.Play(_media);
                long resume = vm.TakeResumeMs();
                if (resume > 0) ResumeWhenReady(resume);
            }, DispatcherPriority.Background);
        }
        catch (Exception ex)
        {
            DevLogService.Log($"[MediaView] VLC init failed: {ex.GetType().Name}: {ex.Message}");
            DisposeVlc();
        }
    }

    // VLC only accepts a seek once playback has actually started, so retry for a couple of seconds.
    private void ResumeWhenReady(long resumeMs)
    {
        int tries = 0;
        var t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        t.Tick += (_, _) =>
        {
            var p = _mediaPlayer;
            if (p == null || ++tries > 12) { t.Stop(); return; }
            if (p.IsPlaying && p.Length > resumeMs) { p.Time = resumeMs; t.Stop(); }
        };
        t.Start();
    }

    private void OnVlcEndReached(object? sender, EventArgs e)
    {
        // The player cannot be disposed from inside its own callback, so hop threads first.
        System.Threading.Tasks.Task.Run(() => Dispatcher.UIThread.Post(() =>
        {
            (DataContext as MediaViewModel)?.MarkVideoCompleted();
            if (DataContext is MediaViewModel vm && vm.NextEpisodePath() is { } next && File.Exists(next))
                StartPlayback(next);
            else
                CloseVlcOverlay();
        }));
    }

    private void OnVlcError(object? sender, EventArgs e)
    {
        System.Threading.Tasks.Task.Run(() =>
            Dispatcher.UIThread.Post(CloseVlcOverlay));
    }

    private void CloseVlcOverlay()
    {
        DisposeVlc();
        if (DataContext is MediaViewModel vm)
            vm.CloseVlcPlayerCommand.Execute(null);
    }

    private void DisposeVlc()
    {
        _videoTimer.Stop();
        if (_mediaPlayer != null)
        {
            _mediaPlayer.EndReached       -= OnVlcEndReached;
            _mediaPlayer.EncounteredError -= OnVlcError;
            try { _mediaPlayer.Stop(); } catch (Exception ex) { DevLogService.Log($"[MediaView] VLC stop: {ex.Message}"); }
            _mediaPlayer.Dispose();
            _mediaPlayer = null;
        }
        _media?.Dispose();
        _media = null;
        _libVlc?.Dispose();
        _libVlc = null;
    }
}
