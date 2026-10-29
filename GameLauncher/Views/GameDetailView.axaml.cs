using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.VisualTree;
using Avalonia.Controls.Primitives;
using System.Linq;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using GameLauncher.Services;
using GameLauncher.ViewModels;
using LibVLCSharp.Shared;
using System;
using System.IO;

namespace GameLauncher.Views;

public partial class GameDetailView : UserControl
{
    // ── VLC local file player state ───────────────────────────────────────────
    private LibVLC?      _libVlc;
    private MediaPlayer? _mediaPlayer;
    private Media?       _media;

    public GameDetailView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Unloaded           += OnUnloaded;
    }

    /// <summary>Scrolls the detail page back to the top so playtime and header info are visible.</summary>
    public void ScrollToTop() => this.FindControl<ScrollViewer>("DetailScroller")?.ScrollToHome();

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        ScrollToTop();
        if (DataContext is GameDetailViewModel vm)
        {
            vm.BrowseLaunchPathRequested  = OnBrowseLaunchPathRequested;
            vm.PlayLocalVideoRequested    = OnPlayLocalVideoRequested;
            vm.OpenControllerEditorRequested = OnOpenControllerEditorRequested;
        }
    }

    // ── Gamepad / keyboard navigation ────────────────────────────────────────

    /// <summary>
    /// Highlights the primary action (Play, or Install when the game is not installed),
    /// falling back to the first visible button.
    /// </summary>
    public void FocusDefault()
    {
        var buttons = this.GetVisualDescendants()
            .OfType<Button>()
            .Where(b => b.IsEffectivelyVisible && b.IsEffectivelyEnabled && b.Focusable && InActiveScope(b))
            .ToList();
        var target = buttons.FirstOrDefault(b => b.Classes.Contains("btn-primary") || b.Classes.Contains("btn-success"))
                     ?? buttons.FirstOrDefault();
        target?.Focus(NavigationMethod.Directional);
    }

    /// <summary>While the modal action menu is open, only controls inside it are navigable.</summary>
    private bool InActiveScope(Control c)
    {
        if (DataContext is GameDetailViewModel { ShowSettings: true } &&
            this.FindControl<Control>("SettingsHost") is { } settingsHost)
            return settingsHost.IsVisualAncestorOf(c);
        if (DataContext is GameDetailViewModel { IsActionMenuOpen: true } or GameDetailViewModel { IsModBrowserOpen: true } &&
            this.FindControl<Control>("ActionMenuHost") is { } host)
            return host.IsVisualAncestorOf(c);
        return true;
    }

    /// <summary>Closes the topmost panel/overlay, or the whole detail page when none is open.</summary>
    public void HandleBack()
    {
        if (DataContext is not GameDetailViewModel vm) return;
        if (vm.ShowSettings)             vm.CloseSettingsCommand.Execute(null);
        else if (vm.IsModBrowserOpen)    vm.CloseModBrowserCommand.Execute(null);
        else if (vm.IsActionMenuOpen)    vm.CloseActionMenuCommand.Execute(null);
        else if (vm.IsVlcPlayerOpen)     CloseVlcOverlay();
        else if (vm.IsTrailerPlayerOpen) vm.CloseTrailerPlayerCommand.Execute(null);
        else if (vm.ShowModsPanel)       vm.CloseModsPanelCommand.Execute(null);
        else                             vm.CloseCommand.Execute(null);
    }

    /// <summary>
    /// Directional focus movement and (for controllers) activation inside the detail page.
    /// Returns true when the key was consumed.
    /// </summary>
    public bool HandleNavKey(Key key, bool activateWithEnter)
    {
        var top = TopLevel.GetTopLevel(this);
        var focusManager = top?.FocusManager;
        if (focusManager == null) return false;

        var focused = focusManager.GetFocusedElement() as Control;
        if (focused is ComboBoxItem || focused is ComboBox { IsDropDownOpen: true }) return false;
        bool inside = focused != null && this.IsVisualAncestorOf(focused);

        NavigationDirection? direction = key switch
        {
            Key.Up    => NavigationDirection.Up,
            Key.Down  => NavigationDirection.Down,
            Key.Left  => NavigationDirection.Left,
            Key.Right => NavigationDirection.Right,
            _         => null,
        };

        if (direction != null)
        {
            if (!inside) { FocusDefault(); return true; }
            FindNextInDirection(focused!, direction.Value)?.Focus(NavigationMethod.Directional);
            return true;
        }

        if (key == Key.Enter && activateWithEnter && inside && focused != null)
        {
            focused.RaiseEvent(new KeyEventArgs
            {
                RoutedEvent = InputElement.KeyDownEvent,
                Key         = Key.Enter,
                Source      = focused,
            });
            return true;
        }
        return false;
    }

    private static bool IsNavTarget(Control c) =>
        c is Button or ToggleButton or ComboBox or TextBox or Slider or ListBoxItem;

    /// <summary>Picks the nearest focusable control in the given direction using on-screen geometry.</summary>
    private Control? FindNextInDirection(Control from, NavigationDirection direction)
    {
        var fromBounds = BoundsInView(from);
        if (fromBounds == null) return null;
        var origin = fromBounds.Value.Center;

        Control? best = null;
        double bestScore = double.MaxValue;
        foreach (var c in this.GetVisualDescendants().OfType<Control>())
        {
            if (c == from || !IsNavTarget(c) || !c.Focusable || !c.IsEffectivelyVisible || !c.IsEffectivelyEnabled || !InActiveScope(c))
                continue;
            if (c.GetVisualAncestors().Any(a => a is ComboBox)) continue;
            var b = BoundsInView(c);
            if (b == null || b.Value.Width <= 0 || b.Value.Height <= 0) continue;

            var center = b.Value.Center;
            double dx = center.X - origin.X, dy = center.Y - origin.Y;
            double primary, cross;
            switch (direction)
            {
                case NavigationDirection.Up:    primary = -dy; cross = Math.Abs(dx); break;
                case NavigationDirection.Down:  primary = dy;  cross = Math.Abs(dx); break;
                case NavigationDirection.Left:  primary = -dx; cross = Math.Abs(dy); break;
                default:                        primary = dx;  cross = Math.Abs(dy); break;
            }
            if (primary <= 1) continue;

            double score = primary + cross * 3;
            if (score < bestScore) { bestScore = score; best = c; }
        }
        return best;
    }

    private Rect? BoundsInView(Visual v)
    {
        var m = v.TransformToVisual(this);
        return m == null ? null : new Rect(v.Bounds.Size).TransformToAABB(m.Value);
    }

    private void OnUnloaded(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        DisposeVlc();
    }

    // ── Executable browse ────────────────────────────────────────────────────

    private async void OnBrowseLaunchPathRequested(Action<string> onPicked)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null) return;

        var files = await topLevel.StorageProvider.OpenFilePickerAsync(
            new FilePickerOpenOptions
            {
                Title         = "Select executable or script",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Executable / Script")
                    {
                        Patterns = new[] { "*.exe", "*.bat", "*.cmd", "*.sh", "*.ps1", "*.AppImage" },
                    },
                    FilePickerFileTypes.All,
                },
            });

        if (files.Count > 0)
            onPicked(files[0].Path.LocalPath);
    }

    // ── VLC local file player ────────────────────────────────────────────────

    /// <summary>
    /// Called by the ViewModel's <see cref="GameDetailViewModel.PlayLocalVideoCommand"/>.
    /// Shows a file picker, then plays the selected video file inside the VLC overlay.
    /// </summary>
    private async void OnPlayLocalVideoRequested()
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null) return;

        var files = await topLevel.StorageProvider.OpenFilePickerAsync(
            new FilePickerOpenOptions
            {
                Title         = "Select a video file to play",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Video files")
                    {
                        Patterns = new[]
                        {
                            "*.mp4", "*.mkv", "*.avi", "*.mov", "*.wmv",
                            "*.flv", "*.webm", "*.m4v", "*.ts", "*.m2ts",
                        },
                    },
                    FilePickerFileTypes.All,
                },
            });

        if (files.Count == 0) return;
        string path = files[0].Path.LocalPath;
        if (!File.Exists(path)) return;

        if (DataContext is not GameDetailViewModel vm) return;

        // Stop any running playback before starting a new one.
        DisposeVlc();

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
            vm.IsVlcPlayerOpen = true;

            // Attach to the VideoView AFTER the overlay is shown (next layout pass).
            Dispatcher.UIThread.Post(() =>
            {
                if (VlcOverlayVideoView != null)
                    VlcOverlayVideoView.MediaPlayer = _mediaPlayer;
                _mediaPlayer?.Play(_media);
            }, DispatcherPriority.Background);
        }
        catch (Exception ex)
        {
            DevLogService.Log($"[GameDetailView] VLC init failed: {ex.GetType().Name}: {ex.Message}");
            DisposeVlc();
        }
    }

    private void OnVlcEndReached(object? sender, EventArgs e)
    {
        System.Threading.Tasks.Task.Run(() =>
            Dispatcher.UIThread.Post(CloseVlcOverlay));
    }

    private void OnVlcError(object? sender, EventArgs e)
    {
        System.Threading.Tasks.Task.Run(() =>
            Dispatcher.UIThread.Post(CloseVlcOverlay));
    }

    private void CloseVlcOverlay()
    {
        DisposeVlc();
        if (DataContext is GameDetailViewModel vm)
            vm.CloseVlcPlayerCommand.Execute(null);
    }

    private void DisposeVlc()
    {
        if (_mediaPlayer != null)
        {
            _mediaPlayer.EndReached       -= OnVlcEndReached;
            _mediaPlayer.EncounteredError -= OnVlcError;
            try { _mediaPlayer.Stop(); } catch (Exception ex) { DevLogService.Log($"[GameDetailView] VLC stop: {ex.Message}"); }
            _mediaPlayer.Dispose();
            _mediaPlayer = null;
        }
        _media?.Dispose();
        _media = null;
        _libVlc?.Dispose();
        _libVlc = null;
    }

    // ── Controller editor window ────────────────────────────────────────────

    /// <summary>
    /// Opens the <see cref="ControllerConfigWindow"/> dedicated editor so the user
    /// can map or remap buttons for a specific controller profile.
    /// Called by <see cref="GameDetailViewModel.OpenControllerEditorRequested"/>.
    /// </summary>
    private void OnOpenControllerEditorRequested(
        string platform, string gameTitle, string author, string profileName)
    {
        var owner = TopLevel.GetTopLevel(this) as Avalonia.Controls.Window;
        if (owner == null) return;

        ControllerConfigWindow.OpenForProfile(
            platform, gameTitle, author, profileName, owner,
            onProfileActivated: profile =>
            {
                // Relay the saved profile back into the game detail VM so it becomes active.
                if (DataContext is GameDetailViewModel vm)
                {
                    Services.ControllerProfileService.AddOrUpdateProfile(platform, gameTitle, profile);
                    vm.SetActiveControllerProfile(profile);
                    // Reload the profiles list so the updated profile is shown.
                    Avalonia.Threading.Dispatcher.UIThread.Post(vm.RefreshControllerProfiles);
                }
            });
    }
}
