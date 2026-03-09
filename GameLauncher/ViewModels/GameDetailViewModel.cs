using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

/// <summary>
/// View-model for the game detail overlay, supporting cloud library games,
/// store games, and locally detected games (with multi-drive switching).
/// </summary>
public partial class GameDetailViewModel : ViewModelBase
{
    // ── Display properties ────────────────────────────────────────────────────
    [ObservableProperty] private string  _title        = "";
    [ObservableProperty] private string  _platform     = "";
    [ObservableProperty] private string  _genre        = "";
    [ObservableProperty] private string  _description  = "";
    [ObservableProperty] private string  _ratingStars  = "";
    [ObservableProperty] private string? _price;
    [ObservableProperty] private string? _releaseYear;
    [ObservableProperty] private string? _coverUrl;
    [ObservableProperty] private string? _coverGradient;

    // ── Trailer ───────────────────────────────────────────────────────────────
    /// <summary>YouTube trailer URL from the real Games.Database (e.g. https://youtu.be/…).</summary>
    [ObservableProperty] private string? _trailerUrl;
    [ObservableProperty] private bool    _hasTrailer;
    [ObservableProperty] private string  _trailerLabel = "▶  Watch Trailer";

    // ── Screenshots ───────────────────────────────────────────────────────────
    public ObservableCollection<string> Screenshots { get; } = new();
    [ObservableProperty] private bool _hasScreenshots;

    // ── Achievements ──────────────────────────────────────────────────────────
    public ObservableCollection<Achievement> Achievements { get; } = new();
    [ObservableProperty] private bool   _hasAchievements;
    [ObservableProperty] private string _achievementsLabel = "";

    // ── Local game / drive info ───────────────────────────────────────────────
    [ObservableProperty] private bool   _isLocalGame;
    [ObservableProperty] private bool   _hasMultipleDrives;
    [ObservableProperty] private int    _selectedDriveIndex;
    [ObservableProperty] private string _activeDriveLabel = "";
    [ObservableProperty] private string _activeDrivePath  = "";
    [ObservableProperty] private string _activeExeType    = "";

    // ── Install / launch state ────────────────────────────────────────────────
    /// <summary>True when the game is found installed on a local drive.</summary>
    [ObservableProperty] private bool _isInstalled;
    /// <summary>True when a repack archive is available to install (but game is not yet installed).</summary>
    [ObservableProperty] private bool _isRepack;
    /// <summary>File path of the repack archive, used by the Install command.</summary>
    [ObservableProperty] private string _repackPath = "";
    /// <summary>Display label for the repack archive size.</summary>
    [ObservableProperty] private string _repackSizeLabel = "";

    public ObservableCollection<string> DriveLabels { get; } = new();

    private List<LocalGameDriveEntry> _driveInstances = new();

    // ── Navigation back-action ────────────────────────────────────────────────
    public System.Action? OnClose { get; set; }

    [RelayCommand]
    private void Close() => OnClose?.Invoke();

    /// <summary>Opens the trailer URL in the system's default browser.</summary>
    [RelayCommand]
    private void OpenTrailer()
    {
        if (string.IsNullOrEmpty(TrailerUrl)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = TrailerUrl,
                UseShellExecute = true
            });
        }
        catch { /* best-effort */ }
    }

    /// <summary>Launches the installed game executable.</summary>
    [RelayCommand]
    private void LaunchGame()
    {
        if (!IsInstalled || string.IsNullOrEmpty(ActiveDrivePath)) return;
        try
        {
            // Find the executable within the active drive path
            if (_driveInstances.Count > 0)
            {
                int idx   = System.Math.Clamp(SelectedDriveIndex, 0, _driveInstances.Count - 1);
                var entry = _driveInstances[idx];
                if (!string.IsNullOrEmpty(entry.ExecutablePath))
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName        = entry.ExecutablePath,
                        UseShellExecute = true
                    });
                    return;
                }
            }
            // Fallback: open the folder
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = ActiveDrivePath,
                UseShellExecute = true
            });
        }
        catch { /* best-effort */ }
    }

    /// <summary>Opens the repack archive with the system extractor (or explorer).</summary>
    [RelayCommand]
    private void InstallRepack()
    {
        if (!IsRepack || string.IsNullOrEmpty(RepackPath)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = RepackPath,
                UseShellExecute = true
            });
        }
        catch { /* best-effort */ }
    }

    /// <summary>Opens the game folder in the system file manager.</summary>
    [RelayCommand]
    private void ShowMoreOptions()
    {
        if (string.IsNullOrEmpty(ActiveDrivePath)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = ActiveDrivePath,
                UseShellExecute = true
            });
        }
        catch { /* best-effort */ }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Populate from a cloud library Game
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Load a cloud library game into the detail view.
    /// </summary>
    /// <param name="game">The cloud library entry.</param>
    /// <param name="localGame">If not null, the game is installed on this drive — shows Play + ··· buttons.</param>
    /// <param name="repack">If not null (and localGame is null), a repack is available — shows Install button.</param>
    public void LoadFromGame(Game game, LocalGame? localGame = null, LocalRepack? repack = null)
    {
        Title         = game.Title;
        Platform      = game.Platform;
        Genre         = game.Genre    ?? "";
        Description   = game.Description ?? "";
        RatingStars   = game.RatingStars;
        Price         = game.Price;
        CoverUrl      = game.CoverUrl;
        CoverGradient = game.CoverGradient;

        PopulateTrailer(game.TrailerUrl);
        PopulateScreenshots(game.Screenshots);
        PopulateAchievements(game.GameAchievements);
        IsLocalGame = false;
        HasMultipleDrives = false;
        DriveLabels.Clear();

        ApplyInstallState(localGame, repack);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Populate from a store StoreGame
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Load a store game into the detail view.
    /// </summary>
    /// <param name="game">The store entry.</param>
    /// <param name="localGame">If not null, the game is installed — shows Play + ··· buttons.</param>
    /// <param name="repack">If not null (and localGame is null), a repack is available — shows Install button.</param>
    public void LoadFromStoreGame(StoreGame game, LocalGame? localGame = null, LocalRepack? repack = null)
    {
        Title         = game.Title;
        Platform      = game.Platform;
        Genre         = game.Genre;
        Description   = game.Description;
        RatingStars   = game.RatingStars;
        Price         = game.Price;
        ReleaseYear   = game.ReleaseYear;
        CoverUrl      = game.CoverUrl;
        CoverGradient = game.CoverGradient;

        PopulateTrailer(game.TrailerUrl);
        PopulateScreenshots(game.Screenshots);
        PopulateAchievements(null);
        IsLocalGame       = false;
        HasMultipleDrives = false;
        DriveLabels.Clear();

        ApplyInstallState(localGame, repack);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Populate from a locally detected LocalGame
    // ─────────────────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────────────────
    // Populate from a locally detected LocalGame
    // ─────────────────────────────────────────────────────────────────────────

    public void LoadFromLocalGame(LocalGame game)
    {
        Title         = game.Title;
        Platform      = "PC";
        Genre         = "";
        CoverGradient = "#0d2137,#163d5e";
        RatingStars   = "—";
        Price         = null;
        CoverUrl      = null;

        PopulateTrailer(null);
        Screenshots.Clear();
        HasScreenshots = false;
        PopulateAchievements(null);
        IsLocalGame    = true;
        IsInstalled    = true;
        IsRepack       = false;
        RepackPath     = "";
        RepackSizeLabel = "";

        _driveInstances = game.DriveInstances.Count > 0
            ? game.DriveInstances
            : new List<LocalGameDriveEntry>
            {
                new LocalGameDriveEntry
                {
                    DriveRoot      = game.DriveRoot,
                    FolderPath     = game.FolderPath,
                    ExecutablePath = game.ExecutablePath,
                    ExecutableType = game.ExecutableType,
                }
            };

        DriveLabels.Clear();
        foreach (var d in _driveInstances)
            DriveLabels.Add(d.DriveRoot);

        HasMultipleDrives  = _driveInstances.Count > 1;
        SelectedDriveIndex = 0;
        RefreshActiveDrive();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Applies installation / repack state shared by <see cref="LoadFromGame"/>
    /// and <see cref="LoadFromStoreGame"/>.
    /// </summary>
    private void ApplyInstallState(LocalGame? localGame, LocalRepack? repack)
    {
        if (localGame != null)
        {
            // Game is installed on a local drive — show Play + ··· buttons
            IsInstalled     = true;
            IsRepack        = false;
            RepackPath      = "";
            RepackSizeLabel = "";

            _driveInstances = localGame.DriveInstances.Count > 0
                ? localGame.DriveInstances
                : new List<LocalGameDriveEntry>
                {
                    new LocalGameDriveEntry
                    {
                        DriveRoot      = localGame.DriveRoot,
                        FolderPath     = localGame.FolderPath,
                        ExecutablePath = localGame.ExecutablePath,
                        ExecutableType = localGame.ExecutableType,
                    }
                };

            DriveLabels.Clear();
            foreach (var d in _driveInstances)
                DriveLabels.Add(d.DriveRoot);

            HasMultipleDrives  = _driveInstances.Count > 1;
            SelectedDriveIndex = 0;
            RefreshActiveDrive();
        }
        else if (repack != null)
        {
            // Repack archive available — show Install button
            IsInstalled      = false;
            IsRepack         = true;
            RepackPath       = repack.FilePath;
            RepackSizeLabel  = repack.SizeLabel;
            _driveInstances  = new List<LocalGameDriveEntry>();
            ActiveDriveLabel = "";
            ActiveDrivePath  = "";
            ActiveExeType    = "";
        }
        else
        {
            // Neither installed nor a repack — no action buttons
            IsInstalled      = false;
            IsRepack         = false;
            RepackPath       = "";
            RepackSizeLabel  = "";
            _driveInstances  = new List<LocalGameDriveEntry>();
            ActiveDriveLabel = "";
            ActiveDrivePath  = "";
            ActiveExeType    = "";
        }
    }

    // ─────────────────────────────────────────────────────────────────────────

    partial void OnSelectedDriveIndexChanged(int value) => RefreshActiveDrive();

    private void RefreshActiveDrive()
    {
        if (_driveInstances.Count == 0) return;
        int idx = System.Math.Clamp(SelectedDriveIndex, 0, _driveInstances.Count - 1);
        var entry = _driveInstances[idx];
        ActiveDriveLabel = entry.DriveRoot;
        ActiveDrivePath  = entry.FolderPath;
        ActiveExeType    = entry.ExecutableType.ToUpperInvariant();
        Description      = $"Installed at: {entry.FolderPath}";
    }

    [RelayCommand]
    private void SelectDrive(string drive)
    {
        int idx = DriveLabels.IndexOf(drive);
        if (idx >= 0) SelectedDriveIndex = idx;
    }

    private void PopulateTrailer(string? url)
    {
        TrailerUrl   = url;
        HasTrailer   = !string.IsNullOrEmpty(url);
        TrailerLabel = HasTrailer ? "▶  Watch Trailer on YouTube" : "▶  Watch Trailer";
    }

    private void PopulateScreenshots(List<string>? shots)
    {
        Screenshots.Clear();
        if (shots != null)
            foreach (var s in shots) Screenshots.Add(s);
        HasScreenshots = Screenshots.Count > 0;
    }

    private void PopulateAchievements(List<Achievement>? achievements)
    {
        Achievements.Clear();
        if (achievements != null)
            foreach (var a in achievements) Achievements.Add(a);
        HasAchievements   = Achievements.Count > 0;
        AchievementsLabel = HasAchievements
            ? $"🏆  Achievements  ({Achievements.Count})"
            : "🏆  Achievements";
    }
}
