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

    // ── Screenshots ───────────────────────────────────────────────────────────
    public ObservableCollection<string> Screenshots { get; } = new();
    [ObservableProperty] private bool _hasScreenshots;

    // ── Local game / drive info ───────────────────────────────────────────────
    [ObservableProperty] private bool   _isLocalGame;
    [ObservableProperty] private bool   _hasMultipleDrives;
    [ObservableProperty] private int    _selectedDriveIndex;
    [ObservableProperty] private string _activeDriveLabel = "";
    [ObservableProperty] private string _activeDrivePath  = "";
    [ObservableProperty] private string _activeExeType    = "";

    public ObservableCollection<string> DriveLabels { get; } = new();

    private List<LocalGameDriveEntry> _driveInstances = new();

    // ── Navigation back-action ────────────────────────────────────────────────
    public System.Action? OnClose { get; set; }

    [RelayCommand]
    private void Close() => OnClose?.Invoke();

    // ─────────────────────────────────────────────────────────────────────────
    // Populate from a cloud library Game
    // ─────────────────────────────────────────────────────────────────────────

    public void LoadFromGame(Game game)
    {
        Title       = game.Title;
        Platform    = game.Platform;
        Genre       = game.Genre    ?? "";
        Description = game.Description ?? "";
        RatingStars = game.RatingStars;
        Price       = game.Price;
        CoverUrl    = game.CoverUrl;

        PopulateScreenshots(game.Screenshots);
        IsLocalGame = false;
        HasMultipleDrives = false;
        DriveLabels.Clear();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Populate from a store StoreGame
    // ─────────────────────────────────────────────────────────────────────────

    public void LoadFromStoreGame(StoreGame game)
    {
        Title       = game.Title;
        Platform    = game.Platform;
        Genre       = game.Genre;
        Description = game.Description;
        RatingStars = game.RatingStars;
        Price       = game.Price;
        ReleaseYear = game.ReleaseYear;
        CoverUrl    = game.CoverUrl;

        PopulateScreenshots(game.Screenshots);
        IsLocalGame = false;
        HasMultipleDrives = false;
        DriveLabels.Clear();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Populate from a locally detected LocalGame
    // ─────────────────────────────────────────────────────────────────────────

    public void LoadFromLocalGame(LocalGame game)
    {
        Title       = game.Title;
        Platform    = "PC";
        Genre       = "";
        RatingStars = "—";
        Price       = null;
        CoverUrl    = null;

        Screenshots.Clear();
        HasScreenshots = false;
        IsLocalGame    = true;

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

    private void PopulateScreenshots(List<string>? shots)
    {
        Screenshots.Clear();
        if (shots != null)
            foreach (var s in shots) Screenshots.Add(s);
        HasScreenshots = Screenshots.Count > 0;
    }
}
