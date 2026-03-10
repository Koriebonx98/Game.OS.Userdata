using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

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

    /// <summary>
    /// Database description stored when <see cref="EnrichFromDatabaseGame"/> is called.
    /// Prevents <see cref="RefreshActiveDrive"/> from overwriting a real description
    /// with the "Installed at: …" placeholder.
    /// </summary>
    private string? _databaseDescription;

    // ── Install / launch state ────────────────────────────────────────────────
    /// <summary>True when the game is found installed on a local drive.</summary>
    [ObservableProperty] private bool _isInstalled;
    /// <summary>True when a repack archive is available to install (but game is not yet installed).</summary>
    [ObservableProperty] private bool _isRepack;
    /// <summary>File path of the repack archive/folder/setup, used by the Install command.</summary>
    [ObservableProperty] private string _repackPath = "";
    /// <summary>Display label for the repack archive size.</summary>
    [ObservableProperty] private string _repackSizeLabel = "";
    /// <summary>True when the repack is a folder with a setup installer (Setup.exe).</summary>
    [ObservableProperty] private bool _isSetupRepack;
    /// <summary>True when the repack is an archive and we should show a drive-selection picker.</summary>
    [ObservableProperty] private bool _showDrivePicker;

    /// <summary>Available drives for archive-repack installation.</summary>
    public ObservableCollection<InstallDriveOption> InstallDrives { get; } = new();

    public ObservableCollection<string> DriveLabels { get; } = new();

    private List<LocalGameDriveEntry> _driveInstances = new();

    // ── Navigation back-action ────────────────────────────────────────────────
    public System.Action? OnClose { get; set; }

    [RelayCommand]
    private void Close() => OnClose?.Invoke();

    // ── Settings panel ────────────────────────────────────────────────────────
    /// <summary>True when the settings overlay is visible.</summary>
    [ObservableProperty] private bool _showSettings;

    /// <summary>Custom .exe or .bat path saved for this game (overrides auto-detected).</summary>
    [ObservableProperty] private string _settingsExePath = "";

    /// <summary>Command-line arguments for the selected executable.</summary>
    [ObservableProperty] private string _settingsExeArgs = "";

    /// <summary>Path typed by the user when adding a new pre-launch entry.</summary>
    [ObservableProperty] private string _newPreLaunchPath  = "";
    [ObservableProperty] private string _newPreLaunchArgs  = "";
    [ObservableProperty] private string _newPreLaunchLabel = "";

    /// <summary>Path typed by the user when adding a new post-launch entry.</summary>
    [ObservableProperty] private string _newPostLaunchPath  = "";
    [ObservableProperty] private string _newPostLaunchArgs  = "";
    [ObservableProperty] private string _newPostLaunchLabel = "";

    /// <summary>Status message shown at the bottom of the settings panel.</summary>
    [ObservableProperty] private string _settingsStatus = "";

    public ObservableCollection<LaunchEntry> PreLaunchEntries  { get; } = new();
    public ObservableCollection<LaunchEntry> PostLaunchEntries { get; } = new();

    /// <summary>Opens the settings panel and loads any saved settings for the current game.</summary>
    private void OpenSettings()
    {
        var saved = GameSettingsService.Load(Title);

        // Apply saved exe path (prefer saved > auto-detected)
        SettingsExePath = saved.ExePath ?? "";
        SettingsExeArgs = saved.ExeArgs ?? "";

        // If no saved exe path but we have a detected one, pre-fill it
        if (string.IsNullOrEmpty(SettingsExePath) && _driveInstances.Count > 0)
        {
            int idx = System.Math.Clamp(SelectedDriveIndex, 0, _driveInstances.Count - 1);
            SettingsExePath = _driveInstances[idx].ExecutablePath ?? "";
        }

        PreLaunchEntries.Clear();
        foreach (var e in saved.PreLaunch)
            PreLaunchEntries.Add(e);

        PostLaunchEntries.Clear();
        foreach (var e in saved.PostLaunch)
            PostLaunchEntries.Add(e);

        NewPreLaunchPath  = "";
        NewPreLaunchArgs  = "";
        NewPreLaunchLabel = "";
        NewPostLaunchPath  = "";
        NewPostLaunchArgs  = "";
        NewPostLaunchLabel = "";
        SettingsStatus    = "";
        ShowSettings      = true;
    }

    [RelayCommand]
    private void SaveSettings()
    {
        var settings = new GameSettings
        {
            GameTitle  = Title,
            ExePath    = string.IsNullOrWhiteSpace(SettingsExePath) ? null : SettingsExePath.Trim(),
            ExeArgs    = string.IsNullOrWhiteSpace(SettingsExeArgs)  ? null : SettingsExeArgs.Trim(),
            PreLaunch  = PreLaunchEntries.ToList(),
            PostLaunch = PostLaunchEntries.ToList(),
        };
        GameSettingsService.Save(settings);
        SettingsStatus = "✓  Settings saved.";
    }

    [RelayCommand]
    private void CloseSettings()
    {
        ShowSettings   = false;
        SettingsStatus = "";
    }

    [RelayCommand]
    private void AddPreLaunch()
    {
        if (string.IsNullOrWhiteSpace(NewPreLaunchPath)) return;
        PreLaunchEntries.Add(new LaunchEntry
        {
            Label     = string.IsNullOrWhiteSpace(NewPreLaunchLabel)
                            ? System.IO.Path.GetFileName(NewPreLaunchPath.Trim())
                            : NewPreLaunchLabel.Trim(),
            Path      = NewPreLaunchPath.Trim(),
            Arguments = string.IsNullOrWhiteSpace(NewPreLaunchArgs) ? null : NewPreLaunchArgs.Trim(),
        });
        NewPreLaunchPath  = "";
        NewPreLaunchArgs  = "";
        NewPreLaunchLabel = "";
    }

    [RelayCommand]
    private void RemovePreLaunch(LaunchEntry? entry)
    {
        if (entry != null) PreLaunchEntries.Remove(entry);
    }

    [RelayCommand]
    private void AddPostLaunch()
    {
        if (string.IsNullOrWhiteSpace(NewPostLaunchPath)) return;
        PostLaunchEntries.Add(new LaunchEntry
        {
            Label     = string.IsNullOrWhiteSpace(NewPostLaunchLabel)
                            ? System.IO.Path.GetFileName(NewPostLaunchPath.Trim())
                            : NewPostLaunchLabel.Trim(),
            Path      = NewPostLaunchPath.Trim(),
            Arguments = string.IsNullOrWhiteSpace(NewPostLaunchArgs) ? null : NewPostLaunchArgs.Trim(),
        });
        NewPostLaunchPath  = "";
        NewPostLaunchArgs  = "";
        NewPostLaunchLabel = "";
    }

    [RelayCommand]
    private void RemovePostLaunch(LaunchEntry? entry)
    {
        if (entry != null) PostLaunchEntries.Remove(entry);
    }

    /// <summary>Opens the game folder in the system file manager.</summary>
    [RelayCommand]
    private void OpenGameFolder()
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

    /// <summary>Deletes the game folder from disk after confirmation via SettingsStatus.</summary>
    [ObservableProperty] private bool _confirmDelete;

    [RelayCommand]
    private void RequestDeleteGame()
    {
        ConfirmDelete  = true;
        SettingsStatus = "⚠  Click 'Confirm Delete' to permanently remove the game folder.";
    }

    [RelayCommand]
    private void ConfirmDeleteGame()
    {
        if (string.IsNullOrEmpty(ActiveDrivePath)) return;

        // Safety guard: only allow deletion of directories whose name contains "Games"
        // or whose parent directory contains "Games" — prevents accidental deletion of
        // root drives, user home folders, or other system directories.
        var normalized = System.IO.Path.GetFullPath(ActiveDrivePath);
        bool looksLikeGameDir =
            normalized.Contains(System.IO.Path.DirectorySeparatorChar + "Games" + System.IO.Path.DirectorySeparatorChar,
                                 StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains(System.IO.Path.DirectorySeparatorChar + "Roms" + System.IO.Path.DirectorySeparatorChar,
                                 StringComparison.OrdinalIgnoreCase);

        if (!looksLikeGameDir)
        {
            SettingsStatus = "⛔  Safety check failed: path does not appear to be inside a Games folder.";
            ConfirmDelete  = false;
            return;
        }

        try
        {
            if (Directory.Exists(normalized))
            {
                Directory.Delete(normalized, recursive: true);
                SettingsStatus  = "✓  Game folder deleted.";
                IsInstalled     = false;
                ActiveDrivePath = "";
            }
        }
        catch (Exception ex)
        {
            SettingsStatus = $"Delete failed: {ex.Message}";
        }
        finally
        {
            ConfirmDelete = false;
        }
    }

    [RelayCommand]
    private void CancelDelete()
    {
        ConfirmDelete  = false;
        SettingsStatus = "";
    }

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
        if (!IsInstalled) return;

        // Load saved settings to get the preferred exe path / arguments
        var saved = GameSettingsService.Load(Title);

        // Run pre-launch entries first (fire-and-forget, best-effort)
        foreach (var pre in saved.PreLaunch)
            TryStartProcess(pre.Path, pre.Arguments);

        // Determine the executable to launch:
        // Priority: saved settings ExePath → detected drive entry → open folder
        string? exePath = null;
        string? exeArgs = string.IsNullOrWhiteSpace(saved.ExeArgs) ? null : saved.ExeArgs;

        if (!string.IsNullOrEmpty(saved.ExePath) && System.IO.File.Exists(saved.ExePath))
        {
            exePath = saved.ExePath;
        }
        else if (_driveInstances.Count > 0)
        {
            int idx   = System.Math.Clamp(SelectedDriveIndex, 0, _driveInstances.Count - 1);
            var entry = _driveInstances[idx];
            if (!string.IsNullOrEmpty(entry.ExecutablePath))
                exePath = entry.ExecutablePath;
        }

        if (!string.IsNullOrEmpty(exePath))
        {
            System.Diagnostics.Process? gameProc = null;
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = exePath,
                    UseShellExecute = true,
                };
                if (!string.IsNullOrEmpty(exeArgs))
                    psi.Arguments = exeArgs;
                gameProc = System.Diagnostics.Process.Start(psi);
            }
            catch { /* best-effort */ }

            // Register post-launch watcher (fire-and-forget)
            if (saved.PostLaunch.Count > 0)
                _ = WatchAndRunPostLaunchAsync(gameProc, saved.PostLaunch);
        }
        else if (!string.IsNullOrEmpty(ActiveDrivePath))
        {
            // Fallback: open the game folder
            OpenWithSystem(ActiveDrivePath);
        }
    }

    private static void TryStartProcess(string path, string? args)
    {
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName        = path,
                UseShellExecute = true,
            };
            if (!string.IsNullOrEmpty(args))
                psi.Arguments = args;
            System.Diagnostics.Process.Start(psi);
        }
        catch { /* best-effort */ }
    }

    private static async System.Threading.Tasks.Task WatchAndRunPostLaunchAsync(
        System.Diagnostics.Process? gameProc, List<LaunchEntry> postEntries)
    {
        if (gameProc != null)
        {
            try
            {
                // Wait up to 24 hours for the game process to exit
                using var cts = new System.Threading.CancellationTokenSource(
                    System.TimeSpan.FromHours(24));
                await gameProc.WaitForExitAsync(cts.Token);
            }
            catch { /* process may have already exited or be inaccessible */ }
            finally
            {
                gameProc.Dispose();
            }
        }

        foreach (var post in postEntries)
            TryStartProcess(post.Path, post.Arguments);
    }

    /// <summary>
    /// Installs the repack.
    /// - If the repack is a folder containing Setup.exe: runs Setup.exe directly.
    /// - If the repack is an archive (.zip/.rar/.7z): populates the drive-selection
    ///   picker so the user can choose where to extract the game.
    /// - Otherwise: opens the archive with the system extractor.
    /// </summary>
    [RelayCommand]
    private void InstallRepack()
    {
        if (!IsRepack || string.IsNullOrEmpty(RepackPath)) return;

        // Folder repack with Setup.exe — run installer directly
        if (IsSetupRepack)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = RepackPath, // already the Setup.exe path
                    UseShellExecute = true
                });
            }
            catch { /* best-effort */ }
            return;
        }

        // Archive repack — show drive picker so user can choose install location
        string ext = Path.GetExtension(RepackPath).ToLowerInvariant();
        bool isArchive = ext is ".zip" or ".rar" or ".7z";
        if (isArchive)
        {
            PopulateInstallDrives();
            ShowDrivePicker = InstallDrives.Count > 0;
            if (!ShowDrivePicker)
            {
                // No Games folder found on any drive — fall back to opening the archive
                OpenWithSystem(RepackPath);
            }
            return;
        }

        // Fallback: open with system handler
        OpenWithSystem(RepackPath);
    }

    /// <summary>
    /// Called when the user selects a drive from the install-drive picker.
    /// Opens the archive with the system extractor — the user completes the
    /// extraction manually to the chosen Games folder.
    /// </summary>
    [RelayCommand]
    private void SelectInstallDrive(InstallDriveOption? option)
    {
        if (option == null) return;
        ShowDrivePicker = false;

        // Ensure the Games folder exists on the target drive
        try { Directory.CreateDirectory(option.GamesFolderPath); } catch { }

        // Open the archive file — the user extracts to the displayed Games folder
        OpenWithSystem(RepackPath);
    }

    /// <summary>Dismisses the drive-picker without installing.</summary>
    [RelayCommand]
    private void CancelInstall() => ShowDrivePicker = false;

    private static void OpenWithSystem(string path)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = path,
                UseShellExecute = true
            });
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Discovers all drives that already have a Games folder, plus drives that
    /// are ready (have free space) for one to be created, for the drive picker.
    /// </summary>
    private void PopulateInstallDrives()
    {
        InstallDrives.Clear();
        try
        {
            var drives = DriveInfo.GetDrives().Where(d => d.IsReady);

            foreach (var drive in drives)
            {
                try
                {
                    string gamesPath = Path.Combine(drive.RootDirectory.FullName, "Games");
                    bool   exists    = Directory.Exists(gamesPath);
                    long   free      = drive.AvailableFreeSpace;
                    string freeLabel = free >= 1_073_741_824
                        ? $"{free / 1_073_741_824.0:F1} GB free"
                        : $"{free / 1_048_576.0:F0} MB free";

                    InstallDrives.Add(new InstallDriveOption
                    {
                        DriveRoot      = drive.RootDirectory.FullName,
                        GamesFolderPath= gamesPath,
                        FreeSpaceLabel = freeLabel,
                        GamesExists    = exists,
                    });
                }
                catch { /* skip inaccessible drive */ }
            }
        }
        catch { }
    }

    /// <summary>Opens the game settings panel (exe select, arguments, pre/post launch, folder ops).</summary>
    [RelayCommand]
    private void ShowMoreOptions()
    {
        OpenSettings();
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
        Title             = game.Title;
        Platform          = "PC";
        Genre             = "";
        CoverGradient     = "#0d2137,#163d5e";
        RatingStars       = "—";
        Price             = null;
        CoverUrl          = null;
        _databaseDescription = null;

        PopulateTrailer(null);
        Screenshots.Clear();
        HasScreenshots = false;
        PopulateAchievements(null);
        IsLocalGame     = true;
        IsInstalled     = true;
        IsRepack        = false;
        IsSetupRepack   = false;
        ShowDrivePicker = false;
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
            IsSetupRepack    = repack.FileType == "setup";
            ShowDrivePicker  = false;
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
            IsSetupRepack    = false;
            ShowDrivePicker  = false;
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

    // ─────────────────────────────────────────────────────────────────────────
    // Enrich a local game detail with data looked up from Games.Database
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Called asynchronously after <see cref="LoadFromLocalGame"/> to fill in
    /// cover image, description, trailer, screenshots and achievements URL from
    /// the public Games.Database — the same data the website shows.
    /// Must be called on the UI thread.
    /// </summary>
    public void EnrichFromDatabaseGame(DatabaseGame dbGame)
    {
        // Use the canonical database title (e.g. "Call of Duty: Black Ops II"
        // instead of the Windows-safe folder name "Call of Duty - Black Ops II")
        if (!string.IsNullOrEmpty(dbGame.Title))
            Title = dbGame.Title;

        if (!string.IsNullOrEmpty(dbGame.CoverUrl))
            CoverUrl = dbGame.CoverUrl;

        if (!string.IsNullOrEmpty(dbGame.Description))
        {
            _databaseDescription = dbGame.Description;
            Description          = dbGame.Description;
        }

        PopulateTrailer(dbGame.TrailerUrl);
        PopulateScreenshots(dbGame.Screenshots);
    }

    // ─────────────────────────────────────────────────────────────────────────

    private void RefreshActiveDrive()
    {
        if (_driveInstances.Count == 0) return;
        int idx = System.Math.Clamp(SelectedDriveIndex, 0, _driveInstances.Count - 1);
        var entry = _driveInstances[idx];
        ActiveDriveLabel = entry.DriveRoot;
        ActiveDrivePath  = entry.FolderPath;
        ActiveExeType    = entry.ExecutableType.ToUpperInvariant();
        // Use the real database description if available; fall back to install path
        if (!string.IsNullOrEmpty(_databaseDescription))
            Description = _databaseDescription;
        else
            Description = $"Installed at: {entry.FolderPath}";
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
