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

    // ── Regions / Language (for ROM games) ───────────────────────────────────
    [ObservableProperty] private string  _regionsLabel  = "";
    [ObservableProperty] private bool    _hasRegions;

    // ── Store page link ───────────────────────────────────────────────────────
    [ObservableProperty] private string? _storePageUrl;
    [ObservableProperty] private bool    _hasStoreUrl;
    [ObservableProperty] private string  _storeButtonLabel = "🛒  View in Store";

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
    /// <summary>Subset of Achievements currently visible (respects ShowAllAchievements flag).</summary>
    public ObservableCollection<Achievement> VisibleAchievements { get; } = new();
    [ObservableProperty] private bool   _hasAchievements;
    [ObservableProperty] private string _achievementsLabel = "";
    /// <summary>When false, only the first <see cref="AchievementsPreviewCount"/> achievements are shown.</summary>
    [ObservableProperty] private bool   _showAllAchievements = false;
    [ObservableProperty] private bool   _hasMoreAchievements = false;
    private const int AchievementsPreviewCount = 6;

    partial void OnShowAllAchievementsChanged(bool value) => RefreshVisibleAchievements();

    [RelayCommand]
    private void ToggleShowAllAchievements()
        => ShowAllAchievements = !ShowAllAchievements;

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

    /// <summary>ROM file path used when launching via an emulator (for non-PC platforms).</summary>
    [ObservableProperty] private string _settingsRomPath = "";

    /// <summary>True when this game is a ROM (non-PC) and shows the Rom Select field.</summary>
    [ObservableProperty] private bool _isRom;

    /// <summary>Path typed by the user when adding a new pre-launch entry.</summary>
    [ObservableProperty] private string _newPreLaunchPath  = "";
    [ObservableProperty] private string _newPreLaunchArgs  = "";
    [ObservableProperty] private string _newPreLaunchLabel = "";

    /// <summary>Path typed by the user when adding a new during-launch entry.</summary>
    [ObservableProperty] private string _newDuringLaunchPath  = "";
    [ObservableProperty] private string _newDuringLaunchArgs  = "";
    [ObservableProperty] private string _newDuringLaunchLabel = "";

    /// <summary>Path typed by the user when adding a new post-launch entry.</summary>
    [ObservableProperty] private string _newPostLaunchPath  = "";
    [ObservableProperty] private string _newPostLaunchArgs  = "";
    [ObservableProperty] private string _newPostLaunchLabel = "";

    /// <summary>Status message shown at the bottom of the settings panel.</summary>
    [ObservableProperty] private string _settingsStatus = "";

    public ObservableCollection<LaunchEntry> PreLaunchEntries    { get; } = new();
    public ObservableCollection<LaunchEntry> DuringLaunchEntries { get; } = new();
    public ObservableCollection<LaunchEntry> PostLaunchEntries   { get; } = new();

    /// <summary>Opens the settings panel and loads any saved settings for the current game.</summary>
    private void OpenSettings()
    {
        var saved = GameSettingsService.Load(Title);

        // Apply saved exe path (prefer saved > auto-detected)
        SettingsExePath = saved.ExePath ?? "";
        SettingsExeArgs = saved.ExeArgs ?? "";
        SettingsRomPath = saved.RomPath ?? "";

        // If no saved exe path but we have a detected one, pre-fill it
        if (string.IsNullOrEmpty(SettingsExePath) && _driveInstances.Count > 0)
        {
            int idx = System.Math.Clamp(SelectedDriveIndex, 0, _driveInstances.Count - 1);
            SettingsExePath = _driveInstances[idx].ExecutablePath ?? "";
        }

        PreLaunchEntries.Clear();
        foreach (var e in saved.PreLaunch)
            PreLaunchEntries.Add(e);

        DuringLaunchEntries.Clear();
        foreach (var e in saved.DuringLaunch)
            DuringLaunchEntries.Add(e);

        PostLaunchEntries.Clear();
        foreach (var e in saved.PostLaunch)
            PostLaunchEntries.Add(e);

        NewPreLaunchPath    = "";
        NewPreLaunchArgs    = "";
        NewPreLaunchLabel   = "";
        NewDuringLaunchPath  = "";
        NewDuringLaunchArgs  = "";
        NewDuringLaunchLabel = "";
        NewPostLaunchPath   = "";
        NewPostLaunchArgs   = "";
        NewPostLaunchLabel  = "";
        SettingsStatus      = "";
        ShowSettings        = true;
    }

    [RelayCommand]
    private void SaveSettings()
    {
        var settings = new GameSettings
        {
            GameTitle    = Title,
            ExePath      = string.IsNullOrWhiteSpace(SettingsExePath) ? null : SettingsExePath.Trim(),
            ExeArgs      = string.IsNullOrWhiteSpace(SettingsExeArgs)  ? null : SettingsExeArgs.Trim(),
            RomPath      = string.IsNullOrWhiteSpace(SettingsRomPath)  ? null : SettingsRomPath.Trim(),
            PreLaunch    = PreLaunchEntries.ToList(),
            DuringLaunch = DuringLaunchEntries.ToList(),
            PostLaunch   = PostLaunchEntries.ToList(),
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
    private void AddDuringLaunch()
    {
        if (string.IsNullOrWhiteSpace(NewDuringLaunchPath)) return;
        DuringLaunchEntries.Add(new LaunchEntry
        {
            Label     = string.IsNullOrWhiteSpace(NewDuringLaunchLabel)
                            ? System.IO.Path.GetFileName(NewDuringLaunchPath.Trim())
                            : NewDuringLaunchLabel.Trim(),
            Path      = NewDuringLaunchPath.Trim(),
            Arguments = string.IsNullOrWhiteSpace(NewDuringLaunchArgs) ? null : NewDuringLaunchArgs.Trim(),
        });
        NewDuringLaunchPath  = "";
        NewDuringLaunchArgs  = "";
        NewDuringLaunchLabel = "";
    }

    [RelayCommand]
    private void RemoveDuringLaunch(LaunchEntry? entry)
    {
        if (entry != null) DuringLaunchEntries.Remove(entry);
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

    /// <summary>Opens the game's store page URL in the system's default browser.</summary>
    [RelayCommand]
    private void OpenStorePage()
    {
        if (string.IsNullOrEmpty(StorePageUrl)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = StorePageUrl,
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
    public void LoadFromGame(Game game, LocalGame? localGame = null, LocalRepack? repack = null,
                             LocalRom? localRom = null)
    {
        ShowSettings    = false;
        ShowDrivePicker = false;
        Title         = game.Title;
        Platform      = game.Platform;
        Genre         = game.Genre    ?? "";
        Description   = game.Description ?? "";
        RatingStars   = game.RatingStars;
        Price         = game.Price;
        CoverUrl      = game.CoverUrl;
        CoverGradient = game.CoverGradient;
        IsRom         = localRom != null;
        PopulateRegions(localRom?.Regions.Count > 0 ? localRom.Regions : null);
        PopulateStoreUrl(null, game.Platform, null);

        PopulateTrailer(game.TrailerUrl);
        PopulateScreenshots(game.Screenshots);
        PopulateAchievements(game.GameAchievements);
        IsLocalGame = false;
        HasMultipleDrives = false;
        DriveLabels.Clear();

        // Load achievements from the database URL when not already populated
        if (!HasAchievements && !string.IsNullOrEmpty(game.AchievementsUrl))
            _ = FetchAndDisplayAchievementsAsync(game.AchievementsUrl);

        ApplyInstallState(localGame, repack, localRom);
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
    public void LoadFromStoreGame(StoreGame game, LocalGame? localGame = null, LocalRepack? repack = null,
                                  LocalRom? localRom = null)
    {
        ShowSettings    = false;
        ShowDrivePicker = false;
        Title         = game.Title;
        Platform      = game.Platform;
        Genre         = game.Genre;
        Description   = game.Description;
        RatingStars   = game.RatingStars;
        Price         = game.Price;
        ReleaseYear   = game.ReleaseYear;
        CoverUrl      = game.CoverUrl;
        CoverGradient = game.CoverGradient;
        IsRom         = localRom != null;
        PopulateRegions(localRom?.Regions.Count > 0 ? localRom.Regions : null);
        PopulateStoreUrl(game.StorePageUrl, game.Platform, null);

        PopulateTrailer(game.TrailerUrl);
        PopulateScreenshots(game.Screenshots);
        PopulateAchievements(null);
        IsLocalGame       = false;
        HasMultipleDrives = false;
        DriveLabels.Clear();

        // Load achievements from the database URL when available
        if (!string.IsNullOrEmpty(game.AchievementsUrl))
            _ = FetchAndDisplayAchievementsAsync(game.AchievementsUrl);

        ApplyInstallState(localGame, repack, localRom);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Populate from a locally detected LocalGame
    // ─────────────────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────────────────
    // Populate from a locally detected LocalGame
    // ─────────────────────────────────────────────────────────────────────────

    public void LoadFromLocalGame(LocalGame game)
    {
        ShowSettings    = false;
        ShowDrivePicker = false;
        Title             = game.Title;
        Platform          = "PC";
        Genre             = "";
        CoverGradient     = "#0d2137,#163d5e";
        RatingStars       = "—";
        Price             = null;
        CoverUrl          = null;
        IsRom             = false;
        _databaseDescription = null;
        PopulateRegions(null);
        PopulateStoreUrl(null, "PC", null);

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
    // Populate from a locally detected LocalRepack (ready-to-install archive)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sets up the detail overlay for a repack archive found on disk.
    /// Shows basic title/size info immediately; the caller should follow up with
    /// <see cref="MainViewModel.EnrichLocalGameDetailAsync"/> to pull real cover
    /// art, description, screenshots and achievements from the Games.Database.
    /// </summary>
    public void LoadFromLocalRepack(LocalRepack repack)
    {
        ShowSettings    = false;
        ShowDrivePicker = false;
        Title             = repack.Title;
        Platform          = "PC";
        Genre             = "";
        CoverGradient     = "#2d1b00,#5c3800";
        RatingStars       = "—";
        Price             = null;
        CoverUrl          = null;
        IsRom             = false;
        _databaseDescription = null;
        PopulateRegions(null);
        PopulateStoreUrl(null, "PC", null);

        Description = $"Repack archive ready to install  ·  {repack.SizeLabel}";

        PopulateTrailer(null);
        Screenshots.Clear();
        HasScreenshots = false;
        PopulateAchievements(null);

        IsLocalGame      = true;
        IsInstalled      = false;
        IsRepack         = true;
        IsSetupRepack    = repack.FileType == "setup";
        ShowDrivePicker  = false;
        RepackPath       = repack.FilePath;
        RepackSizeLabel  = repack.SizeLabel;
        _driveInstances  = new List<LocalGameDriveEntry>();
        DriveLabels.Clear();
        HasMultipleDrives  = false;
        SelectedDriveIndex = 0;
        ActiveDriveLabel   = "";
        ActiveDrivePath    = "";
        ActiveExeType      = "";
    }

    public void LoadFromLocalRom(LocalRom rom)
    {
        ShowSettings    = false;
        ShowDrivePicker = false;
        Title             = rom.Title;
        Platform          = rom.Platform;
        Genre             = "";
        CoverGradient     = "#0d1f3c,#1a3264";
        RatingStars       = "—";
        Price             = null;
        CoverUrl          = null;
        IsRom             = true;
        _databaseDescription = null;

        // Populate region/language metadata from the ROM file
        PopulateRegions(rom.Regions.Count > 0 ? rom.Regions : null);
        PopulateStoreUrl(null, rom.Platform, rom.TitleId);

        Description = $"ROM file  ·  {rom.SizeLabel}";

        PopulateTrailer(null);
        Screenshots.Clear();
        HasScreenshots = false;
        PopulateAchievements(null);

        IsLocalGame      = true;
        IsInstalled      = true;   // ROM is "installed" (the file exists on disk)
        IsRepack         = false;
        IsSetupRepack    = false;
        ShowDrivePicker  = false;
        RepackPath       = "";
        RepackSizeLabel  = "";

        // Store the ROM's directory as the "folder path" so the Open Folder button works
        _driveInstances = new List<LocalGameDriveEntry>
        {
            new LocalGameDriveEntry
            {
                DriveRoot      = System.IO.Path.GetPathRoot(rom.FilePath) ?? "",
                FolderPath     = System.IO.Path.GetDirectoryName(rom.FilePath) ?? "",
                ExecutablePath = rom.FilePath,
                ExecutableType = rom.FileType,
            }
        };
        DriveLabels.Clear();
        foreach (var d in _driveInstances)
            DriveLabels.Add(d.DriveRoot);

        HasMultipleDrives  = false;
        SelectedDriveIndex = 0;
        ActiveDriveLabel   = _driveInstances[0].DriveRoot;
        ActiveDrivePath    = _driveInstances[0].FolderPath;
        ActiveExeType      = rom.FileType.ToUpperInvariant();
    }


    /// <summary>
    /// Applies installation / repack state shared by <see cref="LoadFromGame"/>
    /// and <see cref="LoadFromStoreGame"/>.
    /// </summary>
    private void ApplyInstallState(LocalGame? localGame, LocalRepack? repack, LocalRom? localRom = null)
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
        else if (localRom != null)
        {
            // ROM file is on a local drive — show Play button using the ROM file
            IsInstalled      = true;
            IsRom            = true;
            IsRepack         = false;
            IsSetupRepack    = false;
            ShowDrivePicker  = false;
            RepackPath       = "";
            RepackSizeLabel  = "";

            _driveInstances = new List<LocalGameDriveEntry>
            {
                new LocalGameDriveEntry
                {
                    DriveRoot      = System.IO.Path.GetPathRoot(localRom.FilePath) ?? "",
                    FolderPath     = System.IO.Path.GetDirectoryName(localRom.FilePath) ?? "",
                    ExecutablePath = localRom.FilePath,
                    ExecutableType = localRom.FileType,
                }
            };

            DriveLabels.Clear();
            foreach (var d in _driveInstances)
                DriveLabels.Add(d.DriveRoot);

            HasMultipleDrives  = false;
            SelectedDriveIndex = 0;
            ActiveDriveLabel   = _driveInstances[0].DriveRoot;
            ActiveDrivePath    = _driveInstances[0].FolderPath;
            ActiveExeType      = localRom.FileType.ToUpperInvariant();
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

        // Populate genre if not already set (Xbox 360 and enriched databases include this)
        if (!string.IsNullOrEmpty(dbGame.Genre) && string.IsNullOrEmpty(Genre))
            Genre = dbGame.Genre;

        // Populate release year if not already set
        if (!string.IsNullOrEmpty(dbGame.ReleaseYear) && string.IsNullOrEmpty(ReleaseYear))
            ReleaseYear = dbGame.ReleaseYear;

        // Populate store URL from database (overrides any previously derived one)
        if (!string.IsNullOrEmpty(dbGame.StorePageUrl) || dbGame.AppId.HasValue || !string.IsNullOrEmpty(dbGame.TitleId))
            PopulateStoreUrl(dbGame.StorePageUrl, Platform, dbGame.TitleId ?? (dbGame.AppId.HasValue ? dbGame.AppId.Value.ToString() : null));

        PopulateTrailer(dbGame.TrailerUrl);
        PopulateScreenshots(dbGame.Screenshots);

        // Load achievements from the AchievementsUrl if we don't already have them
        if (!HasAchievements && !string.IsNullOrEmpty(dbGame.AchievementsUrl))
            _ = FetchAndDisplayAchievementsAsync(dbGame.AchievementsUrl);
    }

    /// <summary>
    /// Fetches the achievements JSON from the given URL and populates the
    /// Achievements collection.  Mirrors <c>_loadAchievementsInModal</c> in script.js.
    /// </summary>
    /// <remarks>
    /// Marked <c>internal</c> so <see cref="MainViewModel.EnrichGameAchievementsAsync"/>
    /// can trigger achievement loading for non-PC cloud library games whose
    /// <c>AchievementsUrl</c> was not stored when the game was added to the library.
    /// </remarks>
    internal async System.Threading.Tasks.Task FetchAndDisplayAchievementsAsync(string url)
    {
        try
        {
            using var http = new System.Net.Http.HttpClient();
            http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher/2.0");
            var json = await http.GetStringAsync(url);
            if (string.IsNullOrWhiteSpace(json)) return;

            var opts = new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Achievements JSON can be a root array or { "achievements": [...] }
            System.Text.Json.JsonElement arr;
            if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
                arr = root;
            else if (root.TryGetProperty("achievements", out var sub) && sub.ValueKind == System.Text.Json.JsonValueKind.Array)
                arr = sub;
            else
                return;

            var list = new List<Achievement>();
            foreach (var item in arr.EnumerateArray())
            {
                string name = TryGetStringProp(item, "name", "Name");
                string desc = TryGetStringProp(item, "description", "Description");
                string icon = TryGetStringProp(item, "iconUrl", "IconUrl");

                if (string.IsNullOrEmpty(name)) continue;
                list.Add(new Achievement
                {
                    Name        = name,
                    Description = desc,
                    IconUrl     = string.IsNullOrEmpty(icon) ? null : icon,
                });
            }

            if (list.Count > 0)
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                    PopulateAchievements(list));
            }
        }
        catch { /* best-effort */ }
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
        ShowAllAchievements = false;
        HasMoreAchievements = Achievements.Count > AchievementsPreviewCount;
        AchievementsLabel = HasAchievements
            ? $"🏆  Achievements  ({Achievements.Count})"
            : "🏆  Achievements";
        RefreshVisibleAchievements();
    }

    private void RefreshVisibleAchievements()
    {
        VisibleAchievements.Clear();
        var source = ShowAllAchievements
            ? Achievements
            : Achievements.Take(AchievementsPreviewCount);
        foreach (var a in source)
            VisibleAchievements.Add(a);
        HasMoreAchievements = Achievements.Count > AchievementsPreviewCount;
    }

    private void PopulateRegions(List<string>? regions)
    {
        if (regions != null && regions.Count > 0)
        {
            RegionsLabel = string.Join(" · ", regions);
            HasRegions   = true;
        }
        else
        {
            RegionsLabel = "";
            HasRegions   = false;
        }
    }

    /// <summary>
    /// Builds the store page URL based on the platform, app ID, or title ID.
    /// Platform → URL format:
    ///   PC (Steam): https://store.steampowered.com/app/{AppId}/
    ///   PS3/PS4:    https://store.playstation.com/en-gb/product/{TitleId}
    ///   Switch:     https://www.nintendo.com/search/#q={title}
    ///   Xbox 360:   https://marketplace.xbox.com/en-US/Product/{TitleId}
    /// </summary>
    private void PopulateStoreUrl(string? explicitUrl, string platform, string? idHint)
    {
        string? url = explicitUrl;

        if (string.IsNullOrEmpty(url))
        {
            bool isPlayStation = platform is "PS3" or "PS4" or "PS5";
            bool isXbox        = platform is "Xbox 360" or "Xbox One";

            if (!string.IsNullOrEmpty(idHint))
            {
                if (string.Equals(platform, "PC", StringComparison.OrdinalIgnoreCase))
                {
                    // idHint is AppId (Steam)
                    if (long.TryParse(idHint, out long appId) && appId > 0)
                        url = $"https://store.steampowered.com/app/{appId}/";
                }
                else if (isPlayStation)
                {
                    url = $"https://store.playstation.com/en-gb/product/{idHint}";
                }
                else if (isXbox)
                {
                    url = $"https://www.xbox.com/en-GB/search?q={Uri.EscapeDataString(Title)}";
                }
            }

            if (string.IsNullOrEmpty(url))
            {
                // Fallback: search by title on the platform's storefront
                if (!string.IsNullOrEmpty(Title))
                {
                    if (string.Equals(platform, "Switch", StringComparison.OrdinalIgnoreCase))
                        url = $"https://www.nintendo.com/search/#q={Uri.EscapeDataString(Title)}";
                    else if (isXbox)
                        url = $"https://www.xbox.com/en-GB/search?q={Uri.EscapeDataString(Title)}";
                }
            }
        }

        StorePageUrl   = url;
        HasStoreUrl    = !string.IsNullOrEmpty(url);
        StoreButtonLabel = platform switch
        {
            "PC"                => "🎮  View on Steam",
            "PS3" or "PS4" or "PS5" => "🛒  PlayStation Store",
            "Switch"            => "🛒  Nintendo eShop",
            "Xbox 360" or "Xbox One" => "🛒  Xbox Store",
            _                   => "🛒  View in Store",
        };
    }

    /// <summary>
    /// Returns the string value of the first matching property from an element,
    /// trying each key in order (case-sensitive).  Returns "" when none match.
    /// </summary>
    private static string TryGetStringProp(System.Text.Json.JsonElement el, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (el.TryGetProperty(key, out var val))
                return val.GetString() ?? "";
        }
        return "";
    }
}
