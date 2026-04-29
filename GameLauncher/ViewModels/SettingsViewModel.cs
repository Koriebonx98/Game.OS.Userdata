using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>
/// View-model for the Settings page.
/// Allows the user to configure per-platform emulators and basic app settings.
/// Each platform can have multiple emulators; the user can add, remove, and reorder them.
/// </summary>
public partial class SettingsViewModel : ViewModelBase
{
    // ── Platform emulator groups ───────────────────────────────────────────
    public ObservableCollection<EmulatorPlatformGroupVm> EmulatorGroups { get; } = new();

    // ── Application-wide settings ──────────────────────────────────────────
    /// <summary>Check for Games.Database updates on startup.</summary>
    [ObservableProperty] private bool _autoUpdate = true;
    /// <summary>Play the Game.OS intro animation when the launcher starts.</summary>
    [ObservableProperty] private bool _showIntroVideo = true;
    /// <summary>Allow uploading Ryujinx "Room:" log snippets to the Games.Database.</summary>
    [ObservableProperty] private bool _allowLogUpload = false;

    // ── Status / save ──────────────────────────────────────────────────────
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private bool   _isSaveSuccess;

    // ── Intro-video download ───────────────────────────────────────────────
    [ObservableProperty] private string _introVideoStatus   = "";
    [ObservableProperty] private bool   _isDownloadingIntro = false;
    [ObservableProperty] private bool   _introVideoExists   = false;

    // ── App-update check ───────────────────────────────────────────────────
    [ObservableProperty] private string _updateStatus      = "";
    [ObservableProperty] private bool   _isCheckingUpdate  = false;
    [ObservableProperty] private bool   _updateAvailable   = false;
    [ObservableProperty] private double _updateProgress    = 0;
    [ObservableProperty] private bool   _isInstallingUpdate = false;

    // Held for the "Install now" action after the check succeeds
    private AppUpdateService.UpdateInfo? _pendingUpdate;

    public SettingsViewModel()
    {
        Load();
    }

    public void Load()
    {
        EmulatorGroups.Clear();
        foreach (var platform in EmulatorSettingsService.SupportedPlatforms)
        {
            var allSettings = EmulatorSettingsService.LoadAll(platform);
            var group       = new EmulatorPlatformGroupVm(platform, this);
            foreach (var s in allSettings)
                group.Emulators.Add(new EmulatorRowVm(platform, s));
            EmulatorGroups.Add(group);
        }

        var appSettings   = AppSettingsService.Load();
        AutoUpdate        = appSettings.AutoUpdate;
        ShowIntroVideo    = appSettings.ShowIntroVideo;
        AllowLogUpload    = appSettings.AllowLogUpload;

        IntroVideoExists  = System.IO.File.Exists(IntroVideoLocalPath);
        StatusMessage     = "";
        UpdateStatus      = "";
        IntroVideoStatus  = IntroVideoExists ? "✅ Intro video already downloaded." : "";
    }

    // ── Save ───────────────────────────────────────────────────────────────

    [RelayCommand]
    private void Save()
    {
        foreach (var group in EmulatorGroups)
        {
            var list = group.Emulators.Select(row => new EmulatorSettings
            {
                Platform     = row.Platform,
                EmulatorPath = row.EmulatorPath,
                Arguments    = string.IsNullOrWhiteSpace(row.Arguments) ? "{rom}" : row.Arguments,
                EmulatorName = row.EmulatorName,
                Enabled      = row.Enabled,
            }).ToList();
            EmulatorSettingsService.SaveAll(group.Platform, list);
        }

        AppSettingsService.Save(new Models.AppSettings
        {
            AutoUpdate     = AutoUpdate,
            ShowIntroVideo = ShowIntroVideo,
            AllowLogUpload = AllowLogUpload,
        });

        StatusMessage = "✅ Settings saved!";
        IsSaveSuccess = true;
    }

    // ── Browse emulator ────────────────────────────────────────────────────

    [RelayCommand]
    private void BrowseEmulator(EmulatorRowVm? row)
    {
        if (row == null) return;
        BrowseRequested?.Invoke(row);
    }

    /// <summary>Raised when the user clicks Browse… on an emulator row.</summary>
    public System.Action<EmulatorRowVm>? BrowseRequested { get; set; }

    // ── Intro-video download ───────────────────────────────────────────────

    /// <summary>
    /// Canonical local path where the Game.OS intro video is stored.
    /// The app checks this file at startup to decide whether to play the intro.
    /// </summary>
    public static string IntroVideoLocalPath { get; } = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "GameOS", "intro.mp4");

    /// <summary>
    /// Raw URL of the intro video asset inside the Game.OS releases.
    /// Update this constant whenever the video asset is renamed or hosted elsewhere.
    /// </summary>
    private const string IntroVideoUrl =
        "https://github.com/Koriebonx98/Game.OS.Userdata/releases/download/intro/intro.mp4";

    [RelayCommand]
    private async Task DownloadIntroVideoAsync()
    {
        if (IsDownloadingIntro) return;

        IsDownloadingIntro = true;
        IntroVideoStatus   = "⬇ Downloading intro video…";

        try
        {
            string dir = System.IO.Path.GetDirectoryName(IntroVideoLocalPath)!;
            System.IO.Directory.CreateDirectory(dir);

            using var http = new System.Net.Http.HttpClient();
            http.DefaultRequestHeaders.Add("User-Agent", "GameOS-Launcher/2.0");

            using var resp = await http.GetAsync(IntroVideoUrl, System.Net.Http.HttpCompletionOption.ResponseHeadersRead);
            resp.EnsureSuccessStatusCode();

            await using var src  = await resp.Content.ReadAsStreamAsync();
            await using var dest = System.IO.File.Create(IntroVideoLocalPath);
            await src.CopyToAsync(dest);

            IntroVideoExists = true;
            IntroVideoStatus = "✅ Intro video downloaded successfully.";
        }
        catch (Exception ex)
        {
            IntroVideoStatus = $"❌ Download failed: {ex.Message}";
        }
        finally
        {
            IsDownloadingIntro = false;
        }
    }

    // ── App update check ───────────────────────────────────────────────────

    [RelayCommand]
    private async Task CheckForUpdateAsync()
    {
        if (IsCheckingUpdate) return;

        IsCheckingUpdate = true;
        UpdateAvailable  = false;
        UpdateStatus     = "🔍 Checking for updates…";
        _pendingUpdate   = null;

        try
        {
            var info = await AppUpdateService.CheckForUpdateAsync();
            if (info == null)
            {
                UpdateStatus = "❌ Could not reach the update server. Check your connection.";
                return;
            }

            if (info.IsNewer)
            {
                _pendingUpdate  = info;
                UpdateAvailable = true;
                UpdateStatus    = $"🆕 Version {info.Version} is available! (current: {AppUpdateService.CurrentVersion})";
            }
            else
            {
                UpdateStatus = $"✅ You are on the latest version ({AppUpdateService.CurrentVersion}).";
            }
        }
        catch (Exception ex)
        {
            UpdateStatus = $"❌ Update check failed: {ex.Message}";
        }
        finally
        {
            IsCheckingUpdate = false;
        }
    }

    [RelayCommand]
    private async Task InstallUpdateAsync()
    {
        if (_pendingUpdate == null || IsInstallingUpdate) return;

        if (string.IsNullOrEmpty(_pendingUpdate.DownloadUrl))
        {
            UpdateStatus = "❌ No download available for your operating system.";
            return;
        }

        IsInstallingUpdate = true;
        UpdateProgress     = 0;
        UpdateStatus       = "⬇ Downloading update…";

        try
        {
            var progress = new Progress<double>(p =>
            {
                double pct     = p * 100;
                UpdateProgress = pct;
                UpdateStatus   = $"⬇ Downloading update… {pct:F0}%";
            });

            // This call does not return — the app exits and the updater re-launches it.
            await AppUpdateService.DownloadAndInstallAsync(_pendingUpdate, progress);
        }
        catch (Exception ex)
        {
            UpdateStatus       = $"❌ Update failed: {ex.Message}";
            IsInstallingUpdate = false;
        }
    }
}

/// <summary>
/// View-model for a platform group in the emulator settings grid.
/// Contains 1-N <see cref="EmulatorRowVm"/> entries that can be added or removed.
/// </summary>
public partial class EmulatorPlatformGroupVm : ViewModelBase
{
    private readonly SettingsViewModel _parent;

    public string Platform { get; }
    public ObservableCollection<EmulatorRowVm> Emulators { get; } = new();

    public EmulatorPlatformGroupVm(string platform, SettingsViewModel parent)
    {
        Platform = platform;
        _parent  = parent;
    }

    [RelayCommand]
    private void AddEmulator()
    {
        Emulators.Add(new EmulatorRowVm(Platform, new EmulatorSettings
        {
            Platform  = Platform,
            Arguments = "{rom}",
            Enabled   = true,
        }));
    }

    [RelayCommand]
    private void RemoveEmulator(EmulatorRowVm? row)
    {
        if (row != null && Emulators.Count > 1)
            Emulators.Remove(row);
        // Note: removing the last emulator entry is intentionally blocked to ensure
        // the platform always has at least one (possibly empty) configuration row.
    }
}

/// <summary>Editable row in the emulator settings grid.</summary>
public partial class EmulatorRowVm : ViewModelBase
{
    public string Platform { get; }

    [ObservableProperty] private string _emulatorPath = "";
    [ObservableProperty] private string _arguments    = "{rom}";
    [ObservableProperty] private string _emulatorName = "";
    [ObservableProperty] private bool   _enabled      = true;

    public EmulatorRowVm(string platform, EmulatorSettings settings)
    {
        Platform     = platform;
        EmulatorPath = settings.EmulatorPath;
        Arguments    = settings.Arguments;
        EmulatorName = settings.EmulatorName;
        Enabled      = settings.Enabled;
    }
}
