using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>
/// View-model for the Settings page.
/// Allows the user to configure per-platform emulators and basic app settings.
/// </summary>
public partial class SettingsViewModel : ViewModelBase
{
    // ── Platform emulator list ─────────────────────────────────────────────
    public ObservableCollection<EmulatorRowVm> EmulatorRows { get; } = new();

    // ── Status message ─────────────────────────────────────────────────────
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private bool   _isSaveSuccess;

    public SettingsViewModel()
    {
        Load();
    }

    public void Load()
    {
        EmulatorRows.Clear();
        foreach (var platform in EmulatorSettingsService.SupportedPlatforms)
        {
            var settings = EmulatorSettingsService.Load(platform);
            EmulatorRows.Add(new EmulatorRowVm(platform, settings));
        }
        StatusMessage = "";
    }

    [RelayCommand]
    private void Save()
    {
        foreach (var row in EmulatorRows)
        {
            var settings = new EmulatorSettings
            {
                Platform     = row.Platform,
                EmulatorPath = row.EmulatorPath,
                Arguments    = string.IsNullOrWhiteSpace(row.Arguments) ? "{rom}" : row.Arguments,
                EmulatorName = row.EmulatorName,
                Enabled      = row.Enabled,
            };
            EmulatorSettingsService.Save(settings);
        }
        StatusMessage  = "✅ Settings saved!";
        IsSaveSuccess  = true;
    }

    [RelayCommand]
    private void BrowseEmulator(EmulatorRowVm? row)
    {
        if (row == null) return;
        // Opens a file picker asynchronously – handled in code-behind
        BrowseRequested?.Invoke(row);
    }

    /// <summary>Raised when the user clicks Browse… on an emulator row.</summary>
    public System.Action<EmulatorRowVm>? BrowseRequested { get; set; }
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
