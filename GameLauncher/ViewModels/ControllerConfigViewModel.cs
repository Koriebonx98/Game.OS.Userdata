using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>Row in the controller config grid representing one button's mapping.</summary>
public partial class ControllerButtonMappingVm : ObservableObject
{
    /// <summary>XInput button name (e.g. "A", "DPadUp", "LeftShoulder").</summary>
    public string ButtonName { get; init; } = "";
    /// <summary>Friendly display label shown in the left column.</summary>
    public string ButtonLabel { get; init; } = "";

    [ObservableProperty] private string _pressAction = "Empty";
    [ObservableProperty] private string _holdAction  = "Empty";
}

/// <summary>
/// View-model for the per-game controller configuration window.
/// Mirrors the Steam Input controller mapping screen: each button can be
/// remapped to a key press, key combo, or left empty for native XInput pass-through.
/// Profiles are saved as JSON via <see cref="ControllerProfileService"/>.
/// </summary>
public partial class ControllerConfigViewModel : ViewModelBase
{
    private string _platform = "";
    private string _gameTitle = "";

    // ── Profile metadata ──────────────────────────────────────────────────────
    [ObservableProperty] private string _profileName = "Default";
    [ObservableProperty] private string _description = "";
    [ObservableProperty] private string _authorName  = "";

    // ── Saved profiles list ───────────────────────────────────────────────────
    public ObservableCollection<string> SavedProfileNames { get; } = new();
    [ObservableProperty] private string? _selectedSavedProfile;

    // ── Button mapping rows ───────────────────────────────────────────────────
    public ObservableCollection<ControllerButtonMappingVm> Mappings { get; } = new();

    // ── Status ────────────────────────────────────────────────────────────────
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private bool   _isDirty;

    // ── Callbacks wired by the code-behind ────────────────────────────────────
    public Action<ControllerProfile>? OnProfileActivated { get; set; }
    public Action? OnClose { get; set; }

    // ── Friendly button labels ────────────────────────────────────────────────
    private static readonly (string Name, string Label)[] ButtonDefs =
    {
        ("A",              "A  (Cross / Confirm)"),
        ("B",              "B  (Circle / Back)"),
        ("X",              "X  (Square / Action)"),
        ("Y",              "Y  (Triangle / Tertiary)"),
        ("DPadUp",         "D-Pad Up"),
        ("DPadDown",       "D-Pad Down"),
        ("DPadLeft",       "D-Pad Left"),
        ("DPadRight",      "D-Pad Right"),
        ("LeftShoulder",   "LB  / L1"),
        ("RightShoulder",  "RB  / R1"),
        ("LeftTrigger",    "LT  / L2"),
        ("RightTrigger",   "RT  / R2"),
        ("LeftThumb",      "Left Stick Click"),
        ("RightThumb",     "Right Stick Click"),
        ("Start",          "Start  / Menu"),
        ("Back",           "Back  / View"),
    };

    public ControllerConfigViewModel()
    {
        foreach (var (name, label) in ButtonDefs)
        {
            var row = new ControllerButtonMappingVm { ButtonName = name, ButtonLabel = label };
            row.PropertyChanged += (_, _) => IsDirty = true;
            Mappings.Add(row);
        }
    }

    // ── Public API called by the code-behind ──────────────────────────────────

    /// <summary>Loads all profiles for the given game and sets the first (or Default) profile as active.</summary>
    public void Load(string platform, string gameTitle, string author = "")
    {
        _platform  = platform;
        _gameTitle = gameTitle;
        AuthorName = author;

        RefreshSavedProfiles();

        // Try to load the "Default" profile first; fall back to whatever is first.
        var profiles = ControllerProfileService.LoadProfiles(_platform, _gameTitle);
        var profile = profiles.FirstOrDefault(p =>
            string.Equals(p.ProfileName, "Default", StringComparison.OrdinalIgnoreCase))
            ?? profiles.FirstOrDefault()
            ?? ControllerProfileService.CreateDefaultProfile(author);

        ApplyProfile(profile);
        IsDirty = false;
    }

    // ── Commands ──────────────────────────────────────────────────────────────

    [RelayCommand]
    private void SaveProfile()
    {
        if (string.IsNullOrWhiteSpace(ProfileName)) { StatusMessage = "Profile name cannot be empty."; return; }

        var profile = BuildCurrentProfile();
        ControllerProfileService.AddOrUpdateProfile(_platform, _gameTitle, profile);
        StatusMessage = $"Profile \"{ProfileName}\" saved.";
        IsDirty = false;
        RefreshSavedProfiles();
        OnProfileActivated?.Invoke(profile);
    }

    [RelayCommand]
    private void LoadSelectedProfile()
    {
        if (string.IsNullOrWhiteSpace(SelectedSavedProfile)) return;

        var profiles = ControllerProfileService.LoadProfiles(_platform, _gameTitle);
        var profile  = profiles.FirstOrDefault(p =>
            string.Equals(p.ProfileName, SelectedSavedProfile, StringComparison.OrdinalIgnoreCase));
        if (profile == null) { StatusMessage = "Profile not found."; return; }

        ApplyProfile(profile);
        IsDirty = false;
        StatusMessage = $"Loaded \"{profile.ProfileName}\".";
    }

    [RelayCommand]
    private void DeleteSelectedProfile()
    {
        if (string.IsNullOrWhiteSpace(SelectedSavedProfile)) return;
        ControllerProfileService.DeleteProfile(_platform, _gameTitle, SelectedSavedProfile, "");
        StatusMessage = $"Deleted \"{SelectedSavedProfile}\".";
        RefreshSavedProfiles();
        SelectedSavedProfile = null;
    }

    [RelayCommand]
    private void ResetToDefault()
    {
        var profile = ControllerProfileService.CreateDefaultProfile(AuthorName);
        ApplyProfile(profile);
        IsDirty = true;
        StatusMessage = "Reset to Default (all mappings cleared).";
    }

    [RelayCommand]
    private void ResetToNavigation()
    {
        var profile = ControllerProfileService.CreateNavigationProfile(AuthorName);
        ApplyProfile(profile);
        IsDirty = true;
        StatusMessage = "Applied Navigation preset.";
    }

    [RelayCommand]
    private void Close() => OnClose?.Invoke();

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void ApplyProfile(ControllerProfile profile)
    {
        ProfileName = profile.ProfileName;
        Description = profile.Description;
        if (!string.IsNullOrEmpty(profile.Author)) AuthorName = profile.Author;

        foreach (var row in Mappings)
        {
            if (profile.Mappings.TryGetValue(row.ButtonName, out var action))
            {
                row.PressAction = action.Press ?? "Empty";
                row.HoldAction  = action.Hold  ?? "Empty";
            }
            else
            {
                row.PressAction = "Empty";
                row.HoldAction  = "Empty";
            }
        }
    }

    private ControllerProfile BuildCurrentProfile()
    {
        var mappings = new Dictionary<string, ControllerButtonAction>();
        foreach (var row in Mappings)
        {
            mappings[row.ButtonName] = new ControllerButtonAction
            {
                Press = string.IsNullOrWhiteSpace(row.PressAction) ? "Empty" : row.PressAction.Trim(),
                Hold  = string.IsNullOrWhiteSpace(row.HoldAction)  ? "Empty" : row.HoldAction.Trim(),
            };
        }

        return new ControllerProfile
        {
            ProfileName  = ProfileName.Trim(),
            Description  = Description?.Trim() ?? "",
            Author       = AuthorName?.Trim() ?? "",
            CreatedAt    = DateTime.UtcNow.ToString("o"),
            Mappings     = mappings,
        };
    }

    private void RefreshSavedProfiles()
    {
        SavedProfileNames.Clear();
        var profiles = ControllerProfileService.LoadProfiles(_platform, _gameTitle);
        foreach (var p in profiles)
            SavedProfileNames.Add(p.ProfileName);
    }
}
