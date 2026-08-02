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
    // ── Preset action list (keyboard keys + common combos) shown in the mapping dropdowns ──────

    /// <summary>
    /// Master list of available action strings shown in the Press/Hold combo boxes.
    /// Users can also type any custom value since the boxes are editable.
    /// </summary>
    public static readonly IReadOnlyList<string> ActionPresets = BuildPresets();

    private static IReadOnlyList<string> BuildPresets()
    {
        var list = new List<string>
        {
            // ── Pass-through ──────────────────────────────────────────────────────
            "Empty",

            // ── Common keys ───────────────────────────────────────────────────────
            "Key:Enter",
            "Key:Escape",
            "Key:Space",
            "Key:Tab",
            "Key:Backspace",
            "Key:Delete",
            "Key:Insert",

            // ── Navigation keys ───────────────────────────────────────────────────
            "Key:Up",
            "Key:Down",
            "Key:Left",
            "Key:Right",
            "Key:Home",
            "Key:End",
            "Key:PageUp",
            "Key:PageDown",

            // ── Modifier keys ─────────────────────────────────────────────────────
            "Key:Ctrl",
            "Key:Shift",
            "Key:Alt",
            "Key:Win",

            // ── Function keys ─────────────────────────────────────────────────────
            "Key:F1",  "Key:F2",  "Key:F3",  "Key:F4",
            "Key:F5",  "Key:F6",  "Key:F7",  "Key:F8",
            "Key:F9",  "Key:F10", "Key:F11", "Key:F12",

            // ── Letter keys ───────────────────────────────────────────────────────
            "Key:A","Key:B","Key:C","Key:D","Key:E","Key:F","Key:G","Key:H",
            "Key:I","Key:J","Key:K","Key:L","Key:M","Key:N","Key:O","Key:P",
            "Key:Q","Key:R","Key:S","Key:T","Key:U","Key:V","Key:W","Key:X",
            "Key:Y","Key:Z",

            // ── Digit keys ────────────────────────────────────────────────────────
            "Key:0","Key:1","Key:2","Key:3","Key:4",
            "Key:5","Key:6","Key:7","Key:8","Key:9",

            // ── Numpad keys ───────────────────────────────────────────────────────
            "Key:Numpad0","Key:Numpad1","Key:Numpad2","Key:Numpad3","Key:Numpad4",
            "Key:Numpad5","Key:Numpad6","Key:Numpad7","Key:Numpad8","Key:Numpad9",

            // ── Other keys ────────────────────────────────────────────────────────
            "Key:PrintScreen",
            "Key:Pause",
            "Key:CapsLock",
            "Key:NumLock",
            "Key:ScrollLock",

            // ── Common combos ─────────────────────────────────────────────────────
            "Key:Ctrl+Z",
            "Key:Ctrl+X",
            "Key:Ctrl+C",
            "Key:Ctrl+V",
            "Key:Ctrl+A",
            "Key:Ctrl+S",
            "Key:Ctrl+W",
            "Key:Ctrl+F4",
            "Key:Alt+Enter",
            "Key:Alt+F4",
            "Key:Ctrl+Shift+Esc",
            "Key:Win+D",
            "Key:Win+G",
        };

        return list.AsReadOnly();
    }

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

    /// <summary>
    /// Loads all profiles for the given game and pre-selects the named profile for editing.
    /// Falls back to <see cref="Load(string,string,string)"/> when the named profile is not found.
    /// </summary>
    public void LoadForEdit(string platform, string gameTitle, string author, string profileName)
    {
        _platform  = platform;
        _gameTitle = gameTitle;
        AuthorName = author;

        RefreshSavedProfiles();

        var profiles = ControllerProfileService.LoadProfiles(_platform, _gameTitle);
        var profile  = profiles.FirstOrDefault(p =>
            string.Equals(p.ProfileName, profileName, StringComparison.OrdinalIgnoreCase))
            ?? profiles.FirstOrDefault()
            ?? ControllerProfileService.CreateDefaultProfile(author);

        ApplyProfile(profile);
        IsDirty = false;
        StatusMessage = string.IsNullOrEmpty(profile.ProfileName) ? "" : $"Editing \"{profile.ProfileName}\"";
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
