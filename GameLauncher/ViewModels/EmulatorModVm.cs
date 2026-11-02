using CommunityToolkit.Mvvm.ComponentModel;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>A toggleable emulator-level mod (Xenia optimized settings or a PS2 HD texture pack).</summary>
public partial class EmulatorModVm : ViewModelBase
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Icon { get; set; } = "🧩";
    /// <summary>"Xenia" or "Pcsx2Textures".</summary>
    public string Kind { get; set; } = "";
    public string EmulatorPath { get; set; } = "";
    public string TitleId { get; set; } = "";
    /// <summary>Cached toml (Xenia) or pack source folder (PS2).</summary>
    public string SourcePath { get; set; } = "";
    public EmulatorModsService.TexturePack? Pack { get; set; }

    [ObservableProperty] private bool _enabled;

    public string StatusLabel      => Enabled ? "✓ Enabled"  : "✗ Disabled";
    public string StatusBackground => Enabled ? "#1a4a1a"    : "#2a1a1a";
    public string StatusForeground => Enabled ? "#3fb950"    : "#f85149";
    public string ToggleLabel      => Enabled ? "Disable"    : "Enable";

    partial void OnEnabledChanged(bool value)
    {
        OnPropertyChanged(nameof(StatusLabel));
        OnPropertyChanged(nameof(StatusBackground));
        OnPropertyChanged(nameof(StatusForeground));
        OnPropertyChanged(nameof(ToggleLabel));
    }
}
