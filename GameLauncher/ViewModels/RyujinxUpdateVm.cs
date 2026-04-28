namespace GameLauncher.ViewModels;

/// <summary>
/// View-model wrapping a single game-update path entry from <c>updates.json</c>.
/// </summary>
public sealed class RyujinxUpdateVm
{
    /// <summary>File name of the update NSP/XCI, derived from the path string.</summary>
    public string FileName { get; init; } = "";

    /// <summary><c>true</c> when this update is the currently selected one.</summary>
    public bool IsSelected { get; init; }

    public string StatusLabel      => IsSelected ? "✓ Active"  : "—";
    public string StatusBackground => IsSelected ? "#1a4a1a"   : "#21262d";
    public string StatusForeground => IsSelected ? "#3fb950"   : "#8b949e";
}
