namespace GameLauncher.ViewModels;

/// <summary>
/// View-model wrapping a single Ryujinx DLC pack entry from <c>dlc.json</c>.
/// Exposes only the display-relevant properties needed in the DLC section of
/// the Game Detail panel.
/// </summary>
public sealed class RyujinxDlcVm
{
    /// <summary>File name of the DLC NSP/XCI, derived from <c>path</c> in dlc.json.</summary>
    public string FileName { get; init; } = "";

    /// <summary>Total number of NCA sub-entries in this DLC pack.</summary>
    public int NcaCount { get; init; }

    /// <summary>Number of enabled NCA sub-entries.</summary>
    public int EnabledCount { get; init; }

    /// <summary><c>true</c> when at least one NCA entry is enabled.</summary>
    public bool AnyEnabled => EnabledCount > 0;

    public string StatusLabel      => AnyEnabled ? "✓ Enabled"  : "✗ Disabled";
    public string StatusBackground => AnyEnabled ? "#1a4a1a"    : "#2a1a1a";
    public string StatusForeground => AnyEnabled ? "#3fb950"    : "#f85149";
}
