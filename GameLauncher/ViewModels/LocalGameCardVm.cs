using CommunityToolkit.Mvvm.ComponentModel;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

/// <summary>
/// Unified card view-model for the "My Games" section.
/// Wraps a locally detected game, repack archive, or ROM file so they can be
/// displayed in a single platform-filterable grid with rich cover art from
/// the Games.Database.
/// </summary>
public partial class LocalGameCardVm : ViewModelBase
{
    /// <summary>Display title shown on the card.</summary>
    public string Title    { get; init; } = "";

    /// <summary>Platform tag used by the platform filter ("PC", "PS3", "Switch", etc.).</summary>
    public string Platform { get; init; } = "";

    /// <summary>
    /// Cover art URL enriched asynchronously from the Games.Database.
    /// Null until the background enrichment task populates it.
    /// </summary>
    [ObservableProperty] private string? _coverUrl;

    /// <summary>Gradient placeholder background used while <see cref="CoverUrl"/> is not yet available.</summary>
    [ObservableProperty] private string  _coverGradient = "#0d1117,#1f2937";

    // ── Source objects (exactly one is non-null) ──────────────────────────────

    /// <summary>Non-null when this entry represents a locally installed game folder.</summary>
    public LocalGame?   SourceGame   { get; init; }

    /// <summary>Non-null when this entry represents a ready-to-install repack archive.</summary>
    public LocalRepack? SourceRepack { get; init; }

    /// <summary>Non-null when this entry represents a ROM file.</summary>
    public LocalRom?    SourceRom    { get; init; }

    // ── Derived badge text / colours ──────────────────────────────────────────

    public string KindLabel =>
        SourceRom    != null ? "ROM"    :
        SourceRepack != null && SourceRepack.IsInstalledGame ? "Installed" :
        SourceRepack != null ? "Repack" : "Installed";

    public string KindBackground =>
        SourceRom    != null ? "#1f3a6e" :
        SourceRepack != null && SourceRepack.IsInstalledGame ? "#1a5e34" :
        SourceRepack != null ? "#5c3800" : "#1a5e34";

    public string KindForeground =>
        SourceRom    != null ? "#58a6ff" :
        SourceRepack != null && SourceRepack.IsInstalledGame ? "#3fb950" :
        SourceRepack != null ? "#e3b341" : "#3fb950";

    /// <summary>Comma-separated region tags for ROM entries (e.g. "Europe, USA"). Empty for non-ROM cards.</summary>
    public string RegionsLabel =>
        SourceRom?.Regions.Count > 0
            ? string.Join(", ", SourceRom.Regions)
            : "";

    /// <summary>True when this repack has an "Update" sub-directory available to install alongside it.</summary>
    public bool HasUpdate => SourceRepack?.HasUpdate == true;
}
