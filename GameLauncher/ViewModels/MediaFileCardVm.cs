using CommunityToolkit.Mvvm.ComponentModel;

namespace GameLauncher.ViewModels;

/// <summary>
/// Card view-model for a single media file (movie, TV show episode, or music track)
/// shown in the Media library grid.
/// </summary>
public partial class MediaFileCardVm : ObservableObject
{
    /// <summary>Display title (file name without extension).</summary>
    public string Title    { get; init; } = "";

    /// <summary>Absolute path to the media file.</summary>
    public string FilePath { get; init; } = "";

    /// <summary>Category bucket: "Movies", "TvShows", or "Music".</summary>
    public string Category { get; init; } = "";

    /// <summary>Emoji used as the card icon (🎬, 📺, or 🎵).</summary>
    public string TypeEmoji { get; init; } = "";

    /// <summary>Human-readable type label shown as the badge ("Movie", "TV Show", "Music").</summary>
    public string TypeLabel { get; init; } = "";

    /// <summary>Badge background colour per category.</summary>
    public string BadgeBackground =>
        Category == "Movies"  ? "#1a3a6e" :
        Category == "TvShows" ? "#1a5e34" :
                                "#3d2a1a";  // Music

    /// <summary>Badge foreground colour per category.</summary>
    public string BadgeForeground =>
        Category == "Movies"  ? "#58a6ff" :
        Category == "TvShows" ? "#3fb950" :
                                "#f0883e";  // Music

    /// <summary>Icon area background gradient per category.</summary>
    public string IconGradient =>
        Category == "Movies"  ? "#0d1b2a,#1a3a6e" :
        Category == "TvShows" ? "#0d1f17,#1a4a2e" :
                                "#1a1000,#3d2a0a";  // Music
}
