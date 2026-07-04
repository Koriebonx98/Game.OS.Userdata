using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Services;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;

namespace GameLauncher.ViewModels;

public partial class MediaViewModel : ObservableObject
{
    // ── Supported extensions ──────────────────────────────────────────────────
    private static readonly string[] VideoExts = { ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".ts", ".m2ts" };
    private static readonly string[] AudioExts = { ".mp3", ".flac", ".aac", ".ogg", ".wav", ".m4a", ".wma" };

    // ── Media file collections ────────────────────────────────────────────────
    public ObservableCollection<MediaFileCardVm> MovieFiles  { get; } = new();
    public ObservableCollection<MediaFileCardVm> TvShowFiles { get; } = new();
    public ObservableCollection<MediaFileCardVm> MusicFiles  { get; } = new();

    [ObservableProperty] private bool _hasMovies;
    [ObservableProperty] private bool _hasTvShows;
    [ObservableProperty] private bool _hasMusic;

    // ── VLC local file player ─────────────────────────────────────────────────
    /// <summary>True when the in-app VLC file-player overlay is visible.</summary>
    [ObservableProperty] private bool   _isVlcPlayerOpen;
    /// <summary>File name of the media currently loaded in the VLC player.</summary>
    [ObservableProperty] private string _vlcMediaPath = "";

    /// <summary>
    /// Delegate set by the View code-behind. When invoked, the View shows a file
    /// picker and—once the user selects a file—starts VLC playback in the overlay.
    /// </summary>
    public Action? PlayLocalVideoRequested { get; set; }

    /// <summary>
    /// Delegate set by the View code-behind. When invoked with a file path, the
    /// View starts VLC playback for that specific file without showing a picker.
    /// </summary>
    public Action<string>? PlaySpecificFileRequested { get; set; }

    public MediaViewModel()
    {
        ScanMediaFolders();
    }

    // ── Scanning ──────────────────────────────────────────────────────────────

    [RelayCommand]
    private void ScanMediaFolders()
    {
        LoadCategory(
            MovieFiles,
            folder: Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
            extensions: VideoExts,
            category: "Movies",
            emoji: "🎬",
            label: "Movie",
            excludeSubfolder: "TV Shows");

        LoadCategory(
            TvShowFiles,
            folder: Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
                "TV Shows"),
            extensions: VideoExts,
            category: "TvShows",
            emoji: "📺",
            label: "TV Show");

        LoadCategory(
            MusicFiles,
            folder: Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
            extensions: AudioExts,
            category: "Music",
            emoji: "🎵",
            label: "Music");

        HasMovies  = MovieFiles.Count  > 0;
        HasTvShows = TvShowFiles.Count > 0;
        HasMusic   = MusicFiles.Count  > 0;
    }

    private static void LoadCategory(
        ObservableCollection<MediaFileCardVm> target,
        string folder,
        string[] extensions,
        string category,
        string emoji,
        string label,
        string? excludeSubfolder = null)
    {
        target.Clear();
        if (!Directory.Exists(folder)) return;

        try
        {
            var files = Directory
                .EnumerateFiles(folder, "*.*", SearchOption.AllDirectories)
                .Where(f =>
                {
                    if (excludeSubfolder != null)
                    {
                        var rel = Path.GetRelativePath(folder, f);
                        if (rel.StartsWith(excludeSubfolder, StringComparison.OrdinalIgnoreCase))
                            return false;
                    }
                    return extensions.Contains(
                        Path.GetExtension(f), StringComparer.OrdinalIgnoreCase);
                })
                .OrderBy(f => Path.GetFileNameWithoutExtension(f),
                         StringComparer.OrdinalIgnoreCase);

            foreach (var path in files)
            {
                target.Add(new MediaFileCardVm
                {
                    Title     = Path.GetFileNameWithoutExtension(path),
                    FilePath  = path,
                    Category  = category,
                    TypeEmoji = emoji,
                    TypeLabel = label,
                });
            }
        }
        catch (Exception ex)
        {
            DevLogService.Log($"[MediaViewModel] Scan '{folder}' failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ── Play commands ─────────────────────────────────────────────────────────

    /// <summary>Play a specific media file card via the VLC overlay (no picker).</summary>
    [RelayCommand]
    private void PlayMediaFile(MediaFileCardVm? card)
    {
        if (card == null || !File.Exists(card.FilePath)) return;
        DevLogService.Log($"[MediaViewModel] PlayMediaFile: {card.FilePath}");
        PlaySpecificFileRequested?.Invoke(card.FilePath);
    }

    /// <summary>Open the file-picker and play whatever the user selects.</summary>
    [RelayCommand]
    private void PlayLocalVideo()
    {
        DevLogService.Log("[MediaViewModel] PlayLocalVideo requested");
        PlayLocalVideoRequested?.Invoke();
    }

    [RelayCommand]
    private void CloseVlcPlayer()
    {
        IsVlcPlayerOpen = false;
        VlcMediaPath    = "";
    }
}
