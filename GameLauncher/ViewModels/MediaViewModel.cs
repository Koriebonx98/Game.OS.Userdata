using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;

namespace GameLauncher.ViewModels;

public partial class MediaViewModel : ObservableObject
{
    public sealed partial class MediaLibraryItem : ObservableObject
    {
        /// <summary>True while the controller / keyboard highlight is on this item.</summary>
        [ObservableProperty] private bool _isFocused;
        public string Title { get; init; } = "";
        public string FullPath { get; init; } = "";
        public string SourceFolder { get; init; } = "";
        public string MediaType { get; init; } = "";
        public string Extension { get; init; } = "";
        public long FileSizeBytes { get; init; }
        /// <summary>First sub-folder under the category folder (show / artist); empty when the file sits directly in it.</summary>
        public string Group { get; init; } = "";
        public string DisplayTitle { get; init; } = "";
        public string Initial => DisplayTitle.Length > 0 ? DisplayTitle[..1].ToUpperInvariant() : "?";
        /// <summary>"#start,#end" poster gradient used by CoverImage when there is no artwork.</summary>
        public string Gradient { get; init; } = "#1e1b4b,#312e81";
        /// <summary>Local poster / cover image found next to the file, or empty.</summary>
        public string CoverPath { get; init; } = "";
        public string SizeLabel => FormatFileSize(FileSizeBytes);
    }

    /// <summary>A show / artist / folder and the items inside it.</summary>
    public sealed partial class MediaGroup : ObservableObject
    {
        [ObservableProperty] private bool _isFocused;
        public string Title { get; init; } = "";
        public IReadOnlyList<MediaLibraryItem> Items { get; init; } = Array.Empty<MediaLibraryItem>();
        public string CountLabel => Items.Count == 1 ? "1 item" : $"{Items.Count} items";
    }

    private static readonly string[] PosterGradients =
    {
        "#1e1b4b,#4338ca", "#3b0764,#9333ea", "#7f1d1d,#ef4444", "#064e3b,#10b981",
        "#78350f,#f59e0b", "#0c4a6e,#0ea5e9", "#831843,#ec4899", "#1f2937,#6b7280",
    };

    private static string GradientFor(string title)
    {
        int sum = 0;
        foreach (char c in title) sum += c;
        return PosterGradients[sum % PosterGradients.Length];
    }

    private static string CleanTitle(string fileName)
    {
        var name = Path.GetFileNameWithoutExtension(fileName).Replace('.', ' ').Replace('_', ' ').Trim();
        return name.Length > 0 ? name : fileName;
    }

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
    public Action<string>? PlayMediaItemRequested { get; set; }

    private static readonly HashSet<string> VideoExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".m4v", ".webm", ".flv", ".mpeg", ".mpg", ".ts"
    };

    private static readonly HashSet<string> AudioExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma", ".alac", ".opus"
    };

    private readonly ObservableCollection<MediaLibraryItem> _movies = new();
    private readonly ObservableCollection<MediaLibraryItem> _tvShows = new();
    private readonly ObservableCollection<MediaLibraryItem> _music = new();
    private DateTime _lastScanUtc = DateTime.MinValue;
    private static readonly TimeSpan ScanCacheDuration = TimeSpan.FromMinutes(2);

    public ReadOnlyObservableCollection<MediaLibraryItem> Movies { get; }
    public ReadOnlyObservableCollection<MediaLibraryItem> TvShows { get; }
    public ReadOnlyObservableCollection<MediaLibraryItem> Music { get; }

    // ── Themes (Settings → Design) ────────────────────────────────────────────
    /// <summary>Movies &amp; TV page design: "Default" or "Netflix".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsNetflixMoviesTv))]
    [NotifyPropertyChangedFor(nameof(IsDefaultMoviesTv))]
    private string _moviesTvTheme = "Default";
    /// <summary>Music page design: "Default" or "Spotify".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSpotifyMusic))]
    [NotifyPropertyChangedFor(nameof(IsDefaultMusic))]
    private string _musicTheme = "Default";

    public bool IsNetflixMoviesTv  => string.Equals(MoviesTvTheme, "Netflix", StringComparison.OrdinalIgnoreCase);
    public bool IsDefaultMoviesTv  => !IsNetflixMoviesTv;
    public bool IsSpotifyMusic     => string.Equals(MusicTheme, "Spotify", StringComparison.OrdinalIgnoreCase);
    public bool IsDefaultMusic     => !IsSpotifyMusic;
    public bool IsVideoSection     => SelectedMediaSection != "music";

    /// <summary>Items of the active video section grouped by show / folder (one row each in the Netflix layout).</summary>
    // Cached so controller focus flags live on stable group objects.
    private IReadOnlyList<MediaGroup>? _activeGroups;
    private IReadOnlyList<MediaGroup>? _musicGroups;
    public IReadOnlyList<MediaGroup> ActiveGroups => _activeGroups ??= BuildGroups(ActiveItems);
    public IReadOnlyList<MediaGroup> MusicGroups => _musicGroups ??= BuildGroups(Music);
    public bool HasNoActiveItems => !ActiveItems.Any();
    public bool HasNoMusic => Music.Count == 0;

    /// <summary>Folder (artist / album) filter for the music track list; empty = all tracks.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(MusicTracks))]
    [NotifyPropertyChangedFor(nameof(MusicTracksTitle))]
    private string _selectedMusicGroup = "";
    public IEnumerable<MediaLibraryItem> MusicTracks =>
        string.IsNullOrEmpty(SelectedMusicGroup) ? Music : Music.Where(m => m.Group == SelectedMusicGroup);
    public string MusicTracksTitle => string.IsNullOrEmpty(SelectedMusicGroup) ? "All songs" : SelectedMusicGroup;

    private static IReadOnlyList<MediaGroup> BuildGroups(IEnumerable<MediaLibraryItem> items) =>
        items.GroupBy(i => i.Group, StringComparer.OrdinalIgnoreCase)
             .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
             .Select(g => new MediaGroup { Title = g.Key, Items = g.OrderBy(i => i.DisplayTitle, StringComparer.OrdinalIgnoreCase).ToList() })
             .ToList();

    private void NotifyLibraryChanged()
    {
        _activeGroups = null;
        _musicGroups = null;
        OnPropertyChanged(nameof(ActiveItems));
        OnPropertyChanged(nameof(ActiveGroups));
        OnPropertyChanged(nameof(ActiveSectionSummary));
        OnPropertyChanged(nameof(HasNoActiveItems));
        OnPropertyChanged(nameof(MusicGroups));
        OnPropertyChanged(nameof(MusicTracks));
        OnPropertyChanged(nameof(HasNoMusic));
    }

    public IEnumerable<MediaLibraryItem> ActiveItems => SelectedMediaSection switch
    {
        "movies" => Movies,
        "tvshows" => TvShows,
        _ => Music
    };

    public string ActiveSectionTitle => SelectedMediaSection switch
    {
        "movies" => "Movies",
        "tvshows" => "TV Shows",
        _ => "Music"
    };

    public string ActiveSectionSummary => SelectedMediaSection switch
    {
        "movies" => $"{Movies.Count} item(s) found",
        "tvshows" => $"{TvShows.Count} item(s) found",
        _ => $"{Music.Count} item(s) found"
    };

    public bool IsMoviesSelected => SelectedMediaSection == "movies";
    public bool IsTvShowsSelected => SelectedMediaSection == "tvshows";
    public bool IsMusicSelected => SelectedMediaSection == "music";
    public bool HasSelectedItem => SelectedItem != null;
    public string SelectedItemTitle => SelectedItem?.Title ?? "Select media";
    public string SelectedItemPath => SelectedItem?.FullPath ?? "Pick a media card to view details.";
    public string SelectedItemTypeLabel =>
        SelectedItem is null
            ? ""
            : $"{SelectedItem.MediaType.ToUpperInvariant()} · {SelectedItem.Extension.ToUpperInvariant().TrimStart('.')}";
    public string SelectedItemSizeLabel => SelectedItem is null ? "" : FormatFileSize(SelectedItem.FileSizeBytes);
    public string SelectedItemActionLabel => SelectedItem?.MediaType == "music" ? "▶ Play Track" : "▶ Play";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelectedItem))]
    [NotifyPropertyChangedFor(nameof(SelectedItemTitle))]
    [NotifyPropertyChangedFor(nameof(SelectedItemPath))]
    [NotifyPropertyChangedFor(nameof(SelectedItemTypeLabel))]
    [NotifyPropertyChangedFor(nameof(SelectedItemSizeLabel))]
    [NotifyPropertyChangedFor(nameof(SelectedItemActionLabel))]
    private MediaLibraryItem? _selectedItem;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsMoviesSelected))]
    [NotifyPropertyChangedFor(nameof(IsTvShowsSelected))]
    [NotifyPropertyChangedFor(nameof(IsMusicSelected))]
    [NotifyPropertyChangedFor(nameof(ActiveItems))]
    [NotifyPropertyChangedFor(nameof(ActiveGroups))]
    [NotifyPropertyChangedFor(nameof(HasNoActiveItems))]
    [NotifyPropertyChangedFor(nameof(IsVideoSection))]
    [NotifyPropertyChangedFor(nameof(ActiveSectionTitle))]
    [NotifyPropertyChangedFor(nameof(ActiveSectionSummary))]
    private string _selectedMediaSection = "movies";

    partial void OnSelectedMediaSectionChanged(string value)
    {
        _activeGroups = null;
        EnsureSelectedItemForActiveSection();
    }

    public MediaViewModel()
    {
        Movies = new ReadOnlyObservableCollection<MediaLibraryItem>(_movies);
        TvShows = new ReadOnlyObservableCollection<MediaLibraryItem>(_tvShows);
        Music = new ReadOnlyObservableCollection<MediaLibraryItem>(_music);
        RefreshMediaLibrary();
    }

    public void OpenSection(string section)
    {
        SelectedMediaSection = NormalizeSection(section);
        EnsureMediaLibraryFresh();
        EnsureSelectedItemForActiveSection();
        ResetMediaFocus();
    }

    public void EnsureMediaLibraryFresh()
    {
        if (DateTime.UtcNow - _lastScanUtc > ScanCacheDuration)
            RefreshMediaLibrary();
        else NotifyLibraryChanged();
        EnsureSelectedItemForActiveSection();
    }

    [RelayCommand]
    private void SelectMovies() => SelectedMediaSection = "movies";

    [RelayCommand]
    private void SelectTvShows() => SelectedMediaSection = "tvshows";

    [RelayCommand]
    private void SelectMusic() => SelectedMediaSection = "music";

    [RelayCommand]
    private void SelectMediaItem(MediaLibraryItem? item)
    {
        if (item == null) return;
        SelectedItem = item;
    }

    [RelayCommand]
    private void PlaySelectedMedia()
    {
        if (SelectedItem == null) return;
        if (SelectedItem.MediaType == "music") PlayTrack(SelectedItem);
        else PlayMediaItemRequested?.Invoke(SelectedItem.FullPath);
    }

    /// <summary>Selects an item and plays it straight away (poster / track click).</summary>
    [RelayCommand]
    private void PlayMediaItem(MediaLibraryItem? item)
    {
        if (item == null) return;
        SelectedItem = item;
        PlaySelectedMedia();
    }

    [RelayCommand]
    private void SelectMusicGroup(string? group) => SelectedMusicGroup = group ?? "";

    // ── Controller / keyboard navigation ──────────────────────────────────────
    // Zones: 0 = tab bar (Movies / TV Shows / Music), 1 = content (poster rows or song list),
    //        2 = music folder list (left column, first entry is "All songs").
    private int _zone = 1;
    private int _tabIdx;
    private int _row, _col, _trackIdx, _folderIdx;
    private MediaLibraryItem? _focusedItem;
    private MediaGroup? _focusedGroup;

    /// <summary>Raised after the highlight moved so the view can scroll it into view.</summary>
    public event Action? MediaFocusChanged;

    public bool IsTabMoviesFocused => _zone == 0 && _tabIdx == 0;
    public bool IsTabTvFocused     => _zone == 0 && _tabIdx == 1;
    public bool IsTabMusicFocused  => _zone == 0 && _tabIdx == 2;
    public bool IsAllSongsFocused  => _zone == 2 && _folderIdx == 0;

    private static readonly string[] TabSections = { "movies", "tvshows", "music" };

    private static int TabIndexOf(string section) => Math.Max(0, Array.IndexOf(TabSections, section));

    /// <summary>Puts the highlight on the first item of the page (called when the page opens).</summary>
    public void ResetMediaFocus()
    {
        _zone = 1;
        _row = _col = _trackIdx = _folderIdx = 0;
        _tabIdx = TabIndexOf(SelectedMediaSection);
        ApplyMediaFocus();
    }

    /// <summary>
    /// Moves the highlight. Returns false when Left was pressed at the left edge, so the caller can open the nav menu.
    /// </summary>
    public bool MoveMediaFocus(int dx, int dy)
    {
        bool music = IsMusicSelected;
        switch (_zone)
        {
            case 0:
                if (dx != 0)
                {
                    int next = _tabIdx + dx;
                    if (next < 0) return false;
                    if (next >= TabSections.Length) return true;
                    _tabIdx = next;
                    SelectedMediaSection = TabSections[_tabIdx];
                    _row = _col = _trackIdx = _folderIdx = 0;
                }
                else if (dy > 0 && (music ? MusicTracks.Any() : ActiveGroups.Count > 0)) _zone = 1;
                break;

            case 1 when music:
            {
                int count = MusicTracks.Count();
                if (dy < 0) { if (_trackIdx > 0) _trackIdx--; else { _zone = 0; _tabIdx = 2; } }
                else if (dy > 0) _trackIdx = Math.Min(_trackIdx + 1, Math.Max(0, count - 1));
                else if (dx < 0) _zone = 2;
                break;
            }

            case 1:
            {
                var groups = ActiveGroups;
                if (dy < 0)
                {
                    if (_row > 0) { _row--; _col = Math.Min(_col, groups[_row].Items.Count - 1); }
                    else { _zone = 0; _tabIdx = TabIndexOf(SelectedMediaSection); }
                }
                else if (dy > 0)
                {
                    if (_row < groups.Count - 1) { _row++; _col = Math.Min(_col, groups[_row].Items.Count - 1); }
                }
                else if (dx < 0) { if (_col > 0) _col--; else return false; }
                else if (dx > 0 && groups.Count > 0 && _col < groups[_row].Items.Count - 1) _col++;
                break;
            }

            case 2:
            {
                int max = MusicGroups.Count;
                if (dy < 0) { if (_folderIdx > 0) _folderIdx--; else { _zone = 0; _tabIdx = 2; } }
                else if (dy > 0) _folderIdx = Math.Min(_folderIdx + 1, max);
                else if (dx < 0) return false;
                else if (dx > 0) _zone = 1;
                if (_zone == 2)
                {
                    SelectedMusicGroup = _folderIdx == 0 ? "" : MusicGroups[_folderIdx - 1].Title;
                    _trackIdx = 0;
                }
                break;
            }
        }
        ApplyMediaFocus();
        return true;
    }

    /// <summary>A button: play the highlighted poster / song, or step into the song list from the folder list.</summary>
    public void ActivateMediaFocus()
    {
        if (_zone == 0)
        {
            if (_tabIdx == 2 && IsMusicSelected) SelectedMediaSection = "movies";
            _tabIdx = TabIndexOf(SelectedMediaSection);
            _zone = 1;
            ApplyMediaFocus();
            return;
        }
        if (_zone == 2) { _zone = 1; ApplyMediaFocus(); return; }
        if (_zone == 1 && _focusedItem != null) PlayMediaItem(_focusedItem);
    }

    /// <summary>X button: play / pause the music player (or play the highlighted video).</summary>
    public void QuickActionMediaFocus()
    {
        if (IsMusicSelected) TogglePlayPause();
        else if (_focusedItem != null) PlayMediaItem(_focusedItem);
    }

    private void ApplyMediaFocus()
    {
        if (_focusedItem != null) _focusedItem.IsFocused = false;
        if (_focusedGroup != null) _focusedGroup.IsFocused = false;
        _focusedItem = null;
        _focusedGroup = null;

        if (_zone == 1)
        {
            if (IsMusicSelected)
            {
                var tracks = MusicTracks.ToList();
                if (tracks.Count > 0) _focusedItem = tracks[Math.Clamp(_trackIdx, 0, tracks.Count - 1)];
            }
            else
            {
                var groups = ActiveGroups;
                if (groups.Count > 0)
                {
                    var items = groups[Math.Clamp(_row, 0, groups.Count - 1)].Items;
                    if (items.Count > 0) _focusedItem = items[Math.Clamp(_col, 0, items.Count - 1)];
                }
            }
            if (_focusedItem != null) { _focusedItem.IsFocused = true; SelectedItem = _focusedItem; }
        }
        else if (_zone == 2 && _folderIdx > 0 && _folderIdx <= MusicGroups.Count)
        {
            _focusedGroup = MusicGroups[_folderIdx - 1];
            _focusedGroup.IsFocused = true;
        }

        OnPropertyChanged(nameof(IsTabMoviesFocused));
        OnPropertyChanged(nameof(IsTabTvFocused));
        OnPropertyChanged(nameof(IsTabMusicFocused));
        OnPropertyChanged(nameof(IsAllSongsFocused));
        MediaFocusChanged?.Invoke();
    }

    // ── Music player (audio is played by MediaView through LibVLC, without the video overlay) ──
    public Action<string>? PlayAudioRequested { get; set; }
    public Action? ToggleAudioPauseRequested { get; set; }
    public Action? StopAudioRequested { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasNowPlaying))]
    [NotifyPropertyChangedFor(nameof(NowPlayingTitle))]
    [NotifyPropertyChangedFor(nameof(NowPlayingGroup))]
    private MediaLibraryItem? _nowPlaying;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PlayPauseGlyph))]
    private bool _isMusicPlaying;
    public string PlayPauseGlyph => IsMusicPlaying ? "⏸" : "▶";
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty] private string _positionLabel = "0:00";
    [ObservableProperty] private string _durationLabel = "0:00";
    public bool HasNowPlaying => NowPlaying != null;
    public string NowPlayingTitle => NowPlaying?.DisplayTitle ?? "Nothing playing";
    public string NowPlayingGroup => NowPlaying?.Group ?? "";

    private void PlayTrack(MediaLibraryItem item)
    {
        NowPlaying = item;
        ProgressPercent = 0;
        PositionLabel = "0:00";
        DurationLabel = "0:00";
        PlayAudioRequested?.Invoke(item.FullPath);
    }

    [RelayCommand]
    private void TogglePlayPause()
    {
        if (NowPlaying == null) { PlaySelectedMedia(); return; }
        ToggleAudioPauseRequested?.Invoke();
    }

    [RelayCommand]
    private void NextTrack() => StepTrack(1);

    [RelayCommand]
    private void PreviousTrack() => StepTrack(-1);

    private void StepTrack(int delta)
    {
        var tracks = MusicTracks.ToList();
        if (tracks.Count == 0) return;
        int idx = NowPlaying == null ? -1 : tracks.FindIndex(t => t.FullPath == NowPlaying.FullPath);
        int next = idx < 0 ? 0 : (idx + delta + tracks.Count) % tracks.Count;
        SelectedItem = tracks[next];
        PlayTrack(tracks[next]);
    }

    [RelayCommand]
    private void StopMusic()
    {
        StopAudioRequested?.Invoke();
        NowPlaying = null;
        IsMusicPlaying = false;
        ProgressPercent = 0;
    }

    /// <summary>Called by MediaView as playback advances.</summary>
    public void UpdateAudioProgress(long positionMs, long lengthMs)
    {
        ProgressPercent = lengthMs > 0 ? Math.Clamp(positionMs * 100.0 / lengthMs, 0, 100) : 0;
        PositionLabel = FormatClock(positionMs);
        DurationLabel = FormatClock(lengthMs);
    }

    public void OnAudioEnded() => StepTrack(1);

    private static string FormatClock(long ms)
    {
        var t = TimeSpan.FromMilliseconds(Math.Max(0, ms));
        return t.TotalHours >= 1 ? $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}" : $"{t.Minutes}:{t.Seconds:00}";
    }

    [RelayCommand]
    private void RefreshMediaLibrary()
    {
        _movies.Clear();
        _tvShows.Clear();
        _music.Clear();

        var knownPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var roots = GameScannerService.GetDriveRoots()
            .Where(root => !string.IsNullOrWhiteSpace(root))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var driveRoot in roots)
        {
            TryCollectMediaCategory(driveRoot, _movies, VideoExtensions, knownPaths, "Movies", "Films");
            TryCollectMediaCategory(driveRoot, _music, AudioExtensions, knownPaths, "Music", "Songs");
            TryCollectMediaCategory(driveRoot, _tvShows, VideoExtensions, knownPaths, "TV Shows", "TV", "Series", "Shows", "TV Series");
        }

        _lastScanUtc = DateTime.UtcNow;
        NotifyLibraryChanged();
        EnsureSelectedItemForActiveSection();
    }

    private static string NormalizeSection(string? section) =>
        section?.Trim().ToLowerInvariant() switch
        {
            "movies" => "movies",
            "tvshows" or "tv shows" or "tv" => "tvshows",
            _ => "music"
        };

    /// <summary>
    /// Scans each drive's Media folder for subdirectories matching any provided
    /// category name and adds files with allowed extensions into <paramref name="destination"/>.
    /// </summary>
    private static void TryCollectMediaCategory(
        string driveRoot,
        ICollection<MediaLibraryItem> destination,
        HashSet<string> allowedExtensions,
        HashSet<string> knownPaths,
        params string[] categoryFolderNames)
    {
        // Category folders are accepted under <drive>/Media/ and directly on the drive (<drive>/Movies, ...).
        var categoryDirs = new List<string>();
        foreach (var parent in new[] { Path.Combine(driveRoot, "Media"), driveRoot })
        {
            if (!Directory.Exists(parent)) continue;
            try
            {
                categoryDirs.AddRange(Directory
                    .EnumerateDirectories(parent)
                    .Where(path => categoryFolderNames.Contains(
                        Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)));
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        foreach (var mediaFolder in categoryDirs)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(mediaFolder, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                string extension = Path.GetExtension(file);
                if (!allowedExtensions.Contains(extension)) continue;
                if (!knownPaths.Add(file)) continue;

                var relative = Path.GetRelativePath(mediaFolder, file);
                var segments = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string title = CleanTitle(file);
                destination.Add(new MediaLibraryItem
                {
                    CoverPath = FindArtwork(file, mediaFolder),
                    DisplayTitle = title,
                    Gradient = GradientFor(title),
                    Group = segments.Length > 1 ? segments[0] : categoryFolderNames[0],
                    Title = Path.GetFileName(file),
                    FullPath = file,
                    SourceFolder = mediaFolder,
                    MediaType = categoryFolderNames[0] == "Music" ? "music" : "video",
                    Extension = extension,
                    FileSizeBytes = SafeGetFileSize(file)
                });
            }
        }
    }

    private static readonly string[] ArtworkNames =
        { "poster", "folder", "cover", "front", "thumb", "albumart", "fanart" };
    private static readonly string[] ArtworkExts = { ".jpg", ".jpeg", ".png", ".webp" };

    /// <summary>Local artwork next to the file (name.jpg, poster.jpg, folder.jpg, cover.png ...), or "".</summary>
    private static string FindArtwork(string file, string categoryRoot)
    {
        try
        {
            string? dir = Path.GetDirectoryName(file);
            string stem = Path.GetFileNameWithoutExtension(file);
            while (!string.IsNullOrEmpty(dir))
            {
                foreach (var ext in ArtworkExts)
                {
                    var own = Path.Combine(dir, stem + ext);
                    if (File.Exists(own)) return own;
                    foreach (var n in ArtworkNames)
                    {
                        var candidate = Path.Combine(dir, n + ext);
                        if (File.Exists(candidate)) return candidate;
                    }
                }
                if (string.Equals(Path.GetFullPath(dir), Path.GetFullPath(categoryRoot), StringComparison.OrdinalIgnoreCase)) break;
                dir = Path.GetDirectoryName(dir);
            }
        }
        catch { /* artwork is optional */ }
        return "";
    }

    private void EnsureSelectedItemForActiveSection()
    {
        var active = ActiveItems.ToList();
        if (active.Count == 0)
        {
            SelectedItem = null;
            return;
        }

        if (SelectedItem == null || !active.Any(item =>
                string.Equals(item.FullPath, SelectedItem.FullPath, StringComparison.OrdinalIgnoreCase)))
        {
            SelectedItem = active[0];
        }
    }

    private static long SafeGetFileSize(string filePath)
    {
        try
        {
            return new FileInfo(filePath).Length;
        }
        catch
        {
            return 0;
        }
    }

    private static string FormatFileSize(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double size = bytes;
        int unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }
        return unit == 0 ? $"{size:0} {units[unit]}" : $"{size:0.##} {units[unit]}";
    }

    // ── VLC commands ─────────────────────────────────────────────────────────

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
