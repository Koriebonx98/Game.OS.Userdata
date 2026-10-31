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
        /// <summary>Poster / cover image: local artwork next to the file, otherwise the cached online poster, or empty.</summary>
        [ObservableProperty] private string _coverPath = "";
        public bool HasLocalCover { get; init; }
        public string SizeLabel => FormatFileSize(FileSizeBytes);
        public DateTime AddedUtc { get; init; }
        public string AddedLabel => AddedUtc == default ? "" : AddedUtc.ToLocalTime().ToString("d MMM yyyy");

        // ── play statistics (Data\<user>\Media\stats.json) ──
        [ObservableProperty, NotifyPropertyChangedFor(nameof(PlayCountLabel))] private int _playCount;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(RatingStars)), NotifyPropertyChangedFor(nameof(HasRating))] private int _rating;
        [ObservableProperty] private bool _favourite;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(ProgressFraction)), NotifyPropertyChangedFor(nameof(HasProgress))] private bool _watched;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(ProgressFraction)), NotifyPropertyChangedFor(nameof(HasProgress))] private long _resumeMs;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(ProgressFraction))] private long _durationMs;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(LastPlayedLabel))] private DateTime? _lastPlayedUtc;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(WatchTimeLabel))] private double _totalSeconds;

        // ── online info (Data\MediaCache) ──
        [ObservableProperty, NotifyPropertyChangedFor(nameof(HasOverview))] private string _overview = "";
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine))] private int _year;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine))] private string _genres = "";
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine)), NotifyPropertyChangedFor(nameof(ScoreLabel))] private double _score;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine))] private string _certification = "";
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine))] private int _runtimeMinutes;

        public bool HasOverview => Overview.Length > 0;
        public bool HasRating => Rating > 0;
        public string RatingStars => new string('★', Rating) + new string('☆', 5 - Rating);
        public string PlayCountLabel => PlayCount == 0 ? "Never played" : PlayCount == 1 ? "Played once" : $"Played {PlayCount} times";
        public string LastPlayedLabel => LastPlayedUtc is { } t ? $"Last played {t.ToLocalTime():d MMM yyyy}" : "";
        public string WatchTimeLabel => TotalSeconds < 60 ? "" : TotalSeconds >= 3600 ? $"{TotalSeconds / 3600:0.#} h total" : $"{TotalSeconds / 60:0} min total";
        public string ScoreLabel => Score > 0 ? $"★ {Score:0.0}" : "";
        public bool HasProgress => !Watched && ResumeMs > 0 && DurationMs > 0;
        /// <summary>0..1 for the progress bar under a "Continue Watching" tile.</summary>
        public double ProgressFraction => HasProgress ? Math.Clamp((double)ResumeMs / DurationMs, 0, 1) : 0;
        public string InfoLine => string.Join("  ·  ", new[]
        {
            Year > 0 ? Year.ToString() : "", Certification, RuntimeMinutes > 0 ? $"{RuntimeMinutes} min" : "", Genres,
        }.Where(x => x.Length > 0));

        public void ApplyStat(MediaStat st)
        {
            PlayCount = st.PlayCount; Rating = st.Rating; Favourite = st.Favourite; Watched = st.Watched;
            ResumeMs = st.ResumeMs; DurationMs = st.DurationMs; LastPlayedUtc = st.LastPlayedUtc; TotalSeconds = st.TotalSeconds;
        }

        public void ApplyMeta(MediaMetadata m)
        {
            Overview = m.Overview; Year = m.Year; Genres = string.Join(", ", m.Genres); Score = m.Score;
            Certification = m.Certification; RuntimeMinutes = m.RuntimeMinutes;
            if (!HasLocalCover && m.PosterFile.Length > 0) CoverPath = m.PosterFile;
        }

        /// <summary>Same file on another shelf, with its own focus flag.</summary>
        public MediaLibraryItem Clone()
        {
            var c = new MediaLibraryItem
            {
                Title = Title, FullPath = FullPath, SourceFolder = SourceFolder, MediaType = MediaType,
                Extension = Extension, FileSizeBytes = FileSizeBytes, Group = Group, DisplayTitle = DisplayTitle,
                Gradient = Gradient, HasLocalCover = HasLocalCover, AddedUtc = AddedUtc,
                CoverPath = CoverPath, Overview = Overview, Year = Year, Genres = Genres, Score = Score,
                Certification = Certification, RuntimeMinutes = RuntimeMinutes,
                PlayCount = PlayCount, Rating = Rating, Favourite = Favourite, Watched = Watched, ResumeMs = ResumeMs,
                DurationMs = DurationMs, LastPlayedUtc = LastPlayedUtc, TotalSeconds = TotalSeconds,
            };
            return c;
        }
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
    public Action? StopVideoRequested { get; set; }
    public Action? ToggleVideoPauseRequested { get; set; }
    /// <summary>(isVideo, deltaMs)</summary>
    public Action<bool, long>? SeekByRequested { get; set; }
    /// <summary>(isVideo, fraction 0..1)</summary>
    public Action<bool, double>? SeekToRequested { get; set; }

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(VideoPlayPauseGlyph))] private bool _isVideoPlaying = true;
    [ObservableProperty] private double _videoProgressPercent;
    [ObservableProperty] private string _videoPositionLabel = "0:00";
    [ObservableProperty] private string _videoDurationLabel = "0:00";
    public string VideoPlayPauseGlyph => IsVideoPlaying ? "⏸" : "▶";

    public void UpdateVideoProgress(long positionMs, long lengthMs)
    {
        _lastVideoPos = positionMs;
        _lastVideoLen = lengthMs;
        VideoProgressPercent = lengthMs > 0 ? Math.Clamp(positionMs * 100.0 / lengthMs, 0, 100) : 0;
        VideoPositionLabel = FormatClock(positionMs);
        VideoDurationLabel = FormatClock(lengthMs);
    }

    [RelayCommand] private void ToggleVideoPause() => ToggleVideoPauseRequested?.Invoke();
    [RelayCommand] private void VideoSeekBack() => SeekByRequested?.Invoke(true, -MediaSkipSeconds * 1000L);
    [RelayCommand] private void VideoSeekForward() => SeekByRequested?.Invoke(true, MediaSkipSeconds * 1000L);

    /// <summary>The video that follows the current one in the same show, or null.</summary>
    public string? NextEpisodePath()
    {
        if (SelectedItem == null || !IsTvShowsSelected || !AutoPlayNextEpisode) return null;
        var list = DetailRelated;
        int idx = list.ToList().FindIndex(i => i.FullPath == SelectedItem.FullPath);
        if (idx < 0 || idx >= list.Count - 1) return null;
        _videoCompleted = true;
        EndVideoSession();
        SelectedItem = list[idx + 1];
        BeginVideoSession(SelectedItem);
        return SelectedItem.FullPath;
    }
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
    /// <summary>Movies &amp; TV page design: "Default" or "Cinema".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsCinemaMoviesTv))]
    [NotifyPropertyChangedFor(nameof(IsDefaultMoviesTv))]
    private string _moviesTvTheme = "Default";
    /// <summary>Music page design: "Default" or "Spotify".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSpotifyMusic))]
    [NotifyPropertyChangedFor(nameof(IsDefaultMusic))]
    private string _musicTheme = "Default";

    public bool IsCinemaMoviesTv  => string.Equals(MoviesTvTheme, "Cinema", StringComparison.OrdinalIgnoreCase) || string.Equals(MoviesTvTheme, "Netflix", StringComparison.OrdinalIgnoreCase);
    public bool IsDefaultMoviesTv  => !IsCinemaMoviesTv;
    public bool IsSpotifyMusic     => string.Equals(MusicTheme, "Spotify", StringComparison.OrdinalIgnoreCase);
    public bool IsDefaultMusic     => !IsSpotifyMusic;
    public bool IsVideoSection     => SelectedMediaSection != "music";
    public bool IsMusicPage        => SelectedMediaSection == "music";

    /// <summary>Items of the active video section grouped by show / folder (one row each in the Netflix layout).</summary>
    // Cached so controller focus flags live on stable group objects.
    private IReadOnlyList<MediaGroup>? _activeGroups;
    private IReadOnlyList<MediaGroup>? _musicGroups;
    public IReadOnlyList<MediaGroup> ActiveGroups => _activeGroups ??= BuildShelves();
    public IReadOnlyList<MediaGroup> MusicGroups => _musicGroups ??= BuildGroups(Music);
    public bool HasNoActiveItems => !ActiveItems.Any();
    /// <summary>Titles exist, but the search / filters hide all of them.</summary>
    public bool HasNoResults => !HasNoActiveItems && ActiveGroups.Count == 0;
    public bool HasNoMusic => Music.Count == 0;

    /// <summary>Folder (artist / album) filter for the music track list; empty = all tracks.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(MusicTracks))]
    [NotifyPropertyChangedFor(nameof(MusicTracksTitle))]
    private string _selectedMusicGroup = "";
    public IEnumerable<MediaLibraryItem> MusicTracks =>
        string.IsNullOrEmpty(SelectedMusicGroup) ? Music : Music.Where(m => m.Group == SelectedMusicGroup);
    public string MusicTracksTitle => string.IsNullOrEmpty(SelectedMusicGroup) ? "All songs" : SelectedMusicGroup;

    // ── Filters / sort (Movies & TV page) ─────────────────────────────────────
    public static IReadOnlyList<string> SortModes { get; } = new[] { "Title", "Recently added", "Most played", "Top rated", "Year" };
    public static IReadOnlyList<string> FilterModes { get; } = new[] { "All", "Unwatched", "Watched", "In progress", "My List" };
    public const string AllGenres = "All genres";

    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private string _sortMode = "Title";
    [ObservableProperty] private string _filterMode = "All";
    [ObservableProperty] private string _genreFilter = AllGenres;

    public bool IsFiltering => SearchText.Trim().Length > 0 || FilterMode != "All" || GenreFilter != AllGenres;
    public string SortLabel => $"Sort: {SortMode}";
    public string FilterLabel => FilterMode == "All" ? "Show: All" : $"Show: {FilterMode}";
    public string GenreLabel => GenreFilter;

    /// <summary>Genres found in the active section's online info.</summary>
    public IReadOnlyList<string> AvailableGenres =>
        new[] { AllGenres }.Concat(ActiveItems.SelectMany(i => i.Genres.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(g => g, StringComparer.OrdinalIgnoreCase)).ToList();

    partial void OnSearchTextChanged(string value) => RefreshShelves();
    partial void OnSortModeChanged(string value) { OnPropertyChanged(nameof(SortLabel)); RefreshShelves(); }
    partial void OnFilterModeChanged(string value) { OnPropertyChanged(nameof(FilterLabel)); RefreshShelves(); }
    partial void OnGenreFilterChanged(string value) { OnPropertyChanged(nameof(GenreLabel)); RefreshShelves(); }

    [RelayCommand] private void CycleSort() => SortMode = Next(SortModes, SortMode);
    [RelayCommand] private void CycleFilter() => FilterMode = Next(FilterModes, FilterMode);
    [RelayCommand] private void CycleGenre() => GenreFilter = Next(AvailableGenres, GenreFilter);

    [RelayCommand]
    private void ClearFilters()
    {
        SearchText = "";
        FilterMode = "All";
        GenreFilter = AllGenres;
    }

    private static string Next(IReadOnlyList<string> list, string current)
    {
        int idx = list.ToList().FindIndex(x => string.Equals(x, current, StringComparison.OrdinalIgnoreCase));
        return list[(idx + 1) % list.Count];
    }

    /// <summary>Rebuilds the shelves after a filter / stat change and keeps the highlight on the same title.</summary>
    private void RefreshShelves()
    {
        string? keep = _focusedItem?.FullPath ?? SelectedItem?.FullPath;
        _activeGroups = null;
        OnPropertyChanged(nameof(ActiveGroups));
        OnPropertyChanged(nameof(HasNoResults));
        OnPropertyChanged(nameof(IsFiltering));
        OnPropertyChanged(nameof(ActiveSectionSummary));
        OnPropertyChanged(nameof(AvailableGenres));
        if (GenreFilter != AllGenres && !AvailableGenres.Contains(GenreFilter, StringComparer.OrdinalIgnoreCase)) GenreFilter = AllGenres;

        var groups = ActiveGroups;
        _row = _col = 0;
        if (keep != null)
            for (int r = 0; r < groups.Count; r++)
            {
                int c = groups[r].Items.ToList().FindIndex(x => x.FullPath == keep);
                if (c >= 0) { _row = r; _col = c; break; }
            }
        if (_zone == 1 && !IsMusicSelected) ApplyMediaFocus();
    }

    private bool Passes(MediaLibraryItem i)
    {
        string q = SearchText.Trim();
        if (q.Length > 0 && !(i.DisplayTitle.Contains(q, StringComparison.OrdinalIgnoreCase)
                              || i.Group.Contains(q, StringComparison.OrdinalIgnoreCase)
                              || i.Genres.Contains(q, StringComparison.OrdinalIgnoreCase)))
            return false;
        bool ok = FilterMode switch
        {
            "Unwatched" => !i.Watched && !i.HasProgress,
            "Watched" => i.Watched,
            "In progress" => i.HasProgress,
            "My List" => i.Favourite,
            _ => true,
        };
        if (!ok) return false;
        return GenreFilter == AllGenres
               || i.Genres.Split(',', StringSplitOptions.TrimEntries).Contains(GenreFilter, StringComparer.OrdinalIgnoreCase);
    }

    private IEnumerable<MediaLibraryItem> Sorted(IEnumerable<MediaLibraryItem> items) => SortMode switch
    {
        "Recently added" => items.OrderByDescending(i => i.AddedUtc),
        "Most played" => items.OrderByDescending(i => i.PlayCount).ThenBy(i => i.DisplayTitle, StringComparer.OrdinalIgnoreCase),
        "Top rated" => items.OrderByDescending(i => i.Rating).ThenByDescending(i => i.Score).ThenBy(i => i.DisplayTitle, StringComparer.OrdinalIgnoreCase),
        "Year" => items.OrderByDescending(i => i.Year).ThenBy(i => i.DisplayTitle, StringComparer.OrdinalIgnoreCase),
        _ => items.OrderBy(i => i.DisplayTitle, StringComparer.OrdinalIgnoreCase),
    };

    /// <summary>
    /// Shelves for the active section. With no filter: Continue Watching, My List, Recently Added, Top Rated and Most Played
    /// first, then one shelf per show / folder. With a filter or search: only the matching titles, still grouped.
    /// </summary>
    private IReadOnlyList<MediaGroup> BuildShelves()
    {
        var items = ActiveItems.Where(Passes).ToList();
        var shelves = new List<MediaGroup>();
        if (!IsFiltering)
        {
            void Add(string title, IEnumerable<MediaLibraryItem> src, int min = 1)
            {
                var list = src.Take(15).Select(m => m.Clone()).ToList();
                if (list.Count >= min) shelves.Add(new MediaGroup { Title = title, Items = list });
            }
            Add("Continue Watching", items.Where(i => i.HasProgress).OrderByDescending(i => i.LastPlayedUtc));
            Add("My List", items.Where(i => i.Favourite).OrderBy(i => i.DisplayTitle, StringComparer.OrdinalIgnoreCase));
            Add("Recently Added", items.OrderByDescending(i => i.AddedUtc), 5);
            Add("Top Rated", items.Where(i => i.Rating >= 4).OrderByDescending(i => i.Rating));
            Add("Most Played", items.Where(i => i.PlayCount > 0).OrderByDescending(i => i.PlayCount), 3);
        }
        shelves.AddRange(items.GroupBy(i => i.Group, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new MediaGroup { Title = g.Key, Items = Sorted(g).ToList() }));
        return shelves;
    }

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
        OnPropertyChanged(nameof(HasNoResults));
        OnPropertyChanged(nameof(AvailableGenres));
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
    [NotifyPropertyChangedFor(nameof(HasNoResults))]
    [NotifyPropertyChangedFor(nameof(AvailableGenres))]
    [NotifyPropertyChangedFor(nameof(IsVideoSection))]
    [NotifyPropertyChangedFor(nameof(IsMusicPage))]
    [NotifyPropertyChangedFor(nameof(ActiveSectionTitle))]
    [NotifyPropertyChangedFor(nameof(ActiveSectionSummary))]
    private string _selectedMediaSection = "movies";

    partial void OnSelectedMediaSectionChanged(string value)
    {
        _activeGroups = null;
        IsDetailOpen = false;
        if (GenreFilter != AllGenres) GenreFilter = AllGenres;
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
        else
        {
            _videoItem = SelectedItem;
            _pendingResumeMs = SelectedItem.HasProgress ? SelectedItem.ResumeMs : 0;
            PlayMediaItemRequested?.Invoke(SelectedItem.FullPath);
        }
    }

    /// <summary>Selects an item and plays it straight away (poster / track click).</summary>
    [RelayCommand]
    private void PlayMediaItem(MediaLibraryItem? item)
    {
        if (item == null) return;
        SelectedItem = item;
        PlaySelectedMedia();
    }

    // ── Stats, ratings and sessions ───────────────────────────────────────────
    private IEnumerable<MediaLibraryItem> EveryCopy(string path) =>
        _movies.Concat(_tvShows).Concat(_music).Concat(_activeGroups?.SelectMany(g => g.Items) ?? Enumerable.Empty<MediaLibraryItem>())
               .Where(i => string.Equals(i.FullPath, path, StringComparison.OrdinalIgnoreCase));

    private void Persist(string path, Action<MediaStat> change)
    {
        var stat = MediaStatsService.Update(path, change);
        foreach (var copy in EveryCopy(path)) copy.ApplyStat(stat);
    }

    [RelayCommand]
    private void ToggleFavourite(MediaLibraryItem? item)
    {
        if (item == null) return;
        Persist(item.FullPath, st => st.Favourite = !st.Favourite);
        RefreshShelves();
    }

    [RelayCommand]
    private void ToggleWatched(MediaLibraryItem? item)
    {
        if (item == null) return;
        Persist(item.FullPath, st => { st.Watched = !st.Watched; if (st.Watched) st.ResumeMs = 0; });
        RefreshShelves();
    }

    /// <summary>Sets 1-5 stars (the same star again clears the rating).</summary>
    [RelayCommand]
    private void RateItem(string? stars)
    {
        var target = IsNowPlayingFullScreen && NowPlaying != null ? NowPlaying : SelectedItem;
        if (target == null || !int.TryParse(stars, out int n)) return;
        Persist(target.FullPath, st => st.Rating = st.Rating == n ? 0 : Math.Clamp(n, 0, 5));
    }

    private void AdjustRating(int delta)
    {
        var target = IsNowPlayingFullScreen && NowPlaying != null ? NowPlaying : SelectedItem;
        if (target == null) return;
        Persist(target.FullPath, st => st.Rating = Math.Clamp(st.Rating + delta, 0, 5));
    }

    private void ApplyStatsAndCachedInfo()
    {
        foreach (var item in _movies.Concat(_tvShows).Concat(_music))
        {
            item.ApplyStat(MediaStatsService.Get(item.FullPath));
            if (item.MediaType == "music") continue;
            if (MediaMetadataService.GetCached(KindOf(item), LookupName(item)) is { } meta) item.ApplyMeta(meta);
        }
    }

    private string KindOf(MediaLibraryItem item) =>
        item.MediaType == "music" ? "music" : _tvShows.Contains(item) ? "tv" : "movie";

    private static readonly string[] CategoryFolderNames = { "Movies", "Films", "TV Shows", "TV", "Series", "Shows", "TV Series", "Music", "Songs" };

    /// <summary>What to search online for: the show folder for TV, the file name for movies.</summary>
    private string LookupName(MediaLibraryItem item) =>
        KindOf(item) == "tv" && !CategoryFolderNames.Contains(item.Group, StringComparer.OrdinalIgnoreCase) ? item.Group : item.Title;

    // ── Online info (cached on disk; looked up in the background when enabled) ──
    [ObservableProperty] private bool _onlineInfoEnabled = true;
    private int _enrichRun;

    partial void OnOnlineInfoEnabledChanged(bool value)
    {
        if (value) StartEnrichment();
    }

    [RelayCommand]
    private void RefreshOnlineInfo()
    {
        var it = SelectedItem;
        if (it == null || it.MediaType == "music") return;
        _ = EnrichAsync(new[] { it }, force: true, _enrichRun);
    }

    private void StartEnrichment()
    {
        if (!OnlineInfoEnabled) return;
        int run = ++_enrichRun;
        // One lookup per movie / per TV show, and only for titles that have no cached info yet.
        var todo = _movies.Concat(_tvShows).Where(i => i.Overview.Length == 0)
            .GroupBy(i => (KindOf(i), LookupName(i).ToLowerInvariant())).Select(g => g.First()).Take(60).ToList();
        if (todo.Count > 0) _ = EnrichAsync(todo, false, run);
    }

    private async System.Threading.Tasks.Task EnrichAsync(IReadOnlyList<MediaLibraryItem> items, bool force, int run)
    {
        foreach (var item in items)
        {
            if (run != _enrichRun && !force) return;
            string kind = KindOf(item), name = LookupName(item);
            var meta = await MediaMetadataService.GetAsync(kind, name, item.Group, force).ConfigureAwait(false);
            if (meta != null)
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    foreach (var other in _movies.Concat(_tvShows).Where(x => KindOf(x) == kind && string.Equals(LookupName(x), name, StringComparison.OrdinalIgnoreCase))
                                 .Concat(_activeGroups?.SelectMany(g => g.Items).Where(x => KindOf(x) == kind && string.Equals(LookupName(x), name, StringComparison.OrdinalIgnoreCase)) ?? Enumerable.Empty<MediaLibraryItem>()))
                        other.ApplyMeta(meta);
                    OnPropertyChanged(nameof(AvailableGenres));
                });
            await System.Threading.Tasks.Task.Delay(force ? 0 : 3500).ConfigureAwait(false); // stay well inside the free API rate limits
        }
    }

    /// <summary>Artwork for the playing song, looked up once and cached.</summary>
    private async void EnrichTrack(MediaLibraryItem track)
    {
        if (!OnlineInfoEnabled || track.HasLocalCover || track.CoverPath.Length > 0) return;
        var meta = await MediaMetadataService.GetAsync("music", track.DisplayTitle, track.Group).ConfigureAwait(false);
        if (meta != null)
            Avalonia.Threading.Dispatcher.UIThread.Post(() => { foreach (var c in EveryCopy(track.FullPath)) c.ApplyMeta(meta); });
    }

    // ── Sessions: the media counterpart of a game play session ─────────────────
    /// <summary>Raised with "Watching X" / "Listening to X" when a session starts and null when it ends.</summary>
    public Action<string?>? MediaPresenceChanged { get; set; }

    private MediaLibraryItem? _videoItem, _musicItem;
    private readonly System.Diagnostics.Stopwatch _videoWatch = new(), _musicWatch = new();
    private DateTime _videoStartUtc, _musicStartUtc;
    private long _lastVideoPos, _lastVideoLen;
    private bool _videoCompleted, _musicCounted;
    private long _pendingResumeMs;

    /// <summary>Called by the view right after it starts playback, to jump to where the video stopped.</summary>
    public long TakeResumeMs() { long r = _pendingResumeMs; _pendingResumeMs = 0; return r; }
    public void MarkVideoCompleted() => _videoCompleted = true;

    private string KindLabel(MediaLibraryItem i) => KindOf(i);

    partial void OnIsVlcPlayerOpenChanged(bool value)
    {
        if (value) BeginVideoSession(_videoItem);
        else EndVideoSession();
    }

    partial void OnIsVideoPlayingChanged(bool value)
    {
        if (value) _videoWatch.Start(); else _videoWatch.Stop();
    }

    partial void OnIsMusicPlayingChanged(bool value)
    {
        if (_musicItem == null) return;
        if (value) _musicWatch.Start(); else _musicWatch.Stop();
    }

    private void BeginVideoSession(MediaLibraryItem? item)
    {
        EndMusicSession();
        _videoItem = item;
        _videoStartUtc = DateTime.UtcNow;
        _videoWatch.Restart();
        _lastVideoPos = _lastVideoLen = 0;
        _videoCompleted = false;
        if (item == null) return;
        Persist(item.FullPath, st => { st.PlayCount++; st.LastPlayedUtc = DateTime.UtcNow; });
        MediaPresenceChanged?.Invoke($"Watching {item.DisplayTitle}");
    }

    private void EndVideoSession()
    {
        _videoWatch.Stop();
        var item = _videoItem;
        _videoItem = null;
        if (item == null) return;
        bool done = _videoCompleted || (_lastVideoLen > 0 && _lastVideoPos >= _lastVideoLen * 0.9);
        long pos = _lastVideoPos, len = _lastVideoLen;
        Persist(item.FullPath, st =>
        {
            if (len > 0) st.DurationMs = len;
            if (done) { st.Watched = true; st.ResumeMs = 0; }
            else if (pos > 30_000) st.ResumeMs = pos;
        });
        MediaStatsService.AddSession(new MediaSession
        {
            Path = item.FullPath, Title = item.DisplayTitle, Kind = KindLabel(item),
            StartUtc = _videoStartUtc, Seconds = _videoWatch.Elapsed.TotalSeconds,
        });
        foreach (var copy in EveryCopy(item.FullPath)) copy.ApplyStat(MediaStatsService.Get(item.FullPath));
        MediaPresenceChanged?.Invoke(null);
        RefreshShelves();
    }

    private void BeginMusicSession(MediaLibraryItem item)
    {
        EndMusicSession();
        _musicItem = item;
        _musicStartUtc = DateTime.UtcNow;
        _musicWatch.Restart();
        _musicCounted = false;
        MediaPresenceChanged?.Invoke($"Listening to {item.DisplayTitle}");
        EnrichTrack(item);
    }

    private void EndMusicSession()
    {
        _musicWatch.Stop();
        var item = _musicItem;
        _musicItem = null;
        if (item == null) return;
        MediaStatsService.AddSession(new MediaSession
        {
            Path = item.FullPath, Title = item.DisplayTitle, Kind = "music",
            StartUtc = _musicStartUtc, Seconds = _musicWatch.Elapsed.TotalSeconds,
        });
        foreach (var copy in EveryCopy(item.FullPath)) copy.ApplyStat(MediaStatsService.Get(item.FullPath));
        if (!IsVlcPlayerOpen) MediaPresenceChanged?.Invoke(null);
    }

    /// <summary>Flushes any running session (page unloaded / sign-out).</summary>
    public void EndAllSessions()
    {
        EndVideoSession();
        EndMusicSession();
    }

    // ── Settings → Media ──────────────────────────────────────────────────────
    [ObservableProperty] private int  _mediaSkipSeconds = 10;
    [ObservableProperty] private bool _showMovieDetails = true;
    [ObservableProperty] private bool _showTvDetails = true;
    [ObservableProperty] private bool _autoPlayNextEpisode = true;
    [ObservableProperty] private bool _musicShuffle;
    [ObservableProperty] private bool _musicRepeat = true;

    // ── Detail page (movies and TV shows) ─────────────────────────────────────
    [ObservableProperty] private bool _isDetailOpen;

    partial void OnSelectedItemChanged(MediaLibraryItem? value)
    {
        OnPropertyChanged(nameof(DetailRelated));
        OnPropertyChanged(nameof(DetailRelatedTitle));
        OnPropertyChanged(nameof(HasDetailRelated));
        OnPropertyChanged(nameof(DetailAddedLabel));
        OnPropertyChanged(nameof(DetailKindLabel));
    }

    /// <summary>Other files of the same show / folder (episodes for TV shows).</summary>
    public IReadOnlyList<MediaLibraryItem> DetailRelated =>
        SelectedItem == null || SelectedItem.MediaType == "music"
            ? Array.Empty<MediaLibraryItem>()
            : ActiveItems.Where(i => string.Equals(i.Group, SelectedItem.Group, StringComparison.OrdinalIgnoreCase))
                         .OrderBy(i => i.DisplayTitle, StringComparer.OrdinalIgnoreCase).ToList();
    public bool HasDetailRelated => DetailRelated.Count > 1;
    public string DetailRelatedTitle => IsTvShowsSelected ? $"Episodes · {SelectedItem?.Group}" : $"More in {SelectedItem?.Group}";
    public string DetailAddedLabel => SelectedItem == null || string.IsNullOrEmpty(SelectedItem.AddedLabel) ? "" : $"Added {SelectedItem.AddedLabel}";
    public string DetailKindLabel => IsTvShowsSelected ? "TV SHOW" : "MOVIE";

    /// <summary>Click / A on a poster: music plays, movies and TV shows open their info page (unless disabled in settings).</summary>
    [RelayCommand]
    private void OpenMediaItem(MediaLibraryItem? item)
    {
        if (item == null) return;
        SelectedItem = item;
        bool details = item.MediaType != "music" && (IsTvShowsSelected ? ShowTvDetails : ShowMovieDetails);
        if (details) IsDetailOpen = true;
        else PlaySelectedMedia();
    }

    [RelayCommand]
    private void CloseDetail() => IsDetailOpen = false;

    [RelayCommand]
    private void PlayDetail()
    {
        IsDetailOpen = false;
        PlaySelectedMedia();
    }

    /// <summary>Left / Right on the info page: previous / next episode of the show.</summary>
    public void MoveDetail(int dx)
    {
        var list = DetailRelated;
        if (SelectedItem == null || list.Count < 2) return;
        int idx = list.ToList().FindIndex(i => i.FullPath == SelectedItem.FullPath);
        SelectedItem = list[Math.Clamp(idx + dx, 0, list.Count - 1)];
    }

    [RelayCommand]
    private void SelectMusicGroup(string? group) => SelectedMusicGroup = group ?? "";

    // ── Controller / keyboard navigation ──────────────────────────────────────
    // Zones: 0 = tab bar (Movies / TV Shows), 1 = content (poster rows or song list),
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
    public bool IsFilterSortFocused  => _zone == 0 && _tabIdx == 2;
    public bool IsFilterModeFocused  => _zone == 0 && _tabIdx == 3;
    public bool IsFilterGenreFocused => _zone == 0 && _tabIdx == 4;
    public bool IsAllSongsFocused  => _zone == 2 && _folderIdx == 0;
    private const int TopBarItems = 5; // Movies, TV Shows, Sort, Show, Genre

    private static readonly string[] TabSections = { "movies", "tvshows" };

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
            case 0 when !music:
                if (dx != 0)
                {
                    int next = _tabIdx + dx;
                    if (next < 0) return false;
                    if (next >= TopBarItems) return true;
                    _tabIdx = next;
                    if (next < TabSections.Length)
                    {
                        SelectedMediaSection = TabSections[_tabIdx];
                        _row = _col = _trackIdx = _folderIdx = 0;
                    }
                }
                else if (dy > 0 && ActiveGroups.Count > 0) _zone = 1;
                break;

            case 0:
                _zone = 1;
                break;

            case 1 when music:
            {
                int count = MusicTracks.Count();
                if (dy < 0) { if (_trackIdx > 0) _trackIdx--; }
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
                if (dy < 0) { if (_folderIdx > 0) _folderIdx--; }
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
            switch (_tabIdx)
            {
                case 2: CycleSort(); break;
                case 3: CycleFilter(); break;
                case 4: CycleGenre(); break;
                default: _tabIdx = TabIndexOf(SelectedMediaSection); _zone = 1; break;
            }
            ApplyMediaFocus();
            return;
        }
        if (_zone == 2) { _zone = 1; ApplyMediaFocus(); return; }
        if (_zone == 1 && _focusedItem != null) OpenMediaItem(_focusedItem);
    }

    /// <summary>X button: play / pause the music player (or play the highlighted video).</summary>
    public void QuickActionMediaFocus()
    {
        if (IsMusicSelected) TogglePlayPause();
        else if (_focusedItem != null) PlayMediaItem(_focusedItem);
    }

    /// <summary>Y button: add / remove the highlighted title from My List.</summary>
    public void FavouriteMediaFocus()
    {
        if (_zone == 1 && _focusedItem != null) ToggleFavourite(_focusedItem);
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
        OnPropertyChanged(nameof(IsFilterSortFocused));
        OnPropertyChanged(nameof(IsFilterModeFocused));
        OnPropertyChanged(nameof(IsFilterGenreFocused));
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
        BeginMusicSession(item);
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

    private readonly Random _rng = new();

    private void StepTrack(int delta, bool auto = false)
    {
        var tracks = MusicTracks.ToList();
        if (tracks.Count == 0) return;
        if (auto && !MusicRepeat && NowPlaying != null
            && tracks.FindIndex(t => t.FullPath == NowPlaying.FullPath) == tracks.Count - 1 && !MusicShuffle)
        {
            StopMusic();
            return;
        }
        if (MusicShuffle && tracks.Count > 1)
        {
            MediaLibraryItem pick;
            do pick = tracks[_rng.Next(tracks.Count)]; while (NowPlaying != null && pick.FullPath == NowPlaying.FullPath);
            SelectedItem = pick;
            PlayTrack(pick);
            return;
        }
        int idx = NowPlaying == null ? -1 : tracks.FindIndex(t => t.FullPath == NowPlaying.FullPath);
        int next = idx < 0 ? 0 : (idx + delta + tracks.Count) % tracks.Count;
        SelectedItem = tracks[next];
        PlayTrack(tracks[next]);
    }

    [RelayCommand]
    private void StopMusic()
    {
        StopAudioRequested?.Invoke();
        EndMusicSession();
        IsNowPlayingFullScreen = false;
        NowPlaying = null;
        IsMusicPlaying = false;
        ProgressPercent = 0;
    }

    /// <summary>Called by MediaView as playback advances.</summary>
    public void UpdateAudioProgress(long positionMs, long lengthMs)
    {
        // A play counts once the song has been heard for 30 s (or half of a short one).
        if (!_musicCounted && _musicItem != null && positionMs >= Math.Min(30_000, Math.Max(5_000, lengthMs / 2)))
        {
            _musicCounted = true;
            Persist(_musicItem.FullPath, st => { st.PlayCount++; st.LastPlayedUtc = DateTime.UtcNow; });
        }
        ProgressPercent = lengthMs > 0 ? Math.Clamp(positionMs * 100.0 / lengthMs, 0, 100) : 0;
        PositionLabel = FormatClock(positionMs);
        DurationLabel = FormatClock(lengthMs);
    }

    public void OnAudioEnded() => StepTrack(1, auto: true);

    // ── Full-screen now playing ──────────────────────────────────────────────
    [ObservableProperty] private bool _isNowPlayingFullScreen;

    [RelayCommand]
    private void OpenNowPlayingFullScreen()
    {
        if (NowPlaying != null) IsNowPlayingFullScreen = true;
    }

    [RelayCommand]
    private void CloseNowPlayingFullScreen() => IsNowPlayingFullScreen = false;

    [RelayCommand] private void ToggleShuffle() => MusicShuffle = !MusicShuffle;
    [RelayCommand] private void ToggleRepeat() => MusicRepeat = !MusicRepeat;
    [RelayCommand] private void MusicSeekBack() => SeekByRequested?.Invoke(false, -MediaSkipSeconds * 1000L);
    [RelayCommand] private void MusicSeekForward() => SeekByRequested?.Invoke(false, MediaSkipSeconds * 1000L);

    // ── Transport used by the controller, the quick menu and OS-style media buttons ──
    /// <summary>True when the in-app player has something to control (video overlay or a music track).</summary>
    public bool HasActivePlayback => IsVlcPlayerOpen || NowPlaying != null;

    public void TransportPlayPause()
    {
        if (IsVlcPlayerOpen) ToggleVideoPause();
        else TogglePlayPause();
    }

    public void TransportSeek(int direction)
    {
        long ms = direction * MediaSkipSeconds * 1000L;
        SeekByRequested?.Invoke(IsVlcPlayerOpen, ms);
    }

    public void TransportStep(int delta)
    {
        if (IsVlcPlayerOpen) SeekByRequested?.Invoke(true, delta * 60_000L);
        else StepTrack(delta);
    }

    /// <summary>Handles a key while the video overlay or the full-screen music player is open. Returns true when consumed.</summary>
    public bool HandlePlayerKey(string key)
    {
        if (!IsVlcPlayerOpen && !IsNowPlayingFullScreen) return false;
        switch (key)
        {
            case "LB": AdjustRating(-1); return true;
            case "RB": AdjustRating(1); return true;
            case "Enter": case "X": TransportPlayPause(); return true;
            case "Left":  TransportSeek(-1); return true;
            case "Right": TransportSeek(1); return true;
            case "Up":    if (IsVlcPlayerOpen) TransportStep(1); else StepTrack(-1); return true;
            case "Down":  if (IsVlcPlayerOpen) TransportStep(-1); else StepTrack(1); return true;
            case "Escape": case "Y":
                if (IsVlcPlayerOpen) CloseVlcPlayer(); else IsNowPlayingFullScreen = false;
                return true;
        }
        return false;
    }

    /// <summary>Handles a key on the movie / TV info page. Returns true when consumed.</summary>
    public bool HandleDetailKey(string key)
    {
        if (!IsDetailOpen) return false;
        switch (key)
        {
            case "LB": AdjustRating(-1); return true;
            case "RB": AdjustRating(1); return true;
            case "X": if (SelectedItem != null) ToggleFavourite(SelectedItem); return true;
            case "Enter": PlayDetail(); return true;
            case "Left":  MoveDetail(-1); return true;
            case "Right": MoveDetail(1); return true;
            case "Escape": case "Y": IsDetailOpen = false; return true;
        }
        return true;
    }

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
        ApplyStatsAndCachedInfo();
        NotifyLibraryChanged();
        StartEnrichment();
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
                string artwork = FindArtwork(file, mediaFolder);
                destination.Add(new MediaLibraryItem
                {
                    CoverPath = artwork,
                    HasLocalCover = artwork.Length > 0,
                    DisplayTitle = title,
                    Gradient = GradientFor(title),
                    Group = segments.Length > 1 ? segments[0] : categoryFolderNames[0],
                    Title = Path.GetFileName(file),
                    FullPath = file,
                    SourceFolder = mediaFolder,
                    MediaType = categoryFolderNames[0] == "Music" ? "music" : "video",
                    Extension = extension,
                    FileSizeBytes = SafeGetFileSize(file),
                    AddedUtc = SafeGetAddedUtc(file)
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

    private static DateTime SafeGetAddedUtc(string filePath)
    {
        try { return File.GetLastWriteTimeUtc(filePath); }
        catch { return default; }
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
        StopVideoRequested?.Invoke();
        IsVlcPlayerOpen = false;
        VlcMediaPath    = "";
    }
}
