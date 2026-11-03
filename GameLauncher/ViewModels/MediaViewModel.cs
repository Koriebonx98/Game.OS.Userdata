using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace GameLauncher.ViewModels;

public partial class MediaViewModel : ObservableObject
{
    public sealed partial class MediaLibraryItem : ObservableObject
    {
        /// <summary>True while the controller / keyboard highlight is on this item.</summary>
        [ObservableProperty] private bool _isFocused;
        /// <summary>"all" / "movies" / "tv" for the browse tiles on the home shelves; empty for real files.</summary>
        public string Special { get; init; } = "";
        public bool IsSpecial => Special.Length > 0;
        /// <summary>TV episodes: season / episode (0 = unknown) and the episode name.</summary>
        public int Season { get; init; }
        public int Episode { get; init; }
        public string EpisodeLabel { get; init; } = "";
        /// <summary>Text under a poster tile; a show name when the tile stands for a whole show.</summary>
        public string TileTitle { get; init; } = "";
        public string TileText => TileTitle.Length > 0 ? TileTitle : DisplayTitle;
        /// <summary>Name used in episode lists.</summary>
        public string ListTitle => IsTv && EpisodeLabel.Length > 0 ? EpisodeLabel : DisplayTitle;
        public string Title { get; init; } = "";
        public string FullPath { get; init; } = "";
        public string SourceFolder { get; init; } = "";
        public string MediaType { get; init; } = "";
        public string Extension { get; init; } = "";
        public long FileSizeBytes { get; init; }
        /// <summary>First sub-folder under the category folder (show / artist); empty when the file sits directly in it.</summary>
        public string Group { get; init; } = "";
        public string DisplayTitle { get; init; } = "";
        /// <summary>Second folder level under an artist (music); empty when the song sits directly in the artist folder.</summary>
        public string Album { get; init; } = "";
        public string AlbumLabel => Album.Length > 0 ? Album : "Singles & other";
        /// <summary>True for episodes found in a TV folder; false for movies and music.</summary>
        public bool IsTv { get; init; }
        /// <summary>Resolution parsed from the file name ("1080p"), or empty.</summary>
        public string Quality { get; init; } = "";
        /// <summary>Container format without the dot ("MP4").</summary>
        public string Format => Extension.TrimStart('.').ToUpperInvariant();
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
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine)), NotifyPropertyChangedFor(nameof(FactsLine))] private int _year;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine))] private string _genres = "";
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine)), NotifyPropertyChangedFor(nameof(ScoreLabel)), NotifyPropertyChangedFor(nameof(HasScore))] private double _score;
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine)), NotifyPropertyChangedFor(nameof(FactsLine))] private string _certification = "";
        [ObservableProperty, NotifyPropertyChangedFor(nameof(InfoLine)), NotifyPropertyChangedFor(nameof(FactsLine))] private int _runtimeMinutes;

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
        public IReadOnlyList<string> GenreList => Genres.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        public string FactsLine => string.Join("   ·   ", new[]
        {
            Year > 0 ? Year.ToString() : "", Certification, RuntimeMinutes > 0 ? (RuntimeMinutes >= 60 ? $"{RuntimeMinutes / 60}h {RuntimeMinutes % 60:00}m" : $"{RuntimeMinutes} min") : "", Quality, Format,
        }.Where(x => x.Length > 0));
        public bool HasScore => Score > 0;
        public bool HasGenres => Genres.Length > 0;
        public string InfoLine => string.Join("  ·  ", new[]
        {
            Year > 0 ? Year.ToString() : "", Quality, Format, Certification, RuntimeMinutes > 0 ? $"{RuntimeMinutes} min" : "", Genres,
        }.Where(x => x.Length > 0));

        public void ApplyStat(MediaStat st)
        {
            PlayCount = st.PlayCount; Rating = st.Rating; Favourite = st.Favourite; Watched = st.Watched;
            ResumeMs = st.ResumeMs; DurationMs = st.DurationMs; LastPlayedUtc = st.LastPlayedUtc; TotalSeconds = st.TotalSeconds;
        }

        public void ApplyMeta(MediaMetadata m)
        {
            Overview = m.Overview; if (m.Year > 0) Year = m.Year; Genres = string.Join(", ", m.Genres); Score = m.Score;
            Certification = m.Certification; RuntimeMinutes = m.RuntimeMinutes;
            if (!HasLocalCover && m.PosterFile.Length > 0) CoverPath = m.PosterFile;
        }

        /// <summary>Same file on another shelf, with its own focus flag.</summary>
        public MediaLibraryItem Clone(string? tileTitle = null)
        {
            var c = new MediaLibraryItem
            {
                Season = Season, Episode = Episode, EpisodeLabel = EpisodeLabel, TileTitle = tileTitle ?? TileTitle,
                Special = Special, Title = Title, FullPath = FullPath, SourceFolder = SourceFolder, MediaType = MediaType,
                Extension = Extension, FileSizeBytes = FileSizeBytes, Group = Group, DisplayTitle = DisplayTitle, Album = Album,
                IsTv = IsTv, Quality = Quality, Gradient = Gradient, HasLocalCover = HasLocalCover, AddedUtc = AddedUtc,
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
        /// <summary>False for the continuation rows of the A-Z grid.</summary>
        public bool ShowHeader { get; init; } = true;
        /// <summary>True for the rows of the A-Z grid (as opposed to the shelves above it).</summary>
        public bool IsGrid { get; init; }
        public IReadOnlyList<MediaLibraryItem> Items { get; init; } = Array.Empty<MediaLibraryItem>();
        public int Total { get; init; }
        public string CountLabel => Total > 0 ? (Total == 1 ? "1 title" : $"{Total} titles") : Items.Count == 1 ? "1 item" : $"{Items.Count} items";
        public MediaLibraryItem? Cover => Items.FirstOrDefault(i => i.CoverPath.Length > 0) ?? Items.FirstOrDefault();
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

    private static readonly System.Text.RegularExpressions.Regex QualityRx =
        new(@"\b(2160p|1440p|1080p|720p|576p|480p|4k|uhd)\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>Splits "21 Days Later (2001) (1080p).mp4" into name, year and quality.</summary>
    private static (string Title, int Year, string Quality) ParseFileName(string fileName)
    {
        var raw = Path.GetFileNameWithoutExtension(fileName);
        var qm = QualityRx.Match(raw);
        string quality = qm.Success ? qm.Value.ToLowerInvariant().Replace("uhd", "4K").Replace("4k", "4K") : "";
        var title = MediaMetadataService.CleanQuery(raw, out int year);
        title = System.Text.RegularExpressions.Regex.Replace(title, @"[\(\[][^\)\]]*[\)\]]", " ");
        title = System.Text.RegularExpressions.Regex.Replace(title, @"\s+", " ").Trim(' ', '-', '(', '[', ')', ']');
        if (title.Length == 0) title = raw.Replace('.', ' ').Replace('_', ' ').Trim();
        return (title.Length > 0 ? title : fileName, year, quality);
    }

    // ── VLC local file player ─────────────────────────────────────────────────
    /// <summary>True when the in-app VLC file-player overlay is visible.</summary>
    [ObservableProperty] private bool   _isVlcPlayerOpen;

    // ── Kodi-style on-screen controls: hidden in full screen until input, always shown when windowed ──
    [ObservableProperty, NotifyPropertyChangedFor(nameof(ControlsVisible))] private bool _isOsdActive;
    [ObservableProperty] private int _transportFocus = 1;
    public bool ControlsVisible => !IsPip && (!IsPlayerWindowFullscreen || IsOsdActive);
    public bool IsTransportFocus0 => TransportFocus == 0;
    public bool IsTransportFocus1 => TransportFocus == 1;
    public bool IsTransportFocus2 => TransportFocus == 2;
    public bool IsTransportFocus3 => TransportFocus == 3;
    public bool IsTransportFocus4 => TransportFocus == 4;
    public bool IsTransportFocus5 => TransportFocus == 5;
    private const int TransportButtonCount = 6;
    private System.Threading.CancellationTokenSource? _osdCts;

    partial void OnTransportFocusChanged(int value)
    {
        for (int i = 0; i < TransportButtonCount; i++) OnPropertyChanged("IsTransportFocus" + i);
    }

    /// <summary>Shows the transport controls and hides them again a few seconds after the last input (full screen only).</summary>
    public void ShowOsd()
    {
        IsOsdActive = true;
        _osdCts?.Cancel();
        var cts = _osdCts = new System.Threading.CancellationTokenSource();
        _ = Task.Delay(4000, cts.Token).ContinueWith(t =>
        {
            if (t.IsCanceled) return;
            Avalonia.Threading.Dispatcher.UIThread.Post(() => { if (!cts.IsCancellationRequested) IsOsdActive = false; });
        }, TaskScheduler.Default);
    }

    private void ActivateTransportButton()
    {
        switch (TransportFocus)
        {
            case 0: VideoSeekBack(); break;
            case 1: ToggleVideoPause(); break;
            case 2: VideoSeekForward(); break;
            case 3: ToggleFullscreen(); break;
            case 4: EnterPip(); break;
            case 5: CloseVlcPlayer(); break;
        }
    }
    [ObservableProperty, NotifyPropertyChangedFor(nameof(IsVlcFullView))] private bool _isPip;
    [ObservableProperty] private bool _isPipPromptOpen;
    [ObservableProperty] private int _pipChoice;
    /// <summary>Full-screen player also takes over the window (true) or stays inside it (false).</summary>
    [ObservableProperty] private bool _isPlayerWindowFullscreen = true;
    /// <summary>True while the video fills the page (open and not shrunk to picture-in-picture).</summary>
    public bool IsVlcFullView => IsVlcPlayerOpen && !IsPip;
    public bool IsPipChoice0 => PipChoice == 0;
    public bool IsPipChoice1 => PipChoice == 1;
    public bool IsPipChoice2 => PipChoice == 2;
    public bool IsPipChoice3 => PipChoice == 3;
    public string FullscreenToggleLabel => IsPlayerWindowFullscreen ? "🗗  Exit video full screen" : "⛶  Full screen";

    // The picture-in-picture video is the same overlay, just resized and pinned to a corner of the page.
    private (double w, double h) PipDims => PipSize switch { "Small" => (320, 180), "Large" => (640, 360), _ => (480, 270) };
    private const double PipStripHeight = 40;
    public Avalonia.Layout.HorizontalAlignment PlayerHAlign => !IsPip ? Avalonia.Layout.HorizontalAlignment.Stretch
        : PipPosition.EndsWith("left", StringComparison.OrdinalIgnoreCase) ? Avalonia.Layout.HorizontalAlignment.Left : Avalonia.Layout.HorizontalAlignment.Right;
    public Avalonia.Layout.VerticalAlignment PlayerVAlign => !IsPip ? Avalonia.Layout.VerticalAlignment.Stretch
        : PipPosition.StartsWith("Top", StringComparison.OrdinalIgnoreCase) ? Avalonia.Layout.VerticalAlignment.Top : Avalonia.Layout.VerticalAlignment.Bottom;
    public double PlayerWidth => IsPip ? PipDims.w : double.NaN;
    public double PlayerHeight => IsPip ? PipDims.h + PipStripHeight : double.NaN;
    public Avalonia.Thickness PlayerMargin => IsPip ? new Avalonia.Thickness(20)
        : IsPlayerWindowFullscreen ? new Avalonia.Thickness(0) : new Avalonia.Thickness(56, 36);
    public bool IsPipVisible => IsVlcPlayerOpen && IsPip;
    private void NotifyPlayerLayout()
    {
        foreach (var n in new[] { nameof(PlayerHAlign), nameof(PlayerVAlign), nameof(PlayerWidth), nameof(PlayerHeight), nameof(PlayerMargin), nameof(IsPipVisible), nameof(FullscreenToggleLabel), nameof(ControlsVisible) })
            OnPropertyChanged(n);
    }
    partial void OnPipPositionChanged(string value) => NotifyPlayerLayout();
    partial void OnPipSizeChanged(string value) => NotifyPlayerLayout();
    partial void OnIsPlayerWindowFullscreenChanged(bool value) { NotifyPlayerLayout(); OnPropertyChanged(nameof(ControlsVisible)); if (value) ShowOsd(); }
    public Action<bool>? PipRequested { get; set; }
    [RelayCommand] private void EnterPip() { IsPipPromptOpen = false; IsPip = true; }
    [RelayCommand] private void ExitPip() => IsPip = false;
    [RelayCommand] private void DismissPipPrompt() => IsPipPromptOpen = false;
    [RelayCommand] private void ToggleFullscreen() { IsPipPromptOpen = false; if (IsPip) IsPip = false; IsPlayerWindowFullscreen = !IsPlayerWindowFullscreen; }
    partial void OnIsPipChanged(bool value) { NotifyPlayerLayout(); PipRequested?.Invoke(value); }
    partial void OnPipChoiceChanged(int value)
    {
        OnPropertyChanged(nameof(IsPipChoice0)); OnPropertyChanged(nameof(IsPipChoice1)); OnPropertyChanged(nameof(IsPipChoice2)); OnPropertyChanged(nameof(IsPipChoice3));
    }
    /// <summary>Picture-in-picture on/off from the quick menu.</summary>
    public void TogglePip() { if (IsVlcPlayerOpen) { IsPipPromptOpen = false; IsPip = !IsPip; } }
    public void ToggleWindowFullscreen() { if (IsVlcPlayerOpen) ToggleFullscreen(); }
    public void ClosePlayer() { if (IsVlcPlayerOpen) CloseVlcPlayer(); }
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
        if (SelectedItem == null || SelectedItem.IsTv == false || !AutoPlayNextEpisode) return null;
        var list = DetailRelated;
        int idx = list.ToList().FindIndex(i => i.FullPath == SelectedItem.FullPath);
        int next = idx + 1;
        while (SkipWatchedEpisodes && next < list.Count && list[next].Watched) next++;
        if (idx < 0 || next >= list.Count) return null;
        _videoCompleted = true;
        EndVideoSession();
        SelectedItem = list[next];
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
    /// <summary>Movies &amp; TV page design: "Default", "Cinema", "Prime", "AppleTV" or "Kodi".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsCinemaMoviesTv))]
    [NotifyPropertyChangedFor(nameof(IsPrimeMoviesTv))]
    [NotifyPropertyChangedFor(nameof(IsAppleTvMoviesTv))]
    [NotifyPropertyChangedFor(nameof(IsKodiMoviesTv))]
    [NotifyPropertyChangedFor(nameof(IsDefaultMoviesTv))]
    private string _moviesTvTheme = "Default";
    /// <summary>Music page design: "Default", "Spotify", "iTunes" or "VLC".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSpotifyMusic))]
    [NotifyPropertyChangedFor(nameof(IsItunesMusic))]
    [NotifyPropertyChangedFor(nameof(IsVlcMusic))]
    [NotifyPropertyChangedFor(nameof(IsDefaultMusic))]
    private string _musicTheme = "Default";

    private bool MoviesThemeIs(string name) => string.Equals(MoviesTvTheme, name, StringComparison.OrdinalIgnoreCase);
    private bool MusicThemeIs(string name) => string.Equals(MusicTheme, name, StringComparison.OrdinalIgnoreCase);

    public bool IsCinemaMoviesTv  => MoviesThemeIs("Cinema") || MoviesThemeIs("Netflix");
    public bool IsPrimeMoviesTv   => MoviesThemeIs("Prime");
    public bool IsAppleTvMoviesTv => MoviesThemeIs("AppleTV") || MoviesThemeIs("Apple TV");
    public bool IsKodiMoviesTv    => MoviesThemeIs("Kodi");
    public bool IsDefaultMoviesTv => !IsCinemaMoviesTv && !IsPrimeMoviesTv && !IsAppleTvMoviesTv && !IsKodiMoviesTv;
    public bool IsSpotifyMusic    => MusicThemeIs("Spotify");
    public bool IsItunesMusic     => MusicThemeIs("iTunes");
    public bool IsVlcMusic        => MusicThemeIs("VLC");
    public bool IsDefaultMusic    => !IsSpotifyMusic && !IsItunesMusic && !IsVlcMusic;
    public bool IsVideoSection     => SelectedMediaSection != "music";
    public bool IsMusicPage        => SelectedMediaSection == "music";

    /// <summary>Items of the active video section grouped by show / folder (one row each in the Netflix layout).</summary>
    // Cached so controller focus flags live on stable group objects.
    private IReadOnlyList<MediaGroup>? _activeGroups;
    public IReadOnlyList<MediaGroup> ActiveGroups => _activeGroups ??= BuildShelves();
    public bool HasNoActiveItems => !ActiveItems.Any();
    /// <summary>Titles exist, but the search / filters hide all of them.</summary>
    public bool HasNoResults => !HasNoActiveItems && ActiveGroups.Count == 0;
    public bool HasNoMusic => Music.Count == 0;

    // ── Filters / sort (Movies & TV page) ─────────────────────────────────────
    public static IReadOnlyList<string> SortModes { get; } = new[] { "Title", "Recently added", "Most played", "Top rated", "Year" };
    public static IReadOnlyList<string> FilterModes { get; } = new[] { "All", "Unwatched", "Watched", "In progress", "My List" };
    public const string AllGenres = "All genres";

    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private string _sortMode = "Title";
    [ObservableProperty] private string _filterMode = "All";
    [ObservableProperty] private string _genreFilter = AllGenres;
    public static IReadOnlyList<string> TypeScopes { get; } = new[] { "All", "Movies", "TV Shows" };
    /// <summary>Which kind of video the grid below the shelves lists: everything, only movies or only TV shows.</summary>
    [ObservableProperty] private string _typeScope = "All";
    public bool IsScoped => TypeScope != "All";
    public bool ShowClearFilters => IsFiltering || IsScoped;
    partial void OnTypeScopeChanged(string value)
    {
        OnPropertyChanged(nameof(IsScoped)); OnPropertyChanged(nameof(ShowClearFilters));
        OnPropertyChanged(nameof(AvailableGenres));
        RefreshShelves();
    }
    private const int GridColumns = 5;

    private void ApplyBrowseTile(string special)
    {
        switch (special)
        {
            case "movies": TypeScope = "Movies"; break;
            case "tv": TypeScope = "TV Shows"; break;
            default: TypeScope = "All"; SortMode = "Recently added"; break;
        }
        var groups = ActiveGroups;
        int r = groups.ToList().FindIndex(g => g.IsGrid);
        if (r >= 0) { _row = r; _col = 0; _zone = 1; ApplyMediaFocus(); }
    }

    private static MediaLibraryItem BrowseTile(string special, string title, string sub, string gradient) =>
        new() { Special = special, DisplayTitle = title, Extension = sub, Gradient = gradient };

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
        TypeScope = "All";
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
        OnPropertyChanged(nameof(ShowClearFilters));
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
        if (TypeScope == "Movies" && i.IsTv) return false;
        if (TypeScope == "TV Shows" && !i.IsTv) return false;
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
        _ => items.OrderBy(i => i.IsTv ? i.Group : i.DisplayTitle, StringComparer.OrdinalIgnoreCase).ThenBy(i => i.Season).ThenBy(i => i.Episode),
    };

    /// <summary>
    /// Shelves for the active section. With no filter: Continue Watching, My List, Recently Added, Top Rated and Most Played
    /// first, then one shelf per show / folder. With a filter or search: only the matching titles, still grouped.
    /// </summary>
    /// <summary>
    /// One tile per show instead of one per episode. nextUp: the tile opens the episode to watch next (in progress, else the first
    /// unwatched, else the first). showName: the tile reads as the show name rather than the episode.
    /// </summary>
    private static IEnumerable<MediaLibraryItem> OneTilePerShow(IEnumerable<MediaLibraryItem> ordered, List<MediaLibraryItem> all, bool nextUp, bool showName)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var it in ordered)
        {
            if (!it.IsTv) { yield return it.Clone(); continue; }
            if (!seen.Add(it.Group)) continue;
            var rep = it;
            if (nextUp)
            {
                var eps = all.Where(x => x.IsTv && string.Equals(x.Group, it.Group, StringComparison.OrdinalIgnoreCase))
                             .OrderBy(x => x.Season).ThenBy(x => x.Episode).ThenBy(x => x.DisplayTitle, StringComparer.OrdinalIgnoreCase).ToList();
                rep = eps.FirstOrDefault(x => x.HasProgress) ?? eps.FirstOrDefault(x => !x.Watched) ?? eps[0];
            }
            yield return rep.Clone(showName ? it.Group : null);
        }
    }

    private IReadOnlyList<MediaGroup> BuildShelves()
    {
        var items = ActiveItems.Where(Passes).ToList();
        var shelves = new List<MediaGroup>();
        if (items.Count == 0) return shelves;
        if (!IsFiltering)
        {
            void Add(string title, IEnumerable<MediaLibraryItem> src, int take = 15, MediaLibraryItem? tail = null, bool nextUp = false, bool showName = false)
            {
                var list = OneTilePerShow(src, items, nextUp, showName).Take(take).ToList();
                if (list.Count == 0) return;
                if (tail != null) list.Add(tail);
                shelves.Add(new MediaGroup { Title = title, Items = list });
            }
            Add("Continue Watching", items.Where(i => i.HasProgress).OrderByDescending(i => i.LastPlayedUtc));
            // Ten newest, then an "All" tile that opens the full list.
            Add("Recently Added", items.OrderByDescending(i => i.AddedUtc), 10, BrowseTile("all", "All", "Browse", "#1f2937,#4b5563"), true, true);
            Add("Watch Again", items.Where(i => i.Watched).OrderByDescending(i => i.LastPlayedUtc), showName: true);
            Add("Recommended for You", Recommend(items), nextUp: true, showName: true);
            Add("My List", items.Where(i => i.Favourite).OrderBy(i => i.TileText, StringComparer.OrdinalIgnoreCase), showName: true);
            shelves.Add(new MediaGroup
            {
                Title = "Browse",
                Items = new[]
                {
                    BrowseTile("movies", "Movies", "Browse", "#1e1b4b,#4338ca"),
                    BrowseTile("tv", "TV Shows", "Browse", "#064e3b,#10b981"),
                },
            });
        }
        // Movies and TV combined in A-Z order (or the chosen sort), laid out in rows of tiles.
        var sorted = OneTilePerShow(Sorted(items), items, true, true).ToList();
        string gridTitle = (TypeScope == "All" ? "Movies & TV" : TypeScope) + (SortMode == "Title" ? " · A–Z" : $" · {SortMode}");
        for (int n = 0; n < sorted.Count; n += GridColumns)
            shelves.Add(new MediaGroup
            {
                Title = n == 0 ? gridTitle : "", ShowHeader = n == 0, IsGrid = true,
                Items = sorted.GetRange(n, Math.Min(GridColumns, sorted.Count - n)),
                Total = n == 0 ? sorted.Count : 0,
            });
        return shelves;
    }

    /// <summary>Unwatched titles ranked by how many genres they share with what the user rated 4+, favourited or watched.</summary>
    private static IEnumerable<MediaLibraryItem> Recommend(List<MediaLibraryItem> items)
    {
        static IEnumerable<string> Genres(MediaLibraryItem i) =>
            i.Genres.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var weights = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        foreach (var i in items)
        {
            double w = (i.Rating >= 4 ? i.Rating - 2 : 0) + (i.Favourite ? 2 : 0) + (i.Watched ? 1 : 0) + Math.Min(i.PlayCount, 3) * 0.5;
            if (i.Rating is > 0 and < 3) w = -1;
            if (w == 0) continue;
            foreach (var g in Genres(i)) weights[g] = weights.GetValueOrDefault(g) + w;
        }
        if (weights.Count == 0) return Array.Empty<MediaLibraryItem>();
        return items.Where(i => !i.Watched && !i.HasProgress && i.Rating == 0)
            .Select(i => (item: i, score: Genres(i).Sum(g => weights.GetValueOrDefault(g)) + i.Score / 10.0))
            .Where(x => x.score > 0).OrderByDescending(x => x.score).Select(x => x.item);
    }

    private void NotifyLibraryChanged()
    {
        _activeGroups = null;
        OnPropertyChanged(nameof(ActiveItems));
        OnPropertyChanged(nameof(ActiveGroups));
        OnPropertyChanged(nameof(ActiveSectionSummary));
        OnPropertyChanged(nameof(HasNoActiveItems));
        OnPropertyChanged(nameof(HasNoResults));
        OnPropertyChanged(nameof(AvailableGenres));
        RefreshMusicBrowser();
        OnPropertyChanged(nameof(HasNoMusic));
    }

    public IEnumerable<MediaLibraryItem> ActiveItems => SelectedMediaSection switch
    {
        "movies" => Movies.Concat(TvShows),
        _ => Music
    };

    public string ActiveSectionTitle => SelectedMediaSection switch
    {
        "movies" => "Movies & TV",
        _ => "Music"
    };

    public string ActiveSectionSummary => SelectedMediaSection switch
    {
        "movies" => $"{Movies.Count + TvShows.Count} item(s) found",
        _ => $"{Music.Count} item(s) found"
    };

    public bool IsMoviesSelected => SelectedMediaSection == "movies";
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
        item.MediaType == "music" ? "music" : item.IsTv ? "tv" : "movie";

    /// <summary>Folders searched on every drive (and the user profile) for the Movies / TV Shows / Music category folders.</summary>
    private static readonly string[] MediaParentFolderNames =
        { "Media", "Media Library", "Videos", "Video", "Entertainment", "Downloads", "Plex", "Jellyfin", "Kodi" };

    private static readonly string[] CategoryFolderNames = { "Movies", "Films", "TV Shows", "TV", "Series", "Shows", "TV Series", "Television", "Movie", "Music", "Songs", "Audio" };

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
        _ = EnrichLibraryAsync(todo, run);
    }

    /// <summary>Startup scan: movies / TV first (title + provider lookup), then one artwork lookup per music album.</summary>
    private async System.Threading.Tasks.Task EnrichLibraryAsync(IReadOnlyList<MediaLibraryItem> videos, int run)
    {
        try
        {
            if (videos.Count > 0) await EnrichAsync(videos, false, run).ConfigureAwait(false);
            var albums = _music.Where(t => !t.HasLocalCover && t.CoverPath.Length == 0)
                .GroupBy(t => (t.Group.ToLowerInvariant(), t.Album.ToLowerInvariant())).Select(g => g.First()).Take(40).ToList();
            foreach (var track in albums)
            {
                if (run != _enrichRun) return;
                var meta = await MediaMetadataService.GetAsync("music", track.DisplayTitle, track.Group).ConfigureAwait(false);
                if (meta == null) continue;
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    foreach (var t in _music.Where(x => string.Equals(x.Group, track.Group, StringComparison.OrdinalIgnoreCase)
                                                      && string.Equals(x.Album, track.Album, StringComparison.OrdinalIgnoreCase)))
                        t.ApplyMeta(meta);
                });
                await System.Threading.Tasks.Task.Delay(3500).ConfigureAwait(false);
            }
        }
        catch (Exception ex) { DevLogService.Log($"[Media] Background scan failed: {ex.Message}"); }
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
        try
        {
            var meta = await MediaMetadataService.GetAsync("music", track.DisplayTitle, track.Group).ConfigureAwait(false);
            if (meta != null)
                Avalonia.Threading.Dispatcher.UIThread.Post(() => { foreach (var c in EveryCopy(track.FullPath)) c.ApplyMeta(meta); });
        }
        catch (Exception ex) { DevLogService.Log($"[Media] Artwork lookup failed: {ex.Message}"); } // async void: never let it escape
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
    public long TakeResumeMs() { long r = ResumePlayback ? _pendingResumeMs : 0; _pendingResumeMs = 0; return r; }
    public void MarkVideoCompleted() => _videoCompleted = true;

    private string KindLabel(MediaLibraryItem i) => KindOf(i);

    partial void OnIsVlcPlayerOpenChanged(bool value)
    {
        OnPropertyChanged(nameof(IsVlcFullView));
        NotifyPlayerLayout();
        if (value) { TransportFocus = 1; ShowOsd(); }
        else { _osdCts?.Cancel(); IsOsdActive = false; }
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
        bool done = _videoCompleted || (_lastVideoLen > 0 && _lastVideoPos >= _lastVideoLen * (Math.Clamp(MarkWatchedPercent, 50, 100) / 100.0));
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
    [ObservableProperty] private bool _resumePlayback = true;
    [ObservableProperty] private int  _markWatchedPercent = 90;
    [ObservableProperty] private bool _skipWatchedEpisodes = true;
    [ObservableProperty] private string _pipPosition = "Bottom right";
    [ObservableProperty] private string _pipSize = "Medium";
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
        OnPropertyChanged(nameof(DetailTitle));
        OnPropertyChanged(nameof(DetailEpisodeLabel));
    }

    /// <summary>Other files of the same show / folder (episodes for TV shows).</summary>
    public IReadOnlyList<MediaLibraryItem> DetailRelated =>
        SelectedItem == null || SelectedItem.MediaType == "music"
            ? Array.Empty<MediaLibraryItem>()
            : ActiveItems.Where(i => string.Equals(i.Group, SelectedItem.Group, StringComparison.OrdinalIgnoreCase))
                         .OrderBy(i => i.Season).ThenBy(i => i.Episode).ThenBy(i => i.DisplayTitle, StringComparer.OrdinalIgnoreCase).ToList();
    public bool HasDetailRelated => SelectedItem?.IsTv == true ? DetailRelated.Count > 0 : DetailRelated.Count > 1;
    public string DetailRelatedTitle => SelectedItem?.IsTv == true ? $"Episodes · {SelectedItem?.Group}" : $"More in {SelectedItem?.Group}";
    public string DetailAddedLabel => SelectedItem == null || string.IsNullOrEmpty(SelectedItem.AddedLabel) ? "" : $"Added {SelectedItem.AddedLabel}";
    public string DetailKindLabel => SelectedItem?.IsTv == true ? "TV SHOW" : "MOVIE";
    public string DetailTitle => SelectedItem?.IsTv == true && SelectedItem.Group.Length > 0
        ? SelectedItem.Group
        : SelectedItem?.DisplayTitle ?? "";
    public string DetailEpisodeLabel => SelectedItem is not { IsTv: true } item
        ? ""
        : item.Season > 0 && item.Episode > 0
            ? $"Season {item.Season} · Episode {item.Episode}"
            : item.Season > 0
                ? $"Season {item.Season}"
                : item.Episode > 0
                    ? $"Episode {item.Episode}"
                    : "";

    /// <summary>Click / A on a poster: music plays, movies and TV shows open their info page (unless disabled in settings).</summary>
    [RelayCommand]
    private void OpenMediaItem(MediaLibraryItem? item)
    {
        if (item == null) return;
        if (item.IsSpecial) { ApplyBrowseTile(item.Special); return; }
        SelectedItem = item;
        bool details = item.MediaType != "music" && (item.IsTv ? ShowTvDetails : ShowMovieDetails);
        if (details)
        {
            IsDetailOpen = true;
            // Fetch missing info automatically instead of waiting for a manual refresh.
            if (OnlineInfoEnabled && item.Overview.Length == 0) _ = EnrichAsync(new[] { item }, force: false, _enrichRun);
        }
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

    // ── Info page controller focus: 0..4 = Play, My List, Watched, Info, Back; 5+ = related title (index - 5) ──
    private const int DetailButtonCount = 5;
    private int _detailIdx;
    public bool IsDetailPlayFocused    => IsDetailOpen && _detailIdx == 0;
    public bool IsDetailListFocused    => IsDetailOpen && _detailIdx == 1;
    public bool IsDetailWatchedFocused => IsDetailOpen && _detailIdx == 2;
    public bool IsDetailInfoFocused    => IsDetailOpen && _detailIdx == 3;
    public bool IsDetailBackFocused    => IsDetailOpen && _detailIdx == 4;

    partial void OnIsDetailOpenChanged(bool value)
    {
        _detailIdx = 0;
        ApplyDetailFocus();
    }

    private void ApplyDetailFocus()
    {
        var related = DetailRelated;
        for (int i = 0; i < related.Count; i++) related[i].IsFocused = IsDetailOpen && _detailIdx == DetailButtonCount + i;
        OnPropertyChanged(nameof(IsDetailPlayFocused));
        OnPropertyChanged(nameof(IsDetailListFocused));
        OnPropertyChanged(nameof(IsDetailWatchedFocused));
        OnPropertyChanged(nameof(IsDetailInfoFocused));
        OnPropertyChanged(nameof(IsDetailBackFocused));
    }

    /// <summary>D-pad on the info page: Left / Right across the buttons, Up / Down between the buttons and the episode list.</summary>
    public void MoveDetail(int dx, int dy = 0)
    {
        int related = HasDetailRelated ? DetailRelated.Count : 0;
        if (dx != 0 && _detailIdx < DetailButtonCount)
            _detailIdx = Math.Clamp(_detailIdx + dx, 0, DetailButtonCount - 1);
        else if (dy > 0)
        {
            if (_detailIdx < DetailButtonCount) { if (related > 0) _detailIdx = DetailButtonCount; }
            else _detailIdx = Math.Min(_detailIdx + 1, DetailButtonCount + related - 1);
        }
        else if (dy < 0)
            _detailIdx = _detailIdx > DetailButtonCount ? _detailIdx - 1 : _detailIdx == DetailButtonCount ? 0 : _detailIdx;
        ApplyDetailFocus();
    }

    /// <summary>A on the info page: activates the highlighted button, or switches to the highlighted episode.</summary>
    public void ActivateDetail()
    {
        switch (_detailIdx)
        {
            case 0: PlayDetail(); break;
            case 1: if (SelectedItem != null) ToggleFavourite(SelectedItem); break;
            case 2: if (SelectedItem != null) ToggleWatched(SelectedItem); break;
            case 3: RefreshOnlineInfo(); break;
            case 4: IsDetailOpen = false; break;
            default:
                var related = DetailRelated;
                int i = _detailIdx - DetailButtonCount;
                if (i >= 0 && i < related.Count)
                {
                    SelectedItem = related[i];
                    _detailIdx = 0;
                    ApplyDetailFocus();
                }
                break;
        }
    }

    // ── Controller / keyboard navigation ──────────────────────────────────────
    // Zones: 0 = tab bar (Movies / TV Shows), 1 = content (poster rows or song list),
    //        2 = music folder list (left column, first entry is "All songs").
    private int _zone = 1;
    private int _tabIdx;
    private int _row, _col;
    private MediaLibraryItem? _focusedItem;
    private MediaGroup? _focusedGroup;

    /// <summary>Raised after the highlight moved so the view can scroll it into view.</summary>
    public event Action? MediaFocusChanged;

    public bool IsTabMoviesFocused => _zone == 0 && _tabIdx == 0;
    public bool IsFilterSortFocused  => _zone == 0 && _tabIdx == 1;
    public bool IsFilterModeFocused  => _zone == 0 && _tabIdx == 2;
    public bool IsFilterGenreFocused => _zone == 0 && _tabIdx == 3;
    private const int TopBarItems = 4; // Movies & TV, Sort, Show, Genre

    private static readonly string[] TabSections = { "movies" };

    private static int TabIndexOf(string section) => Math.Max(0, Array.IndexOf(TabSections, section));

    /// <summary>Puts the highlight on the first item of the page (called when the page opens).</summary>
    public void ResetMediaFocus()
    {
        _zone = 1;
        _row = _col = 0;
        _tabIdx = TabIndexOf(SelectedMediaSection);
        if (IsMusicSelected) ResetMusicFocus();
        else ApplyMediaFocus();
    }

    /// <summary>
    /// Moves the highlight. Returns false when Left was pressed at the left edge, so the caller can open the nav menu.
    /// </summary>
    public bool MoveMediaFocus(int dx, int dy)
    {
        if (IsMusicSelected) return MoveMusicFocus(dx, dy);
        bool music = false;
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
                        _row = _col = 0;
                    }
                }
                else if (dy > 0 && ActiveGroups.Count > 0) _zone = 1;
                break;

            case 0:
                _zone = 1;
                break;

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

        }
        ApplyMediaFocus();
        return true;
    }

    /// <summary>A button: play the highlighted poster / song, or step into the song list from the folder list.</summary>
    public void ActivateMediaFocus()
    {
        if (IsMusicSelected) { ActivateMusicFocus(); return; }
        if (_zone == 0)
        {
            switch (_tabIdx)
            {
                case 1: CycleSort(); break;
                case 2: CycleFilter(); break;
                case 3: CycleGenre(); break;
                default: _tabIdx = TabIndexOf(SelectedMediaSection); _zone = 1; break;
            }
            ApplyMediaFocus();
            return;
        }
        if (_zone == 1 && _focusedItem != null) OpenMediaItem(_focusedItem);
    }

    /// <summary>X button: a filter menu (sort, show, genre) like the Games page; on the music page it opens the full-screen player, or the Artists / Playlists tabs when nothing is playing.</summary>
    public void FilterMediaFocus()
    {
        if (IsMusicSelected && HasNowPlaying && !IsMusicMenuOpen) { OpenNowPlayingFullScreen(); return; }
        if (IsMusicSelected) { if (!IsMusicMenuOpen) { _mZone = 0; _mTop = IsMusicPlaylistMode ? 1 : 0; ApplyMusicFocus(); } return; }
        OpenFilterMenu();
    }

    [RelayCommand]
    public void OpenFilterMenu()
    {
        if (IsMusicSelected || IsMusicMenuOpen) return;
        MusicMenuEntries.Clear();
        void Add(string label, Action a) => MusicMenuEntries.Add(new MusicMenuEntry { Label = label, Action = a });
        string Mark(bool on) => on ? "✓  " : "     ";
        foreach (var m in TypeScopes) { var v = m; Add($"{Mark(TypeScope == v)}Type: {v}", () => TypeScope = v); }
        foreach (var m in SortModes) { var v = m; Add($"{Mark(SortMode == v)}Sort: {v}", () => SortMode = v); }
        foreach (var m in FilterModes) { var v = m; Add($"{Mark(FilterMode == v)}Show: {v}", () => FilterMode = v); }
        foreach (var g in AvailableGenres) { var v = g; Add($"{Mark(GenreFilter == v)}Genre: {v}", () => GenreFilter = v); }
        if (ShowClearFilters) Add("✕  Clear all filters", () => ClearFilters());
        MusicMenuTitle = "Filters";
        _menuIdx = 0;
        for (int i = 0; i < MusicMenuEntries.Count; i++) MusicMenuEntries[i].IsFocused = i == 0;
        IsMusicMenuOpen = true;
    }

    /// <summary>Y button: search with the on-screen keyboard.</summary>
    public void SearchMediaFocus()
    {
        if (IsMusicSelected) { OpenMusicSearch(); return; }
        _zone = 0;
        MusicKeyboard.Open(SearchText, "Search", t => SearchText = t, _ => { _zone = 1; ApplyMediaFocus(); });
    }

    /// <summary>Start button: options for the highlighted title / song.</summary>
    public void OpenOptionsMenu()
    {
        if (IsMusicSelected) { OpenMusicMenu(); return; }
        if (IsMusicMenuOpen || _focusedItem == null) return;
        var item = _focusedItem;
        if (item.IsSpecial) { OpenFilterMenu(); return; }
        MusicMenuEntries.Clear();
        void Add(string label, Action a) => MusicMenuEntries.Add(new MusicMenuEntry { Label = label, Action = a });
        Add("▶  Play", () => PlayMediaItem(item));
        Add("ℹ  Details", () => OpenMediaItem(item));
        Add(item.Favourite ? "✓  Remove from My List" : "＋  Add to My List", () => ToggleFavourite(item));
        for (int n = 5; n >= 1; n--)
        {
            int stars = n;
            Add($"{new string('★', stars)}{new string('☆', 5 - stars)}  Rate {stars}" + (item.Rating == stars ? " (tap to clear)" : ""),
                () => Persist(item.FullPath, st => st.Rating = st.Rating == stars ? 0 : stars));
        }
        if (IsPip) { Add("⤢  Expand picture-in-picture", () => IsPip = false); Add("✕  Close player", CloseVlcPlayer); }
        MusicMenuTitle = item.DisplayTitle;
        _menuIdx = 0;
        for (int i = 0; i < MusicMenuEntries.Count; i++) MusicMenuEntries[i].IsFocused = i == 0;
        IsMusicMenuOpen = true;
    }

    private void ApplyMediaFocus()
    {
        if (IsMusicSelected) { ApplyMusicFocus(); return; }
        if (_focusedItem != null) _focusedItem.IsFocused = false;
        if (_focusedGroup != null) _focusedGroup.IsFocused = false;
        _focusedItem = null;
        _focusedGroup = null;

        if (_zone == 1)
        {
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

        OnPropertyChanged(nameof(IsTabMoviesFocused));
        OnPropertyChanged(nameof(IsFilterSortFocused));
        OnPropertyChanged(nameof(IsFilterModeFocused));
        OnPropertyChanged(nameof(IsFilterGenreFocused));
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
        var tracks = _playQueue.Count > 0 ? _playQueue : Music.ToList();
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

    // D-pad / left-stick focus on the full-screen player buttons: previous, back, play / pause, forward, next, stop.
    private const int MusicTransportCount = 6;
    [ObservableProperty] private int _musicTransportFocus = 2;
    public bool IsMusicTransportFocus0 => MusicTransportFocus == 0;
    public bool IsMusicTransportFocus1 => MusicTransportFocus == 1;
    public bool IsMusicTransportFocus2 => MusicTransportFocus == 2;
    public bool IsMusicTransportFocus3 => MusicTransportFocus == 3;
    public bool IsMusicTransportFocus4 => MusicTransportFocus == 4;
    public bool IsMusicTransportFocus5 => MusicTransportFocus == 5;

    partial void OnMusicTransportFocusChanged(int value)
    {
        for (int i = 0; i < MusicTransportCount; i++) OnPropertyChanged("IsMusicTransportFocus" + i);
    }

    partial void OnIsNowPlayingFullScreenChanged(bool value)
    {
        if (value) MusicTransportFocus = 2;
    }

    private void ActivateMusicTransportButton()
    {
        switch (MusicTransportFocus)
        {
            case 0: StepTrack(-1); break;
            case 1: MusicSeekBack(); break;
            case 2: TogglePlayPause(); break;
            case 3: MusicSeekForward(); break;
            case 4: StepTrack(1); break;
            case 5: StopMusic(); break;
        }
    }

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

    // ── Volume (right stick) ─────────────────────────────────────────────────
    [ObservableProperty, NotifyPropertyChangedFor(nameof(VolumeLabel))] private int _volume = 80;
    [ObservableProperty] private bool _isVolumeHudVisible;
    public string VolumeLabel => (Volume == 0 ? "🔇 " : "🔊 ") + Volume + "%";
    public Action<int>? VolumeRequested { get; set; }
    private System.Threading.CancellationTokenSource? _volumeHudCts;

    /// <summary>The right stick controls volume while a video or the full-screen music player is open.</summary>
    public bool IsVolumeStickActive => (IsVlcPlayerOpen || IsNowPlayingFullScreen) && !IsMusicMenuOpen;

    partial void OnVolumeChanged(int value) => VolumeRequested?.Invoke(value);

    public void AdjustVolume(int delta)
    {
        if (delta == 0) return;
        Volume = Math.Clamp(Volume + delta, 0, 100);
        IsVolumeHudVisible = true;
        _volumeHudCts?.Cancel();
        var cts = _volumeHudCts = new System.Threading.CancellationTokenSource();
        _ = System.Threading.Tasks.Task.Delay(1500, cts.Token).ContinueWith(t =>
        {
            if (!t.IsCanceled) Avalonia.Threading.Dispatcher.UIThread.Post(() => IsVolumeHudVisible = false);
        });
    }

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

    /// <summary>LT / RT: a longer jump (3x the skip length) while a video or full-screen music player is open.</summary>
    public void TransportJump(int direction)
    {
        if (!IsVlcPlayerOpen && !IsNowPlayingFullScreen) return;
        SeekByRequested?.Invoke(IsVlcPlayerOpen, direction * MediaSkipSeconds * 3000L);
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
        if (IsVlcPlayerOpen && IsPipPromptOpen)
        {
            switch (key)
            {
                case "Left": case "Up": PipChoice = Math.Max(0, PipChoice - 1); break;
                case "Right": case "Down": PipChoice = Math.Min(3, PipChoice + 1); break;
                case "Escape": IsPipPromptOpen = false; break;
                case "Enter":
                    IsPipPromptOpen = false;
                    if (PipChoice == 0) IsPip = true;
                    else if (PipChoice == 1) ToggleFullscreen();
                    else if (PipChoice == 2) CloseVlcPlayer();
                    break;
            }
            return true;
        }
        if (IsVlcPlayerOpen)
        {
            bool shown = ControlsVisible;
            if (!IsPip) ShowOsd();
            if (shown && HandleVideoControlsKey(key)) return true;
        }
        switch (key)
        {
            case "Menu": if (!IsVlcPlayerOpen) OpenNowPlayingMenu(); return true;
            case "LB": AdjustRating(-1); return true;
            case "RB": AdjustRating(1); return true;
            case "X": TransportPlayPause(); return true;
            case "Enter":
                if (IsVlcPlayerOpen) TransportPlayPause(); else ActivateMusicTransportButton();
                return true;
            case "Left":
                if (IsVlcPlayerOpen) TransportSeek(-1); else MusicTransportFocus = Math.Max(0, MusicTransportFocus - 1);
                return true;
            case "Right":
                if (IsVlcPlayerOpen) TransportSeek(1); else MusicTransportFocus = Math.Min(MusicTransportCount - 1, MusicTransportFocus + 1);
                return true;
            case "Up":    if (IsVlcPlayerOpen) TransportStep(1); else StepTrack(-1); return true;
            case "Down":  if (IsVlcPlayerOpen) TransportStep(-1); else StepTrack(1); return true;
            case "Escape": case "Y":
                if (IsVlcPlayerOpen) { PipChoice = 0; IsPipPromptOpen = true; }
                else IsNowPlayingFullScreen = false;
                return true;
        }
        return false;
    }

    /// <summary>With the on-screen controls showing, ◀ ▶ move between the buttons and A presses one; ▲ ▼ / B hide them.</summary>
    private bool HandleVideoControlsKey(string key)
    {
        switch (key)
        {
            case "Left": TransportFocus = Math.Max(0, TransportFocus - 1); return true;
            case "Right": TransportFocus = Math.Min(TransportButtonCount - 1, TransportFocus + 1); return true;
            case "Enter": ActivateTransportButton(); return true;
            case "Up": case "Down": case "Escape":
                if (IsPlayerWindowFullscreen) { _osdCts?.Cancel(); IsOsdActive = false; return true; }
                return key == "Escape" ? false : true;
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
            case "X": PlayDetail(); return true;
            case "Enter": ActivateDetail(); return true;
            case "Left":  MoveDetail(-1); return true;
            case "Right": MoveDetail(1); return true;
            case "Up":    MoveDetail(0, -1); return true;
            case "Down":  MoveDetail(0, 1); return true;
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
        var roots = GameScannerService.GetDriveRoots().ToList();
        // The user's own folders (Videos, Music, Downloads) live under the profile, not at a drive root.
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(profile)) roots.Add(profile);
        roots = roots.Where(root => !string.IsNullOrWhiteSpace(root) && Directory.Exists(root))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        DevLogService.Log($"[Media] Scanning {roots.Count} root(s): {string.Join(", ", roots)}");

        foreach (var driveRoot in roots)
        {
            try
            {
                TryCollectMediaCategory(driveRoot, _movies, VideoExtensions, knownPaths, "Movies", "Films", "Movie");
                TryCollectMediaCategory(driveRoot, _music, AudioExtensions, knownPaths, "Music", "Songs", "Audio");
                TryCollectMediaCategory(driveRoot, _tvShows, VideoExtensions, knownPaths, "TV Shows", "TV", "Series", "Shows", "TV Series", "Television");
            }
            catch (Exception ex) { DevLogService.Log($"[Media] Scan of '{driveRoot}' failed: {ex.Message}"); }
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
            "movies" or "tvshows" or "tv shows" or "tv" => "movies",
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
        var parents = new List<string> { driveRoot };
        foreach (var name in MediaParentFolderNames) parents.Add(Path.Combine(driveRoot, name));
        foreach (var parent in parents)
        {
            if (!Directory.Exists(parent)) continue;
            try
            {
                categoryDirs.AddRange(Directory
                    .EnumerateDirectories(parent)
                    .Where(path => categoryFolderNames.Contains(
                        Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)));
            }
            catch (Exception ex) { DevLogService.Log($"[Media] Listing '{parent}' failed: {ex.Message}"); }
        }

        foreach (var mediaFolder in categoryDirs)
        {
            // Inaccessible sub-folders are skipped instead of throwing in the middle of the enumeration.
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(mediaFolder, "*", new EnumerationOptions
                {
                    RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.System,
                });
            }
            catch (Exception ex) { DevLogService.Log($"[Media] Scan of '{mediaFolder}' failed: {ex.Message}"); continue; }

            foreach (var file in files)
            {
                string extension = Path.GetExtension(file);
                if (!allowedExtensions.Contains(extension)) continue;
                if (!knownPaths.Add(file)) continue;

                var relative = Path.GetRelativePath(mediaFolder, file);
                var segments = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                bool isMusic = categoryFolderNames[0] == "Music";
                var (title, year, quality) = isMusic ? (Path.GetFileNameWithoutExtension(file).Replace('_', ' ').Trim(), 0, "") : ParseFileName(file);
                bool isTv = categoryFolderNames[0] == "TV Shows";
                string group = segments.Length > 1 ? segments[0] : categoryFolderNames[0];
                int season = 0, episode = 0;
                string episodeLabel = "";
                if (isTv)
                {
                    var tv = TvPathParser.Parse(segments);
                    group = tv.Show; season = tv.Season; episode = tv.Episode;
                    string ep = tv.Episode > 0 ? tv.Code + (tv.EpisodeTitle.Length > 0 ? " · " + tv.EpisodeTitle : "")
                                               : (tv.EpisodeTitle.Length > 0 ? tv.EpisodeTitle : title);
                    episodeLabel = ep;
                    title = string.Equals(ep, tv.Show, StringComparison.OrdinalIgnoreCase) ? ep : $"{tv.Show} · {ep}";
                    year = 0;
                }
                string artwork = FindArtwork(file, mediaFolder);
                destination.Add(new MediaLibraryItem
                {
                    CoverPath = artwork,
                    HasLocalCover = artwork.Length > 0,
                    DisplayTitle = title,
                    Year = year,
                    Quality = quality,
                    IsTv = isTv,
                    Season = season, Episode = episode, EpisodeLabel = episodeLabel,
                    Gradient = GradientFor(isTv ? group : title),
                    Group = group,
                    Album = isMusic && segments.Length > 2 ? segments[1] : "",
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
        IsPipPromptOpen = false;
        IsPip = false;
        StopVideoRequested?.Invoke();
        IsVlcPlayerOpen = false;
        VlcMediaPath    = "";
    }
}
