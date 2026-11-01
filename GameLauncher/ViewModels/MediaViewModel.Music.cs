using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>Music browser: Artist → Album → Song (or Playlists), search, and the Y options menu.</summary>
public sealed partial class MediaViewModel
{
    public sealed partial class MusicEntry : ObservableObject
    {
        [ObservableProperty] private bool _isFocused;
        [ObservableProperty] private bool _isSelected;
        public string Key { get; init; } = "";
        public string Title { get; init; } = "";
        public string Subtitle { get; init; } = "";
        /// <summary>0 = all, 1 = artist, 2 = playlist, 3 = "new playlist", 4 = recommended.</summary>
        public int Kind { get; init; }
    }

    public sealed partial class MusicRow : ObservableObject
    {
        [ObservableProperty] private bool _isFocused;
        public string Title { get; init; } = "";
        public string Subtitle { get; init; } = "";
        public string Detail { get; init; } = "";
        public string CoverPath { get; init; } = "";
        public string Gradient { get; init; } = "#1e1b4b,#312e81";
        public MediaLibraryItem? Track { get; init; }
        public MediaGroup? Album { get; init; }
        public bool IsAlbum => Album != null;
    }

    public sealed partial class MusicMenuEntry : ObservableObject
    {
        [ObservableProperty] private bool _isFocused;
        public string Label { get; init; } = "";
        public Action Action { get; init; } = () => { };
    }

    public ObservableCollection<MusicEntry> MusicEntries { get; } = new();
    public ObservableCollection<MusicRow> MusicRows { get; } = new();
    public ObservableCollection<MusicMenuEntry> MusicMenuEntries { get; } = new();
    public OnScreenKeyboardViewModel MusicKeyboard { get; } = new();

    [ObservableProperty] private string _musicSearchText = "";
    [ObservableProperty] private string _musicContentTitle = "All songs";
    [ObservableProperty] private string _musicContentSubtitle = "";
    [ObservableProperty] private string _musicMenuTitle = "";
    [ObservableProperty] private bool _isMusicMenuOpen;
    [ObservableProperty] private bool _isMusicPlaylistMode;

    public bool IsMusicArtistsMode => !IsMusicPlaylistMode;
    public string MusicSearchLabel => string.IsNullOrEmpty(MusicSearchText) ? "🔍  Search" : "🔍  " + MusicSearchText;
    public bool HasNoMusicRows => MusicRows.Count == 0;

    private const string RecommendedKey = "\u0002rec";
    private List<MediaPlaylist> _playlists = new();
    private int _mZone = 1, _mTop, _mLeft, _mRow, _menuIdx;
    private string _selKey = "";
    private string? _selAlbum;
    private List<MediaLibraryItem> _playQueue = new();
    private List<MediaLibraryItem> _contentTracks = new();

    public bool IsMusicTabArtistsFocused => _mZone == 0 && _mTop == 0;
    public bool IsMusicTabPlaylistsFocused => _mZone == 0 && _mTop == 1;
    public bool IsMusicSearchFocused => _mZone == 0 && _mTop == 2;

    partial void OnIsMusicPlaylistModeChanged(bool value) => OnPropertyChanged(nameof(IsMusicArtistsMode));
    partial void OnMusicSearchTextChanged(string value) => OnPropertyChanged(nameof(MusicSearchLabel));

    private static string ArtistOf(MediaLibraryItem t) => string.IsNullOrEmpty(t.Group) ? "Unknown" : t.Group;

    /// <summary>Rebuilds the left list and the content after the library or playlists changed.</summary>
    public void RefreshMusicBrowser()
    {
        MusicEntries.Clear();
        if (IsMusicPlaylistMode)
        {
            foreach (var p in _playlists)
                MusicEntries.Add(new MusicEntry { Kind = 2, Key = p.Name, Title = p.Name, Subtitle = $"{p.Paths.Count} songs" });
            MusicEntries.Add(new MusicEntry { Kind = 3, Key = "\u0001new", Title = "＋  New playlist" });
        }
        else
        {
            MusicEntries.Add(new MusicEntry { Kind = 0, Key = "", Title = "🎵  All artists", Subtitle = $"{Music.Count} songs" });
            MusicEntries.Add(new MusicEntry { Kind = 4, Key = RecommendedKey, Title = "⭐  Recommended", Subtitle = "Based on your ratings & plays" });
            foreach (var g in Music.GroupBy(ArtistOf, StringComparer.OrdinalIgnoreCase).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
                MusicEntries.Add(new MusicEntry { Kind = 1, Key = g.Key, Title = g.Key, Subtitle = $"{g.Count()} songs" });
        }
        int idx = MusicEntries.ToList().FindIndex(e => e.Key == _selKey);
        if (idx < 0) { idx = 0; _selKey = MusicEntries.Count > 0 && MusicEntries[0].Kind != 3 ? MusicEntries[0].Key : ""; _selAlbum = null; }
        _mLeft = Math.Min(_mLeft, Math.Max(0, MusicEntries.Count - 1));
        RebuildMusicContent();
        ApplyMusicFocus();
        OnPropertyChanged(nameof(HasNoMusic));
    }

    private void RebuildMusicContent()
    {
        MusicRows.Clear();
        _contentTracks = new();
        var search = MusicSearchText.Trim();
        IEnumerable<MediaLibraryItem> tracks;
        string title, sub = "";

        if (search.Length > 0)
        {
            tracks = Music.Where(t => t.DisplayTitle.Contains(search, StringComparison.OrdinalIgnoreCase)
                                      || ArtistOf(t).Contains(search, StringComparison.OrdinalIgnoreCase)
                                      || t.Album.Contains(search, StringComparison.OrdinalIgnoreCase));
            title = $"Search: {search}";
        }
        else if (IsMusicPlaylistMode)
        {
            var pl = _playlists.FirstOrDefault(p => p.Name == _selKey);
            title = pl?.Name ?? "Playlists";
            sub = pl == null ? "Pick a playlist, or create one with ＋ New playlist" : "";
            var byPath = Music.ToDictionary(m => m.FullPath, StringComparer.OrdinalIgnoreCase);
            tracks = pl == null ? Array.Empty<MediaLibraryItem>()
                : pl.Paths.Where(byPath.ContainsKey).Select(p => byPath[p]);
        }
        else if (_selKey == RecommendedKey)
        {
            tracks = RecommendSongs();
            title = "Recommended";
            sub = "Songs from artists you rate and play most";
        }
        else if (_selKey.Length == 0)
        {
            tracks = Music;
            title = "All songs";
        }
        else
        {
            var artistTracks = Music.Where(t => string.Equals(ArtistOf(t), _selKey, StringComparison.OrdinalIgnoreCase)).ToList();
            var albums = artistTracks.GroupBy(t => t.Album, StringComparer.OrdinalIgnoreCase).ToList();
            if (_selAlbum == null && albums.Count > 1)
            {
                MusicContentTitle = _selKey;
                MusicContentSubtitle = $"{albums.Count} albums · {artistTracks.Count} songs";
                foreach (var a in albums.OrderBy(a => a.Key, StringComparer.OrdinalIgnoreCase))
                {
                    var list = a.ToList();
                    var grp = new MediaGroup { Title = list[0].AlbumLabel, Items = list };
                    var cover = grp.Cover;
                    MusicRows.Add(new MusicRow
                    {
                        Title = grp.Title, Subtitle = $"{list.Count} songs", Album = grp,
                        CoverPath = cover?.CoverPath ?? "", Gradient = cover?.Gradient ?? "#1e1b4b,#312e81",
                    });
                }
                _contentTracks = artistTracks;
                OnPropertyChanged(nameof(HasNoMusicRows));
                return;
            }
            tracks = _selAlbum == null ? artistTracks : artistTracks.Where(t => string.Equals(t.Album, _selAlbum, StringComparison.OrdinalIgnoreCase));
            title = _selKey;
            if (_selAlbum != null) sub = "Album: " + (_selAlbum.Length > 0 ? _selAlbum : "Singles & other");
        }

        var list2 = tracks.ToList();
        _contentTracks = list2;
        foreach (var t in list2)
            MusicRows.Add(new MusicRow
            {
                Title = t.DisplayTitle, Subtitle = ArtistOf(t) + (t.Album.Length > 0 ? " · " + t.Album : ""),
                Detail = (t.HasRating ? t.RatingStars + "  ·  " : "") + t.Extension + "  ·  " + t.SizeLabel, Track = t,
                CoverPath = t.CoverPath, Gradient = t.Gradient,
            });
        MusicContentTitle = title;
        MusicContentSubtitle = sub.Length > 0 ? sub : $"{list2.Count} songs";
        OnPropertyChanged(nameof(HasNoMusicRows));
    }

    private List<MediaLibraryItem> RecommendSongs()
    {
        var weights = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in Music)
        {
            double w = (t.Rating >= 4 ? t.Rating - 2 : 0) + (t.Favourite ? 2 : 0) + Math.Min(t.PlayCount, 5) * 0.5;
            if (t.Rating is > 0 and < 3) w = -1;
            if (w != 0) weights[ArtistOf(t)] = weights.GetValueOrDefault(ArtistOf(t)) + w;
        }
        return Music.Where(t => weights.GetValueOrDefault(ArtistOf(t)) > 0 && t.Rating < 3)
            .OrderByDescending(t => t.Rating == 0 && t.PlayCount == 0).ThenByDescending(t => weights[ArtistOf(t)]).Take(100).ToList();
    }

    private void ResetMusicFocus()
    {
        _playlists = MediaPlaylistService.Load();
        _mZone = 1;
        _mRow = 0;
        RefreshMusicBrowser();
    }

    private void ApplyMusicFocus()
    {
        for (int i = 0; i < MusicEntries.Count; i++)
        {
            MusicEntries[i].IsFocused = _mZone == 1 && i == _mLeft;
            MusicEntries[i].IsSelected = MusicEntries[i].Key == _selKey && MusicEntries[i].Kind != 3;
        }
        _mRow = Math.Clamp(_mRow, 0, Math.Max(0, MusicRows.Count - 1));
        for (int i = 0; i < MusicRows.Count; i++) MusicRows[i].IsFocused = _mZone == 2 && i == _mRow;
        OnPropertyChanged(nameof(IsMusicTabArtistsFocused));
        OnPropertyChanged(nameof(IsMusicTabPlaylistsFocused));
        OnPropertyChanged(nameof(IsMusicSearchFocused));
        MediaFocusChanged?.Invoke();
    }

    private void SelectMusicEntry(int idx)
    {
        if (idx < 0 || idx >= MusicEntries.Count) return;
        var e = MusicEntries[idx];
        if (e.Kind == 3) return;
        _selKey = e.Key;
        _selAlbum = null;
        MusicSearchText = "";
        RebuildMusicContent();
    }

    private void SetMusicMode(bool playlists)
    {
        if (IsMusicPlaylistMode == playlists) return;
        IsMusicPlaylistMode = playlists;
        _selKey = ""; _selAlbum = null; _mLeft = 0; _mRow = 0;
        if (playlists) _selKey = _playlists.FirstOrDefault()?.Name ?? "";
        RefreshMusicBrowser();
    }

    private bool MoveMusicFocus(int dx, int dy)
    {
        if (IsMusicMenuOpen) return true;
        switch (_mZone)
        {
            case 0:
                if (dx < 0) { if (_mTop == 0) return false; _mTop--; }
                else if (dx > 0) _mTop = Math.Min(2, _mTop + 1);
                else if (dy > 0) { _mZone = 1; }
                if (dx != 0 && _mTop < 2) SetMusicMode(_mTop == 1);
                break;
            case 1:
                if (dy < 0) { if (_mLeft > 0) { _mLeft--; SelectMusicEntry(_mLeft); } else { _mZone = 0; _mTop = IsMusicPlaylistMode ? 1 : 0; } }
                else if (dy > 0) { if (_mLeft < MusicEntries.Count - 1) { _mLeft++; SelectMusicEntry(_mLeft); } }
                else if (dx < 0) return false;
                else if (dx > 0 && MusicRows.Count > 0) { _mZone = 2; _mRow = 0; }
                break;
            case 2:
                if (dy < 0) { if (_mRow > 0) _mRow--; else { _mZone = 0; _mTop = 2; } }
                else if (dy > 0) _mRow = Math.Min(_mRow + 1, MusicRows.Count - 1);
                else if (dx < 0) _mZone = 1;
                break;
        }
        ApplyMusicFocus();
        return true;
    }

    private void ActivateMusicFocus()
    {
        if (IsMusicMenuOpen) return;
        switch (_mZone)
        {
            case 0:
                if (_mTop == 2) OpenMusicSearch();
                else _mZone = 1;
                break;
            case 1:
                if (_mLeft < MusicEntries.Count && MusicEntries[_mLeft].Kind == 3) PromptNewPlaylist(null);
                else if (MusicRows.Count > 0) { _mZone = 2; _mRow = 0; }
                break;
            case 2:
                if (_mRow < MusicRows.Count) ActivateMusicRow(MusicRows[_mRow]);
                return;
        }
        ApplyMusicFocus();
    }

    private void ActivateMusicRow(MusicRow row)
    {
        if (row.Album != null)
        {
            _selAlbum = row.Album.Items.Count > 0 ? row.Album.Items[0].Album : "";
            _mRow = 0;
            RebuildMusicContent();
            ApplyMusicFocus();
        }
        else if (row.Track != null)
        {
            _playQueue = _contentTracks.ToList();
            SelectedItem = row.Track;
            PlayTrack(row.Track);
        }
    }

    [RelayCommand]
    private void PlayMusicRow(MusicRow? row) { if (row != null) ActivateMusicRow(row); }

    [RelayCommand]
    private void SelectMusicEntryByClick(MusicEntry? e)
    {
        if (e == null) return;
        _mLeft = Math.Max(0, MusicEntries.IndexOf(e));
        _mZone = 1;
        if (e.Kind == 3) PromptNewPlaylist(null); else { SelectMusicEntry(_mLeft); ApplyMusicFocus(); }
    }

    [RelayCommand] private void SelectMusicTab(string? tab) { _mZone = 0; _mTop = tab == "playlists" ? 1 : 0; SetMusicMode(_mTop == 1); ApplyMusicFocus(); }

    [RelayCommand]
    private void OpenMusicSearch()
    {
        _mZone = 0; _mTop = 2;
        MusicKeyboard.Open(MusicSearchText, "Search music", t => { MusicSearchText = t; _selAlbum = null; RebuildMusicContent(); ApplyMusicFocus(); },
            _ => { _mZone = MusicRows.Count > 0 ? 2 : 1; _mRow = 0; ApplyMusicFocus(); });
    }

    /// <summary>B / Escape on the music page. Returns false when the page has nothing to step back from.</summary>
    public bool MusicBack()
    {
        if (IsMusicMenuOpen) { CloseMusicMenu(); return true; }
        if (MusicKeyboard.IsOpen) { MusicKeyboard.Close(); return true; }
        if (!IsMusicPage) return false;
        if (MusicSearchText.Length > 0) { MusicSearchText = ""; RebuildMusicContent(); ApplyMusicFocus(); return true; }
        if (_mZone == 2 && _selAlbum != null) { _selAlbum = null; _mRow = 0; RebuildMusicContent(); ApplyMusicFocus(); return true; }
        if (_mZone == 2) { _mZone = 1; ApplyMusicFocus(); return true; }
        return false;
    }

    /// <summary>Takes every key while the music keyboard or options menu is open. Returns true if consumed.</summary>
    public bool HandleMusicOverlayKey(string name)
    {
        if (MusicKeyboard.IsOpen)
        {
            MusicKeyboard.HandleKey(name switch { "Enter" => "A", "Escape" => "B", _ => name });
            return true;
        }
        if (!IsMusicMenuOpen) return false;
        switch (name)
        {
            case "Up": _menuIdx = Math.Max(0, _menuIdx - 1); break;
            case "Down": _menuIdx = Math.Min(MusicMenuEntries.Count - 1, _menuIdx + 1); break;
            case "Enter":
                if (_menuIdx >= 0 && _menuIdx < MusicMenuEntries.Count) { var a = MusicMenuEntries[_menuIdx].Action; CloseMusicMenu(); a(); }
                return true;
            case "Escape": case "Y": CloseMusicMenu(); return true;
        }
        for (int i = 0; i < MusicMenuEntries.Count; i++) MusicMenuEntries[i].IsFocused = i == _menuIdx;
        MediaFocusChanged?.Invoke();
        return true;
    }

    private void CloseMusicMenu() { IsMusicMenuOpen = false; MusicMenuEntries.Clear(); MediaFocusChanged?.Invoke(); }

    [RelayCommand]
    private void ActivateMusicMenuEntry(MusicMenuEntry? e)
    {
        if (e == null) return;
        CloseMusicMenu();
        e.Action();
    }

    /// <summary>Y: options for the highlighted song / album / artist / playlist.</summary>
    public void OpenMusicMenu()
    {
        if (!IsMusicPage || IsMusicMenuOpen) return;
        List<MediaLibraryItem> targets = new();
        string title = "";
        bool inPlaylistTrack = false;
        MediaPlaylist? playlistTarget = null;

        if (_mZone == 2 && _mRow < MusicRows.Count)
        {
            var row = MusicRows[_mRow];
            targets = row.Album != null ? row.Album.Items.ToList() : row.Track != null ? new() { row.Track } : new();
            title = row.Title;
            inPlaylistTrack = IsMusicPlaylistMode && row.Track != null && MusicSearchText.Length == 0;
        }
        else if (_mZone == 1 && _mLeft < MusicEntries.Count)
        {
            var e = MusicEntries[_mLeft];
            if (e.Kind == 3) return;
            title = e.Title;
            if (e.Kind == 2) playlistTarget = _playlists.FirstOrDefault(p => p.Name == e.Key);
            targets = e.Kind == 4 ? _contentTracks.ToList() : e.Kind == 1 ? Music.Where(t => string.Equals(ArtistOf(t), e.Key, StringComparison.OrdinalIgnoreCase)).ToList()
                    : e.Kind == 0 ? Music.ToList() : _contentTracks.ToList();
        }
        else return;

        MusicMenuEntries.Clear();
        void Add(string label, Action a) => MusicMenuEntries.Add(new MusicMenuEntry { Label = label, Action = a });

        if (targets.Count > 0)
            Add("▶  Play", () => { _playQueue = targets.ToList(); SelectedItem = targets[0]; PlayTrack(targets[0]); });
        if (playlistTarget != null)
        {
            var pl = playlistTarget;
            Add("✎  Rename playlist", () => PromptNewPlaylist(pl));
            Add("🗑  Delete playlist", () =>
            {
                _playlists.Remove(pl); MediaPlaylistService.Save(_playlists);
                _selKey = _playlists.FirstOrDefault()?.Name ?? ""; _mLeft = 0; RefreshMusicBrowser();
            });
        }
        else if (targets.Count > 0)
        {
            foreach (var p in _playlists.ToList())
            {
                var pp = p;
                Add($"＋  Add to playlist: {pp.Name}", () => AddToPlaylist(pp, targets));
            }
            Add("＋  Add to new playlist…", () => PromptNewPlaylist(null, targets));
        }
        if (inPlaylistTrack && MusicRows[_mRow].Track is { } tr)
        {
            var pl = _playlists.FirstOrDefault(p => p.Name == _selKey);
            if (pl != null) Add("−  Remove from this playlist", () =>
            {
                pl.Paths.RemoveAll(p => string.Equals(p, tr.FullPath, StringComparison.OrdinalIgnoreCase));
                MediaPlaylistService.Save(_playlists); RefreshMusicBrowser();
            });
        }
        if (targets.Count == 1)
        {
            var one = targets[0];
            for (int n = 5; n >= 1; n--)
            {
                int stars = n;
                Add($"{new string('★', stars)}{new string('☆', 5 - stars)}  Rate {stars}" + (one.Rating == stars ? " (tap to clear)" : ""),
                    () => { Persist(one.FullPath, st => st.Rating = st.Rating == stars ? 0 : stars); RebuildMusicContent(); ApplyMusicFocus(); });
            }
        }
        if (HasNowPlaying)
        {
            Add("⏯  Pause / resume", () => TogglePlayPause());
            Add("⏭  Next song", () => StepTrack(1));
            Add("⏮  Previous song", () => StepTrack(-1));
        }
        if (HasNowPlaying) Add("⛶  Full-screen player", () => OpenNowPlayingFullScreenCommand.Execute(null));

        MusicMenuTitle = title;
        _menuIdx = 0;
        for (int i = 0; i < MusicMenuEntries.Count; i++) MusicMenuEntries[i].IsFocused = i == 0;
        IsMusicMenuOpen = true;
    }

    private void AddToPlaylist(MediaPlaylist pl, IEnumerable<MediaLibraryItem> items)
    {
        foreach (var t in items)
            if (!pl.Paths.Contains(t.FullPath, StringComparer.OrdinalIgnoreCase)) pl.Paths.Add(t.FullPath);
        MediaPlaylistService.Save(_playlists);
        RefreshMusicBrowser();
    }

    /// <summary>Asks for a name on the on-screen keyboard, then creates a playlist (seeded with <paramref name="seed"/>) or renames <paramref name="rename"/>.</summary>
    private void PromptNewPlaylist(MediaPlaylist? rename, IEnumerable<MediaLibraryItem>? seed = null)
    {
        var seedList = seed?.ToList();
        MusicKeyboard.Open(rename?.Name ?? "", rename == null ? "New playlist name" : "Rename playlist", _ => { }, name =>
        {
            name = name.Trim();
            if (name.Length == 0) return;
            if (rename != null) rename.Name = name;
            else
            {
                var pl = _playlists.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
                if (pl == null) { pl = new MediaPlaylist { Name = name }; _playlists.Add(pl); }
                if (seedList != null) foreach (var t in seedList)
                    if (!pl.Paths.Contains(t.FullPath, StringComparer.OrdinalIgnoreCase)) pl.Paths.Add(t.FullPath);
                name = pl.Name;
            }
            MediaPlaylistService.Save(_playlists);
            if (IsMusicPlaylistMode) { _selKey = name; _mLeft = Math.Max(0, _playlists.FindIndex(p => p.Name == name)); }
            RefreshMusicBrowser();
        });
    }
}
