using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

public partial class LibraryViewModel : ViewModelBase
{
    private List<Game> _allGames = new();
    private List<LocalGame>   _allLocalGames  = new();
    private List<LocalRepack> _allRepacks     = new();
    private List<LocalRom>    _allRoms        = new();

    // ── Unified "My Games" list (LocalGames + Repacks + ROMs) ─────────────
    private List<LocalGameCardVm> _allMyGames = new();

    [ObservableProperty] private string _filterPlatform = "All";
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private int    _totalGames;

    // ── Cloud library ──────────────────────────────────────────────────────
    public ObservableCollection<Game>   FilteredGames { get; } = new();
    public ObservableCollection<string> Platforms     { get; } = new();

    // ── Local drive detection ──────────────────────────────────────────────
    [ObservableProperty] private bool _hasLocalGames;
    [ObservableProperty] private bool _hasRepacks;
    [ObservableProperty] private bool _hasRoms;
    [ObservableProperty] private bool _hasMyGames;
    // Raw (unfiltered) sources — kept so filter can re-apply on the full list
    public ObservableCollection<LocalGame>   LocalGames     { get; } = new();
    public ObservableCollection<LocalRepack> ReadyToInstall { get; } = new();
    public ObservableCollection<LocalRom>    LocalRoms      { get; } = new();
    // Filtered views shown in the UI
    public ObservableCollection<LocalGame>         FilteredLocalGames  { get; } = new();
    public ObservableCollection<LocalRepack>        FilteredRepacks     { get; } = new();
    public ObservableCollection<LocalRom>           FilteredRoms        { get; } = new();
    /// <summary>Unified filtered list combining LocalGames + Repacks + ROMs for "My Games".</summary>
    public ObservableCollection<LocalGameCardVm>    FilteredMyGames     { get; } = new();

    /// <summary>Invoked when the user clicks a cloud game card.</summary>
    public Action<Game>?        OnOpenDetail       { get; set; }
    /// <summary>Invoked when the user clicks a local/detected game card.</summary>
    public Action<LocalGame>?   OnOpenLocalDetail  { get; set; }
    /// <summary>Invoked when the user clicks a ready-to-install repack card.</summary>
    public Action<LocalRepack>? OnOpenRepackDetail { get; set; }
    /// <summary>Invoked when the user clicks a ROM card.</summary>
    public Action<LocalRom>?    OnOpenRomDetail    { get; set; }
    /// <summary>Invoked when the user clicks any card in the unified My Games section.</summary>
    public Action<LocalGameCardVm>? OnOpenMyGameDetail { get; set; }

    public void Load(List<Game> games)
    {
        _allGames = games;

        // Rebuild the platform filter list from all game types combined
        RebuildPlatforms();
        ApplyFilter();
    }

    /// <summary>Called by MainViewModel when the scanner emits new results.</summary>
    public void UpdateLocalGames(IReadOnlyList<LocalGame> games)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            _allLocalGames = games.ToList();
            LocalGames.Clear();
            foreach (var g in games) LocalGames.Add(g);
            HasLocalGames = LocalGames.Count > 0;
            RebuildMyGames();
            RebuildPlatforms();
            ApplyFilter();
        });
    }

    /// <summary>Called by MainViewModel when the scanner emits new repacks.</summary>
    public void UpdateRepacks(IReadOnlyList<LocalRepack> repacks)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            _allRepacks = repacks.ToList();
            ReadyToInstall.Clear();
            foreach (var r in repacks) ReadyToInstall.Add(r);
            HasRepacks = ReadyToInstall.Count > 0;
            RebuildMyGames();
            ApplyFilter();
        });
    }

    /// <summary>Called by MainViewModel when the scanner emits new ROMs.</summary>
    public void UpdateRoms(IReadOnlyList<LocalRom> roms)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            _allRoms = roms.ToList();
            LocalRoms.Clear();
            foreach (var r in roms) LocalRoms.Add(r);
            HasRoms = LocalRoms.Count > 0;
            RebuildMyGames();
            RebuildPlatforms();
            ApplyFilter();
        });
    }

    /// <summary>
    /// Called by MainViewModel after background cover-art enrichment updates a card's
    /// CoverUrl and CoverGradient from the Games.Database.
    /// </summary>
    public LocalGameCardVm? FindMyGameCard(string title, string platform)
    {
        return _allMyGames.FirstOrDefault(c =>
            string.Equals(c.Title, title, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(c.Platform, platform, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Returns a snapshot of all platform/title/titleId tuples in the My Games list so
    /// MainViewModel can enrich cover art without accessing private fields.
    /// </summary>
    public IReadOnlyList<(string Title, string Platform, string? TitleId)> GetMyGameSources()
    {
        return _allMyGames
            .Select(c => (c.Title, c.Platform, c.SourceRom?.TitleId))
            .Distinct()
            .ToList();
    }

    partial void OnFilterPlatformChanged(string value) => ApplyFilter();
    partial void OnSearchTextChanged(string value)     => ApplyFilter();

    [RelayCommand]
    private void SetPlatform(string platform) => FilterPlatform = platform;

    [RelayCommand]
    private void OpenGameDetail(Game? game)
    {
        if (game != null) OnOpenDetail?.Invoke(game);
    }

    [RelayCommand]
    private void OpenLocalGameDetail(LocalGame? game)
    {
        if (game != null) OnOpenLocalDetail?.Invoke(game);
    }

    [RelayCommand]
    private void OpenRepackDetail(LocalRepack? repack)
    {
        if (repack != null) OnOpenRepackDetail?.Invoke(repack);
    }

    [RelayCommand]
    private void OpenRomDetail(LocalRom? rom)
    {
        if (rom != null) OnOpenRomDetail?.Invoke(rom);
    }

    [RelayCommand]
    private void OpenMyGameDetail(LocalGameCardVm? card)
    {
        if (card != null) OnOpenMyGameDetail?.Invoke(card);
    }

    // ── Private helpers ────────────────────────────────────────────────────

    /// <summary>Rebuilds _allMyGames from the current three source lists.</summary>
    private void RebuildMyGames()
    {
        _allMyGames.Clear();

        // Build a set of installed game titles for deduplication below.
        var installedTitles = new HashSet<string>(
            _allLocalGames.Select(g => g.Title), StringComparer.OrdinalIgnoreCase);

        // Build a lookup of cloud library games by (normalizedPlatform, title) so we can
        // skip local ROM entries that are already represented in the cloud library.
        var cloudByPlatform = _allGames
            .GroupBy(g => GameLauncher.Models.PlatformHelper.NormalizePlatform(g.Platform),
                     StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                grp => grp.Key,
                grp => new HashSet<string>(grp.Select(g => g.Title), StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase);

        // LocalGames → platform = "PC"
        foreach (var g in _allLocalGames)
            _allMyGames.Add(new LocalGameCardVm
            {
                Title          = g.Title,
                Platform       = "PC",
                CoverGradient  = "#0d2137,#163d5e",
                SourceGame     = g,
            });

        // Repacks → platform = "PC"
        // Skip repacks that are already represented as installed LocalGames so the user
        // doesn't see duplicate cards for the same title.
        foreach (var r in _allRepacks)
        {
            if (r.IsInstalledGame && installedTitles.Contains(
                    GameScannerService.StripRepackMarkers(r.Title)))
                continue;

            _allMyGames.Add(new LocalGameCardVm
            {
                Title          = r.Title,
                Platform       = "PC",
                CoverGradient  = r.IsInstalledGame ? "#0d2137,#163d5e" : "#2d1b00,#5c3800",
                SourceRepack   = r,
            });
        }

        // ROMs → platform from the ROM itself
        // Skip ROMs whose title + platform already exist in the cloud library to avoid
        // showing the same game twice (once from the library JSON, once from the local scan).
        // Use fuzzy comparison (strip ™/®/© symbols) to handle official titles like
        // "Mario Kart™ 8 Deluxe" (cloud) vs "Mario Kart 8 Deluxe" (local folder).
        foreach (var r in _allRoms)
        {
            if (cloudByPlatform.TryGetValue(r.Platform, out var cloudTitles) &&
                (cloudTitles.Contains(r.Title) ||
                 cloudTitles.Any(ct => string.Equals(
                     PlatformHelper.StripSpecialSymbols(ct),
                     PlatformHelper.StripSpecialSymbols(r.Title),
                     StringComparison.OrdinalIgnoreCase))))
                continue;

            _allMyGames.Add(new LocalGameCardVm
            {
                Title          = r.Title,
                Platform       = r.Platform,
                CoverGradient  = "#0d1f3c,#1a3264",
                SourceRom      = r,
            });
        }
    }

    /// <summary>Rebuilds the Platforms filter list from all game sources combined.</summary>
    private void RebuildPlatforms()
    {
        var current = FilterPlatform;

        var platforms = _allGames
            .Select(g => GameLauncher.Models.PlatformHelper.NormalizePlatform(g.Platform))
            .Concat(_allRoms.Select(r => r.Platform))
            .Concat(_allLocalGames.Select(_ => "PC"))
            .Concat(_allRepacks.Select(_ => "PC"))
            .Where(p => !string.IsNullOrEmpty(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(p => p)
            .ToList();

        Platforms.Clear();
        Platforms.Add("All");
        foreach (var p in platforms)
            Platforms.Add(p);

        // Restore or reset the filter selection
        FilterPlatform = Platforms.Contains(current) ? current : "All";

        // Update total count: cloud + local games + repacks + roms
        TotalGames = _allGames.Count + _allLocalGames.Count + _allRepacks.Count + _allRoms.Count;
    }

    private void ApplyFilter()
    {
        var search = SearchText;
        var plat   = FilterPlatform;

        // ── Cloud games ──────────────────────────────────────────────────
        FilteredGames.Clear();
        var cloudResults = _allGames.AsEnumerable();
        if (plat != "All")
            cloudResults = cloudResults.Where(g =>
                string.Equals(GameLauncher.Models.PlatformHelper.NormalizePlatform(g.Platform),
                               plat, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(search))
            cloudResults = cloudResults.Where(g =>
                g.Title.Contains(search, StringComparison.OrdinalIgnoreCase));
        foreach (var g in cloudResults.OrderByDescending(g => g.Rating ?? 0))
            FilteredGames.Add(g);

        // ── Local installed games (assumed PC) — kept for legacy use ──────
        FilteredLocalGames.Clear();
        if (plat == "All" || string.Equals(plat, "PC", StringComparison.OrdinalIgnoreCase))
        {
            var localResults = _allLocalGames.AsEnumerable();
            if (!string.IsNullOrWhiteSpace(search))
                localResults = localResults.Where(g =>
                    g.Title.Contains(search, StringComparison.OrdinalIgnoreCase));
            foreach (var g in localResults.OrderBy(g => g.Title))
                FilteredLocalGames.Add(g);
        }
        HasLocalGames = FilteredLocalGames.Count > 0;

        // ── Repacks (assumed PC) — kept for legacy use ────────────────────
        FilteredRepacks.Clear();
        if (plat == "All" || string.Equals(plat, "PC", StringComparison.OrdinalIgnoreCase))
        {
            var repackResults = _allRepacks.AsEnumerable();
            if (!string.IsNullOrWhiteSpace(search))
                repackResults = repackResults.Where(r =>
                    r.Title.Contains(search, StringComparison.OrdinalIgnoreCase));
            foreach (var r in repackResults.OrderBy(r => r.Title))
                FilteredRepacks.Add(r);
        }
        HasRepacks = FilteredRepacks.Count > 0;

        // ── ROMs — kept for legacy use ────────────────────────────────────
        FilteredRoms.Clear();
        var romResults = _allRoms.AsEnumerable();
        if (plat != "All")
            romResults = romResults.Where(r =>
                string.Equals(r.Platform, plat, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(search))
            romResults = romResults.Where(r =>
                r.Title.Contains(search, StringComparison.OrdinalIgnoreCase));
        foreach (var r in romResults.OrderBy(r => r.Title))
            FilteredRoms.Add(r);
        HasRoms = FilteredRoms.Count > 0;

        // ── Unified My Games (LocalGames + Repacks + ROMs) ────────────────
        FilteredMyGames.Clear();
        var myResults = _allMyGames.AsEnumerable();
        if (plat != "All")
            myResults = myResults.Where(c =>
                string.Equals(c.Platform, plat, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(search))
            myResults = myResults.Where(c =>
                c.Title.Contains(search, StringComparison.OrdinalIgnoreCase));
        foreach (var c in myResults.OrderBy(c => c.Title))
            FilteredMyGames.Add(c);
        HasMyGames = FilteredMyGames.Count > 0;

        // Recalculate total to reflect filtered counts
        TotalGames = _allGames.Count + _allLocalGames.Count + _allRepacks.Count + _allRoms.Count;
    }
}
