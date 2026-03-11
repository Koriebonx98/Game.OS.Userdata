using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

public partial class LibraryViewModel : ViewModelBase
{
    private List<Game> _allGames = new();
    private List<LocalGame>   _allLocalGames  = new();
    private List<LocalRepack> _allRepacks     = new();
    private List<LocalRom>    _allRoms        = new();

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
    // Raw (unfiltered) sources — kept so filter can re-apply on the full list
    public ObservableCollection<LocalGame>   LocalGames     { get; } = new();
    public ObservableCollection<LocalRepack> ReadyToInstall { get; } = new();
    public ObservableCollection<LocalRom>    LocalRoms      { get; } = new();
    // Filtered views shown in the UI
    public ObservableCollection<LocalGame>   FilteredLocalGames  { get; } = new();
    public ObservableCollection<LocalRepack> FilteredRepacks     { get; } = new();
    public ObservableCollection<LocalRom>    FilteredRoms        { get; } = new();

    /// <summary>Invoked when the user clicks a cloud game card.</summary>
    public Action<Game>?        OnOpenDetail       { get; set; }
    /// <summary>Invoked when the user clicks a local/detected game card.</summary>
    public Action<LocalGame>?   OnOpenLocalDetail  { get; set; }
    /// <summary>Invoked when the user clicks a ready-to-install repack card.</summary>
    public Action<LocalRepack>? OnOpenRepackDetail { get; set; }
    /// <summary>Invoked when the user clicks a ROM card.</summary>
    public Action<LocalRom>?    OnOpenRomDetail    { get; set; }

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
            RebuildPlatforms();
            ApplyFilter();
        });
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

    // ── Private helpers ────────────────────────────────────────────────────

    /// <summary>Rebuilds the Platforms filter list from all game sources combined.</summary>
    private void RebuildPlatforms()
    {
        var current = FilterPlatform;

        var platforms = _allGames
            .Select(g => g.Platform)
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
                string.Equals(g.Platform, plat, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(search))
            cloudResults = cloudResults.Where(g =>
                g.Title.Contains(search, StringComparison.OrdinalIgnoreCase));
        foreach (var g in cloudResults.OrderByDescending(g => g.Rating ?? 0))
            FilteredGames.Add(g);

        // ── Local installed games (assumed PC) ────────────────────────────
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

        // ── Repacks (assumed PC) ──────────────────────────────────────────
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

        // ── ROMs ──────────────────────────────────────────────────────────
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

        // Recalculate total to reflect filtered counts
        TotalGames = _allGames.Count + _allLocalGames.Count + _allRepacks.Count + _allRoms.Count;
    }
}
