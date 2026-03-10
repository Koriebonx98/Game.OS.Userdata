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
    public ObservableCollection<LocalGame>   LocalGames     { get; } = new();
    public ObservableCollection<LocalRepack> ReadyToInstall { get; } = new();
    public ObservableCollection<LocalRom>    LocalRoms      { get; } = new();

    /// <summary>Invoked when the user clicks a cloud game card.</summary>
    public Action<Game>?       OnOpenDetail       { get; set; }
    /// <summary>Invoked when the user clicks a local/detected game card.</summary>
    public Action<LocalGame>?  OnOpenLocalDetail  { get; set; }
    /// <summary>Invoked when the user clicks a ready-to-install repack card.</summary>
    public Action<LocalRepack>? OnOpenRepackDetail { get; set; }

    public void Load(List<Game> games)
    {
        _allGames = games;
        TotalGames = games.Count;

        Platforms.Clear();
        Platforms.Add("All");
        foreach (var p in games.Select(g => g.Platform).Distinct().OrderBy(p => p))
            Platforms.Add(p);

        ApplyFilter();
    }

    /// <summary>Called by MainViewModel when the scanner emits new results.</summary>
    public void UpdateLocalGames(IReadOnlyList<LocalGame> games)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            LocalGames.Clear();
            foreach (var g in games) LocalGames.Add(g);
            HasLocalGames = LocalGames.Count > 0;
        });
    }

    /// <summary>Called by MainViewModel when the scanner emits new repacks.</summary>
    public void UpdateRepacks(IReadOnlyList<LocalRepack> repacks)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            ReadyToInstall.Clear();
            foreach (var r in repacks) ReadyToInstall.Add(r);
            HasRepacks = ReadyToInstall.Count > 0;
        });
    }

    /// <summary>Called by MainViewModel when the scanner emits new ROMs.</summary>
    public void UpdateRoms(IReadOnlyList<LocalRom> roms)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            LocalRoms.Clear();
            foreach (var r in roms) LocalRoms.Add(r);
            HasRoms = LocalRoms.Count > 0;
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

    private void ApplyFilter()
    {
        FilteredGames.Clear();
        var results = _allGames.AsEnumerable();

        if (FilterPlatform != "All")
            results = results.Where(g => g.Platform == FilterPlatform);

        if (!string.IsNullOrWhiteSpace(SearchText))
            results = results.Where(g =>
                g.Title.Contains(SearchText, System.StringComparison.OrdinalIgnoreCase));

        foreach (var g in results.OrderByDescending(g => g.Rating ?? 0))
            FilteredGames.Add(g);
    }
}
