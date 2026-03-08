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

    public ObservableCollection<Game>   FilteredGames { get; } = new();
    public ObservableCollection<string> Platforms     { get; } = new();

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

    partial void OnFilterPlatformChanged(string value) => ApplyFilter();
    partial void OnSearchTextChanged(string value)     => ApplyFilter();

    [RelayCommand]
    private void SetPlatform(string platform) => FilterPlatform = platform;

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
