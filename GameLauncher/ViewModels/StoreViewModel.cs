using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

public partial class StoreViewModel : ViewModelBase
{
    private List<StoreGame> _allStore = new();
    private List<Game>      _library  = new();
    private UserProfile     _profile  = new();
    private GameOsClient    _client   = new(demoMode: true);
    private bool            _demoMode = true;

    [ObservableProperty] private string  _searchText = "";
    [ObservableProperty] private string  _filterGenre = "All";
    [ObservableProperty] private string? _statusMessage;

    public ObservableCollection<StoreGame> Featured      { get; } = new();
    public ObservableCollection<StoreGame> FilteredStore { get; } = new();
    public ObservableCollection<string>    Genres        { get; } = new();

    /// <summary>Invoked when the user clicks a store game card.</summary>
    public Action<StoreGame>? OnOpenDetail { get; set; }

    public void Load(List<StoreGame> store, List<Game> library,
                     UserProfile profile, GameOsClient client, bool demoMode)
    {
        _allStore = store;
        _library  = library;
        _profile  = profile;
        _client   = client;
        _demoMode = demoMode;

        Featured.Clear();
        foreach (var g in store.Where(s => s.IsFeatured))
            Featured.Add(g);

        Genres.Clear();
        Genres.Add("All");
        foreach (var genre in store.Select(s => s.Genre).Distinct().OrderBy(g => g))
            Genres.Add(genre);

        ApplyFilter();
    }

    partial void OnSearchTextChanged(string value)   => ApplyFilter();
    partial void OnFilterGenreChanged(string value)  => ApplyFilter();

    private void ApplyFilter()
    {
        FilteredStore.Clear();
        var results = _allStore.AsEnumerable();

        if (FilterGenre != "All")
            results = results.Where(s => s.Genre == FilterGenre);

        if (!string.IsNullOrWhiteSpace(SearchText))
            results = results.Where(s =>
                s.Title.Contains(SearchText, System.StringComparison.OrdinalIgnoreCase) ||
                s.Genre.Contains(SearchText, System.StringComparison.OrdinalIgnoreCase));

        foreach (var g in results.OrderByDescending(s => s.Rating))
            FilteredStore.Add(g);
    }

    public bool IsOwned(string title) =>
        _library.Any(g => g.Title.Equals(title, System.StringComparison.OrdinalIgnoreCase));

    [RelayCommand]
    private void OpenGameDetail(StoreGame? game)
    {
        if (game != null) OnOpenDetail?.Invoke(game);
    }

    [RelayCommand]
    private async System.Threading.Tasks.Task AddGameAsync(StoreGame? game)
    {
        if (game == null) return;
        if (IsOwned(game.Title))
        {
            StatusMessage = $"'{game.Title}' is already in your library.";
            return;
        }

        StatusMessage = $"Adding '{game.Title}'…";

        if (_demoMode)
        {
            _library.Add(new Game
            {
                Platform    = game.Platform,
                Title       = game.Title,
                Genre       = game.Genre,
                Rating      = game.Rating,
                Description = game.Description,
                CoverUrl    = game.CoverUrl,
                Screenshots = game.Screenshots,
                CoverColor  = game.CoverColor,
                CoverGradient = game.CoverGradient,
                AddedAt     = System.DateTimeOffset.UtcNow.ToString("o")
            });
            StatusMessage = $"✓  '{game.Title}' added to your library!";
        }
        else
        {
            try
            {
                await _client.AddGameAsync(_profile.Username, game.Platform, game.Title);
                _library.Add(new Game
                {
                    Platform = game.Platform,
                    Title    = game.Title,
                    Genre    = game.Genre,
                    Rating   = game.Rating,
                    AddedAt  = System.DateTimeOffset.UtcNow.ToString("o")
                });
                StatusMessage = $"✓  '{game.Title}' added to your library!";
            }
            catch (System.Exception ex)
            {
                StatusMessage = $"Error: {ex.Message}";
            }
        }

        // Refresh owned state
        ApplyFilter();
    }
}
