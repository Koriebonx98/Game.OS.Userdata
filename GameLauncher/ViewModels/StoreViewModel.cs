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
    private GameOsClient    _client   = new();

    [ObservableProperty] private string  _searchText = "";
    [ObservableProperty] private string  _filterGenre = "All";
    [ObservableProperty] private string? _statusMessage;

    // ── Admin catalog management ──────────────────────────────────────────
    [ObservableProperty] private bool   _isAdmin      = false;
    [ObservableProperty] private bool   _showAdminForm = false;
    [ObservableProperty] private string _adminTitle       = "";
    [ObservableProperty] private string _adminPlatform    = "PC";
    [ObservableProperty] private string _adminGenre       = "";
    [ObservableProperty] private string _adminPrice       = "";
    [ObservableProperty] private string _adminDescription = "";
    [ObservableProperty] private string _adminRating      = "8.0";
    [ObservableProperty] private string _adminCoverUrl    = "";

    /// <summary>
    /// Total games across all platforms in the Koriebonx98/Games.Database repository.
    /// PC: ~153,713  |  Xbox 360: 5,132  |  PS3: 4,000  |  Switch: 2,245  |  PS4: 5
    /// Updated by counting each {Platform}.Games.json in the public repository.
    /// </summary>
    private const int RealDatabaseTotal = 165_095;

    [ObservableProperty] private int    _totalCatalogCount = 0;
    [ObservableProperty] private string _catalogCountLabel = "";

    /// <summary>True once the real catalog count has been loaded; drives the subtitle visibility.</summary>
    public bool HasCatalogCount => TotalCatalogCount > 0;

    partial void OnTotalCatalogCountChanged(int value) => OnPropertyChanged(nameof(HasCatalogCount));

    public ObservableCollection<StoreGame> Featured      { get; } = new();
    public ObservableCollection<StoreGame> FilteredStore { get; } = new();
    public ObservableCollection<string>    Genres        { get; } = new();

    /// <summary>Invoked when the user clicks a store game card.</summary>
    public Action<StoreGame>? OnOpenDetail { get; set; }

    public void Load(List<StoreGame> store, List<Game> library,
                     UserProfile profile, GameOsClient client, bool isAdmin,
                     int totalCatalogCount = RealDatabaseTotal)
    {
        _allStore = new List<StoreGame>(store); // work on a copy so admin changes are session-scoped
        _library  = library;
        _profile  = profile;
        _client   = client;
        IsAdmin   = isAdmin;

        TotalCatalogCount = totalCatalogCount;
        CatalogCountLabel = $"{totalCatalogCount:N0}+ games in the database";

        RebuildCollections();
    }

    private void RebuildCollections()
    {
        Featured.Clear();
        foreach (var g in _allStore.Where(s => s.IsFeatured))
            Featured.Add(g);

        Genres.Clear();
        Genres.Add("All");
        foreach (var genre in _allStore.Select(s => s.Genre).Distinct().OrderBy(g => g))
            Genres.Add(genre);

        FilterGenre = "All";
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
        try
        {
            await _client.AddGameAsync(game.Platform, game.Title);
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
        catch (System.Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }

        ApplyFilter();
    }

    // ── Admin: toggle add-game form ───────────────────────────────────────
    [RelayCommand]
    private void AdminToggleForm()
    {
        ShowAdminForm = !ShowAdminForm;
        if (ShowAdminForm)
        {
            AdminTitle = ""; AdminPlatform = "PC"; AdminGenre = "";
            AdminPrice = ""; AdminDescription = ""; AdminRating = "8.0";
            AdminCoverUrl = "";
        }
    }

    // ── Admin: add a new game to the catalog (session-only) ───────────────
    [RelayCommand]
    private void AdminAddCatalogGame()
    {
        if (string.IsNullOrWhiteSpace(AdminTitle) || string.IsNullOrWhiteSpace(AdminPlatform))
        {
            StatusMessage = "Title and Platform are required.";
            return;
        }
        if (!double.TryParse(AdminRating, System.Globalization.NumberStyles.Any,
                System.Globalization.CultureInfo.InvariantCulture, out double rating))
            rating = 8.0;

        var newGame = new StoreGame
        {
            Title       = AdminTitle.Trim(),
            Platform    = AdminPlatform.Trim(),
            Genre       = string.IsNullOrWhiteSpace(AdminGenre) ? "Other" : AdminGenre.Trim(),
            Price       = string.IsNullOrWhiteSpace(AdminPrice) ? "Free" : AdminPrice.Trim(),
            Description = AdminDescription.Trim(),
            Rating      = Math.Clamp(rating, 0, 10),
            CoverUrl    = string.IsNullOrWhiteSpace(AdminCoverUrl) ? null : AdminCoverUrl.Trim(),
            IsFeatured  = false,
            ReleaseYear = System.DateTime.Now.Year.ToString()
        };

        _allStore.Add(newGame);
        RebuildCollections();
        ShowAdminForm = false;
        StatusMessage = $"✓  '{newGame.Title}' added to the catalog (this session only).";
    }

    // ── Admin: remove a game from the catalog (session-only) ─────────────
    [RelayCommand]
    private void AdminDeleteCatalogGame(StoreGame? game)
    {
        if (game == null) return;
        _allStore.RemoveAll(s => s.Title == game.Title && s.Platform == game.Platform);
        RebuildCollections();
        StatusMessage = $"✓  '{game.Title}' removed from the catalog (this session only).";
    }
}
