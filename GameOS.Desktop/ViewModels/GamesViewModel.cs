using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameOS.Desktop.Models;
using GameOS.Desktop.Services;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace GameOS.Desktop.ViewModels;

public partial class GameItemViewModel : ViewModelBase
{
    private readonly GamesViewModel _parent;

    public string Title { get; }
    public string Platform { get; }

    [ObservableProperty] private bool _isInLibrary;
    [ObservableProperty] private bool _isInWishlist;

    public GameItemViewModel(Game game, GamesViewModel parent, bool isInLibrary, bool isInWishlist)
    {
        _parent = parent;
        Title = game.Title;
        Platform = game.Platform;
        IsInLibrary = isInLibrary;
        IsInWishlist = isInWishlist;
    }

    [RelayCommand]
    private async Task AddToLibrary()
    {
        await _parent.AddToLibraryAsync(this);
    }

    [RelayCommand]
    private async Task RemoveFromLibrary()
    {
        await _parent.RemoveFromLibraryAsync(this);
    }

    [RelayCommand]
    private async Task AddToWishlist()
    {
        await _parent.AddToWishlistAsync(this);
    }

    [RelayCommand]
    private async Task RemoveFromWishlist()
    {
        await _parent.RemoveFromWishlistAsync(this);
    }
}

public partial class GamesViewModel : ViewModelBase
{
    [ObservableProperty] private ObservableCollection<GameItemViewModel> _browseGames = new();
    [ObservableProperty] private ObservableCollection<GameItemViewModel> _libraryGames = new();
    [ObservableProperty] private ObservableCollection<GameItemViewModel> _wishlistGames = new();
    [ObservableProperty] private string _selectedPlatform = "All";
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private int _selectedTabIndex;
    [ObservableProperty] private bool _isLoggedIn;
    [ObservableProperty] private string _statusMessage = "";

    public System.Collections.Generic.List<string> Platforms { get; } = GameService.GetPlatforms();

    private System.Collections.Generic.List<Game> _allGames = new();
    private System.Collections.Generic.List<Game> _library = new();
    private System.Collections.Generic.List<Game> _wishlist = new();

    public GamesViewModel()
    {
        IsLoggedIn = App.CurrentUser != null;
        _allGames = GameService.GetAllGames();
    }

    public async Task LoadAsync()
    {
        if (App.CurrentUser != null)
        {
            _library = await GameService.GetLibraryAsync(App.CurrentUser.Username);
            _wishlist = await GameService.GetWishlistAsync(App.CurrentUser.Username);
        }
        ApplyBrowseFilter();
        RefreshLibraryView();
        RefreshWishlistView();
    }

    partial void OnSelectedPlatformChanged(string value) => ApplyBrowseFilter();
    partial void OnSearchTextChanged(string value) => ApplyBrowseFilter();

    private void ApplyBrowseFilter()
    {
        var filtered = _allGames.AsEnumerable();
        if (SelectedPlatform != "All")
            filtered = filtered.Where(g => g.Platform == SelectedPlatform);
        if (!string.IsNullOrWhiteSpace(SearchText))
            filtered = filtered.Where(g => g.Title.Contains(SearchText, System.StringComparison.OrdinalIgnoreCase));

        BrowseGames = new ObservableCollection<GameItemViewModel>(
            filtered.Select(g => new GameItemViewModel(
                g, this,
                _library.Any(l => l.Platform == g.Platform && l.Title == g.Title),
                _wishlist.Any(w => w.Platform == g.Platform && w.Title == g.Title)
            ))
        );
    }

    private void RefreshLibraryView()
    {
        LibraryGames = new ObservableCollection<GameItemViewModel>(
            _library.Select(g => new GameItemViewModel(g, this, true, false))
        );
    }

    private void RefreshWishlistView()
    {
        WishlistGames = new ObservableCollection<GameItemViewModel>(
            _wishlist.Select(g => new GameItemViewModel(g, this, false, true))
        );
    }

    public async Task AddToLibraryAsync(GameItemViewModel item)
    {
        if (App.CurrentUser == null) return;
        var game = new Game { Platform = item.Platform, Title = item.Title };
        await GameService.AddGameAsync(App.CurrentUser.Username, game);
        _library = await GameService.GetLibraryAsync(App.CurrentUser.Username);
        item.IsInLibrary = true;
        RefreshLibraryView();
        StatusMessage = $"Added '{item.Title}' to library!";
    }

    public async Task RemoveFromLibraryAsync(GameItemViewModel item)
    {
        if (App.CurrentUser == null) return;
        await GameService.RemoveGameAsync(App.CurrentUser.Username, item.Platform, item.Title);
        _library = await GameService.GetLibraryAsync(App.CurrentUser.Username);
        item.IsInLibrary = false;
        RefreshLibraryView();
        StatusMessage = $"Removed '{item.Title}' from library.";
    }

    public async Task AddToWishlistAsync(GameItemViewModel item)
    {
        if (App.CurrentUser == null) return;
        var game = new Game { Platform = item.Platform, Title = item.Title };
        await GameService.AddToWishlistAsync(App.CurrentUser.Username, game);
        _wishlist = await GameService.GetWishlistAsync(App.CurrentUser.Username);
        item.IsInWishlist = true;
        RefreshWishlistView();
        StatusMessage = $"Added '{item.Title}' to wishlist!";
    }

    public async Task RemoveFromWishlistAsync(GameItemViewModel item)
    {
        if (App.CurrentUser == null) return;
        await GameService.RemoveFromWishlistAsync(App.CurrentUser.Username, item.Platform, item.Title);
        _wishlist = await GameService.GetWishlistAsync(App.CurrentUser.Username);
        item.IsInWishlist = false;
        RefreshWishlistView();
        StatusMessage = $"Removed '{item.Title}' from wishlist.";
    }
}
