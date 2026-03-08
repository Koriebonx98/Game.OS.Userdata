using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameOS.Desktop.Models;
using GameOS.Desktop.Services;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace GameOS.Desktop.ViewModels;

/// <summary>
/// Represents a single game card shown in the merged "My Games" grid on the dashboard.
/// </summary>
public partial class DashboardGameItemViewModel : ViewModelBase
{
    public string Title { get; }
    public string Platform { get; }
    public string PlatformIcon { get; }
    public string PlatformColor { get; }
    public string AddedAt { get; }
    public string AddedAtShort { get; }

    public DashboardGameItemViewModel(Game game)
    {
        Title = game.Title;
        Platform = game.Platform;
        AddedAt = game.AddedAt;
        PlatformIcon = GetPlatformIcon(game.Platform);
        PlatformColor = GetPlatformColor(game.Platform);

        AddedAtShort = string.IsNullOrEmpty(game.AddedAt) ? ""
            : System.DateTime.TryParse(game.AddedAt, out var dt)
                ? dt.ToString("MMM d")
                : "";
    }

    private static string GetPlatformIcon(string platform) => platform switch
    {
        "PC"       => "🖥️",
        "PS3"      => "🎮",
        "PS4"      => "🎮",
        "PS5"      => "🎮",
        "Switch"   => "🕹️",
        "Xbox 360" => "🎮",
        "Xbox One" => "🎮",
        _          => "🎮"
    };

    private static string GetPlatformColor(string platform) => platform switch
    {
        "PC"       => "#1a9fe0",
        "PS3"      => "#003087",
        "PS4"      => "#003087",
        "PS5"      => "#003087",
        "Switch"   => "#e4000f",
        "Xbox 360" => "#107c10",
        "Xbox One" => "#107c10",
        _          => "#533483"
    };
}

/// <summary>
/// ViewModel for the post-login dashboard. Inspired by Steam/Xbox/PlayStation hub:
/// shows a personalised welcome banner, stats strip, and a merged "My Games" grid.
/// </summary>
public partial class DashboardViewModel : ViewModelBase
{
    private readonly MainWindowViewModel _main;

    // ── User info ──────────────────────────────────────────────────────────────
    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _avatarInitial = "";
    [ObservableProperty] private string _memberSince = "";

    // ── Stats ──────────────────────────────────────────────────────────────────
    [ObservableProperty] private int _totalGames;
    [ObservableProperty] private int _totalPlatforms;
    [ObservableProperty] private int _wishlistCount;
    [ObservableProperty] private int _friendsCount;
    [ObservableProperty] private int _inboxCount;

    // ── My Games (merged, all platforms) ──────────────────────────────────────
    [ObservableProperty] private ObservableCollection<DashboardGameItemViewModel> _myGames = new();
    [ObservableProperty] private ObservableCollection<DashboardGameItemViewModel> _recentGames = new();
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private bool _isLoading = true;
    [ObservableProperty] private string _statusMessage = "";

    private System.Collections.Generic.List<DashboardGameItemViewModel> _allGameItems = new();

    public DashboardViewModel(MainWindowViewModel main)
    {
        _main = main;
        var user = App.CurrentUser;
        if (user != null)
        {
            Username = user.Username;
            AvatarInitial = user.Username.Length > 0 ? user.Username[0].ToString().ToUpperInvariant() : "?";
            MemberSince = System.DateTime.TryParse(user.CreatedAt, out var dt)
                ? dt.ToString("MMMM yyyy")
                : "";
        }
        _ = LoadAsync();
    }

    public async Task LoadAsync()
    {
        IsLoading = true;
        try
        {
            if (App.CurrentUser == null) return;

            var library  = await GameService.GetLibraryAsync(App.CurrentUser.Username);
            var wishlist = await GameService.GetWishlistAsync(App.CurrentUser.Username);
            var friends  = await FriendService.GetFriendsAsync(App.CurrentUser.Username);
            var requests = await FriendService.GetFriendRequestsAsync(App.CurrentUser.Username);

            // Stats
            TotalGames     = library.Count;
            TotalPlatforms = library.Select(g => g.Platform).Distinct().Count();
            WishlistCount  = wishlist.Count;
            FriendsCount   = friends.Count;
            InboxCount     = requests.Count;
            _main.InboxCount = requests.Count;

            // Merged My Games — sorted alphabetically, newest-added first as tie-breaker
            _allGameItems = library
                .OrderBy(g => g.Title)
                .ThenByDescending(g => g.AddedAt)
                .Select(g => new DashboardGameItemViewModel(g))
                .ToList();

            ApplySearch();

            // Recent Games — last 6 added
            RecentGames = new ObservableCollection<DashboardGameItemViewModel>(
                library
                    .OrderByDescending(g => g.AddedAt)
                    .Take(6)
                    .Select(g => new DashboardGameItemViewModel(g))
            );
        }
        finally
        {
            IsLoading = false;
        }
    }

    partial void OnSearchTextChanged(string value) => ApplySearch();

    private void ApplySearch()
    {
        var text = SearchText.Trim();
        var filtered = string.IsNullOrEmpty(text)
            ? _allGameItems
            : _allGameItems
                .Where(g => g.Title.Contains(text, System.StringComparison.OrdinalIgnoreCase)
                         || g.Platform.Contains(text, System.StringComparison.OrdinalIgnoreCase))
                .ToList();

        MyGames = new ObservableCollection<DashboardGameItemViewModel>(filtered);
    }

    // ── Navigation ──────────────────────────────────────────────────────────────

    [RelayCommand]
    private void GoToBrowse()
    {
        var vm = new GamesViewModel();
        _ = vm.LoadAsync();
        _main.CurrentView = vm;
    }

    [RelayCommand]
    private void GoToLibrary()
    {
        var vm = new GamesViewModel();
        _ = vm.LoadAsync();
        _main.CurrentView = vm;
        vm.SelectedTabIndex = 1;   // Library tab
    }

    [RelayCommand]
    private void GoToWishlist()
    {
        var vm = new GamesViewModel();
        _ = vm.LoadAsync();
        _main.CurrentView = vm;
        vm.SelectedTabIndex = 2;   // Wishlist tab
    }

    [RelayCommand]
    private void GoToFriends()
    {
        var vm = new FriendsViewModel(_main);
        _ = vm.LoadAsync();
        _main.CurrentView = vm;
    }

    [RelayCommand]
    private void GoToInbox()
    {
        var vm = new InboxViewModel(_main);
        _ = vm.LoadAsync();
        _main.CurrentView = vm;
    }

    [RelayCommand]
    private void GoToAccount() => _main.CurrentView = new AccountViewModel(_main);

    [RelayCommand]
    private async Task RemoveGame(DashboardGameItemViewModel item)
    {
        if (App.CurrentUser == null) return;
        await GameService.RemoveGameAsync(App.CurrentUser.Username, item.Platform, item.Title);
        await LoadAsync();
        StatusMessage = $"Removed '{item.Title}' from library.";
    }
}
