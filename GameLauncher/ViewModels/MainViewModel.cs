using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>
/// Root view-model that owns navigation and the shared session state.
/// </summary>
public partial class MainViewModel : ViewModelBase, IDisposable
{
    private readonly GameOsClient        _client;
    private readonly GameScannerService  _scanner;
    private readonly SessionCacheService _sessionCache;

    // ── Session data ───────────────────────────────────────────────────────
    private UserProfile     _profile      = new();
    private List<Game>      _library      = new();
    private List<Achievement> _achievements = new();

    // ── Child view models ──────────────────────────────────────────────────
    public LoginViewModel     LoginVm     { get; }
    public DashboardViewModel DashboardVm { get; }
    public LibraryViewModel   LibraryVm   { get; }
    public StoreViewModel     StoreVm     { get; }
    public ProfileViewModel   ProfileVm   { get; }
    public FriendsViewModel   FriendsVm   { get; }
    public GameDetailViewModel DetailVm   { get; }

    // ── Navigation state ───────────────────────────────────────────────────
    [ObservableProperty] private bool _showLogin    = true;
    [ObservableProperty] private bool _showMain     = false;
    [ObservableProperty] private bool _showDetail   = false;
    [ObservableProperty] private string _activePage = "dashboard";

    public bool IsHome        => ActivePage == "dashboard";
    public bool IsLibrary     => ActivePage == "library";
    public bool IsStore       => ActivePage == "store";
    public bool IsProfile     => ActivePage == "profile";
    public bool IsFriends     => ActivePage == "friends";

    partial void OnActivePageChanged(string value)
    {
        OnPropertyChanged(nameof(IsHome));
        OnPropertyChanged(nameof(IsLibrary));
        OnPropertyChanged(nameof(IsStore));
        OnPropertyChanged(nameof(IsProfile));
        OnPropertyChanged(nameof(IsFriends));
    }

    public MainViewModel()
    {
        _client       = new GameOsClient();
        _sessionCache = new SessionCacheService();

        LoginVm     = new LoginViewModel(_client, _sessionCache);
        DashboardVm = new DashboardViewModel();
        LibraryVm   = new LibraryViewModel();
        StoreVm     = new StoreViewModel();
        ProfileVm   = new ProfileViewModel();
        FriendsVm   = new FriendsViewModel();
        DetailVm    = new GameDetailViewModel();

        DetailVm.OnClose = () => ShowDetail = false;

        LoginVm.OnLoginSuccess = OnLoginSuccess;

        // Wire up OpenDetail from child VMs
        DashboardVm.OnOpenDetail      = OpenDetailFromGame;
        DashboardVm.OnOpenStoreDetail = OpenDetailFromStoreGame;
        LibraryVm.OnOpenDetail        = OpenDetailFromGame;
        LibraryVm.OnOpenLocalDetail   = OpenDetailFromLocalGame;
        StoreVm.OnOpenDetail          = OpenDetailFromStoreGame;

        // Start background scanner regardless of login state
        _scanner = new GameScannerService();
        _scanner.GamesUpdated   += games   => LibraryVm.UpdateLocalGames(games);
        _scanner.RepacksUpdated += repacks => LibraryVm.UpdateRepacks(repacks);
        _ = _scanner.StartAsync();

        // Attempt silent auto-login from cached session (mirrors web localStorage restore)
        _ = LoginVm.TryAutoLoginAsync();

    }

    private void OnLoginSuccess(UserProfile profile, List<Game> library,
                                List<Achievement> achievements)
    {
        _profile      = profile;
        _library      = library;
        _achievements = achievements;

        bool isAdmin = _client.IsAdmin;

        DashboardVm.Load(profile, library, achievements);
        LibraryVm.Load(library);
        StoreVm.Load(DemoData.Store, library, profile, _client, isAdmin);
        ProfileVm.Load(profile, library, achievements, isAdmin);
        FriendsVm.Load(_client, profile.Username);

        ShowLogin = false;
        ShowMain  = true;
        ActivePage = "dashboard";
    }

    [RelayCommand]
    private void Navigate(string page)
    {
        ShowDetail = false;
        ActivePage = page;
        if (page == "library")
            LibraryVm.Load(_library);
        if (page == "friends")
            FriendsVm.Load(_client, _profile.Username);
        if (page == "profile")
            ProfileVm.Load(_profile, _library, _achievements, _client.IsAdmin);
    }

    private void OpenDetailFromGame(Game game)
    {
        // Check if this game is installed locally or has a repack available
        LocalGame? localGame = LibraryVm.LocalGames
            .FirstOrDefault(lg => lg.Title.Equals(game.Title, StringComparison.OrdinalIgnoreCase));
        LocalRepack? repack = null;
        if (localGame == null)
            repack = LibraryVm.ReadyToInstall
                .FirstOrDefault(r => r.Title.Equals(game.Title, StringComparison.OrdinalIgnoreCase));

        DetailVm.LoadFromGame(game, localGame, repack);
        ShowDetail = true;
    }

    private void OpenDetailFromStoreGame(StoreGame game)
    {
        // Check if this store game is installed locally or has a repack available
        LocalGame? localGame = LibraryVm.LocalGames
            .FirstOrDefault(lg => lg.Title.Equals(game.Title, StringComparison.OrdinalIgnoreCase));
        LocalRepack? repack = null;
        if (localGame == null)
            repack = LibraryVm.ReadyToInstall
                .FirstOrDefault(r => r.Title.Equals(game.Title, StringComparison.OrdinalIgnoreCase));

        DetailVm.LoadFromStoreGame(game, localGame, repack);
        ShowDetail = true;
    }

    private void OpenDetailFromLocalGame(LocalGame game)
    {
        DetailVm.LoadFromLocalGame(game);
        ShowDetail = true;
    }

    [RelayCommand]
    private void SignOut()
    {
        // Clear the saved token so the next launch shows the login form
        // (equivalent to the web calling localStorage.removeItem('gameOSUser'))
        if (_client.LoggedInUser != null)
            _sessionCache.ClearToken(_client.LoggedInUser);

        _client.Logout();
        _library      = new();
        _achievements = new();
        _profile      = new();

        LoginVm.Username = "";
        LoginVm.Password = "";
        LoginVm.ErrorMessage = "";
        LoginVm.ShowRegister = false;

        ShowMain  = false;
        ShowDetail = false;
        ShowLogin = true;
    }

    public void Dispose()
    {
        _scanner.Dispose();
        (_client as IDisposable)?.Dispose();
    }
}
