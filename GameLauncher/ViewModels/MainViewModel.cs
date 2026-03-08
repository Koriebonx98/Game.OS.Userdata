using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

/// <summary>
/// Root view-model that owns navigation and the shared session state.
/// </summary>
public partial class MainViewModel : ViewModelBase, IDisposable
{
    private readonly GameOsClient      _client;
    private readonly GameScannerService _scanner;

    // ── Session data ───────────────────────────────────────────────────────
    private UserProfile     _profile      = new();
    private List<Game>      _library      = new();
    private List<Achievement> _achievements = new();
    private bool            _demoMode     = false;

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
        bool hasPat = !string.IsNullOrWhiteSpace(
            System.Environment.GetEnvironmentVariable("GAMEOS_PAT"));
        _client = new GameOsClient(demoMode: !hasPat);

        LoginVm     = new LoginViewModel(_client);
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
    }

    private void OnLoginSuccess(UserProfile profile, List<Game> library,
                                List<Achievement> achievements, bool demoMode)
    {
        _profile      = profile;
        _library      = library;
        _achievements = achievements;
        _demoMode     = demoMode;

        DashboardVm.Load(profile, library, achievements);
        LibraryVm.Load(library);
        StoreVm.Load(DemoData.Store, library, profile, _client, demoMode);
        ProfileVm.Load(profile, library, achievements, demoMode);

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
        if (page == "profile")
            ProfileVm.Load(_profile, _library, _achievements, _demoMode);
    }

    private void OpenDetailFromGame(Game game)
    {
        DetailVm.LoadFromGame(game);
        ShowDetail = true;
    }

    private void OpenDetailFromStoreGame(StoreGame game)
    {
        DetailVm.LoadFromStoreGame(game);
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
