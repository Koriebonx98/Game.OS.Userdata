using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

/// <summary>
/// Root view-model that owns navigation and the shared session state.
/// </summary>
public partial class MainViewModel : ViewModelBase
{
    private readonly GameOsClient _client;

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

    // ── Navigation state ───────────────────────────────────────────────────
    [ObservableProperty] private bool _showLogin    = true;
    [ObservableProperty] private bool _showMain     = false;
    [ObservableProperty] private string _activePage = "dashboard";

    public bool IsHome        => ActivePage == "dashboard";
    public bool IsLibrary     => ActivePage == "library";
    public bool IsStore       => ActivePage == "store";
    public bool IsProfile     => ActivePage == "profile";

    partial void OnActivePageChanged(string value)
    {
        OnPropertyChanged(nameof(IsHome));
        OnPropertyChanged(nameof(IsLibrary));
        OnPropertyChanged(nameof(IsStore));
        OnPropertyChanged(nameof(IsProfile));
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

        LoginVm.OnLoginSuccess = OnLoginSuccess;
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
        ActivePage = page;
        if (page == "library")
            LibraryVm.Load(_library);
        if (page == "profile")
            ProfileVm.Load(_profile, _library, _achievements, _demoMode);
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
        ShowLogin = true;
    }
}
