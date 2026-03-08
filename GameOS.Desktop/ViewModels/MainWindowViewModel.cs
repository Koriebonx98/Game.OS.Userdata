using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameOS.Desktop.Models;
using GameOS.Desktop.Services;
using System.Threading.Tasks;

namespace GameOS.Desktop.ViewModels;

public partial class MainWindowViewModel : ViewModelBase
{
    [ObservableProperty] private ViewModelBase _currentView = null!;
    [ObservableProperty] private bool _isLoggedIn;
    [ObservableProperty] private string _currentUsername = "";
    [ObservableProperty] private int _inboxCount;

    public MainWindowViewModel()
    {
        NavigationService.Initialize(vm => CurrentView = vm);
        // App always starts on the Login screen; dashboard is shown after auth.
        var startView = System.Environment.GetEnvironmentVariable("GAMEOS_START_VIEW") ?? "login";

        // Screenshot helper: auto-load a specific user when GAMEOS_DEMO_USER is set.
        var demoUserName = System.Environment.GetEnvironmentVariable("GAMEOS_DEMO_USER");
        if (!string.IsNullOrEmpty(demoUserName))
        {
            var demoUser = AuthService.GetUserAsync(demoUserName).GetAwaiter().GetResult();
            if (demoUser != null) { App.CurrentUser = demoUser; IsLoggedIn = true; CurrentUsername = demoUser.Username; }
        }

        _currentView = startView switch
        {
            "signup"    => (ViewModelBase)new SignupViewModel(this),
            "games"     => new GamesViewModel(),
            "friends"   => new FriendsViewModel(this),
            "inbox"     => new InboxViewModel(this),
            "account"   => new AccountViewModel(this),
            "dashboard" => new DashboardViewModel(this),
            _           => new LoginViewModel(this)   // default = login
        };
        if (_currentView is GamesViewModel gvm) _ = gvm.LoadAsync();
        if (_currentView is FriendsViewModel fvm) _ = fvm.LoadAsync();
        if (_currentView is InboxViewModel ivm) _ = ivm.LoadAsync();
    }

    public void SetUser(User user)
    {
        App.CurrentUser = user;
        IsLoggedIn = true;
        CurrentUsername = user.Username;
        // Navigate straight to the dashboard after a successful login / signup.
        var dash = new DashboardViewModel(this);
        CurrentView = dash;
    }

    public void ClearUser()
    {
        App.CurrentUser = null;
        IsLoggedIn = false;
        CurrentUsername = "";
        InboxCount = 0;
    }

    public async Task RefreshInboxCountAsync()
    {
        if (App.CurrentUser == null) return;
        var requests = await FriendService.GetFriendRequestsAsync(App.CurrentUser.Username);
        InboxCount = requests.Count;
    }

    // ── Navigation commands ────────────────────────────────────────────────────

    [RelayCommand]
    private void NavigateDashboard()
    {
        if (!IsLoggedIn) { CurrentView = new LoginViewModel(this); return; }
        CurrentView = new DashboardViewModel(this);
    }

    [RelayCommand]
    private void NavigateHome() => CurrentView = new LoginViewModel(this);   // Home ≡ Login when logged-out

    [RelayCommand]
    private void NavigateGames()
    {
        if (!IsLoggedIn) { CurrentView = new LoginViewModel(this); return; }
        var vm = new GamesViewModel();
        _ = vm.LoadAsync();
        CurrentView = vm;
    }

    [RelayCommand]
    private void NavigateFriends()
    {
        if (!IsLoggedIn) { CurrentView = new LoginViewModel(this); return; }
        var vm = new FriendsViewModel(this);
        _ = vm.LoadAsync();
        CurrentView = vm;
    }

    [RelayCommand]
    private void NavigateInbox()
    {
        if (!IsLoggedIn) { CurrentView = new LoginViewModel(this); return; }
        var vm = new InboxViewModel(this);
        _ = vm.LoadAsync();
        CurrentView = vm;
    }

    [RelayCommand]
    private void NavigateAccount()
    {
        if (!IsLoggedIn) { CurrentView = new LoginViewModel(this); return; }
        CurrentView = new AccountViewModel(this);
    }

    [RelayCommand]
    private void NavigateLogin() => CurrentView = new LoginViewModel(this);

    [RelayCommand]
    private void NavigateSignup() => CurrentView = new SignupViewModel(this);

    [RelayCommand]
    private void Logout()
    {
        ClearUser();
        // After logout always return to the Login screen.
        CurrentView = new LoginViewModel(this);
    }
}
