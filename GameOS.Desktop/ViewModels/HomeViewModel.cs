using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameOS.Desktop.Services;

namespace GameOS.Desktop.ViewModels;

public partial class HomeViewModel : ViewModelBase
{
    private readonly MainWindowViewModel _main;

    [ObservableProperty] private int _userCount;
    [ObservableProperty] private bool _isLoggedIn;
    [ObservableProperty] private string _welcomeMessage = "Welcome to Game OS";

    public HomeViewModel(MainWindowViewModel main)
    {
        _main = main;
        IsLoggedIn = main.IsLoggedIn;
        UserCount = DataService.GetUserCount();
        if (main.IsLoggedIn)
            WelcomeMessage = $"Welcome back, {main.CurrentUsername}!";
    }

    [RelayCommand]
    private void BrowseGames()
    {
        if (!_main.IsLoggedIn) { _main.CurrentView = new LoginViewModel(_main); return; }
        var vm = new GamesViewModel();
        _ = vm.LoadAsync();
        _main.CurrentView = vm;
    }

    [RelayCommand]
    private void GoToSignup() => _main.CurrentView = new SignupViewModel(_main);

    [RelayCommand]
    private void GoToLibrary()
    {
        if (!_main.IsLoggedIn) { _main.CurrentView = new LoginViewModel(_main); return; }
        var vm = new GamesViewModel();
        _ = vm.LoadAsync();
        _main.CurrentView = vm;
    }
}
