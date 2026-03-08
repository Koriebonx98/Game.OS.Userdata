using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameOS.Desktop.Services;
using System.Threading.Tasks;

namespace GameOS.Desktop.ViewModels;

public partial class LoginViewModel : ViewModelBase
{
    private readonly MainWindowViewModel _main;

    [ObservableProperty] private string _emailOrUsername = "";
    [ObservableProperty] private string _password = "";
    [ObservableProperty] private string _errorMessage = "";
    [ObservableProperty] private bool _isLoading;

    public LoginViewModel(MainWindowViewModel main)
    {
        _main = main;
    }

    [RelayCommand]
    private async Task Login()
    {
        ErrorMessage = "";
        IsLoading = true;
        try
        {
            var (user, error) = await AuthService.LoginAsync(EmailOrUsername, Password);
            if (user == null)
            {
                ErrorMessage = error;
                return;
            }
            // SetUser navigates to the Dashboard automatically.
            _main.SetUser(user);
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private void GoToSignup() => _main.CurrentView = new SignupViewModel(_main);
}
