using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameOS.Desktop.Services;
using System.Threading.Tasks;

namespace GameOS.Desktop.ViewModels;

public partial class SignupViewModel : ViewModelBase
{
    private readonly MainWindowViewModel _main;

    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _email = "";
    [ObservableProperty] private string _password = "";
    [ObservableProperty] private string _confirmPassword = "";
    [ObservableProperty] private string _errorMessage = "";
    [ObservableProperty] private string _successMessage = "";
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private bool _acceptTerms;

    public SignupViewModel(MainWindowViewModel main)
    {
        _main = main;
    }

    [RelayCommand]
    private async Task Signup()
    {
        ErrorMessage = "";
        SuccessMessage = "";

        if (!AcceptTerms) { ErrorMessage = "Please accept the terms of service."; return; }
        if (Password != ConfirmPassword) { ErrorMessage = "Passwords do not match."; return; }

        IsLoading = true;
        try
        {
            var (success, error) = await AuthService.SignupAsync(Username, Email, Password);
            if (!success) { ErrorMessage = error; return; }

            SuccessMessage = "Account created! You can now log in.";
            await Task.Delay(1500);
            _main.CurrentView = new LoginViewModel(_main);
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private void GoToLogin() => _main.CurrentView = new LoginViewModel(_main);
}
