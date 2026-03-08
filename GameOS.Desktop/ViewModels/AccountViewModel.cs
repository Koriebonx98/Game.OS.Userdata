using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameOS.Desktop.Models;
using GameOS.Desktop.Services;
using System.Threading.Tasks;

namespace GameOS.Desktop.ViewModels;

public partial class AccountViewModel : ViewModelBase
{
    private readonly MainWindowViewModel _main;

    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _email = "";
    [ObservableProperty] private string _createdAt = "";
    [ObservableProperty] private string _apiToken = "";
    [ObservableProperty] private string _apiTokenIssuedAt = "";
    [ObservableProperty] private bool _hasApiToken;

    [ObservableProperty] private string _newEmail = "";
    [ObservableProperty] private string _currentPassword = "";
    [ObservableProperty] private string _newPassword = "";
    [ObservableProperty] private string _confirmNewPassword = "";

    [ObservableProperty] private string _errorMessage = "";
    [ObservableProperty] private string _successMessage = "";
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private bool _showToken;

    public string DisplayToken => ShowToken ? ApiToken : (HasApiToken ? "gos_••••••••••••••••••" : "No token");
    public string CodeExample => HasApiToken
        ? BuildCodeExample()
        : "// Generate a token to see the usage example";

    private string BuildCodeExample() => @$"// C# usage example
var client = new HttpClient();
client.DefaultRequestHeaders.Add(""X-GameOS-Token"", ""{(ShowToken ? ApiToken : "YOUR_TOKEN_HERE")}"");";

    public AccountViewModel(MainWindowViewModel main)
    {
        _main = main;
        LoadUserData();
    }

    private void LoadUserData()
    {
        var user = App.CurrentUser;
        if (user == null) return;
        Username = user.Username;
        Email = user.Email;
        CreatedAt = user.CreatedAt;
        ApiToken = user.ApiToken ?? "";
        ApiTokenIssuedAt = user.ApiTokenIssuedAt ?? "";
        HasApiToken = !string.IsNullOrEmpty(user.ApiToken);
    }

    partial void OnShowTokenChanged(bool value)
    {
        OnPropertyChanged(nameof(DisplayToken));
        OnPropertyChanged(nameof(CodeExample));
    }

    [RelayCommand]
    private async Task UpdateAccount()
    {
        ErrorMessage = "";
        SuccessMessage = "";
        if (string.IsNullOrWhiteSpace(CurrentPassword)) { ErrorMessage = "Current password is required."; return; }
        if (!string.IsNullOrWhiteSpace(NewPassword) && NewPassword != ConfirmNewPassword)
        { ErrorMessage = "New passwords do not match."; return; }

        IsLoading = true;
        try
        {
            var (success, error) = await AuthService.UpdateAccountAsync(
                Username, CurrentPassword,
                string.IsNullOrWhiteSpace(NewEmail) ? null : NewEmail,
                string.IsNullOrWhiteSpace(NewPassword) ? null : NewPassword);

            if (!success) { ErrorMessage = error; return; }

            var updatedUser = await AuthService.GetUserAsync(Username);
            if (updatedUser != null)
            {
                App.CurrentUser = updatedUser;
                _main.CurrentUsername = updatedUser.Username;
            }
            LoadUserData();
            SuccessMessage = "Account updated successfully!";
            CurrentPassword = "";
            NewPassword = "";
            ConfirmNewPassword = "";
        }
        finally { IsLoading = false; }
    }

    [RelayCommand]
    private async Task GenerateToken()
    {
        if (App.CurrentUser == null) return;
        IsLoading = true;
        try
        {
            var token = await AuthService.GenerateApiTokenAsync(Username);
            var updatedUser = await AuthService.GetUserAsync(Username);
            if (updatedUser != null) App.CurrentUser = updatedUser;
            LoadUserData();
            ShowToken = true;
            SuccessMessage = "API token generated!";
        }
        finally { IsLoading = false; }
    }

    [RelayCommand]
    private async Task RevokeToken()
    {
        if (App.CurrentUser == null) return;
        await AuthService.RevokeApiTokenAsync(Username);
        var updatedUser = await AuthService.GetUserAsync(Username);
        if (updatedUser != null) App.CurrentUser = updatedUser;
        LoadUserData();
        ShowToken = false;
        SuccessMessage = "API token revoked.";
    }

    [RelayCommand]
    private void ToggleShowToken()
    {
        ShowToken = !ShowToken;
        OnPropertyChanged(nameof(DisplayToken));
        OnPropertyChanged(nameof(CodeExample));
    }
}
