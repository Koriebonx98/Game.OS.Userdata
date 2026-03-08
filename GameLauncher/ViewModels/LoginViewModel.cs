using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

public partial class LoginViewModel : ViewModelBase
{
    private readonly GameOsClient _client;

    [ObservableProperty] private string _username  = "";
    [ObservableProperty] private string _password  = "";
    [ObservableProperty] private string _email     = "";
    [ObservableProperty] private string _confirmPassword = "";
    [ObservableProperty] private string _errorMessage = "";
    [ObservableProperty] private bool   _isLoading    = false;
    [ObservableProperty] private bool   _showRegister = false;

    public System.Action<UserProfile, List<Game>, List<Achievement>, bool>? OnLoginSuccess { get; set; }

    public LoginViewModel(GameOsClient client)
    {
        _client = client;
    }

    [RelayCommand]
    private async System.Threading.Tasks.Task SignInAsync()
    {
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password))
        {
            ErrorMessage = "Please enter your username and password.";
            return;
        }

        IsLoading = true;
        ErrorMessage = "";
        try
        {
            var profile = await _client.LoginAsync(Username, Password);
            var (games, _) = await _client.GetGamesAsync(profile.Username);
            var (achievements, _) = await _client.GetAchievementsAsync(profile.Username);

            var lib = games ?? new List<Game>();
            // Enrich with demo metadata if missing
            foreach (var g in lib)
            {
                var demo = DemoData.Library.FirstOrDefault(d =>
                    d.Title.Equals(g.Title, System.StringComparison.OrdinalIgnoreCase));
                if (demo != null)
                {
                    g.Genre       ??= demo.Genre;
                    g.Description ??= demo.Description;
                    g.Rating      ??= demo.Rating;
                    g.CoverColor  ??= demo.CoverColor;
                }
            }

            OnLoginSuccess?.Invoke(profile, lib, achievements ?? new List<Achievement>(), _client.DemoMode);
        }
        catch (GameOsException ex)
        {
            ErrorMessage = ex.Message;
        }
        catch (System.Exception ex)
        {
            ErrorMessage = $"Connection error: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private async System.Threading.Tasks.Task RegisterAsync()
    {
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Email)
            || string.IsNullOrWhiteSpace(Password))
        {
            ErrorMessage = "Please fill in all fields.";
            return;
        }
        if (Password != ConfirmPassword)
        {
            ErrorMessage = "Passwords do not match.";
            return;
        }
        if (Password.Length < 8)
        {
            ErrorMessage = "Password must be at least 8 characters.";
            return;
        }

        IsLoading = true;
        ErrorMessage = "";
        try
        {
            var profile = await _client.RegisterAsync(Username, Email, Password);
            OnLoginSuccess?.Invoke(profile, new List<Game>(),
                new List<Achievement>(), _client.DemoMode);
        }
        catch (GameOsException ex)
        {
            ErrorMessage = ex.Message;
        }
        catch (System.Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private void DemoMode()
    {
        _client.DemoMode = true;
        IsLoading = false;
        ErrorMessage = "";

        // Bypass network entirely — load demo data directly
        var profile = new UserProfile
        {
            Username     = "Demo",
            Email        = "demo@gameos.local",
            CreatedAt    = "2025-01-01T00:00:00Z",
            PasswordHash = ""
        };
        OnLoginSuccess?.Invoke(
            profile,
            new System.Collections.Generic.List<Models.Game>(DemoData.Library),
            new System.Collections.Generic.List<Models.Achievement>(DemoData.Achievements),
            true);
    }

    [RelayCommand]
    private void ToggleForm() => ShowRegister = !ShowRegister;
}
