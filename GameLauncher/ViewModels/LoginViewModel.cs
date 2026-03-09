using System.Collections.Generic;
using System.Collections.ObjectModel;
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

    /// <summary>Local saved accounts shown in the quick-login panel.</summary>
    public ObservableCollection<SavedSession> SavedAccounts { get; } = new()
    {
        new SavedSession
        {
            Username    = "koriebonx98",
            DisplayName = "koriebonx98",
            AvatarColor = "#e4000f",
            SavedAt     = "2024-01-01T00:00:00Z"
        }
    };

    public System.Action<UserProfile, List<Game>, List<Achievement>>? OnLoginSuccess { get; set; }

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
            var profile      = await _client.LoginAsync(Username, Password);
            var games        = await _client.GetGamesAsync();
            var achievements = await _client.GetAchievementsAsync();

            var lib = games;
            // Enrich with static metadata where the API response lacks UI fields
            foreach (var g in lib)
            {
                var meta = DemoData.Library.FirstOrDefault(d =>
                    d.Title.Equals(g.Title, System.StringComparison.OrdinalIgnoreCase));
                if (meta != null)
                {
                    g.Genre       ??= meta.Genre;
                    g.Description ??= meta.Description;
                    g.Rating      ??= meta.Rating;
                    g.CoverColor  ??= meta.CoverColor;
                    g.CoverUrl    ??= meta.CoverUrl;
                }
            }

            OnLoginSuccess?.Invoke(profile, lib, achievements);
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
            OnLoginSuccess?.Invoke(profile, new List<Game>(), new List<Achievement>());
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
    private void ToggleForm() => ShowRegister = !ShowRegister;

    /// <summary>Quick-login — pre-fills the username field from a saved session.</summary>
    [RelayCommand]
    private void QuickLogin(SavedSession? session)
    {
        if (session == null) return;
        Username = session.Username;
        ErrorMessage = "";
    }
}
