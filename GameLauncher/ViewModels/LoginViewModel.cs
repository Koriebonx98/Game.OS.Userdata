using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

public partial class LoginViewModel : ViewModelBase
{
    private readonly GameOsClient        _client;
    private readonly SessionCacheService _cache;

    [ObservableProperty] private string _username  = "";
    [ObservableProperty] private string _password  = "";
    [ObservableProperty] private string _email     = "";
    [ObservableProperty] private string _confirmPassword = "";
    [ObservableProperty] private string _errorMessage = "";
    [ObservableProperty] private bool   _isLoading    = false;
    [ObservableProperty] private bool   _showRegister = false;
    /// <summary>When true the session token is saved to disk so the next launch
    /// auto-logs the user in — mirrors the "Remember me" checkbox on the website.</summary>
    [ObservableProperty] private bool   _rememberMe   = true;

    /// <summary>Local saved accounts shown in the quick-login panel.
    /// Populated from <see cref="SessionCacheService"/> so the list always
    /// reflects real previously-logged-in accounts.</summary>
    public ObservableCollection<SavedSession> SavedAccounts { get; } = new();

    public System.Action<UserProfile, List<Game>, List<Achievement>>? OnLoginSuccess { get; set; }

    public LoginViewModel(GameOsClient client, SessionCacheService cache)
    {
        _client = client;
        _cache  = cache;
        RefreshSavedAccounts();
    }

    // ── Auto-login on startup ─────────────────────────────────────────────

    /// <summary>
    /// Called once at application startup.  If the user previously ticked
    /// "Remember me" the session is restored silently — exactly like the
    /// website returning you to the dashboard because <c>gameOSUser</c> is
    /// still in <c>localStorage</c>.
    /// </summary>
    public async System.Threading.Tasks.Task TryAutoLoginAsync()
    {
        var saved = _cache.GetRememberedSession();
        if (saved == null) return;

        IsLoading    = true;
        ErrorMessage = "";
        try
        {
            var profile      = await _client.RestoreSessionAsync(saved.Token, saved.Username);
            var games        = await _client.GetGamesAsync();
            var achievements = await _client.GetAchievementsAsync();
            EnrichGames(games);
            OnLoginSuccess?.Invoke(profile, games, achievements);
        }
        catch (Exception ex) when (ex is GameOsException or System.Net.Http.HttpRequestException)
        {
            // Token expired or server unavailable — clear the stale token so
            // the user sees the login form (same as the web invalidating an old session).
            _cache.ClearToken(saved.Username);
            _client.Logout();
            System.Diagnostics.Debug.WriteLine($"[AutoLogin] Session restore failed: {ex.Message}");
            ErrorMessage = "";
        }
        finally
        {
            IsLoading = false;
        }
    }

    // ── Commands ──────────────────────────────────────────────────────────

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
            EnrichGames(games);

            // Persist the session so the user stays logged in across launches
            // (same as the website writing to localStorage when "Remember me" is checked).
            _cache.SaveSession(new CachedSession
            {
                Username    = profile.Username,
                Email       = profile.Email,
                Token       = _client.Token ?? "",
                AvatarColor = "#1e90ff",
                SavedAt     = System.DateTime.UtcNow.ToString("o"),
                RememberMe  = RememberMe,
            });
            RefreshSavedAccounts();

            OnLoginSuccess?.Invoke(profile, games, achievements);
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

            _cache.SaveSession(new CachedSession
            {
                Username    = profile.Username,
                Email       = profile.Email,
                Token       = _client.Token ?? "",
                AvatarColor = "#1e90ff",
                SavedAt     = System.DateTime.UtcNow.ToString("o"),
                RememberMe  = RememberMe,
            });
            RefreshSavedAccounts();

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

    /// <summary>
    /// Demo mode — loads the full launcher with rich sample data without
    /// needing a backend server or an account.  Shows every page exactly
    /// as it appears when logged in.
    /// </summary>
    [RelayCommand]
    private void DemoLogin()
    {
        var profile = new UserProfile
        {
            Username  = "DemoPlayer",
            Email     = "demo@gameos.example.com",
            CreatedAt = "2024-06-15T10:00:00Z",
        };

        // Use all DemoData library entries as the player's library
        var games = DemoData.Library
            .Select(g => new Game
            {
                Platform    = g.Platform,
                Title       = g.Title,
                TitleId     = g.TitleId,
                CoverUrl    = g.CoverUrl,
                Screenshots = g.Screenshots,
                AddedAt     = g.AddedAt,
                Genre       = g.Genre,
                Description = g.Description,
                Rating      = g.Rating,
                CoverColor  = g.CoverColor,
                CoverGradient = g.CoverGradient,
            })
            .ToList();

        var achievements = new List<Achievement>
        {
            new() { Platform = "Switch", GameTitle = "Mario Kart 8 Deluxe",  AchievementId = "mk8_1",  Name = "Speed Racer",        Description = "Win your first online race.",             UnlockedAt = "2025-06-02T18:00:00Z" },
            new() { Platform = "Switch", GameTitle = "Mario Kart 8 Deluxe",  AchievementId = "mk8_2",  Name = "All Cups Gold",      Description = "Win every cup on 150cc.",                 UnlockedAt = "2025-06-10T20:30:00Z" },
            new() { Platform = "Switch", GameTitle = "Zelda: TOTK",          AchievementId = "totk_1", Name = "Sky Explorer",       Description = "Reach the highest sky island.",           UnlockedAt = "2025-04-20T14:00:00Z" },
            new() { Platform = "PC",     GameTitle = "Cyberpunk 2077",        AchievementId = "cp_1",   Name = "Night City Legend",  Description = "Complete the main story.",                UnlockedAt = "2025-01-15T22:00:00Z" },
            new() { Platform = "PC",     GameTitle = "Elden Ring",            AchievementId = "er_1",   Name = "Elden Lord",         Description = "Achieve the Elden Lord ending.",          UnlockedAt = "2025-02-28T21:00:00Z" },
            new() { Platform = "PC",     GameTitle = "Baldur's Gate 3",       AchievementId = "bg3_1",  Name = "Honour Among Thieves",Description = "Complete the game on Honour Mode.",     UnlockedAt = "2025-03-10T19:00:00Z" },
            new() { Platform = "Xbox",   GameTitle = "Halo Infinite",         AchievementId = "hi_1",   Name = "Demon",              Description = "Complete the campaign on Legendary.",     UnlockedAt = "2025-01-25T16:00:00Z" },
            new() { Platform = "PS5",    GameTitle = "God of War Ragnarök",   AchievementId = "gow_1",  Name = "Ragnarök Survivor",  Description = "Defeat Odin.",                            UnlockedAt = "2025-02-08T20:00:00Z" },
            new() { Platform = "PC",     GameTitle = "Hogwarts Legacy",       AchievementId = "hl_1",   Name = "Legend of Hogwarts", Description = "Discover all ancient magic secrets.",    UnlockedAt = "2025-04-05T17:00:00Z" },
            new() { Platform = "PC",     GameTitle = "Starfield",             AchievementId = "sf_1",   Name = "Into the Starfield", Description = "Join Constellation.",                     UnlockedAt = "2025-05-12T11:00:00Z" },
        };

        OnLoginSuccess?.Invoke(profile, games, achievements);
    }

    /// <summary>
    /// Quick-login — if the saved session has a token, restore it silently.
    /// Otherwise pre-fill the username field so the user just needs to type
    /// the password (same UX as the web's single-session model).
    /// </summary>
    [RelayCommand]
    private async System.Threading.Tasks.Task QuickLogin(SavedSession? session)
    {
        if (session == null) return;

        // Try token-based silent restore first
        var cached = _cache.GetSession(session.Username);
        if (cached != null && !string.IsNullOrEmpty(cached.Token))
        {
            IsLoading    = true;
            ErrorMessage = "";
            try
            {
                var profile      = await _client.RestoreSessionAsync(cached.Token, cached.Username);
                var games        = await _client.GetGamesAsync();
                var achievements = await _client.GetAchievementsAsync();
                EnrichGames(games);
                OnLoginSuccess?.Invoke(profile, games, achievements);
                return;
            }
            catch (Exception ex) when (ex is GameOsException or System.Net.Http.HttpRequestException)
            {
                // Token expired — clear it and fall through to password form
                _cache.ClearToken(session.Username);
                _client.Logout();
                System.Diagnostics.Debug.WriteLine($"[QuickLogin] Session restore failed: {ex.Message}");
            }
            finally
            {
                IsLoading = false;
            }
        }

        // Token not available or expired — pre-fill username so the user
        // only needs to enter the password (same as web behaviour).
        Username     = session.Username;
        Password     = "";
        ErrorMessage = "";
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private void RefreshSavedAccounts()
    {
        SavedAccounts.Clear();
        foreach (var s in _cache.GetSavedAccounts())
            SavedAccounts.Add(s);
    }

    /// <summary>
    /// Enrich API-returned games with UI metadata (cover URL, genre, etc.)
    /// that the backend does not store — same as the website falling back to
    /// static game metadata when the API response lacks those fields.
    /// </summary>
    private static void EnrichGames(List<Game> games)
    {
        foreach (var g in games)
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
    }
}
