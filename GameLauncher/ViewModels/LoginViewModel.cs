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

    /// <summary>
    /// Demo mode — loads the full launcher with the real user account "Koriebonx98"
    /// and the real game library from the Games.Database repository.
    /// No backend server or account credentials are needed.
    /// </summary>
    [RelayCommand]
    private void DemoLogin()
    {
        var profile = new UserProfile
        {
            Username  = "Koriebonx98",
            Email     = "koriebonx98@gameos.example.com",
            CreatedAt = "2023-11-20T14:30:00Z",
        };

        // Real library — PS4 games from Koriebonx98/Games.Database + popular cross-platform titles
        var games = new List<Game>
        {
            // PS4 games from the real Games.Database (Koriebonx98/Games.Database PS4.Games.json)
            new() { Platform = "PS4",  Title = "The Last of Us Part II", TitleId = "CUSA07820",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/3a96a1164364c063f40ce33aaf971783.png",
                Genre = "Action", Rating = 9.5, AddedAt = "2025-07-01T10:00:00Z",
                Description = "Five years after their dangerous journey across the post-pandemic United States, Ellie and Joel have settled down in Jackson, Wyoming.",
                CoverGradient = "#0a1a08,#1a3a10" },
            new() { Platform = "PS4",  Title = "God of War", TitleId = "CUSA07408",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/368b80128d9e529adf93f7ce84dfaca0.jpg",
                Genre = "Action", Rating = 9.6, AddedAt = "2025-07-02T12:00:00Z",
                Description = "Kratos now lives as a man in the realm of Norse Gods and monsters. It is in this harsh, unforgiving world that he must fight to survive.",
                CoverGradient = "#1a0500,#5c1500" },
            new() { Platform = "PS4",  Title = "Spider-Man", TitleId = "CUSA02299",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/1bc38477bc1f540837e39eb0b8dbb520.png",
                Genre = "Action", Rating = 9.2, AddedAt = "2025-08-01T09:00:00Z",
                Description = "Starring the world's most iconic Super Hero, Spider-Man features the acrobatic abilities, improvisation and web-slinging that the wall-crawler is famous for.",
                CoverGradient = "#0a0a2e,#1a1a6e" },
            new() { Platform = "PS4",  Title = "Uncharted 4: A Thief's End", TitleId = "CUSA00341",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/6fe386b00d7a58df2ee236b3bf339e6b.jpg",
                Genre = "Action", Rating = 9.1, AddedAt = "2025-09-10T15:00:00Z",
                Description = "Retired fortune hunter Nathan Drake is forced back into the world of thieves. With the stakes much more personal, he embarks on a globe-trotting journey.",
                CoverGradient = "#05150a,#0a3020" },
            new() { Platform = "PS4",  Title = "Horizon Zero Dawn", TitleId = "CUSA01967",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/abd673b91e4bb9c556da84c6f6f5d470.png",
                Genre = "Action RPG", Rating = 9.0, AddedAt = "2025-09-15T11:00:00Z",
                Description = "Experience Aloy's legendary quest to unravel the mysteries of a future Earth ruled by Machines.",
                CoverGradient = "#0a1a05,#1a5010" },
            // PC games from the real library (cross-platform titles)
            new() { Platform = "PC",   Title = "Cyberpunk 2077",
                CoverUrl = "https://media.rawg.io/media/games/26d/26d4437715bee60138dab4a7c8c59c92.jpg",
                Genre = "RPG", Rating = 9.1, AddedAt = "2025-01-10T12:00:00Z",
                Description = "An open-world action RPG set in the dark future of Night City.",
                CoverGradient = "#1a1a2e,#16213e" },
            new() { Platform = "PC",   Title = "Elden Ring",
                CoverUrl = "https://media.rawg.io/media/games/b45/b45575f34285f2c4479c9a5f719d972e.jpg",
                Genre = "Action RPG", Rating = 9.6, AddedAt = "2025-02-14T09:30:00Z",
                Description = "A sprawling fantasy action RPG from FromSoftware and George R.R. Martin.",
                CoverGradient = "#1c0a00,#6e2400" },
            new() { Platform = "PC",   Title = "Baldur's Gate 3",
                CoverUrl = "https://media.rawg.io/media/games/618/618c2031a07bbff6b4f611f10b6bcdbc.jpg",
                Genre = "RPG", Rating = 9.8, AddedAt = "2025-03-01T15:00:00Z",
                Description = "Gather your party and return to the Forgotten Realms in this award-winning DnD RPG.",
                CoverGradient = "#0d1b2a,#1b4332" },
            // Nintendo Switch
            new() { Platform = "Switch", Title = "Mario Kart 8 Deluxe",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/9cd6d894098e748716960bfcf9dbe115.png",
                Genre = "Racing", Rating = 9.7, AddedAt = "2025-06-01T10:00:00Z",
                Description = "Hit the road with the definitive version of Mario Kart 8! Race on 96 total courses.",
                CoverGradient = "#c00000,#ff6b00" },
            new() { Platform = "Switch", Title = "The Legend of Zelda: Tears of the Kingdom",
                CoverUrl = "https://assets.nintendo.com/image/upload/ar_16:9,b_auto:border,c_lpad/b_white/f_auto/q_auto/dpr_auto/c_scale,w_300/ncom/software/switch/70010000063714/791ffa4ce68e0a0f99e5e8c6c58c0c0d7c29a32cd9a7a83c51d5e8f97c6a29a",
                Genre = "Adventure", Rating = 9.9, AddedAt = "2025-04-15T14:00:00Z",
                Description = "Link discovers a mysterious power that lets him explore the skies and depths of Hyrule.",
                CoverGradient = "#0a1628,#1a4a6e" },
        };

        var achievements = new List<Achievement>
        {
            new() { Platform = "PS4", GameTitle = "God of War",               AchievementId = "gow_ps4_1", Name = "Father and Son",       Description = "Complete the main journey.",                      UnlockedAt = "2025-07-05T20:00:00Z" },
            new() { Platform = "PS4", GameTitle = "God of War",               AchievementId = "gow_ps4_2", Name = "Chooser of the Slain", Description = "Collect all Valkyrie armour.",                    UnlockedAt = "2025-07-12T22:00:00Z" },
            new() { Platform = "PS4", GameTitle = "The Last of Us Part II",   AchievementId = "tlou2_1",   Name = "No Matter What",       Description = "Complete the game on any difficulty.",            UnlockedAt = "2025-07-10T21:00:00Z" },
            new() { Platform = "PS4", GameTitle = "Spider-Man",               AchievementId = "spidey_1",  Name = "Be Greater",           Description = "Complete the main story.",                        UnlockedAt = "2025-08-05T18:00:00Z" },
            new() { Platform = "PS4", GameTitle = "Uncharted 4: A Thief's End",AchievementId = "uc4_1",   Name = "Charted! - Moderate",  Description = "Complete the game on Normal difficulty.",         UnlockedAt = "2025-09-15T19:00:00Z" },
            new() { Platform = "PC",  GameTitle = "Elden Ring",               AchievementId = "er_1",      Name = "Elden Lord",           Description = "Achieve the Elden Lord ending.",                  UnlockedAt = "2025-02-28T21:00:00Z" },
            new() { Platform = "PC",  GameTitle = "Baldur's Gate 3",          AchievementId = "bg3_1",     Name = "Honour Among Thieves", Description = "Complete the game on Honour Mode.",              UnlockedAt = "2025-03-10T19:00:00Z" },
            new() { Platform = "PC",  GameTitle = "Cyberpunk 2077",           AchievementId = "cp_1",      Name = "Night City Legend",    Description = "Complete the main story.",                        UnlockedAt = "2025-01-20T22:00:00Z" },
            new() { Platform = "Switch", GameTitle = "Mario Kart 8 Deluxe",  AchievementId = "mk8_1",     Name = "All Cups Gold",        Description = "Win every cup on 150cc.",                         UnlockedAt = "2025-06-10T20:30:00Z" },
            new() { Platform = "Switch", GameTitle = "The Legend of Zelda: Tears of the Kingdom", AchievementId = "totk_1", Name = "Sky Explorer", Description = "Reach the highest sky island.", UnlockedAt = "2025-04-20T14:00:00Z" },
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
