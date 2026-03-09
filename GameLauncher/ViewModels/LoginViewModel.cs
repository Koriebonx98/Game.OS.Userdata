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
    /// Demo / preview mode — loads the full launcher with account "Koriebonx98"
    /// and complete real data sourced from the public Koriebonx98/Games.Database
    /// repository (covers, trailers, achievements).
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

        // ── Real achievements for each game — sourced from Koriebonx98/Games.Database ──

        // Mario Kart 8 Deluxe — all 27 real achievements from Switch-Achievements- repo
        var mk8Achievements = new List<Achievement>
        {
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_mushroom",   Name="Magic Mushroom's",              Description="Win 1st In Mushroom Cup",      IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_MushroomCup.png?raw=true",            UnlockedAt="2025-06-01T10:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_rock",       Name="Paper, Sissors, Rock",           Description="Win 1st in Rock Cup",          IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Rock_Emblem.png?raw=true",        UnlockedAt="2025-06-01T11:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_propeller",  Name="Flying High",                    Description="Win 1st in Propeller Cup",     IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Propeller_Emblem.png?raw=true",  UnlockedAt="2025-06-02T09:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_moon",       Name="First Mii On The Moon",          Description="Win 1st in Moon Cup",          IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Moon_Emblem.png?raw=true",        UnlockedAt="2025-06-02T10:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_fruit",      Name="A Bit of a Fruity Taste",        Description="Win 1st in Fruit Cup",         IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Fruit_Emblem.png?raw=true",      UnlockedAt="2025-06-03T14:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_feather",    Name="Light As a Feather",             Description="Win 1st in Feather Cup",       IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Feather_Emblem.png?raw=true",    UnlockedAt="2025-06-04T15:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_cherry",     Name="Tangfastic",                     Description="Win 1st in Cherry Cup",        IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Cherry_Emblem.png?raw=true",     UnlockedAt="2025-06-05T16:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_boomerang",  Name="What Goes Around, Comes Around", Description="Win 1st in Boomerang Cup",     IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Boomerang_Emblem.png?raw=true", UnlockedAt="2025-06-06T17:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_acorn",      Name="Pretty Nuts",                    Description="Win 1st in Acorn Cup",         IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Acorn_Emblem.png?raw=true",      UnlockedAt="2025-06-07T18:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_goldmario",  Name="It's Me.. G-ario",               Description="Unlock Gold Mario",             IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Drivers/MK8DX_Gold_Mario_Icon.png?raw=true",    UnlockedAt="2025-06-10T20:30:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_1000coins",  Name="1000",                           Description="1000 Coins Total",              IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Items/100px-CoinMK8.png?raw=true",               UnlockedAt="2025-06-08T12:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_500coins",   Name="500",                            Description="500 Coins Total",               IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Items/100px-CoinMK8.png?raw=true",               UnlockedAt="2025-06-07T09:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_100coins",   Name="100",                            Description="100 Coins Total",               IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Items/100px-CoinMK8.png?raw=true",               UnlockedAt="2025-06-02T08:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_spiny",      Name="Sonic, The Turtle",              Description="Win 1st in Spiny Cup",          IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Spiny_Emblem.png?raw=true",      UnlockedAt="2025-06-08T15:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_crossing",   Name="Animal Crossing",                Description="Win 1st in Crossing Cup",       IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Special_Cup_Emblem.png?raw=true",     UnlockedAt="2025-06-09T11:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_triforce",   Name="Arrow Head",                     Description="Win 1st in Triforce Cup",       IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Triforce_Cup_Emblem.png?raw=true",    UnlockedAt="2025-06-09T14:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_star",       Name="You want A Gold Star?",          Description="Win 1st in Star Cup",           IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Star_Cup_Emblem.png?raw=true",         UnlockedAt="2025-06-09T16:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_special",    Name="Special Oylimpics",              Description="Win 1st in Special Cup",        IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Special_Cup_Emblem.png?raw=true",     UnlockedAt="2025-06-10T10:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_shell",      Name="Shell Shocked",                  Description="Win 1st in Shell Cup",          IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Shell_Cup_Emblem.png?raw=true",         UnlockedAt="2025-06-03T16:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_egg",        Name="Egg cell lent",                  Description="Win 1st in Egg Cup",            IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Egg_Cup_Emblem.png?raw=true",           UnlockedAt="2025-06-04T12:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_leaf",       Name="Leaf Me Alone",                  Description="Win 1st in Leaf Cup",           IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Leaf_Cup_Emblem.png?raw=true",           UnlockedAt="2025-06-05T14:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_lightning",  Name="Lightning Mcqueen",              Description="Win 1st in Lightning Cup",      IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Lightning_Cup_Emblem.png?raw=true",    UnlockedAt="2025-06-06T11:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_flower",     Name="Flower Power",                   Description="Win 1st in Flower Cup",         IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_FlowerCup.png?raw=true",               UnlockedAt="2025-06-03T10:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_banana",     Name="Banana Split",                   Description="Win 1st in Banana Cup",         IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Banana_Cup_Emblem.png?raw=true",        UnlockedAt="2025-06-04T09:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_bell",       Name="Bell End",                       Description="Win 1st in Bell Cup",           IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8_Bell_Cup_Emblem.png?raw=true",           UnlockedAt="2025-06-10T18:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_turnip",     Name="Ol Mcdonald",                    Description="Win 1st in Turnip Cup",         IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Cups/MK8D_BCP_Turnip_Emblem.png?raw=true",      UnlockedAt="2025-06-10T19:00:00Z" },
            new() { Platform="Switch", GameTitle="Mario Kart 8 Deluxe", AchievementId="mk8_locness",    Name="Locness Monster",                Description="3 Fifty Coins Total",           IconUrl="https://github.com/Koriebonx98/ss-custom/blob/main/Unlocked/Items/100px-CoinMK8.png?raw=true",               UnlockedAt="2025-06-08T10:00:00Z" },
        };

        // God of War PS4 — real achievements from Koriebonx98/Games.Database CUSA07408/achievements.json
        var gowAchievements = new List<Achievement>
        {
            new() { Platform="PS4", GameTitle="God of War", AchievementId="gow_1",  Name="Father and Son",            Description="Obtain all other trophies",                 IconUrl="https://m.exophase.com/psn/awards/s/76dj48.png?b814bbd735b1e5e875054b83e55687ba",  UnlockedAt="2025-07-05T20:00:00Z" },
            new() { Platform="PS4", GameTitle="God of War", AchievementId="gow_2",  Name="The Journey Begins",        Description="Defend your home from The Stranger",        IconUrl="https://m.exophase.com/psn/awards/s/51be3d.png?b814bbd735b1e5e875054b83e55687ba",  UnlockedAt="2025-07-05T14:00:00Z" },
            new() { Platform="PS4", GameTitle="God of War", AchievementId="gow_3",  Name="A New Friend",              Description="Survive the Witch's Woods",                 IconUrl="https://m.exophase.com/psn/awards/s/0617de.png?b814bbd735b1e5e875054b83e55687ba",  UnlockedAt="2025-07-05T15:30:00Z" },
            new() { Platform="PS4", GameTitle="God of War", AchievementId="gow_4",  Name="Feels Like Home",           Description="Allow the Light Elves to return home",      IconUrl="https://m.exophase.com/psn/awards/s/8b416d.png?b814bbd735b1e5e875054b83e55687ba",  UnlockedAt="2025-07-05T17:00:00Z" },
            new() { Platform="PS4", GameTitle="God of War", AchievementId="gow_5",  Name="Dragon Slayer",             Description="Defeat the Dragon of the Mountain",         IconUrl="https://m.exophase.com/psn/awards/s/ej8dgd.png?b814bbd735b1e5e875054b83e55687ba",  UnlockedAt="2025-07-05T18:00:00Z" },
            new() { Platform="PS4", GameTitle="God of War", AchievementId="gow_6",  Name="Troubling Consequences",    Description="Defeat Magni and Modi",                     IconUrl="https://m.exophase.com/psn/awards/s/4j65b0.png?b814bbd735b1e5e875054b83e55687ba",  UnlockedAt="2025-07-05T19:00:00Z" },
            new() { Platform="PS4", GameTitle="God of War", AchievementId="gow_7",  Name="Hello, Old Friend",         Description="Retrieve the Blades of Chaos",              IconUrl="https://m.exophase.com/psn/awards/s/6eg037.png?b814bbd735b1e5e875054b83e55687ba",  UnlockedAt="2025-07-05T19:30:00Z" },
            new() { Platform="PS4", GameTitle="God of War", AchievementId="gow_8",  Name="Promise Fulfilled",         Description="Heal Atreus",                               IconUrl="https://m.exophase.com/psn/awards/s/bb3746.png?b814bbd735b1e5e875054b83e55687ba",  UnlockedAt="2025-07-05T20:00:00Z" },
        };

        // ── Real game library from Koriebonx98/Games.Database ──────────────────────────

        var games = new List<Game>
        {
            // Nintendo Switch — Mario Kart 8 Deluxe
            // Source: Koriebonx98/Games.Database Switch.Games.json (title_id: 0100152000022000)
            new() {
                Platform = "Switch", Title = "Mario Kart 8 Deluxe",
                TitleId  = "0100152000022000",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/9cd6d894098e748716960bfcf9dbe115.png",
                Genre    = "Racing", Rating = 9.7, AddedAt = "2025-06-01T10:00:00Z",
                Description  = "Hit the road with the definitive version of Mario Kart 8! Race on 96 total courses with friends online or locally.",
                TrailerUrl   = "https://youtu.be/tKlRN2YpxRE",
                AchievementsUrl = "https://raw.githubusercontent.com/Koriebonx98/Switch-Achievements-/main/Games/Mario%20Kart%208%20Deluxe.json",
                Screenshots  = new List<string>
                {
                    "https://cdn2.steamgriddb.com/hero/85e1b8bbda1bd1ec3465c9728f7d7d2e.png",
                    "https://cdn2.steamgriddb.com/hero/c384385739d41027edba51f4fbf65e96.png",
                },
                CoverGradient  = "#c00000,#ff6b00",
                GameAchievements = mk8Achievements,
            },

            // PS4 — God of War (CUSA07408)
            // Source: Koriebonx98/Games.Database PS4.Games.json
            new() {
                Platform = "PS4", Title = "God of War",
                TitleId  = "CUSA07408",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/368b80128d9e529adf93f7ce84dfaca0.jpg",
                Genre    = "Action", Rating = 9.6, AddedAt = "2025-07-02T12:00:00Z",
                Description  = "His vengeance against the Gods of Olympus years behind him, Kratos now lives as a man in the realm of Norse Gods and monsters. It is in this harsh, unforgiving world that he must fight to survive and teach his son to do the same.",
                TrailerUrl   = "https://youtu.be/K0u_kAWLJOA",
                AchievementsUrl = "https://raw.githubusercontent.com/Koriebonx98/Games.Database/main/Data/Sony%20-%20PlayStation%204/Games/CUSA07408/achievements.json",
                Screenshots  = new List<string>
                {
                    "https://cdn2.steamgriddb.com/hero/08d03839959b58b7a25e22c8536f04e1.png",
                    "https://cdn2.steamgriddb.com/hero/f4d3d2d59003d83fb3ef32f78610b4a2.png",
                },
                CoverGradient  = "#1a0500,#5c1500",
                GameAchievements = gowAchievements,
            },

            // PS4 — The Last of Us Part II (CUSA07820)
            new() {
                Platform = "PS4", Title = "The Last of Us Part II",
                TitleId  = "CUSA07820",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/3a96a1164364c063f40ce33aaf971783.png",
                Genre    = "Action", Rating = 9.5, AddedAt = "2025-07-01T10:00:00Z",
                Description  = "Five years after their dangerous journey across the post-pandemic United States, Ellie and Joel have settled down in Jackson, Wyoming. Living amongst a thriving community gives them stability, despite the constant threat of the infected and other, more desperate survivors.",
                TrailerUrl   = "https://youtu.be/X0VubwgS2Y4",
                Screenshots  = new List<string>
                {
                    "https://cdn2.steamgriddb.com/hero/5f4e2b7e69414bdb3c0fce8c2c17c3d3.png",
                    "https://cdn2.steamgriddb.com/hero/a5e3c240b5b39b60cdab10b44f3f6b84.png",
                },
                CoverGradient = "#0a1a08,#1a3a10",
                GameAchievements = new List<Achievement>
                {
                    new() { Platform="PS4", GameTitle="The Last of Us Part II", AchievementId="tlou2_1", Name="No Matter What", Description="Complete the game on any difficulty.", UnlockedAt="2025-07-10T21:00:00Z" },
                    new() { Platform="PS4", GameTitle="The Last of Us Part II", AchievementId="tlou2_2", Name="Dig Two Graves",  Description="Complete the game on Survivor difficulty.", UnlockedAt="2025-07-12T23:00:00Z" },
                },
            },

            // PS4 — Spider-Man (CUSA02299)
            new() {
                Platform = "PS4", Title = "Spider-Man",
                TitleId  = "CUSA02299",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/1bc38477bc1f540837e39eb0b8dbb520.png",
                Genre    = "Action", Rating = 9.2, AddedAt = "2025-08-01T09:00:00Z",
                Description  = "Starring the world's most iconic Super Hero, Spider-Man features the acrobatic abilities, improvisation and web-slinging that the wall-crawler is famous for.",
                TrailerUrl   = "https://youtu.be/q4GdJVvdxss",
                Screenshots  = new List<string>
                {
                    "https://cdn2.steamgriddb.com/hero/e72d760a8952d3ae95a15f40cf8f56d3.jpg",
                    "https://cdn2.steamgriddb.com/hero/98b5f28b6e8e7d5fc18baf0f6a5d4e73.jpg",
                },
                CoverGradient = "#0a0a2e,#1a1a6e",
                GameAchievements = new List<Achievement>
                {
                    new() { Platform="PS4", GameTitle="Spider-Man", AchievementId="spidey_1", Name="Be Greater", Description="Complete the main story.", UnlockedAt="2025-08-05T18:00:00Z" },
                    new() { Platform="PS4", GameTitle="Spider-Man", AchievementId="spidey_2", Name="Friendly Neighbourhood Spider-Man", Description="Clear all crimes.", UnlockedAt="2025-08-10T20:00:00Z" },
                },
            },

            // PS4 — Uncharted 4 (CUSA00341)
            new() {
                Platform = "PS4", Title = "Uncharted 4: A Thief's End",
                TitleId  = "CUSA00341",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/6fe386b00d7a58df2ee236b3bf339e6b.jpg",
                Genre    = "Action", Rating = 9.1, AddedAt = "2025-09-10T15:00:00Z",
                Description  = "Retired fortune hunter Nathan Drake is forced back into the world of thieves. With the stakes much more personal, he embarks on a globe-trotting journey.",
                TrailerUrl   = "https://youtu.be/hh5HV4iic1Y",
                CoverGradient = "#05150a,#0a3020",
            },

            // PS4 — Horizon Zero Dawn (CUSA01967)
            new() {
                Platform = "PS4", Title = "Horizon Zero Dawn",
                TitleId  = "CUSA01967",
                CoverUrl = "https://cdn2.steamgriddb.com/grid/abd673b91e4bb9c556da84c6f6f5d470.png",
                Genre    = "Action RPG", Rating = 9.0, AddedAt = "2025-09-15T11:00:00Z",
                Description  = "Experience Aloy's legendary quest to unravel the mysteries of a future Earth ruled by Machines. Use devastating tactical attacks against unique Machines and explore a lush, post-apocalyptic open world.",
                TrailerUrl   = "https://youtu.be/u4-FCsiF5x4",
                CoverGradient = "#0a1a05,#1a5010",
            },

            // PC games
            new() { Platform = "PC", Title = "Cyberpunk 2077",
                CoverUrl = "https://media.rawg.io/media/games/26d/26d4437715bee60138dab4a7c8c59c92.jpg",
                Genre = "RPG", Rating = 9.1, AddedAt = "2025-01-10T12:00:00Z",
                Description = "An open-world action RPG set in the dark future of Night City.",
                TrailerUrl = "https://youtu.be/8X2kIfS6fb8",
                CoverGradient = "#1a1a2e,#16213e" },
            new() { Platform = "PC", Title = "Elden Ring",
                CoverUrl = "https://media.rawg.io/media/games/b45/b45575f34285f2c4479c9a5f719d972e.jpg",
                Genre = "Action RPG", Rating = 9.6, AddedAt = "2025-02-14T09:30:00Z",
                Description = "A sprawling fantasy action RPG from FromSoftware and George R.R. Martin.",
                TrailerUrl = "https://youtu.be/E3Huy2cdih0",
                CoverGradient = "#1c0a00,#6e2400" },
            new() { Platform = "PC", Title = "Baldur's Gate 3",
                CoverUrl = "https://media.rawg.io/media/games/618/618c2031a07bbff6b4f611f10b6bcdbc.jpg",
                Genre = "RPG", Rating = 9.8, AddedAt = "2025-03-01T15:00:00Z",
                Description = "Gather your party and return to the Forgotten Realms in this award-winning DnD RPG.",
                TrailerUrl = "https://youtu.be/I-BQm3fOt3E",
                CoverGradient = "#0d1b2a,#1b4332" },
        };

        // ── Top-level achievements list (for dashboard/profile summary) ─────────────
        var achievements = mk8Achievements.Concat(gowAchievements).Concat(new[]
        {
            new Achievement { Platform="PS4",    GameTitle="The Last of Us Part II",  AchievementId="tlou2_1",   Name="No Matter What",         Description="Complete the game on any difficulty.",            UnlockedAt="2025-07-10T21:00:00Z" },
            new Achievement { Platform="PS4",    GameTitle="Spider-Man",              AchievementId="spidey_1",  Name="Be Greater",             Description="Complete the main story.",                        UnlockedAt="2025-08-05T18:00:00Z" },
            new Achievement { Platform="PC",     GameTitle="Elden Ring",              AchievementId="er_1",      Name="Elden Lord",             Description="Achieve the Elden Lord ending.",                  UnlockedAt="2025-02-28T21:00:00Z" },
            new Achievement { Platform="PC",     GameTitle="Baldur's Gate 3",         AchievementId="bg3_1",     Name="Honour Among Thieves",   Description="Complete the game on Honour Mode.",               UnlockedAt="2025-03-10T19:00:00Z" },
            new Achievement { Platform="PC",     GameTitle="Cyberpunk 2077",          AchievementId="cp_1",      Name="Night City Legend",      Description="Complete the main story.",                        UnlockedAt="2025-01-20T22:00:00Z" },
        }).ToList();

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
