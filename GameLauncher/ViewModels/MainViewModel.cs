using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>
/// Root view-model that owns navigation and the shared session state.
/// </summary>
public partial class MainViewModel : ViewModelBase, IDisposable
{
    private readonly GameOsClient        _client;
    private readonly GameScannerService  _scanner;
    private readonly SessionCacheService _sessionCache;

    // ── Session data ───────────────────────────────────────────────────────
    private UserProfile     _profile      = new();
    private List<Game>      _library      = new();
    private List<Achievement> _achievements = new();

    // ── Child view models ──────────────────────────────────────────────────
    public LoginViewModel     LoginVm     { get; }
    public DashboardViewModel DashboardVm { get; }
    public LibraryViewModel   LibraryVm   { get; }
    public StoreViewModel     StoreVm     { get; }
    public ProfileViewModel   ProfileVm   { get; }
    public FriendsViewModel   FriendsVm   { get; }
    public GameDetailViewModel DetailVm   { get; }

    // ── Navigation state ───────────────────────────────────────────────────
    [ObservableProperty] private bool _showLogin    = true;
    [ObservableProperty] private bool _showMain     = false;
    [ObservableProperty] private bool _showDetail   = false;
    [ObservableProperty] private string _activePage = "dashboard";

    public bool IsHome        => ActivePage == "dashboard";
    public bool IsLibrary     => ActivePage == "library";
    public bool IsStore       => ActivePage == "store";
    public bool IsProfile     => ActivePage == "profile";
    public bool IsFriends     => ActivePage == "friends";

    partial void OnActivePageChanged(string value)
    {
        OnPropertyChanged(nameof(IsHome));
        OnPropertyChanged(nameof(IsLibrary));
        OnPropertyChanged(nameof(IsStore));
        OnPropertyChanged(nameof(IsProfile));
        OnPropertyChanged(nameof(IsFriends));
    }

    public MainViewModel()
    {
        _client       = new GameOsClient();
        _sessionCache = new SessionCacheService();

        LoginVm     = new LoginViewModel(_client, _sessionCache);
        DashboardVm = new DashboardViewModel();
        LibraryVm   = new LibraryViewModel();
        StoreVm     = new StoreViewModel();
        ProfileVm   = new ProfileViewModel();
        FriendsVm   = new FriendsViewModel();
        DetailVm    = new GameDetailViewModel();

        DetailVm.OnClose = () => ShowDetail = false;

        LoginVm.OnLoginSuccess = OnLoginSuccess;

        // Wire up OpenDetail from child VMs
        DashboardVm.OnOpenDetail      = OpenDetailFromGame;
        DashboardVm.OnOpenStoreDetail = OpenDetailFromStoreGame;
        LibraryVm.OnOpenDetail        = OpenDetailFromGame;
        LibraryVm.OnOpenLocalDetail   = OpenDetailFromLocalGame;
        StoreVm.OnOpenDetail          = OpenDetailFromStoreGame;

        // Start background scanner regardless of login state
        _scanner = new GameScannerService();
        _scanner.GamesUpdated   += games   => LibraryVm.UpdateLocalGames(games);
        _scanner.RepacksUpdated += repacks => LibraryVm.UpdateRepacks(repacks);
        _scanner.RomsUpdated    += roms    => LibraryVm.UpdateRoms(roms);
        _ = _scanner.StartAsync();

        // Attempt silent auto-login from cached session (mirrors web localStorage restore)
        _ = LoginVm.TryAutoLoginAsync();

    }

    /// <summary>
    /// Enters demo / screenshot mode: skips authentication and pre-populates
    /// every page with rich, realistic sample data so screenshots can be taken
    /// on any machine without a live backend connection.
    /// Called by <see cref="App.OnFrameworkInitializationCompleted"/> when
    /// <see cref="DemoMode.IsEnabled"/> is true.
    /// </summary>
    public void LoadDemo()
    {
        // ── Demo profile ─────────────────────────────────────────────────
        _profile = new UserProfile
        {
            Username  = "Koriebonx98",
            Email     = "koriebonx98@gameos.io",
            CreatedAt = "2023-09-12T08:00:00Z",
        };

        // ── Demo library (mix of platforms, realistic dates) ─────────────
        _library = new List<Game>
        {
            new() { Title = "Cyberpunk 2077",          Platform = "PC",     Genre = "RPG",        Rating = 9.1, AddedAt = "2025-01-10T12:00:00Z",
                    CoverUrl = "https://media.rawg.io/media/games/26d/26d4437715bee60138dab4a7c8c59c92.jpg",
                    CoverColor = "#1a1a2e", CoverGradient = "#1a1a2e,#16213e",
                    Description = "An open-world action RPG set in Night City." },
            new() { Title = "Elden Ring",               Platform = "PC",     Genre = "Action RPG", Rating = 9.6, AddedAt = "2025-02-14T09:30:00Z",
                    CoverUrl = "https://media.rawg.io/media/games/b45/b45575f34285f2c4479c9a5f719d972e.jpg",
                    CoverColor = "#1c0a00", CoverGradient = "#1c0a00,#6e2400" },
            new() { Title = "Baldur's Gate 3",          Platform = "PC",     Genre = "RPG",        Rating = 9.8, AddedAt = "2025-03-01T15:00:00Z",
                    CoverUrl = "https://media.rawg.io/media/games/618/618c2031a07bbff6b4f611f10b6bcdbc.jpg",
                    CoverColor = "#0d1b2a", CoverGradient = "#0d1b2a,#1b4332" },
            new() { Title = "God of War Ragnarök",      Platform = "PS5",    Genre = "Action",     Rating = 9.7, AddedAt = "2025-02-05T08:00:00Z",
                    CoverUrl = "https://media.rawg.io/media/games/fc1/fc1307a2774506b5bd65d7e8424664a7.jpg",
                    CoverColor = "#1a0a00", CoverGradient = "#1a0a00,#8b0000" },
            new() { Title = "The Last of Us Part II",   Platform = "PS4",    Genre = "Action",     Rating = 9.5, AddedAt = "2025-01-22T10:00:00Z",
                    CoverUrl = "https://cdn2.steamgriddb.com/grid/3a96a1164364c063f40ce33aaf971783.png",
                    CoverColor = "#0a1a08", CoverGradient = "#0a1a08,#1a3a10" },
            new() { Title = "Mario Kart 8 Deluxe",      Platform = "Switch", Genre = "Racing",     Rating = 9.7, AddedAt = "2025-06-01T10:00:00Z",
                    CoverUrl = "https://cdn2.steamgriddb.com/grid/9cd6d894098e748716960bfcf9dbe115.png",
                    CoverColor = "#c00000", CoverGradient = "#c00000,#ff6b00" },
            new() { Title = "Halo Infinite",             Platform = "Xbox",   Genre = "FPS",        Rating = 8.5, AddedAt = "2025-01-20T11:00:00Z",
                    CoverUrl = "https://media.rawg.io/media/games/3ea/3ea3c9bbd940b6cb7f2139e42d3d443f.jpg",
                    CoverColor = "#003153", CoverGradient = "#003153,#0056a8" },
            new() { Title = "Hogwarts Legacy",           Platform = "PC",     Genre = "RPG",        Rating = 8.7, AddedAt = "2025-04-01T10:00:00Z",
                    CoverUrl = "https://media.rawg.io/media/games/5ec/5ecac5cb026ec26a56efcc546364e348.jpg",
                    CoverColor = "#1e0a2a", CoverGradient = "#1e0a2a,#4a0080" },
            new() { Title = "Zelda: Tears of the Kingdom", Platform = "Switch", Genre = "Adventure", Rating = 9.9, AddedAt = "2025-04-15T14:00:00Z",
                    CoverColor = "#0a1628", CoverGradient = "#0a1628,#1a4a6e" },
            new() { Title = "God of War",                Platform = "PS4",    Genre = "Action",     Rating = 9.6, AddedAt = "2025-01-18T07:30:00Z",
                    CoverUrl = "https://cdn2.steamgriddb.com/grid/368b80128d9e529adf93f7ce84dfaca0.jpg",
                    CoverColor = "#1a0500", CoverGradient = "#1a0500,#5c1500" },
        };

        // ── Demo achievements ─────────────────────────────────────────────
        _achievements = new List<Achievement>
        {
            new() { Name = "Night City Legend",   GameTitle = "Cyberpunk 2077",         UnlockedAt = "2025-01-15T14:00:00Z" },
            new() { Name = "Elden Lord",           GameTitle = "Elden Ring",              UnlockedAt = "2025-02-20T11:30:00Z" },
            new() { Name = "Illithid Powers",      GameTitle = "Baldur's Gate 3",         UnlockedAt = "2025-03-10T16:00:00Z" },
            new() { Name = "Platinum Kart Racer",  GameTitle = "Mario Kart 8 Deluxe",     UnlockedAt = "2025-06-05T09:00:00Z" },
            new() { Name = "Muspelheim Conquered", GameTitle = "God of War Ragnarök",     UnlockedAt = "2025-02-10T18:00:00Z" },
        };

        // ── Demo local games (scanner results replaced with richer entries) ─
        var demoLocalGames = new List<LocalGame>
        {
            new() { Title = "Cyberpunk 2077",    ExecutablePath = "/Games/Cyberpunk 2077/Cyberpunk2077.elf",    ExecutableType = "elf", DriveRoot = "/Games" },
            new() { Title = "The Witcher 3",     ExecutablePath = "/Games/The Witcher 3/witcher3.elf",          ExecutableType = "elf", DriveRoot = "/Games" },
            new() { Title = "Grand Theft Auto V",ExecutablePath = "/Games/Grand Theft Auto V/GTAV.elf",         ExecutableType = "elf", DriveRoot = "/Games" },
        };

        var demoRepacks = new List<LocalRepack>
        {
            new() { Title = "Elden Ring",         FilePath = "/Repacks/Elden Ring [FitGirl Repack].iso",       FileType = "iso",  SizeBytes = 30_000_000_000L },
            new() { Title = "Baldur's Gate 3",    FilePath = "/Repacks/Baldurs Gate 3 [DODI Repack].zip",      FileType = "zip",  SizeBytes = 64_000_000_000L },
            new() { Title = "Resident Evil 4",    FilePath = "/Repacks/Resident Evil 4 [Repack].rar",          FileType = "rar",  SizeBytes = 12_500_000_000L },
        };

        var demoRoms = new List<LocalRom>
        {
            new() { Title = "Halo 3",             Platform = "Xbox 360", FilePath = "/Roms/Xbox 360/Games/Halo 3.iso",              FileType = "iso",  SizeBytes = 6_800_000_000L  },
            new() { Title = "Gears of War",       Platform = "Xbox 360", FilePath = "/Roms/Xbox 360/Games/Gears of War.iso",        FileType = "iso",  SizeBytes = 7_200_000_000L  },
            new() { Title = "Forza Motorsport 4", Platform = "Xbox 360", FilePath = "/Roms/Xbox 360/Games/Forza Motorsport 4.iso",  FileType = "iso",  SizeBytes = 8_100_000_000L  },
            new() { Title = "God of War III",     Platform = "PS3",      FilePath = "/Roms/PS3/Games/God of War III.iso",           FileType = "iso",  SizeBytes = 35_000_000_000L },
            new() { Title = "Uncharted 2",        Platform = "PS3",      FilePath = "/Roms/PS3/Games/Uncharted 2.iso",              FileType = "iso",  SizeBytes = 25_000_000_000L },
            new() { Title = "Breath of the Wild", Platform = "Switch",   FilePath = "/Roms/Switch/Games/Breath of the Wild.nsp",    FileType = "nsp",  SizeBytes = 14_200_000_000L },
            new() { Title = "Red Dead Redemption", Platform = "Xbox 360",FilePath = "/Roms/Xbox 360/Games/Red Dead Redemption.iso", FileType = "iso",  SizeBytes = 7_600_000_000L  },
        };

        // Push local data into LibraryViewModel directly (bypasses file-system scanner)
        LibraryVm.UpdateLocalGames(demoLocalGames);
        LibraryVm.UpdateRepacks(demoRepacks);
        LibraryVm.UpdateRoms(demoRoms);

        // ── Load child view models ─────────────────────────────────────────
        DashboardVm.Load(_profile, _library, _achievements);
        LibraryVm.Load(_library);
        StoreVm.Load(GameCatalog.Store, _library, _profile, _client, false);
        ProfileVm.Load(_profile, _library, _achievements, false);
        FriendsVm.LoadDemo();

        // Open the inline conversation for screenshot purposes
        FriendsVm.OpenConversationDemo();

        // Skip the login screen
        ShowLogin = false;
        ShowMain  = true;
        ActivePage = "dashboard";
    }

    private void OnLoginSuccess(UserProfile profile, List<Game> library,
                                List<Achievement> achievements)
    {
        _profile      = profile;
        _library      = library;
        _achievements = achievements;

        bool isAdmin = _client.IsAdmin;

        // Create the per-user data folder hierarchy beneath the executable
        UserDataService.CreateUserFolders(profile.Username);

        // Update presence so the user appears "Online" to friends (mirrors the web app)
        _ = _client.UpdatePresenceAsync();

        DashboardVm.Load(profile, library, achievements);
        LibraryVm.Load(library);
        StoreVm.Load(GameCatalog.Store, library, profile, _client, isAdmin);
        ProfileVm.Load(profile, library, achievements, isAdmin);
        FriendsVm.Load(_client, profile.Username);

        ShowLogin = false;
        ShowMain  = true;
        ActivePage = "dashboard";
    }

    [RelayCommand]
    private void Navigate(string page)
    {
        ShowDetail = false;
        ActivePage = page;
        if (page == "library")
            LibraryVm.Load(_library);
        if (page == "friends")
            FriendsVm.Load(_client, _profile.Username);
        if (page == "profile")
            ProfileVm.Load(_profile, _library, _achievements, _client.IsAdmin);
    }

    private void OpenDetailFromGame(Game game)
    {
        // Check if this game is installed locally or has a repack available
        LocalGame? localGame = LibraryVm.LocalGames
            .FirstOrDefault(lg => lg.Title.Equals(game.Title, StringComparison.OrdinalIgnoreCase));
        LocalRepack? repack = null;
        if (localGame == null)
            repack = LibraryVm.ReadyToInstall
                .FirstOrDefault(r => r.Title.Equals(game.Title, StringComparison.OrdinalIgnoreCase));

        DetailVm.LoadFromGame(game, localGame, repack);
        ShowDetail = true;
    }

    private void OpenDetailFromStoreGame(StoreGame game)
    {
        // Check if this store game is installed locally or has a repack available
        LocalGame? localGame = LibraryVm.LocalGames
            .FirstOrDefault(lg => lg.Title.Equals(game.Title, StringComparison.OrdinalIgnoreCase));
        LocalRepack? repack = null;
        if (localGame == null)
            repack = LibraryVm.ReadyToInstall
                .FirstOrDefault(r => r.Title.Equals(game.Title, StringComparison.OrdinalIgnoreCase));

        DetailVm.LoadFromStoreGame(game, localGame, repack);
        ShowDetail = true;
    }

    private void OpenDetailFromLocalGame(LocalGame game)
    {
        // Show basic info immediately so the UI is responsive
        DetailVm.LoadFromLocalGame(game);
        ShowDetail = true;

        // Asynchronously enrich with cover/description/trailer from Games.Database
        _ = EnrichLocalGameDetailAsync(game.Title);
    }

    /// <summary>
    /// Looks up <paramref name="localTitle"/> in the PC Games.Database and, if found,
    /// enriches the currently-open detail panel with cover, description, trailer and
    /// screenshots — the same data shown on the website.
    /// Title matching handles Windows-safe folder names such as
    /// "Call of Duty - Black Ops II" → "Call of Duty: Black Ops II".
    /// </summary>
    private async Task EnrichLocalGameDetailAsync(string localTitle)
    {
        try
        {
            var dbGames = await GameOsClient.FetchGamesDatabaseAsync("PC");
            var dbGame  = FindDatabaseGame(dbGames, localTitle);
            if (dbGame != null)
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(
                    () => DetailVm.EnrichFromDatabaseGame(dbGame));
            }
        }
        catch { /* best-effort — basic info already displayed */ }
    }

    /// <summary>
    /// Tries to match a local game folder title against the Games.Database.
    /// Attempts (in order):
    ///   1. Exact case-insensitive match.
    ///   2. After removing [Repack] / [repack] style markers.
    ///   3. After applying NormalizeGameTitle (Windows " - " → ": " and HTML entities).
    ///   4. After applying both stripping and normalisation.
    /// </summary>
    private static DatabaseGame? FindDatabaseGame(List<DatabaseGame> dbGames, string localTitle)
    {
        var exact = dbGames.FirstOrDefault(g =>
            string.Equals(g.Title, localTitle, StringComparison.OrdinalIgnoreCase));
        if (exact != null) return exact;

        // Strip [Repack] / [repack] / "[FitGirl Repack]" style suffixes
        string stripped = StripRepackMarkers(localTitle);
        if (!string.Equals(stripped, localTitle, StringComparison.Ordinal))
        {
            var byStripped = dbGames.FirstOrDefault(g =>
                string.Equals(g.Title, stripped, StringComparison.OrdinalIgnoreCase));
            if (byStripped != null) return byStripped;
        }

        // Normalise Windows-safe title separators and HTML entities
        string normalized = NormalizeGameTitle(localTitle);
        if (!string.Equals(normalized, localTitle, StringComparison.Ordinal))
        {
            var byNorm = dbGames.FirstOrDefault(g =>
                string.Equals(g.Title, normalized, StringComparison.OrdinalIgnoreCase));
            if (byNorm != null) return byNorm;
        }

        // Try stripping + normalising together
        string strippedNorm = NormalizeGameTitle(stripped);
        if (!string.Equals(strippedNorm, localTitle, StringComparison.Ordinal))
        {
            return dbGames.FirstOrDefault(g =>
                string.Equals(g.Title, strippedNorm, StringComparison.OrdinalIgnoreCase));
        }

        return null;
    }

    /// <summary>
    /// Removes common repack annotation patterns from a folder/file name so
    /// the clean game title can be matched against the Games.Database.
    /// Examples:
    ///   "Call of Duty [Repack]"         → "Call of Duty"
    ///   "The Witcher 3 [FitGirl Repack]"→ "The Witcher 3"
    ///   "[Repack] Cyberpunk 2077"        → "Cyberpunk 2077"
    /// </summary>
    internal static string StripRepackMarkers(string title)
    {
        if (string.IsNullOrEmpty(title)) return title;
        return _repackMarkerRegex.Replace(title, "").Trim();
    }

    // Matches "[Repack]", "[FitGirl Repack]", "[DODI Repack]", etc. (case-insensitive)
    private static readonly Regex _repackMarkerRegex =
        new(@"\[[\w\s]*[Rr]epack[\w\s]*\]", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Converts a Windows folder-safe game name to its canonical form.
    /// Windows folder names cannot contain ":" so installers often replace
    /// "Franchise: Subtitle" with "Franchise - Subtitle".
    /// This method reverses that substitution so the database lookup succeeds
    /// and the correct title is displayed in the UI.
    /// Only the first " - " separator is replaced (non-greedy) to preserve any
    /// additional dashes in the subtitle (e.g. "Game - Part 1 - Episode 2"
    /// becomes "Game: Part 1 - Episode 2").
    /// Also decodes HTML entities such as &amp;#39; → ' and &amp;amp; → &amp;
    /// </summary>
    internal static string NormalizeGameTitle(string title)
    {
        if (string.IsNullOrEmpty(title)) return title;
        // Replace only the first " - " with ": " to reconstruct subtitle separators
        string result = _titleNormalizeRegex.Replace(title, "$1: $2");
        // Decode HTML entities that sometimes appear in database titles
        result = WebUtility.HtmlDecode(result);
        return result;
    }

    // Compiled once for the process lifetime (called on every local game detail open)
    private static readonly Regex _titleNormalizeRegex =
        new(@"^(.+?) - (.+)$", RegexOptions.Compiled);

    [RelayCommand]
    private void SignOut()
    {
        // Clear the saved token so the next launch shows the login form
        // (equivalent to the web calling localStorage.removeItem('gameOSUser'))
        if (_client.LoggedInUser != null)
            _sessionCache.ClearToken(_client.LoggedInUser);

        _client.Logout();
        _library      = new();
        _achievements = new();
        _profile      = new();

        LoginVm.Username = "";
        LoginVm.Password = "";
        LoginVm.ErrorMessage = "";
        LoginVm.ShowRegister = false;

        ShowMain  = false;
        ShowDetail = false;
        ShowLogin = true;
    }

    public void Dispose()
    {
        _scanner.Dispose();
        (_client as IDisposable)?.Dispose();
        StoreVm.Dispose();
    }
}
