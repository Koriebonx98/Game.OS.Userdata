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

    private void OnLoginSuccess(UserProfile profile, List<Game> library,
                                List<Achievement> achievements)
    {
        _profile      = profile;
        _library      = library;
        _achievements = achievements;

        bool isAdmin = _client.IsAdmin;

        // Create the per-user data folder hierarchy beneath the executable
        UserDataService.CreateUserFolders(profile.Username);

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
