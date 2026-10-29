using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

public partial class StoreViewModel : ViewModelBase, IDisposable
{
    private List<StoreGame> _allStore     = new();
    private List<StoreGame> _allStoreBase = new(); // curated catalog, restored on "All"
    private List<Game>      _library  = new();
    private List<Game>      _wishlist = new();
    private UserProfile     _profile  = new();
    private GameOsClient    _client   = new();

    [ObservableProperty] private string  _searchText = "";
    [ObservableProperty] private string  _filterGenre = "All";
    [ObservableProperty] private string? _statusMessage;

    // ── Platform selector ─────────────────────────────────────────────────
    [ObservableProperty] private string _selectedPlatform = "All";
    [ObservableProperty] private bool   _isLoading        = false;
    [ObservableProperty] private string _loadingMessage   = "";
    [ObservableProperty] private string _browseCountLabel = "";

    /// <summary>Platforms available in the Games.Database (plus "All" for the curated catalog).</summary>
    public ObservableCollection<string> Platforms { get; } = new()
        { "All", "PC", "PS3", "PS4", "Switch", "Xbox 360" };

    // ── Tab navigation: Games Store vs App Store ──────────────────────────
    [ObservableProperty] private bool _isGamesTab    = true;
    [ObservableProperty] private bool _isAppStoreTab = false;

    [ObservableProperty] private string _appStoreSearchText = "";
    [ObservableProperty] private string _appStoreGenreFilter = "All";
    public ObservableCollection<AppStoreEntry> AllAppStoreEntries    { get; } = new();
    public ObservableCollection<AppStoreEntry> FilteredAppStoreEntries { get; } = new();
    public ObservableCollection<string>        AppStoreGenres        { get; } = new();

    partial void OnAppStoreSearchTextChanged(string value)  => ApplyAppStoreFilter();
    partial void OnAppStoreGenreFilterChanged(string value) => ApplyAppStoreFilter();

    // ── Admin catalog management ──────────────────────────────────────────
    [ObservableProperty] private bool   _isAdmin      = false;
    [ObservableProperty] private bool   _showAdminForm = false;
    [ObservableProperty] private string _adminTitle       = "";
    [ObservableProperty] private string _adminPlatform    = "PC";
    [ObservableProperty] private string _adminGenre       = "";
    [ObservableProperty] private string _adminPrice       = "";
    [ObservableProperty] private string _adminDescription = "";
    [ObservableProperty] private string _adminRating      = "8.0";
    [ObservableProperty] private string _adminCoverUrl    = "";

    /// <summary>
    /// Total games across all platforms in the Koriebonx98/Games.Database repository.
    /// PC: ~153,713  |  Xbox 360: 5,132  |  PS3: 4,000  |  Switch: 2,245  |  PS4: 5
    /// Updated by counting each {Platform}.Games.json in the public repository.
    /// </summary>
    private const int RealDatabaseTotal = 165_095;

    /// <summary>
    /// Maximum number of game cards to render at once in the UI.
    /// Prevents the WrapPanel from rendering 150,000+ items for large platforms.
    /// The search box can be used to narrow the results below this threshold,
    /// or the "Load More" button appends the next page of results.
    /// </summary>
    private const int MaxDisplayedGames = 200;

    [ObservableProperty] private int    _totalCatalogCount = 0;
    [ObservableProperty] private string _catalogCountLabel = "";
    [ObservableProperty] private bool   _hasMoreGames      = false;

    /// <summary>Current upper limit on how many games are shown. Increases with each "Load More" click.</summary>
    private int _displayLimit = MaxDisplayedGames;
    public int DisplayLimit
    {
        get => _displayLimit;
        private set { _displayLimit = value; OnPropertyChanged(); }
    }

    /// <summary>True once the real catalog count has been loaded; drives the subtitle visibility.</summary>
    public bool HasCatalogCount => TotalCatalogCount > 0;

    partial void OnTotalCatalogCountChanged(int value) => OnPropertyChanged(nameof(HasCatalogCount));

    public ObservableCollection<StoreGame> Featured      { get; } = new();
    public ObservableCollection<StoreGame> FilteredStore { get; } = new();
    public ObservableCollection<string>    Genres        { get; } = new();

    /// <summary>Recently added games (Steam auto-adds and new/edited platform games).</summary>
    public ObservableCollection<StoreGame> NewGames { get; } = new();
    public bool HasNewGames => NewGames.Count > 0;

    // ── Storefront shelves (same shelves as the website store) ────────────
    private const int ShelfMax = 20;
    public ObservableCollection<StoreGame> UpdatedShelf    { get; } = new();
    public ObservableCollection<StoreGame> ExclusivesShelf { get; } = new();
    public ObservableCollection<StoreGame> ComingSoonShelf { get; } = new();
    public bool HasUpdatedShelf    => UpdatedShelf.Count > 0;
    public bool HasExclusivesShelf => ExclusivesShelf.Count > 0;
    public bool HasComingSoonShelf => ComingSoonShelf.Count > 0;
    /// <summary>Shelves are shown on the unfiltered home view only, like a storefront.</summary>
    public bool ShowShelves => IsGamesTab && string.IsNullOrWhiteSpace(SearchText) && FilterGenre == "All";

    // Shelf candidates gathered from every platform's database (not just the selected one),
    // like the website which keeps all platform games in memory.
    private readonly Dictionary<string, List<StoreGame>> _shelfPool = new();
    private CancellationTokenSource? _shelfCts;

    private static StoreGame ToStoreGame(DatabaseGame g, string platform) => new()
    {
        Title           = WebUtility.HtmlDecode(g.Title ?? ""),
        Platform        = platform,
        Genre           = g.Genre ?? "Unknown",
        Price           = "N/A",
        CoverUrl        = g.CoverUrl,
        Description     = g.Description ?? "",
        TrailerUrl      = g.TrailerUrl,
        AchievementsUrl = g.AchievementsUrl,
        Screenshots     = g.Screenshots,
        StorePageUrl    = g.StorePageUrl,
        Categories      = g.Categories,
        UpdatedAt       = DateTime.TryParse(g.UpdatedAt, null, System.Globalization.DateTimeStyles.AdjustToUniversal, out var upd) ? upd : null,
    };

    /// <summary>Loads every platform database in the background and keeps only shelf-relevant games.</summary>
    private async Task LoadShelvesAsync(IReadOnlyList<string> platforms)
    {
        _shelfCts?.Cancel();
        var cts = _shelfCts = new CancellationTokenSource();
        var cutoff = DateTime.UtcNow.AddDays(-30);
        foreach (var platform in platforms.Where(p => p != "All"))
        {
            if (cts.IsCancellationRequested) return;
            try
            {
                var db = await GameOsClient.FetchGamesDatabaseAsync(platform, cts.Token).ConfigureAwait(false);
                var picked = db.Select(g => ToStoreGame(g, platform))
                    .Where(g => g.Categories != null || g.UpdatedAt is { } d && d > cutoff)
                    .Where(g => g.HasCategory("Updated") || g.HasCategory("Exclusive") || g.HasCategory("Coming Soon")
                                || (g.UpdatedAt is { } u && u > cutoff))
                    .ToList();
                if (cts.IsCancellationRequested) return;
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    _shelfPool[platform] = picked;
                    RebuildShelves();
                });
            }
            catch { /* best-effort: skip platforms that fail to load */ }
        }
    }

    private void RebuildShelves()
    {
        static void Fill(ObservableCollection<StoreGame> target, IEnumerable<StoreGame> src)
        {
            target.Clear();
            foreach (var g in src.Take(ShelfMax)) target.Add(g);
        }
        // Interleave platforms so one big platform (PC) doesn't fill a whole shelf.
        static IEnumerable<StoreGame> Mix(IEnumerable<IEnumerable<StoreGame>> lists)
        {
            var enums = lists.Select(l => l.GetEnumerator()).ToList();
            bool any = true;
            while (any)
            {
                any = false;
                foreach (var e in enums)
                    if (e.MoveNext()) { any = true; yield return e.Current; }
            }
        }
        var cutoff = DateTime.UtcNow.AddDays(-30);
        var pools = _shelfPool.OrderBy(k => k.Key).Select(k => k.Value).ToList();
        Fill(UpdatedShelf, Mix(pools.Select(l => l
            .Where(g => g.HasCategory("Updated") || (g.UpdatedAt is { } d && d > cutoff))
            .OrderByDescending(g => g.UpdatedAt ?? DateTime.MinValue))));
        Fill(ExclusivesShelf, Mix(pools.Select(l => l.Where(g => g.HasCategory("Exclusive")))));
        Fill(ComingSoonShelf, Mix(pools.Select(l => l.Where(g => g.HasCategory("Coming Soon")))));
        OnPropertyChanged(nameof(HasUpdatedShelf));
        OnPropertyChanged(nameof(HasExclusivesShelf));
        OnPropertyChanged(nameof(HasComingSoonShelf));
        OnPropertyChanged(nameof(ShowShelves));
    }

    private async Task LoadNewGamesAsync()
    {
        try
        {
            var entries = await _client.GetNewGamesAsync().ConfigureAwait(false);
            var items = entries
                .Where(e => !string.IsNullOrWhiteSpace(e.Title))
                .OrderByDescending(e => e.AddedAt, StringComparer.Ordinal)
                .Take(30)
                .Select(e => new StoreGame
                {
                    Title       = e.Title,
                    Platform    = e.Platform,
                    CoverUrl    = e.CoverUrl,
                    Genre       = $"{e.Platform} · {NewSourceLabel(e.Source)}",
                    Description = $"Recently {NewSourceLabel(e.Source).ToLowerInvariant()}.",
                    StorePageUrl = e.SteamAppId is > 0 ? $"https://store.steampowered.com/app/{e.SteamAppId}" : null,
                }).ToList();
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                NewGames.Clear();
                foreach (var g in items) NewGames.Add(g);
                OnPropertyChanged(nameof(HasNewGames));
            });
        }
        catch { /* best-effort */ }
    }

    private static string NewSourceLabel(string source) => source switch
    {
        "steam-auto-add" => "Added via Steam",
        "admin-add"      => "New to database",
        "admin-edit"     => "Updated",
        _                => "Added",
    };

    /// <summary>True when Featured contains at least one game.</summary>
    public bool HasFeatured => Featured.Count > 0;

    /// <summary>Invoked when the user clicks a store game card.</summary>
    public Action<StoreGame>? OnOpenDetail { get; set; }

    public void Load(List<StoreGame> store, List<Game> library,
                     UserProfile profile, GameOsClient client, bool isAdmin,
                     int totalCatalogCount = RealDatabaseTotal)
    {
        _allStoreBase = new List<StoreGame>(store); // keep the curated catalog
        _allStore     = new List<StoreGame>(store); // work on a copy so admin changes are session-scoped
        _library  = library;
        _profile  = profile;
        _client   = client;
        IsAdmin   = isAdmin;

        TotalCatalogCount = totalCatalogCount;
        CatalogCountLabel = $"{totalCatalogCount:N0}+ games in the database";

        // Reset to curated "All" view (if already "All" the setter is a no-op;
        // if coming back from a different platform, LoadPlatformAsync("All") runs
        // synchronously to restore the curated catalog before RebuildCollections below).
        SelectedPlatform = "All";

        RebuildCollections();

        // Eagerly load App Store in the background
        _ = LoadAppStoreAsync();
        _ = LoadNewGamesAsync();
        _ = LoadWishlistAsync();
        _ = LoadShelvesAsync(Platforms.ToList());

        // Discover all platform JSON files from the Games.Database repository so new
        // platforms appear automatically without requiring an app update.
        _ = RefreshPlatformListAsync();
    }

    private async Task LoadWishlistAsync()
    {
        try
        {
            var wishlist = await _client.GetWishlistAsync().ConfigureAwait(false);
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                _wishlist = wishlist;
                ApplyFilter();
            });
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Fetches the list of available platforms from the Games.Database GitHub repository
    /// and updates the <see cref="Platforms"/> collection so new platforms are discovered
    /// automatically without hard-coding them in the app.
    /// </summary>
    private async Task RefreshPlatformListAsync()
    {
        try
        {
            var discovered = await Services.GitHubDataService
                .FetchAvailablePlatformsAsync().ConfigureAwait(false);

            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                var current = SelectedPlatform;
                Platforms.Clear();
                Platforms.Add("All");
                foreach (var p in discovered)
                    Platforms.Add(p);

                // Keep the current selection if it still exists.
                if (!Platforms.Contains(current))
                    SelectedPlatform = "All";
                _ = LoadShelvesAsync(Platforms.ToList());
            });
        }
        catch { /* best-effort — the built-in list remains usable */ }
    }

    [RelayCommand]
    private void SwitchToGamesTab()
    {
        IsGamesTab    = true;
        IsAppStoreTab = false;
    }

    [RelayCommand]
    private void SwitchToAppStoreTab()
    {
        IsGamesTab    = false;
        IsAppStoreTab = true;
        if (AllAppStoreEntries.Count == 0)
            _ = LoadAppStoreAsync();
    }

    private async Task LoadAppStoreAsync()
    {
        try
        {
            var entries = await GameOsClient.FetchAppStoreAsync();
            AllAppStoreEntries.Clear();
            foreach (var e in entries)
                AllAppStoreEntries.Add(e);

            // Build genre list
            AppStoreGenres.Clear();
            AppStoreGenres.Add("All");
            foreach (var genre in entries.Select(e => e.Genre).Distinct().OrderBy(g => g))
                AppStoreGenres.Add(genre);

            AppStoreGenreFilter = "All";
            ApplyAppStoreFilter();
        }
        catch { /* best-effort */ }
    }

    private void ApplyAppStoreFilter()
    {
        FilteredAppStoreEntries.Clear();
        var results = AllAppStoreEntries.AsEnumerable();

        if (AppStoreGenreFilter != "All")
            results = results.Where(e => e.Genre == AppStoreGenreFilter);

        if (!string.IsNullOrWhiteSpace(AppStoreSearchText))
            results = results.Where(e =>
                e.Name.Contains(AppStoreSearchText, StringComparison.OrdinalIgnoreCase) ||
                e.Genre.Contains(AppStoreSearchText, StringComparison.OrdinalIgnoreCase) ||
                e.Platform.Contains(AppStoreSearchText, StringComparison.OrdinalIgnoreCase));

        foreach (var e in results.OrderBy(e => e.Genre).ThenBy(e => e.Name))
            FilteredAppStoreEntries.Add(e);
    }

    [RelayCommand]
    private void OpenAppUrl(AppStoreEntry? app)
    {
        if (app == null || string.IsNullOrEmpty(app.Url)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = app.Url,
                UseShellExecute = true,
            });
        }
        catch { /* best-effort */ }
    }

    /// <summary>Clears the disk cache for the current platform and re-fetches from GitHub.</summary>
    [RelayCommand]
    private void RefreshPlatform()
    {
        if (SelectedPlatform == "All") return;
        // Force a fresh fetch by removing the platform from the in-memory cache
        Services.GitHubDataService.InvalidatePlatformCache(SelectedPlatform);
        // Re-trigger the load
        var platform = SelectedPlatform;
        SelectedPlatform = "All"; // reset first to ensure the setter fires
        SelectedPlatform = platform;
    }

    private void RebuildCollections()
    {
        Featured.Clear();
        foreach (var g in _allStore.Where(s => s.IsFeatured))
            Featured.Add(g);
        OnPropertyChanged(nameof(HasFeatured));

        Genres.Clear();
        Genres.Add("All");
        foreach (var genre in _allStore.Select(s => s.Genre).Distinct().OrderBy(g => g))
            Genres.Add(genre);
        if (!Genres.Contains("Wishlist"))
            Genres.Add("Wishlist");

        FilterGenre = "All"; // resets genre filter; callback fires ApplyFilter() if changed
        ApplyFilter();       // always re-apply in case FilterGenre was already "All"
    }

    // Debounce timer — avoids re-filtering on every keystroke when browsing
    // large platform catalogs (150 k+ entries) which would freeze the UI.
    private System.Threading.Timer? _searchDebounce;
    private const int SearchDebounceMs = 300;

    partial void OnSearchTextChanged(string value)
    {
        DisplayLimit = MaxDisplayedGames;
        _searchDebounce?.Change(System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
        _searchDebounce = new System.Threading.Timer(_ =>
            Avalonia.Threading.Dispatcher.UIThread.Post(ApplyFilter,
                Avalonia.Threading.DispatcherPriority.Background),
            null, SearchDebounceMs, System.Threading.Timeout.Infinite);
    }

    partial void OnFilterGenreChanged(string value)  { DisplayLimit = MaxDisplayedGames; ApplyFilter(); }

    /// <summary>
    /// Cycles between the Games Store tab and the App Store tab.
    /// Called by the controller LB/RB handler in MainWindow.
    /// </summary>
    public void CycleTab()
    {
        if (IsGamesTab)
        {
            IsGamesTab    = false;
            IsAppStoreTab = true;
            if (AllAppStoreEntries.Count == 0)
                _ = LoadAppStoreAsync();
        }
        else
        {
            IsGamesTab    = true;
            IsAppStoreTab = false;
        }
    }

    /// <summary>
    /// Invoked by MainWindow when the user presses Y on the controller while in the
    /// store — should focus the search TextBox so the user can type immediately.
    /// Wired in StoreView.axaml.cs.
    /// </summary>
    public Action? FocusSearchRequested { get; set; }

    /// <summary>
    /// Cycles the platform filter to the next platform in <see cref="Platforms"/>.
    /// Called by the X button controller handler in MainWindow.
    /// </summary>
    public void CyclePlatform()
    {
        if (Platforms.Count == 0) return;
        var list = Platforms.ToList();
        int idx = list.IndexOf(SelectedPlatform);
        if (idx < 0) idx = 0;
        SelectedPlatform = list[(idx + 1) % list.Count];
    }


    // ── Themes (pushed from Settings by MainViewModel) ─────────────────────
    [ObservableProperty] private string _gamesTheme = "Default";
    partial void OnGamesThemeChanged(string value) { }

    [ObservableProperty] private string _storeTheme = "Default";
    public bool IsSonyStore     => string.Equals(StoreTheme, "Sony", StringComparison.OrdinalIgnoreCase);
    public bool IsXboxStore     => string.Equals(StoreTheme, "Xbox", StringComparison.OrdinalIgnoreCase);
    public bool IsNintendoStore => string.Equals(StoreTheme, "Nintendo", StringComparison.OrdinalIgnoreCase);
    public bool IsDefaultStoreTheme => !IsSonyStore && !IsXboxStore && !IsNintendoStore;
    partial void OnStoreThemeChanged(string value)
    {
        OnPropertyChanged(nameof(IsSonyStore));
        OnPropertyChanged(nameof(IsXboxStore));
        OnPropertyChanged(nameof(IsNintendoStore));
        OnPropertyChanged(nameof(IsDefaultStoreTheme));
    }

    [ObservableProperty] private string _keyboardTheme = "Default";
    public bool IsPs5Keyboard     => string.Equals(KeyboardTheme, "PS5", StringComparison.OrdinalIgnoreCase);
    public bool IsDefaultKeyboard => !IsPs5Keyboard;
    partial void OnKeyboardThemeChanged(string value)
    {
        OnPropertyChanged(nameof(IsPs5Keyboard));
        OnPropertyChanged(nameof(IsDefaultKeyboard));
    }

    // ── Controller / keyboard card focus ───────────────────────────────────
    /// <summary>Returns the number of cards per row (measured from the live panel); wired by StoreView.</summary>
    public Func<int>? ColumnsProvider { get; set; }
    /// <summary>Asks the view to scroll the focused card into view.</summary>
    public Action? ScrollFocusedIntoView { get; set; }

    private IStoreFocusable? _focused;

    private IReadOnlyList<IStoreFocusable> ActiveItems() => IsAppStoreTab
        ? FilteredAppStoreEntries.Cast<IStoreFocusable>().ToList()
        : FilteredStore.Cast<IStoreFocusable>().ToList();

    public void ClearFocus()
    {
        if (_focused != null) _focused.IsFocused = false;
        _focused = null;
    }

    private void FocusAt(IReadOnlyList<IStoreFocusable> items, int index)
    {
        ClearFocus();
        if (index < 0 || index >= items.Count) return;
        _focused = items[index];
        _focused.IsFocused = true;
        ScrollFocusedIntoView?.Invoke();
    }

    private int FocusedIndex(IReadOnlyList<IStoreFocusable> items)
    {
        if (_focused == null) return -1;
        for (int i = 0; i < items.Count; i++)
            if (ReferenceEquals(items[i], _focused)) return i;
        return -1;
    }

    /// <summary>Left/Right (cols = 1 step) — first press focuses the first card.</summary>
    public void MoveFocus(int delta)
    {
        var items = ActiveItems();
        if (items.Count == 0) return;
        int cur = FocusedIndex(items);
        FocusAt(items, cur < 0 ? 0 : Math.Clamp(cur + delta, 0, items.Count - 1));
    }

    /// <summary>Up/Down — moves a whole row.</summary>
    public void MoveFocusRow(int direction)
    {
        var items = ActiveItems();
        if (items.Count == 0) return;
        int cur = FocusedIndex(items);
        if (cur < 0) { FocusAt(items, 0); return; }
        int cols = Math.Max(1, ColumnsProvider?.Invoke() ?? 1);
        int next = cur + direction * cols;
        if (next < 0 || next >= items.Count) return;
        FocusAt(items, next);
    }

    public void ActivateFocused()
    {
        switch (_focused)
        {
            case StoreGame g:      OnOpenDetail?.Invoke(g); break;
            case AppStoreEntry a:  OpenAppUrl(a); break;
        }
    }

    // ── Filter box (X) ────────────────────────────────────────────────────
    [ObservableProperty] private bool _isFilterMenuOpen;
    [ObservableProperty] private int  _filterMenuIndex;

    public sealed partial class FilterMenuItem : ObservableObject
    {
        public string Kind  { get; init; } = "";
        public string Value { get; init; } = "";
        public string Label { get; init; } = "";
        [ObservableProperty] private bool _isHighlighted;
        [ObservableProperty] private bool _isActive;
    }

    public ObservableCollection<FilterMenuItem> FilterMenuItems { get; } = new();

    public void OpenFilterMenu()
    {
        FilterMenuItems.Clear();
        if (IsAppStoreTab)
        {
            foreach (var g in AppStoreGenres)
                FilterMenuItems.Add(new FilterMenuItem { Kind = "AppGenre", Value = g, Label = g });
        }
        else
        {
            foreach (var p in Platforms)
                FilterMenuItems.Add(new FilterMenuItem { Kind = "Platform", Value = p, Label = p });
            foreach (var g in Genres)
                FilterMenuItems.Add(new FilterMenuItem { Kind = "Genre", Value = g, Label = "Genre: " + g });
        }
        FilterMenuIndex = 0;
        RefreshFilterMenu();
        IsFilterMenuOpen = true;
    }

    [RelayCommand] public void CloseFilterMenu() => IsFilterMenuOpen = false;

    public void MoveFilterMenu(int delta)
    {
        if (FilterMenuItems.Count == 0) return;
        FilterMenuIndex = Math.Clamp(FilterMenuIndex + delta, 0, FilterMenuItems.Count - 1);
        RefreshFilterMenu();
    }

    public void ApplyFilterMenuSelection()
    {
        if (FilterMenuIndex < 0 || FilterMenuIndex >= FilterMenuItems.Count) return;
        var item = FilterMenuItems[FilterMenuIndex];
        switch (item.Kind)
        {
            case "Platform": SelectedPlatform = item.Value; break;
            case "Genre":    FilterGenre = item.Value; break;
            case "AppGenre": AppStoreGenreFilter = item.Value; break;
        }
        ClearFocus();
        RefreshFilterMenu();
    }

    private void RefreshFilterMenu()
    {
        for (int i = 0; i < FilterMenuItems.Count; i++)
        {
            var it = FilterMenuItems[i];
            it.IsHighlighted = i == FilterMenuIndex;
            it.IsActive = it.Kind switch
            {
                "Platform" => it.Value == SelectedPlatform,
                "Genre"    => it.Value == FilterGenre,
                _          => it.Value == AppStoreGenreFilter,
            };
        }
    }

    // ── On-screen keyboard (Y) ────────────────────────────────────────────
    public static readonly string[][] KeyboardRows =
    {
        new[] { "1","2","3","4","5","6","7","8","9","0" },
        new[] { "Q","W","E","R","T","Y","U","I","O","P" },
        new[] { "A","S","D","F","G","H","J","K","L","'" },
        new[] { "Z","X","C","V","B","N","M",":","-","." },
        new[] { "Space","Backspace","Clear","Done" },
    };

    [ObservableProperty] private bool _isKeyboardOpen;
    [ObservableProperty] private int  _keyboardRow;
    [ObservableProperty] private int  _keyboardCol;

    public ObservableCollection<KeyboardRowVm> KeyboardRowItems { get; } = new();

    public sealed partial class KeyboardKeyVm : ObservableObject
    {
        public string Label { get; init; } = "";
        public bool IsWide => Label.Length > 1;
        [ObservableProperty] private bool _isHighlighted;
    }

    public sealed class KeyboardRowVm
    {
        public List<KeyboardKeyVm> Keys { get; init; } = new();
    }

    /// <summary>Text currently being edited by the on-screen keyboard (depends on the active tab).</summary>
    public string ActiveSearchText => IsAppStoreTab ? AppStoreSearchText : SearchText;

    private void SetActiveSearchText(string value)
    {
        if (IsAppStoreTab) AppStoreSearchText = value; else SearchText = value;
        OnPropertyChanged(nameof(ActiveSearchText));
    }

    public void OpenKeyboard()
    {
        if (KeyboardRowItems.Count == 0)
            foreach (var row in KeyboardRows)
                KeyboardRowItems.Add(new KeyboardRowVm { Keys = row.Select(k => new KeyboardKeyVm { Label = k }).ToList() });
        KeyboardRow = 1; KeyboardCol = 0;
        RefreshKeyboard();
        OnPropertyChanged(nameof(ActiveSearchText));
        IsKeyboardOpen = true;
    }

    [RelayCommand] public void CloseKeyboard() { IsKeyboardOpen = false; ClearFocus(); }

    public void MoveKeyboard(int dRow, int dCol)
    {
        if (KeyboardRowItems.Count == 0) return;
        int r = Math.Clamp(KeyboardRow + dRow, 0, KeyboardRowItems.Count - 1);
        int rowLen = KeyboardRowItems[r].Keys.Count;
        int c = dRow != 0 ? Math.Min(KeyboardCol, rowLen - 1)
                          : Math.Clamp(KeyboardCol + dCol, 0, rowLen - 1);
        KeyboardRow = r; KeyboardCol = c;
        RefreshKeyboard();
    }

    public void PressKeyboardKey()
    {
        if (KeyboardRow >= KeyboardRowItems.Count) return;
        var key = KeyboardRowItems[KeyboardRow].Keys[KeyboardCol].Label;
        switch (key)
        {
            case "Space":     SetActiveSearchText(ActiveSearchText + " "); break;
            case "Backspace": BackspaceSearch(); break;
            case "Clear":     SetActiveSearchText(""); break;
            case "Done":      CloseKeyboard(); break;
            default:          SetActiveSearchText(ActiveSearchText + key.ToLowerInvariant()); break;
        }
    }

    public void BackspaceSearch()
    {
        var t = ActiveSearchText;
        if (t.Length > 0) SetActiveSearchText(t[..^1]);
    }

    private void RefreshKeyboard()
    {
        for (int r = 0; r < KeyboardRowItems.Count; r++)
            for (int c = 0; c < KeyboardRowItems[r].Keys.Count; c++)
                KeyboardRowItems[r].Keys[c].IsHighlighted = r == KeyboardRow && c == KeyboardCol;
    }

    /// <summary>True while the filter box or on-screen keyboard is covering the store.</summary>
    public bool IsOverlayOpen => IsFilterMenuOpen || IsKeyboardOpen;
    partial void OnIsFilterMenuOpenChanged(bool value) => OnPropertyChanged(nameof(IsOverlayOpen));
    partial void OnIsKeyboardOpenChanged(bool value)   => OnPropertyChanged(nameof(IsOverlayOpen));

    partial void OnIsAppStoreTabChanged(bool value) { ClearFocus(); OnPropertyChanged(nameof(ShowShelves)); }

    // Cancellation source for in-flight platform loads
    private CancellationTokenSource _loadCts = new();

    partial void OnSelectedPlatformChanged(string value)
    {
        // Reset pagination and cancel any previous in-flight load
        DisplayLimit = MaxDisplayedGames;
        _loadCts.Cancel();
        _loadCts.Dispose();
        _loadCts = new CancellationTokenSource();
        _ = LoadPlatformAsync(value, _loadCts.Token);
    }

    private async Task LoadPlatformAsync(
        string platform, CancellationToken ct)
    {
        if (platform == "All")
        {
            // Restore curated catalog instantly — no network needed
            _allStore = new List<StoreGame>(_allStoreBase);
            RebuildCollections();
            return;
        }

        IsLoading      = true;
        LoadingMessage = $"Loading {platform} games…";
        StatusMessage  = null;
        FilteredStore.Clear();
        Featured.Clear();
        OnPropertyChanged(nameof(HasFeatured));

        try
        {
            var dbGames = await GameOsClient.FetchGamesDatabaseAsync(platform, ct);
            if (ct.IsCancellationRequested) return;

            _allStore = dbGames
                .Select(g => new StoreGame
                {
                    Title           = WebUtility.HtmlDecode(g.Title ?? ""),
                    Platform        = platform,
                    Genre           = "Unknown",
                    Price           = "N/A",
                    Rating          = 0,
                    CoverUrl        = g.CoverUrl,
                    Description     = g.Description ?? "",
                    TrailerUrl      = g.TrailerUrl,
                    AchievementsUrl = g.AchievementsUrl,
                    Screenshots     = g.Screenshots,
                    StorePageUrl    = g.StorePageUrl,
                    Categories      = g.Categories,
                    UpdatedAt       = DateTime.TryParse(g.UpdatedAt, null, System.Globalization.DateTimeStyles.AdjustToUniversal, out var upd) ? upd : null,
                })
                .ToList();

            RebuildCollections();
        }
        catch (OperationCanceledException)
        {
            // Platform changed before load completed — silently discard
        }
        catch (System.Net.Http.HttpRequestException ex)
        {
            if (ct.IsCancellationRequested) return;

            // Network unavailable — try to serve from the stale disk cache so the Store
            // remains functional offline (mirrors the offline-first goal from PR #218).
            System.Diagnostics.Debug.WriteLine(
                $"[StoreVM] Network unavailable loading {platform}: {ex.Message}. " +
                "Trying local disk cache (may be stale).");

            var stale = Services.GitHubDataService.TryLoadStaleDiskCacheForStore(platform);
            if (stale != null && stale.Count > 0)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[StoreVM] Loaded {stale.Count} games for {platform} from local cache (offline).");
                _allStore = stale
                    .Select(g => new StoreGame
                    {
                        Title           = System.Net.WebUtility.HtmlDecode(g.Title ?? ""),
                        Platform        = platform,
                        Genre           = "Unknown",
                        Price           = "N/A",
                        Rating          = 0,
                        CoverUrl        = g.CoverUrl,
                        Description     = g.Description ?? "",
                        TrailerUrl      = g.TrailerUrl,
                        AchievementsUrl = g.AchievementsUrl,
                        Screenshots     = g.Screenshots,
                        StorePageUrl    = g.StorePageUrl,
                        Categories      = g.Categories,
                    })
                    .ToList();
                StatusMessage = $"Offline — showing cached {platform} data.";
            }
            else
            {
                StatusMessage = $"Offline — no cached data available for {platform}.";
                _allStore = new List<StoreGame>();
            }
            RebuildCollections();
        }
        catch (Exception ex)
        {
            if (!ct.IsCancellationRequested)
            {
                StatusMessage = $"Failed to load {platform} games: {ex.Message}";
                // Restore an empty (but consistent) view so the UI doesn't stay blank
                _allStore = new List<StoreGame>();
                RebuildCollections();
            }
        }
        finally
        {
            if (!ct.IsCancellationRequested)
            {
                IsLoading      = false;
                LoadingMessage = "";
            }
        }
    }

    private void ApplyFilter()
    {
        OnPropertyChanged(nameof(ShowShelves));
        FilteredStore.Clear();
        var results = _allStore.AsEnumerable();

        if (FilterGenre == "Wishlist")
            results = results.Where(s => _wishlist.Any(w =>
                w.Platform.Equals(s.Platform, StringComparison.OrdinalIgnoreCase) &&
                w.Title.Equals(s.Title, StringComparison.OrdinalIgnoreCase)));
        else if (FilterGenre != "All")
            results = results.Where(s => s.Genre == FilterGenre);

        if (!string.IsNullOrWhiteSpace(SearchText))
            results = results.Where(s =>
                s.Title.Contains(SearchText, System.StringComparison.OrdinalIgnoreCase) ||
                s.Genre.Contains(SearchText, System.StringComparison.OrdinalIgnoreCase));

        // Materialize once to get the total count, then sort and take the display page.
        var allMatches = results.ToList();
        int total = allMatches.Count;
        int shown = Math.Min(total, DisplayLimit);

        foreach (var g in allMatches
            .OrderByDescending(s => s.Rating)
            .ThenBy(s => s.Title, StringComparer.OrdinalIgnoreCase)
            .Take(shown))
            FilteredStore.Add(g);

        HasMoreGames = shown < total;

        BrowseCountLabel = total == 0
            ? ""
            : shown < total
                ? $"Showing {shown:N0} of {total:N0} games — use search to filter or load more below"
                : $"{total:N0} game{(total == 1 ? "" : "s")}";
    }

    /// <summary>Appends the next page of games to the current filtered view.</summary>
    [RelayCommand]
    private void LoadMore()
    {
        DisplayLimit += MaxDisplayedGames;
        ApplyFilter();
    }

    public bool IsOwned(string title) =>
        _library.Any(g => g.Title.Equals(title, System.StringComparison.OrdinalIgnoreCase));

    [RelayCommand]
    private void OpenGameDetail(StoreGame? game)
    {
        if (game != null) OnOpenDetail?.Invoke(game);
    }

    [RelayCommand]
    private async System.Threading.Tasks.Task AddGameAsync(StoreGame? game)
    {
        if (game == null) return;
        if (IsOwned(game.Title))
        {
            StatusMessage = $"'{game.Title}' is already in your library.";
            return;
        }

        StatusMessage = $"Adding '{game.Title}'…";
        try
        {
            // Build the full Game so all metadata (cover URL, genre, description,
            // rating, screenshots) is persisted to GitHub — the same data that
            // accounts/{user}/games.json stores on the website backend.
            var newGame = new Game
            {
                Platform        = game.Platform,
                Title           = game.Title,
                Genre           = game.Genre,
                Rating          = game.Rating,
                Description     = game.Description,
                CoverUrl        = game.CoverUrl,
                Screenshots     = game.Screenshots,
                Price           = game.Price,
                TrailerUrl      = game.TrailerUrl,
                AchievementsUrl = game.AchievementsUrl,
                AddedAt         = System.DateTimeOffset.UtcNow.ToString("o"),
            };
            // CoverColor / CoverGradient are [JsonIgnore] — UI-only, not persisted
            newGame.CoverColor    = game.CoverColor;
            newGame.CoverGradient = game.CoverGradient;

            await _client.AddGameAsync(newGame);
            _library.Add(newGame);
            StatusMessage = $"✓  '{game.Title}' added to your library!";
        }
        catch (System.Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }

        ApplyFilter();
    }

    // ── Admin: toggle add-game form ───────────────────────────────────────
    [RelayCommand]
    private void AdminToggleForm()
    {
        ShowAdminForm = !ShowAdminForm;
        if (ShowAdminForm)
        {
            AdminTitle = ""; AdminPlatform = "PC"; AdminGenre = "";
            AdminPrice = ""; AdminDescription = ""; AdminRating = "8.0";
            AdminCoverUrl = "";
        }
    }

    // ── Admin: add a new game to the catalog (session-only) ───────────────
    [RelayCommand]
    private void AdminAddCatalogGame()
    {
        if (string.IsNullOrWhiteSpace(AdminTitle) || string.IsNullOrWhiteSpace(AdminPlatform))
        {
            StatusMessage = "Title and Platform are required.";
            return;
        }
        if (!double.TryParse(AdminRating, System.Globalization.NumberStyles.Any,
                System.Globalization.CultureInfo.InvariantCulture, out double rating))
            rating = 8.0;

        var newGame = new StoreGame
        {
            Title       = AdminTitle.Trim(),
            Platform    = AdminPlatform.Trim(),
            Genre       = string.IsNullOrWhiteSpace(AdminGenre) ? "Other" : AdminGenre.Trim(),
            Price       = string.IsNullOrWhiteSpace(AdminPrice) ? "Free" : AdminPrice.Trim(),
            Description = AdminDescription.Trim(),
            Rating      = Math.Clamp(rating, 0, 10),
            CoverUrl    = string.IsNullOrWhiteSpace(AdminCoverUrl) ? null : AdminCoverUrl.Trim(),
            IsFeatured  = false,
            ReleaseYear = System.DateTime.Now.Year.ToString()
        };

        _allStore.Add(newGame);
        RebuildCollections();
        ShowAdminForm = false;
        StatusMessage = $"✓  '{newGame.Title}' added to the catalog (this session only).";
    }

    // ── Admin: remove a game from the catalog (session-only) ─────────────
    [RelayCommand]
    private void AdminDeleteCatalogGame(StoreGame? game)
    {
        if (game == null) return;
        _allStore.RemoveAll(s => s.Title == game.Title && s.Platform == game.Platform);
        RebuildCollections();
        StatusMessage = $"✓  '{game.Title}' removed from the catalog (this session only).";
    }

    public void Dispose()
    {
        _loadCts.Cancel();
        _loadCts.Dispose();
        _searchDebounce?.Change(System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
        _searchDebounce?.Dispose();
        _searchDebounce = null;
    }
}
