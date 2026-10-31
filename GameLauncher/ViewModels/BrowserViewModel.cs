using System;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

public enum BrowserMenuKind { ReturnToGame, Resume, NewTab, CloseTab, Downloads, AddFavourite, Favourite, Exit, SaveLink, SearchWeb, GameLink }

public sealed class BrowserMenuEntry
{
    public string Label { get; init; } = "";
    public BrowserMenuKind Kind { get; init; }
    public BrowserFavourite? Favourite { get; init; }
    public GameLink? Link { get; init; }
    public string Kind2 { get; init; } = "";
}

public partial class BrowserTabVm : ObservableObject
{
    public Guid Id { get; } = Guid.NewGuid();
    [ObservableProperty] private string _title = "New tab";
    [ObservableProperty] private string _url = "";
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private bool _isSelected;
}

/// <summary>
/// State of the built-in browser: tabs, address bar, and the Start-button menu (resume / tabs / downloads / favourites / exit).
/// The WebView controls themselves live in <c>BrowserView</c>; this model raises events the view acts on.
/// </summary>
public partial class BrowserViewModel : ViewModelBase
{
    public ObservableCollection<BrowserTabVm> Tabs { get; } = new();
    public ObservableCollection<BrowserMenuEntry> MenuEntries { get; } = new();

    [ObservableProperty] private BrowserTabVm? _activeTab;
    [ObservableProperty] private string _addressText = "";
    [ObservableProperty] private bool _isMenuOpen;
    [ObservableProperty] private int _menuIndex;
    [ObservableProperty] private string _statusText = "";
    [ObservableProperty] private bool _adBlockOn = true;
    [ObservableProperty] private long _blockedCount;
    [ObservableProperty] private bool _isActive;
    /// <summary>True while something drawn by the main window (nav sidebar, quick menu, download prompt) must sit above the native WebView.</summary>
    [ObservableProperty] private bool _suspendWebView;
    public DownloadsViewModel? Downloads { get; set; }

    /// <summary>Game / ROM the browser was opened for (null = plain browsing). Drives saved links, walkthroughs and download naming.</summary>
    [ObservableProperty] private string _contextGame = "";
    [ObservableProperty] private string _contextPlatform = "";
    /// <summary>True when opened from the in-game quick menu: compact page view, and exiting returns to the running game.</summary>
    [ObservableProperty] private bool _isPeek;
    public event Action? ReturnToGameRequested;
    [RelayCommand] public void ReturnToGame() { IsMenuOpen = false; IsPeek = false; ReturnToGameRequested?.Invoke(); }

    /// <summary>Opens the start menu (saved links / favourites) if it isn't open yet.</summary>
    public void OpenMenu() { if (!IsMenuOpen) ToggleMenu(); }
    public bool HasContext => !string.IsNullOrWhiteSpace(ContextGame);
    public string ContextLabel => HasContext ? $"🎮 {ContextGame} ({ContextPlatform})" : "";
    partial void OnContextGameChanged(string value) { OnPropertyChanged(nameof(HasContext)); OnPropertyChanged(nameof(ContextLabel)); }
    partial void OnContextPlatformChanged(string value) => OnPropertyChanged(nameof(ContextLabel));

    public void SetContext(string? platform, string? game)
    {
        ContextPlatform = (platform ?? "").Trim();
        ContextGame = (game ?? "").Trim();
    }
    public OnScreenKeyboardViewModel Keyboard { get; } = new();

    public BrowserSettings Settings { get; private set; } = new();

    /// <summary>Raised when a tab needs a WebView navigated to a URL.</summary>
    public event Action<BrowserTabVm, string>? NavigateRequested;
    public event Action<BrowserTabVm>? TabAdded;
    public event Action<BrowserTabVm>? TabClosed;
    public event Action<BrowserTabVm?>? TabSelected;
    public event Action? GoBackRequested;
    public event Action? GoForwardRequested;
    public event Action? ReloadRequested;
    public event Action? FocusAddressRequested;
    /// <summary>The user chose Exit in the browser menu.</summary>
    public event Action? ExitRequested;
    /// <summary>The user chose Downloads in the browser menu.</summary>
    public event Action? OpenDownloadsRequested;
    public event Action<string, string, string>? DownloadRequested;

    public void ApplySettings(BrowserSettings s)
    {
        Settings = s;
        AdBlockOn = s.AdBlockEnabled;
        AdBlockService.Configure(s.CustomFilters, s.AllowList);
    }

    public void EnsureTab()
    {
        if (Tabs.Count == 0) NewTab(null);
    }

    public BrowserTabVm NewTab(string? url, bool select = true)
    {
        var tab = new BrowserTabVm { Url = url ?? Settings.HomePage };
        Tabs.Add(tab);
        TabAdded?.Invoke(tab);
        if (select) SelectTab(tab);
        NavigateRequested?.Invoke(tab, tab.Url);
        return tab;
    }

    [RelayCommand] private void AddTab() => NewTab(null);

    [RelayCommand]
    private void SelectTab(BrowserTabVm? tab)
    {
        if (tab == null) return;
        foreach (var t in Tabs) t.IsSelected = ReferenceEquals(t, tab);
        ActiveTab = tab;
        AddressText = tab.Url;
        TabSelected?.Invoke(tab);
    }

    [RelayCommand]
    private void CloseTab(BrowserTabVm? tab)
    {
        tab ??= ActiveTab;
        if (tab == null) return;
        int idx = Tabs.IndexOf(tab);
        Tabs.Remove(tab);
        TabClosed?.Invoke(tab);
        if (Tabs.Count == 0) { NewTab(null); return; }
        if (ReferenceEquals(ActiveTab, tab)) SelectTab(Tabs[Math.Min(idx, Tabs.Count - 1)]);
    }

    public void NextTab() => CycleTab(1);
    public void PreviousTab() => CycleTab(-1);

    private void CycleTab(int delta)
    {
        if (Tabs.Count < 2 || ActiveTab == null) return;
        int idx = (Tabs.IndexOf(ActiveTab) + delta + Tabs.Count) % Tabs.Count;
        SelectTab(Tabs[idx]);
    }

    /// <summary>Navigates the active tab: URLs are opened directly, anything else is searched with the configured engine.</summary>
    [RelayCommand]
    public void Go(string? text)
    {
        if (ActiveTab == null) EnsureTab();
        if (ActiveTab == null) return;
        string url = ResolveInput(text ?? AddressText, Settings.SearchEngine);
        if (DownloadManagerService.IsMagnet(url)) { DownloadRequested?.Invoke(url, "", ""); return; }
        NavigateRequested?.Invoke(ActiveTab, url);
    }

    public static string ResolveInput(string input, string engine)
    {
        input = (input ?? "").Trim();
        if (input.Length == 0) return "about:blank";
        if (DownloadManagerService.IsMagnet(input)) return input;
        if (Uri.TryCreate(input, UriKind.Absolute, out var abs) && (abs.Scheme == "http" || abs.Scheme == "https" || abs.Scheme == "file"))
            return abs.ToString();
        if (!input.Contains(' ') && input.Contains('.') && Uri.TryCreate("https://" + input, UriKind.Absolute, out var guess))
            return guess.ToString();
        string q = Uri.EscapeDataString(input);
        return (engine ?? "").ToLowerInvariant() switch
        {
            "google" => $"https://www.google.com/search?q={q}",
            "bing"   => $"https://www.bing.com/search?q={q}",
            "brave"  => $"https://search.brave.com/search?q={q}",
            _        => $"https://duckduckgo.com/?q={q}",
        };
    }

    [RelayCommand] public void GoBack() => GoBackRequested?.Invoke();
    [RelayCommand] public void GoForward() => GoForwardRequested?.Invoke();
    [RelayCommand] public void Reload() => ReloadRequested?.Invoke();
    [RelayCommand] public void GoHome() => Go(Settings.HomePage);
    [RelayCommand] public void FocusAddress() => FocusAddressRequested?.Invoke();
    [RelayCommand] public void OpenDownloads() { IsMenuOpen = false; OpenDownloadsRequested?.Invoke(); }
    [RelayCommand] public void ExitBrowser() { IsMenuOpen = false; if (IsPeek) { ReturnToGame(); return; } ExitRequested?.Invoke(); }

    [RelayCommand]
    public void ToggleFavourite()
    {
        if (ActiveTab == null || string.IsNullOrWhiteSpace(ActiveTab.Url) || ActiveTab.Url == "about:blank") return;
        var existing = Settings.Favourites.FirstOrDefault(f => string.Equals(f.Url, ActiveTab.Url, StringComparison.OrdinalIgnoreCase));
        if (existing != null) Settings.Favourites.Remove(existing);
        else Settings.Favourites.Add(new BrowserFavourite { Title = string.IsNullOrWhiteSpace(ActiveTab.Title) ? ActiveTab.Url : ActiveTab.Title, Url = ActiveTab.Url });
        PersistFavourites();
        StatusText = existing != null ? "Removed from favourites" : "Added to favourites ★";
        if (IsMenuOpen) RebuildMenu();
    }

    private void PersistFavourites()
    {
        var all = AppSettingsService.Load();
        all.Browser.Favourites = Settings.Favourites;
        AppSettingsService.Save(all);
    }

    // ── Start menu ────────────────────────────────────────────────────────

    public void ToggleMenu()
    {
        if (IsMenuOpen) { IsMenuOpen = false; return; }
        RebuildMenu();
        MenuIndex = 0;
        IsMenuOpen = true;
    }

    public void CloseMenu() => IsMenuOpen = false;

    private void RebuildMenu()
    {
        MenuEntries.Clear();
        if (IsPeek) MenuEntries.Add(new() { Label = "🎮  Return to game", Kind = BrowserMenuKind.ReturnToGame });
        MenuEntries.Add(new() { Label = "▶  Resume browsing", Kind = BrowserMenuKind.Resume });
        MenuEntries.Add(new() { Label = "➕  New tab", Kind = BrowserMenuKind.NewTab });
        MenuEntries.Add(new() { Label = "✕  Close this tab", Kind = BrowserMenuKind.CloseTab });
        MenuEntries.Add(new() { Label = "⬇  Downloads", Kind = BrowserMenuKind.Downloads });
        bool isFav = ActiveTab != null && Settings.Favourites.Any(f => string.Equals(f.Url, ActiveTab.Url, StringComparison.OrdinalIgnoreCase));
        MenuEntries.Add(new() { Label = isFav ? "★  Remove this page from favourites" : "☆  Add this page to favourites", Kind = BrowserMenuKind.AddFavourite });
        foreach (var f in Settings.Favourites)
            MenuEntries.Add(new() { Label = $"★  {f.Title}", Kind = BrowserMenuKind.Favourite, Favourite = f });
        if (HasContext)
        {
            bool hasPage = ActiveTab != null && !string.IsNullOrWhiteSpace(ActiveTab.Url) && ActiveTab.Url != "about:blank";
            if (hasPage)
            {
                MenuEntries.Add(new() { Label = $"⬇  Save page as download link for {ContextGame}", Kind = BrowserMenuKind.SaveLink, Kind2 = GameLink.KindDownload });
                MenuEntries.Add(new() { Label = $"📖  Save page as walkthrough for {ContextGame}", Kind = BrowserMenuKind.SaveLink, Kind2 = GameLink.KindWalkthrough });
                MenuEntries.Add(new() { Label = $"📘  Save page as guide for {ContextGame}", Kind = BrowserMenuKind.SaveLink, Kind2 = GameLink.KindGuide });
                MenuEntries.Add(new() { Label = $"🧩  Save page as mod for {ContextGame}", Kind = BrowserMenuKind.SaveLink, Kind2 = GameLink.KindMod });
            }
            MenuEntries.Add(new() { Label = $"🔍  Search walkthrough: {ContextGame}", Kind = BrowserMenuKind.SearchWeb, Kind2 = "walkthrough" });
            MenuEntries.Add(new() { Label = $"🔍  Search download: {ContextGame} {ContextPlatform}", Kind = BrowserMenuKind.SearchWeb, Kind2 = "download" });
            foreach (var l in GameLinksService.ForGame(ContextPlatform, ContextGame))
                MenuEntries.Add(new() { Label = $"{l.Icon}  {l.Name}  ·  {l.Kind}", Kind = BrowserMenuKind.GameLink, Link = l });
        }
        MenuEntries.Add(new() { Label = "⏏  Exit browser", Kind = BrowserMenuKind.Exit });
        MenuIndex = Math.Min(MenuIndex, MenuEntries.Count - 1);
    }

    public void MoveMenu(int delta)
    {
        if (MenuEntries.Count == 0) return;
        MenuIndex = (MenuIndex + delta + MenuEntries.Count) % MenuEntries.Count;
    }

    public void ActivateMenu() => ActivateMenu(MenuEntries.ElementAtOrDefault(MenuIndex));

    [RelayCommand]
    public void ActivateMenu(BrowserMenuEntry? entry)
    {
        if (entry == null) return;
        switch (entry.Kind)
        {
            case BrowserMenuKind.ReturnToGame: ReturnToGame(); break;
            case BrowserMenuKind.Resume: IsMenuOpen = false; break;
            case BrowserMenuKind.NewTab: IsMenuOpen = false; NewTab(null); break;
            case BrowserMenuKind.CloseTab: IsMenuOpen = false; CloseTab(ActiveTab); break;
            case BrowserMenuKind.Downloads: OpenDownloads(); break;
            case BrowserMenuKind.AddFavourite: ToggleFavourite(); break;
            case BrowserMenuKind.Favourite when entry.Favourite != null:
                IsMenuOpen = false; Go(entry.Favourite.Url); break;
            case BrowserMenuKind.Exit: ExitBrowser(); break;
            case BrowserMenuKind.SaveLink: IsMenuOpen = false; BeginSaveLink(entry.Kind2); break;
            case BrowserMenuKind.SearchWeb:
            {
                IsMenuOpen = false;
                string q = entry.Kind2 == "download" ? $"{ContextGame} {ContextPlatform} download" : $"{ContextGame} {ContextPlatform} walkthrough";
                Go(q);
                break;
            }
            case BrowserMenuKind.GameLink when entry.Link != null:
                IsMenuOpen = false; Go(entry.Link.Url); break;
        }
    }

    /// <summary>Lets the user name the current page (on-screen keyboard) and stores it in Urls.json for the current game.</summary>
    private void BeginSaveLink(string kind)
    {
        if (ActiveTab == null || !HasContext) return;
        string url = ActiveTab.Url;
        string platform = ContextPlatform, game = ContextGame;
        string initial = string.IsNullOrWhiteSpace(ActiveTab.Title) ? "" : ActiveTab.Title.Trim();
        void Save(string name)
        {
            var link = GameLinksService.Add(platform, game, name, url, kind);
            StatusText = $"Saved “{link.Name}” ({kind}) for {game}";
        }
        Keyboard.Open(initial, $"Name this {kind.ToLowerInvariant()} link — Go / Y saves", _ => { }, Save);
    }

    /// <summary>X on a favourite in the menu removes it.</summary>
    public void RemoveSelectedFavourite()
    {
        var e = MenuEntries.ElementAtOrDefault(MenuIndex);
        if (e?.Kind == BrowserMenuKind.GameLink && e.Link != null)
        {
            GameLinksService.Remove(e.Link);
            RebuildMenu();
            return;
        }
        if (e?.Kind != BrowserMenuKind.Favourite || e.Favourite == null) return;
        Settings.Favourites.Remove(e.Favourite);
        PersistFavourites();
        RebuildMenu();
    }

    /// <summary>Called from the view when the page's own URL/title changes.</summary>
    public void UpdateTab(BrowserTabVm tab, string? url, string? title)
    {
        if (!string.IsNullOrEmpty(url)) tab.Url = url;
        if (!string.IsNullOrWhiteSpace(title)) tab.Title = title;
        if (ReferenceEquals(tab, ActiveTab) && !string.IsNullOrEmpty(url)) AddressText = url;
    }

    public void RequestDownload(string url, string referer = "", string cookie = "") => DownloadRequested?.Invoke(url, referer, cookie);
}
