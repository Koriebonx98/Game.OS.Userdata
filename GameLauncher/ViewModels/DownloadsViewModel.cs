using System;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>Downloads page (list + controls) and the "Game / Mod / Other → platform" prompt shown when a download starts.</summary>
public partial class DownloadsViewModel : ViewModelBase
{
    public ObservableCollection<DownloadItem> Items => DownloadManagerService.Instance.Items;
    public string[] Categories => DownloadPathResolver.Categories;
    public string[] PlatformNames => DownloadPathResolver.PlatformNames;

    [ObservableProperty] private string _newUrl = "";
    [ObservableProperty] private bool _isPromptOpen;
    [ObservableProperty] private string _promptUrl = "";
    [ObservableProperty] private string _promptName = "";
    [ObservableProperty] private string _promptCategory = DownloadPathResolver.CategoryGame;
    [ObservableProperty] private string _promptPlatform = "PC";
    [ObservableProperty] private string _promptFolder = "";
    [ObservableProperty] private string _promptGame = "";
    public bool HasPromptGame => !string.IsNullOrEmpty(PromptGame);
    partial void OnPromptGameChanged(string value) => OnPropertyChanged(nameof(HasPromptGame));
    /// <summary>Resolves the game (platform + title) for a download: a saved link for the source page/URL, else the browser's game context.</summary>
    public Func<string, string, (string Platform, string Game)?>? ResolveGame { get; set; }
    private string _promptReferer = "";
    private string _promptCookie = "";
    /// <summary>Controller focus row inside the prompt: 0 = category, 1 = platform, 2 = start.</summary>
    [ObservableProperty] private int _promptRow;
    [ObservableProperty] private string _statusText = "";

    public OnScreenKeyboardViewModel Keyboard { get; } = new();
    private int _selectedIndex = -1;

    public bool HasItems => Items.Count > 0;
    public bool IsPromptCategoryRow => PromptRow == 0;
    public bool IsPromptPlatformRow => PromptRow == 1;
    public bool IsPromptStartRow => PromptRow == 2;
    public bool IsGameCategory => PromptCategory == DownloadPathResolver.CategoryGame;
    public bool IsModCategory => PromptCategory == DownloadPathResolver.CategoryMod;
    public bool IsOtherCategory => PromptCategory == DownloadPathResolver.CategoryOther;

    /// <summary>Raised after a download is queued so the shell can notify the user / switch pages.</summary>
    public event Action<DownloadItem>? DownloadQueued;

    public DownloadsViewModel()
    {
        DownloadManagerService.Instance.Load();
        Items.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasItems));
    }

    partial void OnPromptRowChanged(int value)
    {
        OnPropertyChanged(nameof(IsPromptCategoryRow));
        OnPropertyChanged(nameof(IsPromptPlatformRow));
        OnPropertyChanged(nameof(IsPromptStartRow));
    }

    partial void OnPromptCategoryChanged(string value)
    {
        OnPropertyChanged(nameof(IsGameCategory));
        OnPropertyChanged(nameof(IsModCategory));
        OnPropertyChanged(nameof(IsOtherCategory));
        RefreshFolder();
    }

    partial void OnPromptPlatformChanged(string value) => RefreshFolder();

    private void RefreshFolder()
    {
        var s = AppSettingsService.Load().Downloads;
        PromptFolder = DownloadPathResolver.Resolve(DownloadPathResolver.ResolveRoot(s.RootFolder), PromptPlatform, PromptCategory);
    }

    /// <summary>Starts the Game / Mod / Other + platform prompt for a URL, magnet link or .torrent.</summary>
    public void BeginDownload(string url, string referer = "", string cookie = "")
    {
        url = (url ?? "").Trim();
        if (url.Length == 0) return;
        _promptReferer = referer ?? "";
        _promptCookie = cookie ?? "";
        PromptUrl = url;
        PromptName = DownloadManagerService.GuessName(url);
        PromptCategory = DownloadPathResolver.CategoryGame;
        PromptGame = "";
        PromptPlatform = "PC";
        if (ResolveGame?.Invoke(url, _promptReferer) is { } g && !string.IsNullOrWhiteSpace(g.Game))
        {
            PromptGame = g.Game;
            var match = PlatformNames.FirstOrDefault(n => string.Equals(n, g.Platform, StringComparison.OrdinalIgnoreCase))
                        ?? PlatformNames.FirstOrDefault(n => g.Platform.Contains(n, StringComparison.OrdinalIgnoreCase) && n.Length > 2);
            if (match != null) PromptPlatform = match;
        }
        PromptRow = 0;
        RefreshFolder();
        IsPromptOpen = true;
    }

    [RelayCommand] private void AddUrl() { BeginDownload(NewUrl); }

    [RelayCommand] private void SetCategory(string? category)
    {
        if (!string.IsNullOrEmpty(category)) PromptCategory = category;
    }

    [RelayCommand] private void ConfirmPrompt()
    {
        if (!IsPromptOpen) return;
        IsPromptOpen = false;
        var item = DownloadManagerService.Instance.Add(PromptUrl, PromptName, PromptCategory, PromptPlatform, _promptReferer, _promptCookie, PromptGame);
        NewUrl = "";
        StatusText = $"Queued: {item.Name} → {item.Folder}";
        DownloadQueued?.Invoke(item);
    }

    [RelayCommand] private void CancelPrompt() => IsPromptOpen = false;

    /// <summary>Controller navigation inside the prompt (D-pad / stick).</summary>
    public void PromptMove(int dx, int dy)
    {
        if (dy != 0) PromptRow = Math.Clamp(PromptRow + dy, 0, 2);
        if (dx == 0) return;
        if (PromptRow == 0)
        {
            int i = Array.IndexOf(Categories, PromptCategory);
            PromptCategory = Categories[(i + dx + Categories.Length) % Categories.Length];
        }
        else if (PromptRow == 1)
        {
            int i = Array.IndexOf(PlatformNames, PromptPlatform);
            PromptPlatform = PlatformNames[(i + dx + PlatformNames.Length) % PlatformNames.Length];
        }
    }

    public void PromptActivate()
    {
        if (PromptRow == 2) ConfirmPrompt();
        else PromptRow++;
    }

    /// <summary>Controller handling for the Downloads page. Returns true when the key was consumed.</summary>
    public bool HandleKey(string name)
    {
        if (Keyboard.IsOpen) return Keyboard.HandleKey(name);
        if (IsPromptOpen)
        {
            switch (name)
            {
                case "Up": PromptMove(0, -1); break;
                case "Down": PromptMove(0, 1); break;
                case "Left": PromptMove(-1, 0); break;
                case "Right": PromptMove(1, 0); break;
                case "A": PromptActivate(); break;
                case "B": case "Y": CancelPrompt(); break;
            }
            return true;
        }
        switch (name)
        {
            case "Up": MoveSelection(-1); return true;
            case "Down": MoveSelection(1); return true;
            case "A": ActivateSelected(); return true;
            case "X": RemoveSelected(); return true;
            case "Y": OpenLinkKeyboard(); return true;
            case "Start": ClearFinished(); return true;
        }
        return false;
    }

    private DownloadItem? Selected => _selectedIndex >= 0 && _selectedIndex < Items.Count ? Items[_selectedIndex] : null;

    public void MoveSelection(int d)
    {
        if (Items.Count == 0) return;
        _selectedIndex = Math.Clamp((_selectedIndex < 0 ? (d > 0 ? -1 : Items.Count) : _selectedIndex) + d, 0, Items.Count - 1);
        for (int i = 0; i < Items.Count; i++) Items[i].IsSelected = i == _selectedIndex;
    }

    private void ActivateSelected()
    {
        var i = Selected ?? (Items.Count > 0 ? Items[0] : null);
        if (i == null) { OpenLinkKeyboard(); return; }
        if (i.CanPause) DownloadManagerService.Instance.Pause(i);
        else if (i.CanResume) DownloadManagerService.Instance.Resume(i);
        else DownloadManagerService.Instance.OpenFolder(i);
    }

    private void RemoveSelected()
    {
        var i = Selected;
        if (i == null) return;
        DownloadManagerService.Instance.Remove(i, false);
        if (_selectedIndex >= Items.Count) _selectedIndex = Items.Count - 1;
        for (int k = 0; k < Items.Count; k++) Items[k].IsSelected = k == _selectedIndex;
    }

    [RelayCommand] public void OpenLinkKeyboard() =>
        Keyboard.Open(NewUrl, "Paste or type a link / magnet", t => NewUrl = t, t => { NewUrl = t; BeginDownload(t); });

    [RelayCommand] private void Pause(DownloadItem? i) { if (i != null) DownloadManagerService.Instance.Pause(i); }
    [RelayCommand] private void Resume(DownloadItem? i) { if (i != null) DownloadManagerService.Instance.Resume(i); }
    [RelayCommand] private void Cancel(DownloadItem? i) { if (i != null) DownloadManagerService.Instance.Cancel(i); }
    [RelayCommand] private void Remove(DownloadItem? i) { if (i != null) DownloadManagerService.Instance.Remove(i, false); }
    [RelayCommand] private void RemoveWithFiles(DownloadItem? i) { if (i != null) DownloadManagerService.Instance.Remove(i, true); }
    [RelayCommand] private void OpenFolder(DownloadItem? i) { if (i != null) DownloadManagerService.Instance.OpenFolder(i); }
    [RelayCommand] private void ClearFinished() => DownloadManagerService.Instance.ClearFinished();
    [RelayCommand] private void PauseAll() { foreach (var i in Items.Where(x => x.CanPause).ToList()) DownloadManagerService.Instance.Pause(i); }
    [RelayCommand] private void ResumeAll() { foreach (var i in Items.Where(x => x.CanResume).ToList()) DownloadManagerService.Instance.Resume(i); }
}
