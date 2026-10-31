using System;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>
/// Steam Big Picture dashboard: controller / keyboard focus across the game row, the
/// WHAT'S NEW / FRIENDS / RECOMMENDED tabs and the shelf under them.
/// </summary>
public partial class DashboardViewModel
{
    private enum SteamZone { Games, Tabs, Shelf }

    private const int SteamTabCount = 3;
    private const int SteamShelfSize = 10;

    private SteamZone _steamZone = SteamZone.Games;
    private int _steamGameIdx;   // 0 = hero, 1.. = SteamRecentSideGames
    private int _steamShelfIdx;

    [ObservableProperty] private int _steamTab;
    [ObservableProperty] private string _steamShelfTitle = "What's new";
    [ObservableProperty] private bool _isSteamHeroFocused;
    [ObservableProperty] private bool _isSteamTabsFocused;
    [ObservableProperty] private bool _hasSteamShelf;

    public ObservableCollection<SteamDashboardNewsTileVm> SteamShelfTiles { get; } = new();

    public bool IsSteamTab0 => SteamTab == 0;
    public bool IsSteamTab1 => SteamTab == 1;
    public bool IsSteamTab2 => SteamTab == 2;

    /// <summary>Raised after the Steam highlight moves so the view can scroll it into view.</summary>
    public event Action? SteamFocusChanged;

    partial void OnSteamTabChanged(int value)
    {
        OnPropertyChanged(nameof(IsSteamTab0));
        OnPropertyChanged(nameof(IsSteamTab1));
        OnPropertyChanged(nameof(IsSteamTab2));
        RebuildSteamShelf();
    }

    [RelayCommand]
    private void SetSteamTab(int tab)
    {
        _steamZone = SteamZone.Tabs;
        SteamTab = Math.Clamp(tab, 0, SteamTabCount - 1);
        ApplySteamFocus();
    }

    [RelayCommand]
    private void OpenSteamTile(SteamDashboardNewsTileVm? tile)
    {
        if (tile == null) return;
        switch (tile.Action)
        {
            case "store": if (tile.Store != null) OnOpenStoreDetail?.Invoke(tile.Store); break;
            case "library": NavigateToAllGames(); break;
            case "media": OnNavigateToMediaSection?.Invoke("movies"); break;
            case "profile":
            case "friends":
            case "inbox":
                OnNavigateToPage?.Invoke(tile.Action); break;
        }
    }

    private void RebuildSteamShelf()
    {
        SteamShelfTiles.Clear();
        switch (SteamTab)
        {
            case 0:
                SteamShelfTitle = "What's new";
                foreach (var t in SteamNewsTiles) SteamShelfTiles.Add(t);
                break;
            case 1:
                SteamShelfTitle = OnlineFriends.Count > 0 ? "Friends online" : "Friends";
                foreach (var f in OnlineFriends.Take(SteamShelfSize))
                    SteamShelfTiles.Add(new SteamDashboardNewsTileVm
                    {
                        Category = f.IsPlaying ? "IN GAME" : "ONLINE",
                        Title = f.Username,
                        Subtitle = f.StatusLabel,
                        Meta = "FRIEND",
                        CoverGradient = f.IsPlaying ? "#1f4d2b,#0f2233" : "#1c3c52,#0f2233",
                        Action = "friends",
                    });
                if (SteamShelfTiles.Count == 0)
                    SteamShelfTiles.Add(new SteamDashboardNewsTileVm
                    {
                        Category = "FRIENDS",
                        Title = "No friends online",
                        Subtitle = "Open the friends page to invite someone.",
                        Meta = "SOCIAL",
                        CoverGradient = "#1c3c52,#0f2233",
                        Action = "friends",
                    });
                break;
            default:
                SteamShelfTitle = "Recommended for you";
                try
                {
                    var owned = _libraryGames.Select(g => (g.Platform, g.Title, g.Genre))
                        .Concat(RecentLocalGames.Select(c => (c.Platform, c.EffectiveTitle, "")));
                    foreach (var g in StoreRecommendations.ForUser(StoreCatalog(), owned, SteamShelfSize))
                        SteamShelfTiles.Add(new SteamDashboardNewsTileVm
                        {
                            Category = g.Platform.ToUpperInvariant(),
                            Title = g.Title,
                            Subtitle = g.Genre ?? "",
                            Meta = g.Price ?? "",
                            CoverUrl = g.CoverUrl,
                            CoverGradient = g.CoverGradient ?? "#0d2137,#163d5e",
                            Action = "store",
                            Store = g,
                        });
                }
                catch (Exception ex) { DevLogService.Log($"[Dashboard] Steam recommendations failed: {ex.Message}"); }
                break;
        }
        HasSteamShelf = SteamShelfTiles.Count > 0;
        _steamShelfIdx = Math.Clamp(_steamShelfIdx, 0, Math.Max(0, SteamShelfTiles.Count - 1));
        if (_steamZone == SteamZone.Shelf && !HasSteamShelf) _steamZone = SteamZone.Tabs;
        ApplySteamFocus();
    }

    private int SteamHeroSlots => Options.ShowFeatured ? 1 : 0;
    private int SteamSideCount => Options.ShowRecent ? SteamRecentSideGames.Count : 0;
    private int SteamGameCount => SteamHeroSlots + SteamSideCount;
    private bool SteamIdxIsHero => SteamHeroSlots == 1 && _steamGameIdx == 0;
    private int SteamSideIdx => _steamGameIdx - SteamHeroSlots;

    /// <summary>Highlights the hero so the dashboard never opens without a visible selection.</summary>
    private void ResetSteamFocus()
    {
        _steamZone = SteamZone.Games;
        _steamGameIdx = 0;
        _steamShelfIdx = 0;
        RebuildSteamShelf();
    }

    private void ClampSteamFocus()
    {
        _steamGameIdx = Math.Clamp(_steamGameIdx, 0, Math.Max(0, SteamGameCount - 1));
        if (_steamZone == SteamZone.Tabs && !Options.ShowTabs) _steamZone = SteamZone.Games;
        ApplySteamFocus();
    }

    private void ApplySteamFocus()
    {
        IsSteamHeroFocused = _steamZone == SteamZone.Games && SteamIdxIsHero;
        for (int i = 0; i < SteamRecentSideGames.Count; i++)
            SteamRecentSideGames[i].IsSteamFocused = _steamZone == SteamZone.Games && !SteamIdxIsHero && SteamSideIdx == i;
        IsSteamTabsFocused = _steamZone == SteamZone.Tabs;
        for (int i = 0; i < SteamShelfTiles.Count; i++)
            SteamShelfTiles[i].IsFocused = _steamZone == SteamZone.Shelf && _steamShelfIdx == i;
        SteamFocusChanged?.Invoke();
    }

    private void SteamEnterTabsOrShelf()
    {
        if (Options.ShowTabs) _steamZone = SteamZone.Tabs;
        else if (HasSteamShelf) _steamZone = SteamZone.Shelf;
    }

    /// <summary>
    /// Handles a D-pad / A / X / Y / bumper press on the Steam dashboard. <paramref name="openNav"/> is called when
    /// Left is pressed at the left edge. Returns true when the key was consumed.
    /// </summary>
    public bool HandleSteamKey(Key key, Action openNav)
    {
        if (key == Key.PageUp || key == Key.PageDown)
        {
            if (!Options.ShowTabs) return true;
            SteamTab = Math.Clamp(SteamTab + (key == Key.PageDown ? 1 : -1), 0, SteamTabCount - 1);
            ApplySteamFocus();
            return true;
        }

        switch (_steamZone)
        {
            case SteamZone.Games:
                switch (key)
                {
                    case Key.Left:
                        if (_steamGameIdx <= 0) openNav(); else _steamGameIdx--;
                        break;
                    case Key.Right: _steamGameIdx = Math.Clamp(_steamGameIdx + 1, 0, Math.Max(0, SteamGameCount - 1)); break;
                    case Key.Down: SteamEnterTabsOrShelf(); break;
                    case Key.Up: break;
                    case Key.Enter:
                        if (SteamIdxIsHero) OpenFeaturedDetail();
                        else if (SteamSideIdx >= 0 && SteamSideIdx < SteamSideCount)
                            OnOpenLocalDetail?.Invoke(SteamRecentSideGames[SteamSideIdx]);
                        break;
                    case Key.X:
                        if (SteamIdxIsHero) ContinuePlaying();
                        else if (SteamSideIdx >= 0 && SteamSideIdx < SteamSideCount)
                            OnPlayFocusedCard?.Invoke(SteamRecentSideGames[SteamSideIdx]);
                        break;
                    case Key.Y: NavigateToAllGames(); break;
                    default: return false;
                }
                break;

            case SteamZone.Tabs:
                switch (key)
                {
                    case Key.Left:
                        if (SteamTab == 0) openNav(); else SteamTab--;
                        break;
                    case Key.Right: SteamTab = Math.Min(SteamTab + 1, SteamTabCount - 1); break;
                    case Key.Up: _steamZone = SteamZone.Games; break;
                    case Key.Down:
                    case Key.Enter:
                        if (HasSteamShelf) _steamZone = SteamZone.Shelf;
                        break;
                    case Key.Y: NavigateToAllGames(); break;
                    default: return false;
                }
                break;

            default:
                switch (key)
                {
                    case Key.Left:
                        if (_steamShelfIdx == 0) openNav(); else _steamShelfIdx--;
                        break;
                    case Key.Right: _steamShelfIdx = Math.Min(_steamShelfIdx + 1, SteamShelfTiles.Count - 1); break;
                    case Key.Up: _steamZone = Options.ShowTabs ? SteamZone.Tabs : SteamZone.Games; break;
                    case Key.Down: break;
                    case Key.Enter:
                    case Key.X:
                        if (_steamShelfIdx < SteamShelfTiles.Count) OpenSteamTile(SteamShelfTiles[_steamShelfIdx]);
                        break;
                    case Key.Y: NavigateToAllGames(); break;
                    default: return false;
                }
                break;
        }
        ApplySteamFocus();
        return true;
    }
}
