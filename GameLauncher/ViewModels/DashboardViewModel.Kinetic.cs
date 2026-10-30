using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace GameLauncher.ViewModels;

/// <summary>One tile of the XB360 "Kinetic" mosaic. Position is in grid cells.</summary>
public partial class KineticTileVm : ObservableObject
{
    public string Title { get; init; } = "";
    public string Subtitle { get; init; } = "";
    public string Glyph { get; init; } = "";
    public string? CoverUrl { get; init; }
    public string? CoverGradient { get; init; }
    public int Col { get; init; }
    public int Row { get; init; }
    public int ColSpan { get; init; } = 1;
    public int RowSpan { get; init; } = 1;
    public Action? Action { get; init; }
    public bool HasCover => !string.IsNullOrEmpty(CoverUrl) || !string.IsNullOrEmpty(CoverGradient);
    public bool IsSolid => !HasCover;
    [ObservableProperty] private bool _isFocused;
    public ICommand ActivateCommand => new RelayCommand(() => Action?.Invoke());
}

/// <summary>One header tab ("home", "social", …) of the Kinetic dashboard.</summary>
public partial class KineticTabVm : ObservableObject
{
    public string Key { get; init; } = "";
    public string Title { get; init; } = "";
    [ObservableProperty] private bool _isActive;
}

public enum KineticKeyResult { NotHandled, Handled, OpenNav }

public partial class DashboardViewModel
{
    public ObservableCollection<KineticTabVm> KineticTabs { get; } = new(new[]
    {
        new KineticTabVm { Key = "home", Title = "home" },
        new KineticTabVm { Key = "social", Title = "social" },
        new KineticTabVm { Key = "games", Title = "games" },
        new KineticTabVm { Key = "tv", Title = "tv & movies" },
        new KineticTabVm { Key = "music", Title = "music" },
        new KineticTabVm { Key = "apps", Title = "apps" },
        new KineticTabVm { Key = "settings", Title = "settings" },
    });

    /// <summary>Tiles of the active tab.</summary>
    public ObservableCollection<KineticTileVm> KineticTiles { get; } = new();

    [ObservableProperty] private int _kineticTabIndex;
    [ObservableProperty] private int _kineticTileIndex = -1;
    /// <summary>True while the header (tab row) has the controller focus.</summary>
    [ObservableProperty] private bool _kineticInHeader;

    [RelayCommand]
    private void SelectKineticTab(KineticTabVm? tab)
    {
        if (tab == null) return;
        KineticTabIndex = Math.Max(0, KineticTabs.IndexOf(tab));
        KineticInHeader = true;
        RebuildKineticTiles();
    }

    /// <summary>Rebuilds the active tab's tiles from the current library / profile data.</summary>
    public void RebuildKineticTiles()
    {
        for (int i = 0; i < KineticTabs.Count; i++) KineticTabs[i].IsActive = i == KineticTabIndex;
        KineticTiles.Clear();
        foreach (var t in BuildKineticTiles(KineticTabs[Math.Clamp(KineticTabIndex, 0, KineticTabs.Count - 1)].Key))
            KineticTiles.Add(t);
        KineticTileIndex = -1;
        if (!KineticInHeader && KineticTiles.Count > 0) SetKineticTile(0);
    }

    private KineticTileVm Page(int col, int row, int cs, int rs, string title, string glyph, string page, string sub = "") =>
        new() { Col = col, Row = row, ColSpan = cs, RowSpan = rs, Title = title, Glyph = glyph, Subtitle = sub,
                Action = () => OnNavigateToPage?.Invoke(page) };

    private KineticTileVm GameTile(int col, int row, int cs, int rs, LocalGameCardVm c, string? caption = null) =>
        new() { Col = col, Row = row, ColSpan = cs, RowSpan = rs, Title = caption ?? c.EffectiveTitle, Subtitle = c.Platform,
                CoverUrl = c.CoverUrl, CoverGradient = c.CoverGradient, Glyph = "🎮",
                Action = () => OnOpenLocalDetail?.Invoke(c) };

    private List<KineticTileVm> BuildKineticTiles(string tab)
    {
        var list = new List<KineticTileVm>();
        var recent = RecentLocalGames.ToList();
        switch (tab)
        {
            case "home":
                if (recent.Count > 0) list.Add(GameTile(0, 0, 2, 1, recent[0], "Play " + recent[0].EffectiveTitle));
                list.Add(Page(0, 1, 2, 1, "My Library", "📌", "library"));
                list.Add(Page(0, 2, 2, 1, "Achievements", "🏆", "profile", $"{AchievementsCount} unlocked"));
                if (FeaturedGame != null)
                    list.Add(new KineticTileVm
                    {
                        Col = 2, Row = 0, ColSpan = 4, RowSpan = 2,
                        Title = IsFeaturedLastPlayed ? "Continue " + FeaturedGame.Title : FeaturedGame.Title,
                        Subtitle = FeaturedGame.Platform,
                        CoverUrl = FeaturedGame.CoverUrl, CoverGradient = FeaturedGame.CoverGradient ?? FeaturedGradient,
                        Glyph = "🎮",
                        Action = () =>
                        {
                            if (IsFeaturedLastPlayed) ContinuePlayingCommand.Execute(null);
                            else OpenFeaturedDetailCommand.Execute(null);
                        },
                    });
                else
                    list.Add(Page(2, 0, 4, 2, "Store", "🛍", "store", "Find your next game"));
                list.Add(Page(6, 0, 2, 1, "Store", "🛍", "store"));
                list.Add(Page(6, 1, 2, 1, "Friends", "👥", "friends"));
                if (recent.Count > 1) list.Add(GameTile(2, 2, 2, 1, recent[1]));
                else list.Add(Page(2, 2, 2, 1, "All Games", "▦", "library"));
                if (recent.Count > 2) list.Add(GameTile(4, 2, 2, 1, recent[2]));
                else list.Add(Page(4, 2, 2, 1, "Inbox", "✉", "inbox"));
                list.Add(Page(6, 2, 2, 1, "Inbox", "✉", "inbox"));
                break;

            case "social":
                list.Add(Page(0, 0, 3, 2, "Friends", "👥", "friends", "See who is online"));
                list.Add(Page(3, 0, 3, 2, "Inbox", "✉", "inbox", "Messages and invites"));
                list.Add(Page(6, 0, 2, 2, "My Profile", "🙂", "profile"));
                break;

            case "games":
                list.Add(Page(0, 0, 2, 1, "My Library", "📌", "library"));
                list.Add(Page(0, 1, 2, 1, "Store", "🛍", "store"));
                var games = LocalLibraryGames.Take(7).ToList();
                int[][] slots = { new[]{2,0,2,2}, new[]{4,0,2,1}, new[]{6,0,2,1}, new[]{4,1,2,1}, new[]{6,1,2,1}, new[]{2,2,2,1}, new[]{4,2,2,1} };
                for (int i = 0; i < games.Count; i++)
                    list.Add(GameTile(slots[i][0], slots[i][1], slots[i][2], slots[i][3], games[i]));
                list.Add(Page(0, 2, 2, 1, "All Games", "▦", "library", $"{GamesCount} games"));
                break;

            case "tv":
                list.Add(new KineticTileVm { Col = 0, Row = 0, ColSpan = 4, RowSpan = 2, Title = "Movies", Glyph = "🎬",
                    Subtitle = "Browse your movie collection", Action = () => OnNavigateToMediaSection?.Invoke("movies") });
                list.Add(new KineticTileVm { Col = 4, Row = 0, ColSpan = 4, RowSpan = 2, Title = "TV Shows", Glyph = "📺",
                    Subtitle = "Browse your TV show collection", Action = () => OnNavigateToMediaSection?.Invoke("tvshows") });
                break;

            case "music":
                list.Add(new KineticTileVm { Col = 0, Row = 0, ColSpan = 4, RowSpan = 2, Title = "Music", Glyph = "🎵",
                    Subtitle = "Play your music library", Action = () => OnNavigateToMediaSection?.Invoke("music") });
                break;

            case "apps":
                list.Add(Page(0, 0, 2, 1, "Store", "🛍", "store"));
                list.Add(Page(2, 0, 2, 1, "Achievements", "🏆", "profile"));
                list.Add(Page(4, 0, 2, 1, "Friends", "👥", "friends"));
                list.Add(Page(0, 1, 2, 1, "Inbox", "✉", "inbox"));
                list.Add(Page(2, 1, 2, 1, "Library", "▦", "library"));
                break;

            default:
                list.Add(Page(0, 0, 4, 1, "Settings", "⚙", "settings", "Configure the launcher"));
                list.Add(Page(0, 1, 4, 1, "Design", "🎨", "settings", "Dashboard version, colours and layout"));
                list.Add(new KineticTileVm { Col = 4, Row = 0, ColSpan = 2, RowSpan = 2, Title = $"{GamesCount} Games",
                    Glyph = "🎮", Subtitle = "in your library", Action = () => OnNavigateToPage?.Invoke("library") });
                break;
        }
        return list;
    }

    private void SetKineticTile(int index)
    {
        foreach (var t in KineticTiles) t.IsFocused = false;
        KineticTileIndex = index;
        if (index >= 0 && index < KineticTiles.Count) KineticTiles[index].IsFocused = true;
    }

    private void FocusKineticHeader(bool on)
    {
        KineticInHeader = on;
        if (on) SetKineticTile(-1);
        else if (KineticTiles.Count > 0) SetKineticTile(Math.Max(0, KineticTileIndex));
    }

    /// <summary>D-pad / A handling for the Kinetic dashboard (shared by keyboard and controller).</summary>
    public KineticKeyResult HandleKineticKey(string key)
    {
        if (KineticTiles.Count == 0 && KineticTabs.All(t => !t.IsActive)) RebuildKineticTiles();

        if (KineticInHeader)
        {
            switch (key)
            {
                case "Left":
                    if (KineticTabIndex == 0) return KineticKeyResult.OpenNav;
                    KineticTabIndex--; RebuildKineticTiles(); return KineticKeyResult.Handled;
                case "Right":
                    if (KineticTabIndex < KineticTabs.Count - 1) { KineticTabIndex++; RebuildKineticTiles(); }
                    return KineticKeyResult.Handled;
                case "Down":
                case "Enter":
                    if (KineticTiles.Count > 0) FocusKineticHeader(false);
                    return KineticKeyResult.Handled;
                case "Up":
                    return KineticKeyResult.Handled;
            }
            return KineticKeyResult.NotHandled;
        }

        if (key == "Enter")
        {
            if (KineticTileIndex >= 0 && KineticTileIndex < KineticTiles.Count) KineticTiles[KineticTileIndex].Action?.Invoke();
            return KineticKeyResult.Handled;
        }
        if (key is not ("Left" or "Right" or "Up" or "Down")) return KineticKeyResult.NotHandled;

        if (KineticTileIndex < 0) { FocusKineticHeader(KineticTiles.Count == 0); if (KineticTiles.Count > 0) SetKineticTile(0); return KineticKeyResult.Handled; }

        var cur = KineticTiles[KineticTileIndex];
        double cx = cur.Col + cur.ColSpan / 2.0, cy = cur.Row + cur.RowSpan / 2.0;
        int best = -1; double bestScore = double.MaxValue;
        for (int i = 0; i < KineticTiles.Count; i++)
        {
            if (i == KineticTileIndex) continue;
            var t = KineticTiles[i];
            double tx = t.Col + t.ColSpan / 2.0, ty = t.Row + t.RowSpan / 2.0;
            double dx = tx - cx, dy = ty - cy, main, cross;
            switch (key)
            {
                case "Left":  main = -dx; cross = Math.Abs(dy); break;
                case "Right": main = dx;  cross = Math.Abs(dy); break;
                case "Up":    main = -dy; cross = Math.Abs(dx); break;
                default:      main = dy;  cross = Math.Abs(dx); break;
            }
            if (main <= 0.01) continue;
            double score = main + cross * 2;
            if (score < bestScore) { bestScore = score; best = i; }
        }

        if (best >= 0) { SetKineticTile(best); return KineticKeyResult.Handled; }
        if (key == "Up") { FocusKineticHeader(true); return KineticKeyResult.Handled; }
        if (key == "Left") return KineticKeyResult.OpenNav;
        return KineticKeyResult.Handled;
    }
}
