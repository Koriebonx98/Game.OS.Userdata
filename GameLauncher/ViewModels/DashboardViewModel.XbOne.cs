using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;

namespace GameLauncher.ViewModels;

/// <summary>
/// "XBOne" dashboard: the Xbox One tile home screen. It reuses the Kinetic tile mosaic, tab row and
/// controller navigation (HandleKineticKey) but with its own pivots and tiles, including a Settings pivot.
/// </summary>
public partial class DashboardViewModel
{
    private static readonly (string Key, string Title)[] KineticDefaultTabs =
    {
        ("home", "home"), ("social", "social"), ("games", "games"), ("tv", "tv & movies"),
        ("music", "music"), ("apps", "apps"), ("settings", "settings"),
    };

    private static readonly (string Key, string Title)[] XbOneTabs =
    {
        ("pins", "Pins"), ("home", "Home"), ("friends", "Friends"), ("media", "What's on"), ("store", "Store"), ("settings", "Settings"),
    };

    /// <summary>True on the Home pivot, which also shows the Featured and Friends columns.</summary>
    [ObservableProperty] private bool _xbOneHomeActive;

    private string _kineticDesign = "";

    /// <summary>Opens Settings on the given section (app, design, controller, …); wired by MainViewModel.</summary>
    public Action<string>? OnOpenSettingsSection { get; set; }

    private void SyncKineticTabs()
    {
        _kineticDesign = Options.Design;
        var wanted = Options.IsXbOne ? XbOneTabs : KineticDefaultTabs;
        if (KineticTabs.Select(t => t.Key).SequenceEqual(wanted.Select(w => w.Key))) return;
        KineticTabs.Clear();
        foreach (var (key, title) in wanted) KineticTabs.Add(new KineticTabVm { Key = key, Title = title });
        KineticTabIndex = Options.IsXbOne ? 1 : 0;
    }

    private KineticTileVm SettingsTile(int col, int row, string title, string glyph, string section) =>
        new() { Col = col, Row = row, ColSpan = 1, RowSpan = 1, Title = title, Glyph = glyph,
                Action = () => OnOpenSettingsSection?.Invoke(section) };

    private KineticTileVm Cell(int col, int row, string title, string glyph, string page) => Page(col, row, 1, 1, title, glyph, page);

    private List<KineticTileVm> BuildXbOneTiles(string tab)
    {
        var list = new List<KineticTileVm>();
        var recent = RecentLocalGames.ToList();
        XbOneHomeActive = tab == "home";
        switch (tab)
        {
            case "home":
                if (recent.Count > 0) list.Add(GameTile(0, 0, 4, 2, recent[0], recent[0].EffectiveTitle));
                else list.Add(Page(0, 0, 4, 2, "My games & apps", "▦", "library", $"{GamesCount} games"));
                list.Add(Cell(4, 0, "Browser", "🌐", "browser"));
                list.Add(Cell(4, 1, "My games & apps", "▦", "library"));
                list.Add(Cell(0, 2, "Media Player", "🎬", "media"));
                list.Add(new KineticTileVm { Col = 1, Row = 2, Title = "Settings", Glyph = "⚙",
                    Action = () => OnNavigateToPage?.Invoke("settings") });
                if (recent.Count > 1) list.Add(GameTile(2, 2, 1, 1, recent[1]));
                else list.Add(Cell(2, 2, "Downloads", "⬇", "downloads"));
                if (recent.Count > 2) list.Add(GameTile(3, 2, 1, 1, recent[2]));
                else list.Add(Cell(3, 2, "Achievements", "🏆", "profile"));
                list.Add(Cell(4, 2, "Downloads", "⬇", "downloads"));
                if (FeaturedGame != null)
                    list.Add(new KineticTileVm
                    {
                        Col = 5, Row = 0, Title = IsFeaturedLastPlayed ? "Continue " + FeaturedGame.Title : FeaturedGame.Title,
                        CoverUrl = FeaturedGame.CoverUrl, CoverGradient = FeaturedGame.CoverGradient ?? FeaturedGradient, Glyph = "🎮",
                        Action = () => { if (IsFeaturedLastPlayed) ContinuePlayingCommand.Execute(null); else OpenFeaturedDetailCommand.Execute(null); },
                    });
                else list.Add(Cell(5, 0, "Find your next game", "🛍", "store"));
                if (recent.Count > 3) list.Add(GameTile(5, 1, 1, 1, recent[3]));
                else list.Add(Cell(5, 1, "Store", "🛍", "store"));
                list.Add(Page(5, 2, 1, 1, "Achievements", "🏆", "profile", $"{AchievementsCount} unlocked"));
                list.Add(Page(6, 0, 1, 1, "Friends", "👥", "friends", "See who is online"));
                list.Add(Page(6, 1, 1, 2, Profile.Username, "🙂", "profile", "Home"));
                break;

            case "pins":
                var games = LocalLibraryGames.Take(8).ToList();
                int[][] slots = { new[]{0,0,4,2}, new[]{4,0,1,1}, new[]{4,1,1,1}, new[]{0,2,1,1}, new[]{1,2,1,1}, new[]{2,2,1,1}, new[]{3,2,1,1}, new[]{4,2,1,1} };
                for (int i = 0; i < games.Count; i++)
                    list.Add(GameTile(slots[i][0], slots[i][1], slots[i][2], slots[i][3], games[i]));
                if (games.Count == 0) list.Add(Page(0, 0, 2, 1, "My games & apps", "▦", "library", $"{GamesCount} games"));
                break;

            case "friends":
                list.Add(Page(0, 0, 2, 2, "Friends", "👥", "friends", "See who is online"));
                list.Add(Page(2, 0, 2, 2, "Messages", "✉", "inbox", "Messages and invites"));
                list.Add(Page(4, 0, 1, 2, "Profile", "🙂", "profile"));
                list.Add(Page(0, 2, 2, 1, "Achievements", "🏆", "profile", $"{AchievementsCount} unlocked"));
                break;

            case "media":
                list.Add(new KineticTileVm { Col = 0, Row = 0, ColSpan = 2, RowSpan = 2, Title = "Movies", Glyph = "🎬",
                    Action = () => OnNavigateToMediaSection?.Invoke("movies") });
                list.Add(new KineticTileVm { Col = 2, Row = 0, ColSpan = 2, RowSpan = 2, Title = "TV Shows", Glyph = "📺",
                    Action = () => OnNavigateToMediaSection?.Invoke("tvshows") });
                list.Add(new KineticTileVm { Col = 4, Row = 0, ColSpan = 1, RowSpan = 2, Title = "Music", Glyph = "🎵",
                    Action = () => OnNavigateToMediaSection?.Invoke("music") });
                break;

            case "store":
                if (FeaturedGame != null)
                    list.Add(new KineticTileVm
                    {
                        Col = 0, Row = 0, ColSpan = 4, RowSpan = 2, Title = FeaturedGame.Title,
                        CoverUrl = FeaturedGame.CoverUrl, CoverGradient = FeaturedGame.CoverGradient ?? FeaturedGradient, Glyph = "🎮",
                        Action = () => OpenFeaturedDetailCommand.Execute(null),
                    });
                else list.Add(Page(0, 0, 4, 2, "Store", "🛍", "store", "Find your next game"));
                list.Add(Cell(4, 0, "Store", "🛍", "store"));
                list.Add(Cell(4, 1, "Downloads", "⬇", "downloads"));
                break;

            default:
                var sections = new (string Title, string Glyph, string Section)[]
                {
                    ("General", "⚙", "app"), ("Account", "🙂", "account"), ("Design", "🎨", "design"),
                    ("Customise", "🖌", "customise"), ("Library", "▦", "design"), ("Controller", "🎮", "controller"),
                    ("Notifications", "🔔", "notifications"), ("Downloads", "⬇", "downloads"), ("Media", "🎬", "media"),
                    ("Emulators", "🕹", "emulator"), ("Sync", "☁", "sync"), ("System", "🖥", "system"),
                    ("Browser", "🌐", "browser"),
                };
                for (int i = 0; i < sections.Length; i++)
                    list.Add(SettingsTile(i % 5, i / 5, sections[i].Title, sections[i].Glyph, sections[i].Section));
                break;
        }
        return list;
    }
}
