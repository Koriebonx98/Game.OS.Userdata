using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

public partial class DashboardViewModel : ViewModelBase
{
    [ObservableProperty] private UserProfile _profile = new();
    [ObservableProperty] private string _greeting = "";
    [ObservableProperty] private int _gamesCount;
    [ObservableProperty] private int _achievementsCount;
    [ObservableProperty] private int _platformsCount;
    [ObservableProperty] private string _totalPlaytimeLabel = "";

    // Hero featured game
    [ObservableProperty] private StoreGame? _featuredGame;
    [ObservableProperty] private string     _featuredGradient = "#1a1a2e,#16213e";

    // Recently added / played (cloud + local combined)
    public ObservableCollection<Game> RecentGames { get; } = new();
    /// <summary>True when there are recently detected local ROMs or installed games to show.</summary>
    [ObservableProperty] private bool _hasRecentLocalGames;
    public ObservableCollection<LocalGameCardVm> RecentLocalGames { get; } = new();

    // Recent achievements
    public ObservableCollection<Achievement> RecentAchievements { get; } = new();

    /// <summary>Invoked when the user clicks a game card to open the detail overlay.</summary>
    public Action<Game>?            OnOpenDetail        { get; set; }
    public Action<StoreGame>?       OnOpenStoreDetail   { get; set; }
    public Action<LocalGameCardVm>? OnOpenLocalDetail   { get; set; }

    public void Load(UserProfile profile, List<Game> library, List<Achievement> achievements,
                     IReadOnlyList<LocalGameCardVm>? localCards = null)
    {
        Profile           = profile;
        GamesCount        = library.Count;
        AchievementsCount = achievements.Count;
        PlatformsCount    = library.Select(g => g.Platform).Distinct().Count();

        // Total playtime across all games — show days/hours/minutes breakdown
        int totalMinutes = library.Sum(g => g.PlaytimeMinutes);
        if (totalMinutes <= 0)
        {
            TotalPlaytimeLabel = "0m";
        }
        else
        {
            int days  = totalMinutes / 1440;
            int hours = (totalMinutes % 1440) / 60;
            int mins  = totalMinutes % 60;
            if (days > 0)
                TotalPlaytimeLabel = mins > 0 ? $"{days}d {hours}h {mins}m" : $"{days}d {hours}h";
            else if (hours > 0)
                TotalPlaytimeLabel = mins > 0 ? $"{hours}h {mins}m" : $"{hours}h";
            else
                TotalPlaytimeLabel = $"{mins}m";
        }

        string hour = System.DateTime.Now.Hour switch
        {
            < 12 => "Good morning",
            < 17 => "Good afternoon",
            _    => "Good evening"
        };
        Greeting = $"{hour}, {profile.Username}!";

        // Recently Played — only games that have actually been played (have LastPlayedAt set)
        // Parse ISO 8601 strings to DateTime for correct chronological comparison.
        static DateTime ParseDate(string? s) =>
            DateTime.TryParse(s, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt)
                ? dt : DateTime.MinValue;

        RecentGames.Clear();
        var recentlyPlayed = library
            .Where(g => !string.IsNullOrEmpty(g.LastPlayedAt))
            .OrderByDescending(g => ParseDate(g.LastPlayedAt))
            .Take(8)
            .ToList();
        foreach (var g in recentlyPlayed)
            RecentGames.Add(g);

        RecentAchievements.Clear();
        foreach (var a in achievements.OrderByDescending(a => ParseDate(a.UnlockedAt)).Take(4))
            RecentAchievements.Add(a);

        // Continue Playing — local games/ROMs that have recorded playtime OR are actively running now
        RecentLocalGames.Clear();
        if (localCards != null)
        {
            foreach (var c in localCards
                .Where(c => PlaytimeService.GetTotalMinutes(c.Platform, c.EffectiveTitle) > 0
                         || PlaytimeService.IsBeingTracked(c.Platform, c.EffectiveTitle))
                .OrderByDescending(c => PlaytimeService.IsBeingTracked(c.Platform, c.EffectiveTitle) ? int.MaxValue
                                       : PlaytimeService.GetTotalMinutes(c.Platform, c.EffectiveTitle))
                .Take(8))
            {
                // Show "▶ Playing now" for active sessions, otherwise show accumulated time
                if (PlaytimeService.IsBeingTracked(c.Platform, c.EffectiveTitle))
                    c.PlaytimeLabel = "▶ Playing now";
                else
                {
                    int mins = PlaytimeService.GetTotalMinutes(c.Platform, c.EffectiveTitle);
                    c.PlaytimeLabel = FormatMinutes(mins);
                }
                RecentLocalGames.Add(c);
            }
        }
        HasRecentLocalGames = RecentLocalGames.Count > 0;

        // Featured — pick the highest-rated store game (same static catalog as script.js)
        FeaturedGame = GameCatalog.Store.OrderByDescending(s => s.Rating).FirstOrDefault();
        if (FeaturedGame != null)
            FeaturedGradient = FeaturedGame.CoverGradient;
    }

    // Keep the original 3-arg overload for backwards compatibility with existing callers.
    public void Load(UserProfile profile, List<Game> library, List<Achievement> achievements)
        => Load(profile, library, achievements, null);

    [RelayCommand]
    private void OpenGameDetail(Game? game)
    {
        if (game != null) OnOpenDetail?.Invoke(game);
    }

    [RelayCommand]
    private void OpenLocalGameDetail(LocalGameCardVm? card)
    {
        if (card != null) OnOpenLocalDetail?.Invoke(card);
    }

    [RelayCommand]
    private void OpenFeaturedDetail()
    {
        if (FeaturedGame != null) OnOpenStoreDetail?.Invoke(FeaturedGame);
    }

    private static string FormatMinutes(int minutes)
    {
        if (minutes <= 0) return "";
        int days  = minutes / 1440;
        int hours = (minutes % 1440) / 60;
        int mins  = minutes % 60;
        if (days > 0)
            return mins > 0 ? $"{days}d {hours}h {mins}m" : $"{days}d {hours}h";
        if (hours > 0)
            return mins > 0 ? $"{hours}h {mins}m" : $"{hours}h";
        return $"{mins}m";
    }
}
