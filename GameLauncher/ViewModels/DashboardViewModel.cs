using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

public partial class DashboardViewModel : ViewModelBase
{
    [ObservableProperty] private UserProfile _profile = new();
    [ObservableProperty] private string _greeting = "";
    [ObservableProperty] private int _gamesCount;
    [ObservableProperty] private int _achievementsCount;
    [ObservableProperty] private int _platformsCount;

    // Hero featured game
    [ObservableProperty] private StoreGame? _featuredGame;
    [ObservableProperty] private string     _featuredGradient = "#1a1a2e,#16213e";

    // Recently added
    public ObservableCollection<Game> RecentGames { get; } = new();

    // Recent achievements
    public ObservableCollection<Achievement> RecentAchievements { get; } = new();

    /// <summary>Invoked when the user clicks a game card to open the detail overlay.</summary>
    public Action<Game>?      OnOpenDetail      { get; set; }
    public Action<StoreGame>? OnOpenStoreDetail { get; set; }

    public void Load(UserProfile profile, List<Game> library, List<Achievement> achievements)
    {
        Profile           = profile;
        GamesCount        = library.Count;
        AchievementsCount = achievements.Count;
        PlatformsCount    = library.Select(g => g.Platform).Distinct().Count();

        string hour = System.DateTime.Now.Hour switch
        {
            < 12 => "Good morning",
            < 17 => "Good afternoon",
            _    => "Good evening"
        };
        Greeting = $"{hour}, {profile.Username}!";

        RecentGames.Clear();
        foreach (var g in library.OrderByDescending(g => g.AddedAt).Take(8))
            RecentGames.Add(g);

        RecentAchievements.Clear();
        foreach (var a in achievements.OrderByDescending(a => a.UnlockedAt).Take(4))
            RecentAchievements.Add(a);

        // Featured — pick the highest-rated store game
        FeaturedGame = DemoData.Store.OrderByDescending(s => s.Rating).FirstOrDefault();
        if (FeaturedGame != null)
            FeaturedGradient = FeaturedGame.CoverGradient;
    }

    [RelayCommand]
    private void OpenGameDetail(Game? game)
    {
        if (game != null) OnOpenDetail?.Invoke(game);
    }

    [RelayCommand]
    private void OpenFeaturedDetail()
    {
        if (FeaturedGame != null) OnOpenStoreDetail?.Invoke(FeaturedGame);
    }
}
