using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

public partial class ProfileViewModel : ViewModelBase
{
    [ObservableProperty] private string _username        = "";
    [ObservableProperty] private string _email           = "";
    [ObservableProperty] private string _memberSince     = "";
    [ObservableProperty] private int    _gamesCount;
    [ObservableProperty] private int    _achievementsCount;
    [ObservableProperty] private string _avatarInitial   = "?";
    [ObservableProperty] private string _modeBadge       = "Demo";
    [ObservableProperty] private bool   _isLiveMode      = false;

    public ObservableCollection<Achievement> AllAchievements { get; } = new();

    public void Load(UserProfile profile, List<Game> library,
                     List<Achievement> achievements, bool demoMode)
    {
        Username          = profile.Username;
        Email             = profile.Email;
        GamesCount        = library.Count;
        AchievementsCount = achievements.Count;
        AvatarInitial     = profile.Username.Length > 0
            ? profile.Username[0].ToString().ToUpper() : "?";
        ModeBadge = demoMode ? "DEMO" : "LIVE";
        IsLiveMode = !demoMode;

        if (System.DateTimeOffset.TryParse(profile.CreatedAt, out var dt))
            MemberSince = dt.ToString("dd MMMM yyyy");
        else
            MemberSince = profile.CreatedAt;

        AllAchievements.Clear();
        foreach (var a in achievements.OrderByDescending(a => a.UnlockedAt))
            AllAchievements.Add(a);
    }
}
