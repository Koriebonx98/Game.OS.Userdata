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
    [ObservableProperty] private string _modeBadge       = "LIVE";
    [ObservableProperty] private bool   _isAdmin         = false;

    public ObservableCollection<Achievement> AllAchievements { get; } = new();

    public void Load(UserProfile profile, List<Game> library,
                     List<Achievement> achievements, bool isAdmin)
    {
        Username          = profile.Username;
        Email             = profile.Email;
        GamesCount        = library.Count;
        AchievementsCount = achievements.Count;
        AvatarInitial     = profile.Username.Length > 0
            ? profile.Username[0].ToString().ToUpper() : "?";
        IsAdmin   = isAdmin;
        ModeBadge = isAdmin ? "ADMIN" : "LIVE";

        if (System.DateTimeOffset.TryParse(profile.CreatedAt, out var dt))
            MemberSince = dt.ToString("dd MMMM yyyy");
        else
            MemberSince = profile.CreatedAt;

        AllAchievements.Clear();
        foreach (var a in achievements.OrderByDescending(a => a.UnlockedAt))
            AllAchievements.Add(a);
    }

    /// <summary>
    /// Loads a placeholder state while the real profile data is being fetched.
    /// Called immediately when opening a friend's profile so something shows right away.
    /// </summary>
    public void LoadPlaceholder(string username)
    {
        Username          = username;
        Email             = "";
        GamesCount        = 0;
        AchievementsCount = 0;
        AvatarInitial     = username.Length > 0 ? username[0].ToString().ToUpper() : "?";
        IsAdmin           = false;
        ModeBadge         = "LIVE";
        MemberSince       = "Loading…";
        AllAchievements.Clear();
    }
}
