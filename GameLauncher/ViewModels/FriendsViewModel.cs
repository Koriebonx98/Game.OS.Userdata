using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace GameLauncher.ViewModels;

/// <summary>
/// View-model for the Friends screen – shows online friends, offline friends,
/// and (in demo mode) a list of incoming friend requests.
/// </summary>
public partial class FriendsViewModel : ViewModelBase
{
    [ObservableProperty] private int _onlineCount;
    [ObservableProperty] private int _totalCount;

    public ObservableCollection<DemoFriend> OnlineFriends  { get; } = new();
    public ObservableCollection<DemoFriend> OfflineFriends { get; } = new();

    /// <summary>Pending friend requests (demo only).</summary>
    public ObservableCollection<DemoFriendRequest> PendingRequests { get; } = new()
    {
        new DemoFriendRequest { FromUsername = "SpeedRunner42",   AvatarInitial = "S", AvatarGradient = "#f59e0b,#b45309", SentAgo = "5 min ago"   },
        new DemoFriendRequest { FromUsername = "GamingQueen_Lily", AvatarInitial = "G", AvatarGradient = "#ec4899,#9d174d", SentAgo = "2 hours ago" },
    };

    public void Load()
    {
        OnlineFriends.Clear();
        OfflineFriends.Clear();

        foreach (var f in DemoData.Friends)
        {
            if (f.IsOnline || f.IsAway)
                OnlineFriends.Add(f);
            else
                OfflineFriends.Add(f);
        }

        OnlineCount = OnlineFriends.Count;
        TotalCount  = DemoData.Friends.Count;
    }
}

/// <summary>A pending incoming friend request (demo).</summary>
public class DemoFriendRequest
{
    public string FromUsername   { get; set; } = "";
    public string AvatarInitial  { get; set; } = "";
    public string AvatarGradient { get; set; } = "#1e90ff,#0056a8";
    public string SentAgo        { get; set; } = "";
}
