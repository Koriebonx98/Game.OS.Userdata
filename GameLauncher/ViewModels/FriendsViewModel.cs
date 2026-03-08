using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace GameLauncher.ViewModels;

public class FriendItem
{
    public string Username    { get; set; } = "";
    public bool   IsOnline    { get; set; }
    public string StatusDot   => IsOnline ? "🟢" : "⚫";
    public string StatusLabel => IsOnline ? "Online" : "Offline";
    public string SharedGames { get; set; } = "";
    public string Initial     => string.IsNullOrEmpty(Username) ? "?" : Username[0].ToString().ToUpperInvariant();
}

public partial class FriendsViewModel : ViewModelBase
{
    [ObservableProperty] private string _searchQuery = "";
    [ObservableProperty] private string _statusMessage = "";

    public ObservableCollection<FriendItem> Friends { get; } = new();

    public int FriendCount => Friends.Count;

    public FriendsViewModel()
    {
        Friends.CollectionChanged += (_, _) => OnPropertyChanged(nameof(FriendCount));
        LoadDemoFriends();
    }

    private void LoadDemoFriends()
    {
        Friends.Clear();

        var demoFriends = new List<FriendItem>
        {
            new FriendItem { Username = "GamerXtreme99",    IsOnline = true,  SharedGames = "3 shared games"  },
            new FriendItem { Username = "NintendoFan2025",  IsOnline = true,  SharedGames = "5 shared games"  },
            new FriendItem { Username = "SwitchMaster",     IsOnline = false, SharedGames = "2 shared games"  },
            new FriendItem { Username = "SpeedRacer2025",   IsOnline = true,  SharedGames = "1 shared game"   },
            new FriendItem { Username = "ProGamer_UK",      IsOnline = false, SharedGames = "4 shared games"  },
        };

        foreach (var f in demoFriends)
            Friends.Add(f);

        OnPropertyChanged(nameof(FriendCount));
    }
}
