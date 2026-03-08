using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameOS.Desktop.Services;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace GameOS.Desktop.ViewModels;

public partial class FriendItemViewModel : ViewModelBase
{
    private readonly FriendsViewModel _parent;
    public string Username { get; }

    public FriendItemViewModel(string username, FriendsViewModel parent)
    {
        Username = username;
        _parent = parent;
    }

    [RelayCommand]
    private async Task Remove() => await _parent.RemoveFriendAsync(Username);

    [RelayCommand]
    private void ViewProfile() => _parent.ViewProfile(Username);
}

public partial class RequestItemViewModel : ViewModelBase
{
    private readonly FriendsViewModel _parent;
    public string Username { get; }
    public string SentAt { get; }
    public bool IsIncoming { get; }

    public RequestItemViewModel(string username, string sentAt, bool isIncoming, FriendsViewModel parent)
    {
        Username = username;
        SentAt = sentAt;
        IsIncoming = isIncoming;
        _parent = parent;
    }

    [RelayCommand]
    private async Task Accept() => await _parent.AcceptRequestAsync(Username);

    [RelayCommand]
    private async Task Decline() => await _parent.DeclineRequestAsync(Username);

    [RelayCommand]
    private async Task Cancel() => await _parent.CancelRequestAsync(Username);
}

public partial class FriendsViewModel : ViewModelBase
{
    private readonly MainWindowViewModel _main;

    [ObservableProperty] private ObservableCollection<FriendItemViewModel> _friends = new();
    [ObservableProperty] private ObservableCollection<RequestItemViewModel> _incomingRequests = new();
    [ObservableProperty] private ObservableCollection<RequestItemViewModel> _sentRequests = new();
    [ObservableProperty] private string _addFriendUsername = "";
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private string _errorMessage = "";

    public FriendsViewModel(MainWindowViewModel main)
    {
        _main = main;
    }

    public async Task LoadAsync()
    {
        if (App.CurrentUser == null) return;
        var username = App.CurrentUser.Username;

        var friends = await FriendService.GetFriendsAsync(username);
        Friends = new ObservableCollection<FriendItemViewModel>(
            friends.Select(f => new FriendItemViewModel(f, this)));

        var incoming = await FriendService.GetFriendRequestsAsync(username);
        IncomingRequests = new ObservableCollection<RequestItemViewModel>(
            incoming.Select(r => new RequestItemViewModel(r.From, r.SentAt, true, this)));

        var sent = await FriendService.GetSentRequestsAsync(username);
        SentRequests = new ObservableCollection<RequestItemViewModel>(
            sent.Select(r => new RequestItemViewModel(r.From, r.SentAt, false, this)));
    }

    [RelayCommand]
    private async Task AddFriend()
    {
        StatusMessage = "";
        ErrorMessage = "";
        if (App.CurrentUser == null) return;
        var (success, error) = await FriendService.SendFriendRequestAsync(App.CurrentUser.Username, AddFriendUsername);
        if (success)
        {
            StatusMessage = $"Friend request sent to {AddFriendUsername}!";
            AddFriendUsername = "";
            await LoadAsync();
        }
        else
        {
            ErrorMessage = error;
        }
    }

    public async Task RemoveFriendAsync(string username)
    {
        if (App.CurrentUser == null) return;
        await FriendService.RemoveFriendAsync(App.CurrentUser.Username, username);
        StatusMessage = $"Removed {username} from friends.";
        await LoadAsync();
    }

    public async Task AcceptRequestAsync(string fromUsername)
    {
        if (App.CurrentUser == null) return;
        await FriendService.AcceptFriendRequestAsync(App.CurrentUser.Username, fromUsername);
        StatusMessage = $"Accepted friend request from {fromUsername}!";
        await LoadAsync();
        await _main.RefreshInboxCountAsync();
    }

    public async Task DeclineRequestAsync(string fromUsername)
    {
        if (App.CurrentUser == null) return;
        await FriendService.DeclineFriendRequestAsync(App.CurrentUser.Username, fromUsername);
        StatusMessage = $"Declined friend request from {fromUsername}.";
        await LoadAsync();
        await _main.RefreshInboxCountAsync();
    }

    public async Task CancelRequestAsync(string toUsername)
    {
        if (App.CurrentUser == null) return;
        await FriendService.CancelFriendRequestAsync(App.CurrentUser.Username, toUsername);
        StatusMessage = $"Cancelled request to {toUsername}.";
        await LoadAsync();
    }

    public void ViewProfile(string username)
    {
        var vm = new ProfileViewModel(username);
        _ = vm.LoadAsync();
        _main.CurrentView = vm;
    }
}
