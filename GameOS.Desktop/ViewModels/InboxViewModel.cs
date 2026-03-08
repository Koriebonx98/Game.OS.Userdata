using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameOS.Desktop.Services;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

namespace GameOS.Desktop.ViewModels;

public partial class InboxRequestItemViewModel : ViewModelBase
{
    private readonly InboxViewModel _parent;
    public string From { get; }
    public string SentAt { get; }

    public InboxRequestItemViewModel(string from, string sentAt, InboxViewModel parent)
    {
        From = from;
        SentAt = sentAt;
        _parent = parent;
    }

    [RelayCommand]
    private async Task Accept() => await _parent.AcceptAsync(From);

    [RelayCommand]
    private async Task Decline() => await _parent.DeclineAsync(From);
}

public partial class InboxViewModel : ViewModelBase
{
    private readonly MainWindowViewModel _main;

    [ObservableProperty] private ObservableCollection<InboxRequestItemViewModel> _requests = new();
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private bool _hasRequests;

    public InboxViewModel(MainWindowViewModel main)
    {
        _main = main;
    }

    public async Task LoadAsync()
    {
        if (App.CurrentUser == null) return;
        var incoming = await FriendService.GetFriendRequestsAsync(App.CurrentUser.Username);
        Requests = new ObservableCollection<InboxRequestItemViewModel>(
            incoming.Select(r => new InboxRequestItemViewModel(r.From, r.SentAt, this)));
        HasRequests = Requests.Count > 0;
        await _main.RefreshInboxCountAsync();
    }

    public async Task AcceptAsync(string fromUsername)
    {
        if (App.CurrentUser == null) return;
        await FriendService.AcceptFriendRequestAsync(App.CurrentUser.Username, fromUsername);
        StatusMessage = $"You are now friends with {fromUsername}!";
        await LoadAsync();
    }

    public async Task DeclineAsync(string fromUsername)
    {
        if (App.CurrentUser == null) return;
        await FriendService.DeclineFriendRequestAsync(App.CurrentUser.Username, fromUsername);
        StatusMessage = $"Declined request from {fromUsername}.";
        await LoadAsync();
    }
}
