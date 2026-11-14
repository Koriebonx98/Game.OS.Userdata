using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

public partial class InboxViewModel : ViewModelBase
{
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _errorMessage = "";
    [ObservableProperty] private bool _showConversation;
    [ObservableProperty] private string _conversationFriend = "";
    [ObservableProperty] private string _newMessageText = "";
    [ObservableProperty] private bool _isSendingMessage;
    [ObservableProperty] private string _messageError = "";

    public ObservableCollection<InboxConversationVm> Conversations { get; } = new();
    public ObservableCollection<GameInvite> PendingInvites { get; } = new();
    public ObservableCollection<Services.PendingModShare> PendingModShares { get; } = new();
    public bool HasPendingModShares => PendingModShares.Count > 0;
    [ObservableProperty] private string _modShareStatus = "";
    public ObservableCollection<Message> ConversationMessages { get; } = new();

    public bool HasConversations => Conversations.Count > 0;
    public bool HasPendingInvites => PendingInvites.Count > 0;
    public bool HasEmptyInbox => !IsLoading && Conversations.Count == 0 && PendingInvites.Count == 0 && PendingModShares.Count == 0;

    partial void OnIsLoadingChanged(bool value) => OnPropertyChanged(nameof(HasEmptyInbox));

    private GameOsClient? _client;
    private string _username = "";

    public Action<string>? OnViewFriendProfile { get; set; }
    public Action<GameInvite>? OnInviteAccepted { get; set; }
    public Func<GameInvite, Task>? BeforeInviteAccepted { get; set; }

    public void Load(GameOsClient client, string username)
    {
        _client = client;
        _username = username;
        _ = LoadAsync();
    }

    public void LoadDemo(string username)
    {
        _client = null;
        _username = username;
        IsLoading = false;
        ErrorMessage = "";
        Conversations.Clear();
        PendingInvites.Clear();
        ConversationMessages.Clear();

        Conversations.Add(new InboxConversationVm
        {
            FriendUsername = "NintendoFan42",
            LastMessage = "Dude, have you tried the new DLC for Elden Ring yet?!",
            LastMessageAt = "2026-03-10T18:15:00Z"
        });
        Conversations.Add(new InboxConversationVm
        {
            FriendUsername = "GamingWithLex",
            LastMessage = "We should queue Mario Kart tonight.",
            LastMessageAt = "2026-03-10T16:15:00Z"
        });
        PendingInvites.Add(new GameInvite
        {
            InviteId = "demo-invite",
            From = "RetroKing",
            GameName = "Halo 3",
            Platform = "PC",
            ConnectionType = "Radmin",
            SentAt = "2026-03-10T17:00:00Z",
            Status = "pending"
        });

        OnPropertyChanged(nameof(HasConversations));
        OnPropertyChanged(nameof(HasPendingInvites));
        OnPropertyChanged(nameof(HasEmptyInbox));
    }

    [RelayCommand]
    private async Task OpenConversation(string friendUsername)
    {
        if (string.IsNullOrWhiteSpace(friendUsername) || _client == null) return;

        ConversationFriend = friendUsername;
        MessageError = "";
        ShowConversation = true;
        ConversationMessages.Clear();

        try
        {
            var messages = await _client.GetMessagesAsync(friendUsername);
            foreach (var message in messages.OrderBy(m => m.SentAt))
                ConversationMessages.Add(message);
        }
        catch (Exception ex)
        {
            MessageError = $"Could not load messages: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task SendMessage()
    {
        if (_client == null || string.IsNullOrWhiteSpace(NewMessageText) || string.IsNullOrWhiteSpace(ConversationFriend))
            return;

        string text = NewMessageText.Trim();
        NewMessageText = "";
        MessageError = "";
        IsSendingMessage = true;
        try
        {
            await _client.SendMessageAsync(ConversationFriend, text);
            ConversationMessages.Add(new Message
            {
                From = _username,
                Text = text,
                SentAt = DateTimeOffset.UtcNow.ToString("o"),
            });
            UpdateConversationPreview(ConversationFriend, text, DateTimeOffset.UtcNow.ToString("o"));
        }
        catch (Exception ex)
        {
            MessageError = $"Send failed: {ex.Message}";
            NewMessageText = text;
        }
        finally
        {
            IsSendingMessage = false;
        }
    }

    [RelayCommand]
    private void CloseConversation()
    {
        ShowConversation = false;
        ConversationFriend = "";
        ConversationMessages.Clear();
        MessageError = "";
    }

    [RelayCommand]
    private void ViewFriendProfile(string friendUsername)
    {
        if (!string.IsNullOrWhiteSpace(friendUsername))
            OnViewFriendProfile?.Invoke(friendUsername);
    }

    [RelayCommand]
    private async Task AcceptInvite(GameInvite? invite)
    {
        if (_client == null || invite == null || string.IsNullOrWhiteSpace(invite.InviteId)) return;
        try
        {
            if (BeforeInviteAccepted != null) await BeforeInviteAccepted(invite);
            await _client.RespondInviteAsync(invite, "accepted");
        }
        catch (Exception ex) { ErrorMessage = "Could not accept invite: " + ex.Message; return; }
        PendingInvites.Remove(invite);
        OnPropertyChanged(nameof(HasPendingInvites));
        OnPropertyChanged(nameof(HasEmptyInbox));
        try { OnInviteAccepted?.Invoke(invite); }
        catch (Exception ex) { ErrorMessage = "Invite accepted, but it could not be opened: " + ex.Message; }
    }

    [RelayCommand]
    private void AcceptModShare(Services.PendingModShare? share)
    {
        if (share == null) return;
        try { ModShareStatus = Services.ModShareService.Accept(share); }
        catch (Exception ex) { ModShareStatus = "Could not accept: " + ex.Message; return; }
        PendingModShares.Remove(share);
        OnPropertyChanged(nameof(HasPendingModShares));
    }

    [RelayCommand]
    private void DeclineModShare(Services.PendingModShare? share)
    {
        if (share == null) return;
        Services.ModShareService.Decline(share);
        PendingModShares.Remove(share);
        OnPropertyChanged(nameof(HasPendingModShares));
    }

    [RelayCommand]
    private async Task DeclineInvite(GameInvite? invite)
    {
        if (_client == null || invite == null || string.IsNullOrWhiteSpace(invite.InviteId)) return;
        try { await _client.RespondInviteAsync(invite, "declined"); }
        catch (Exception ex) { ErrorMessage = "Could not decline invite: " + ex.Message; return; }
        PendingInvites.Remove(invite);
        OnPropertyChanged(nameof(HasPendingInvites));
        OnPropertyChanged(nameof(HasEmptyInbox));
    }

    // ── Controller navigation + on-screen keyboard ────────────────────────────
    public OnScreenKeyboardViewModel Keyboard { get; } = new();
    private object? _focused;

    private List<object> FocusList() =>
        PendingInvites.Cast<object>().Concat(PendingModShares).Concat(Conversations).ToList();

    private void SetFocus(object? item)
    {
        foreach (var i in FocusList())
        {
            bool on = ReferenceEquals(i, item);
            if (i is SelectableItem s) s.IsSelected = on;
            else if (i is InboxConversationVm c) c.IsSelected = on;
        }
        _focused = item;
    }

    private void MoveFocus(int delta)
    {
        var list = FocusList();
        if (list.Count == 0) return;
        int idx = _focused == null ? -1 : list.FindIndex(i => ReferenceEquals(i, _focused));
        idx = Math.Clamp((idx < 0 ? (delta > 0 ? -1 : list.Count) : idx) + delta, 0, list.Count - 1);
        SetFocus(list[idx]);
    }

    /// <summary>Controller handling for the Inbox page. Returns true when the key was consumed.</summary>
    public bool HandleKey(string name)
    {
        if (Keyboard.IsOpen) return Keyboard.HandleKey(name);
        if (ShowConversation)
        {
            switch (name)
            {
                case "A": Keyboard.Open(NewMessageText, $"Message {ConversationFriend}", t => NewMessageText = t,
                                        _ => SendMessageCommand.Execute(null)); break;
                case "X": SendMessageCommand.Execute(null); break;
                case "B": CloseConversationCommand.Execute(null); break;
            }
            return true;
        }
        switch (name)
        {
            case "Up": MoveFocus(-1); return true;
            case "Down": MoveFocus(1); return true;
        }
        switch (_focused)
        {
            case GameInvite inv when name == "A": AcceptInviteCommand.Execute(inv); return true;
            case GameInvite inv when name == "X": DeclineInviteCommand.Execute(inv); return true;
            case Services.PendingModShare sh when name == "A": AcceptModShareCommand.Execute(sh); return true;
            case Services.PendingModShare sh when name == "X": DeclineModShareCommand.Execute(sh); return true;
            case InboxConversationVm c when name == "A": OpenConversationCommand.Execute(c.FriendUsername); return true;
            case InboxConversationVm c when name == "Y": ViewFriendProfileCommand.Execute(c.FriendUsername); return true;
        }
        return false;
    }

    private int _loadVersion;

    private async Task LoadAsync()
    {
        if (_client == null) return;
        int version = ++_loadVersion;

        IsLoading = true;
        ErrorMessage = "";
        Conversations.Clear();
        PendingInvites.Clear();
        PendingModShares.Clear();
        try
        {
            var friendsTask = _client.GetFriendsAsync();
            var invitesTask = _client.GetInvitesAsync();
            var friends = await friendsTask;
            if (version != _loadVersion) return;
            var messageInvitesTask = _client.GetMessageInvitesAsync(friends);
            try
            {
                foreach (var invite in (await invitesTask)
                    .Where(i => string.Equals(i.Status, "pending", StringComparison.OrdinalIgnoreCase)))
                    PendingInvites.Add(invite);
            }
            catch (Exception ex) { ErrorMessage = "Could not load older invites: " + ex.Message; }
            try
            {
                foreach (var invite in await messageInvitesTask) PendingInvites.Add(invite);
            }
            catch (Exception ex) { ErrorMessage = "Could not load friend invitations: " + ex.Message; }
            var convoTasks = friends.Select(async friend =>
            {
                try
                {
                    var raw = await _client.GetRawMessagesAsync(friend);
                    var shares = Services.ModShareService.FindPending(friend, raw);
                    if (shares.Count > 0)
                        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                        {
                            if (version != _loadVersion) return;
                            foreach (var sh in shares) PendingModShares.Add(sh);
                            OnPropertyChanged(nameof(HasPendingModShares));
                        });
                    var messages = raw.Where(m => !Services.ModShareService.IsShareMessage(m.Text)
                        && !Services.InviteMessageService.IsInviteMessage(m.Text)).ToList();
                    var last = messages.OrderByDescending(m => m.SentAt).FirstOrDefault();
                    return last == null ? null : new InboxConversationVm
                    {
                        FriendUsername = friend,
                        LastMessage = last.Text,
                        LastMessageAt = last.SentAt
                    };
                }
                catch { return null; }
            });

            var convos = await Task.WhenAll(convoTasks);
            if (version != _loadVersion) return;
            foreach (var convo in convos
                .Where(c => c != null)
                .OrderByDescending(c => c!.LastMessageAt))
            {
                Conversations.Add(convo!);
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not load inbox: {ex.Message}";
        }
        finally
        {
            if (version == _loadVersion) IsLoading = false;
            OnPropertyChanged(nameof(HasConversations));
            OnPropertyChanged(nameof(HasPendingInvites));
            OnPropertyChanged(nameof(HasEmptyInbox));
        }
    }

    private void UpdateConversationPreview(string friendUsername, string text, string sentAt)
    {
        var existing = Conversations.FirstOrDefault(c =>
            string.Equals(c.FriendUsername, friendUsername, StringComparison.OrdinalIgnoreCase));
        if (existing != null)
        {
            existing.LastMessage = text;
            existing.LastMessageAt = sentAt;
            return;
        }

        Conversations.Insert(0, new InboxConversationVm
        {
            FriendUsername = friendUsername,
            LastMessage = text,
            LastMessageAt = sentAt
        });
        OnPropertyChanged(nameof(HasConversations));
    }
}

public partial class InboxConversationVm : ViewModelBase
{
    [ObservableProperty] private string _friendUsername = "";
    [ObservableProperty] private string _lastMessage = "";
    [ObservableProperty] private string _lastMessageAt = "";
    [ObservableProperty] private bool _isSelected;
}
