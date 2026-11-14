using System;
using System.Threading;
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
        _respondedIds.Add(invite.InviteId);
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
        // Build fresh lists off to the side and swap them in at the end so the page (and the Quick Guide
        // badge) never flashes empty and overlapping loads cannot interleave their items.
        var invites = new List<GameInvite>();
        var shares = new List<Services.PendingModShare>();
        var convos = new List<InboxConversationVm>();
        string? error = null;
        try
        {
            var friendsTask = _client.GetFriendsAsync();
            var invitesTask = _client.GetInvitesAsync();
            var friends = await friendsTask;
            if (version != _loadVersion) return;
            var messageInvitesTask = _client.GetMessageInvitesAsync(friends);
            try
            {
                invites.AddRange((await invitesTask)
                    .Where(i => i != null && string.Equals(i.Status, "pending", StringComparison.OrdinalIgnoreCase)));
            }
            catch (Exception ex) { error = "Could not load older invites: " + ex.Message; }
            try { invites.AddRange(await messageInvitesTask); }
            catch (Exception ex) { error = "Could not load friend invitations: " + ex.Message; }

            var convoTasks = friends.Select(async friend =>
            {
                try
                {
                    var raw = await _client.GetRawMessagesAsync(friend);
                    lock (shares) shares.AddRange(Services.ModShareService.FindPending(friend, raw));
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
            convos.AddRange((await Task.WhenAll(convoTasks))
                .Where(c => c != null).Select(c => c!).OrderByDescending(c => c.LastMessageAt));
            if (version != _loadVersion) return;

            invites.RemoveAll(i => _respondedIds.Contains(i.InviteId));

            ReplaceAll(PendingInvites, invites);
            ReplaceAll(PendingModShares, shares);
            ReplaceAll(Conversations, convos);
            if (error != null) ErrorMessage = error;
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
            OnPropertyChanged(nameof(HasPendingModShares));
            OnPropertyChanged(nameof(HasEmptyInbox));
        }
    }

    // Invites answered locally; message-based invites stay "pending" until the response message is readable.
    private readonly HashSet<string> _respondedIds = new(StringComparer.Ordinal);

    private static void ReplaceAll<T>(ObservableCollection<T> target, List<T> items)
    {
        target.Clear();
        foreach (var item in items) target.Add(item);
    }

    private int _pollRunning;

    /// <summary>
    /// Lightweight background refresh: adds invites / mod shares that are not listed yet and returns them.
    /// Never clears the lists, so it is safe to run while the user is looking at the inbox.
    /// </summary>
    public async Task<(List<GameInvite> Invites, List<Services.PendingModShare> Shares)> PollPendingAsync()
    {
        var newInvites = new List<GameInvite>();
        var newShares = new List<Services.PendingModShare>();
        LastPollCompleted = false;
        if (_client == null || IsLoading || Interlocked.Exchange(ref _pollRunning, 1) == 1) return (newInvites, newShares);
        try
        {
            var friends = await _client.GetFriendsAsync();
            var found = new List<GameInvite>();
            try
            {
                found.AddRange((await _client.GetInvitesAsync())
                    .Where(i => string.Equals(i.Status, "pending", StringComparison.OrdinalIgnoreCase)));
            }
            catch { }
            try { found.AddRange(await _client.GetMessageInvitesAsync(friends)); } catch { }
            var shares = new List<Services.PendingModShare>();
            foreach (var friend in friends)
            {
                try { shares.AddRange(Services.ModShareService.FindPending(friend, await _client.GetRawMessagesAsync(friend))); }
                catch { }
            }
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                foreach (var inv in found)
                {
                    if (string.IsNullOrEmpty(inv.InviteId) || _respondedIds.Contains(inv.InviteId) || PendingInvites.Any(p => p.InviteId == inv.InviteId)) continue;
                    PendingInvites.Add(inv);
                    newInvites.Add(inv);
                }
                foreach (var sh in shares)
                {
                    if (PendingModShares.Any(p => p.Id == sh.Id)) continue;
                    PendingModShares.Add(sh);
                    newShares.Add(sh);
                }
                OnPropertyChanged(nameof(HasPendingInvites));
                OnPropertyChanged(nameof(HasPendingModShares));
                OnPropertyChanged(nameof(HasEmptyInbox));
            });
            LastPollCompleted = true;
        }
        catch { }
        finally { Interlocked.Exchange(ref _pollRunning, 0); }
        return (newInvites, newShares);
    }

    /// <summary>True when the last <see cref="PollPendingAsync"/> actually fetched and merged data (not skipped or failed).</summary>
    public volatile bool LastPollCompleted;

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
