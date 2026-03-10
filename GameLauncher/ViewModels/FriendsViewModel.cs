using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

/// <summary>
/// View-model for the Friends screen.  Loads the friend list and incoming
/// requests from the Game.OS backend API, or shows demo friend data when
/// running in demo mode (no backend connected).
/// Also manages the inline direct-message conversation panel.
/// </summary>
public partial class FriendsViewModel : ViewModelBase
{
    [ObservableProperty] private int    _onlineCount;
    [ObservableProperty] private int    _totalCount;
    [ObservableProperty] private bool   _isLoading  = false;
    [ObservableProperty] private string _errorMessage = "";

    // ── Messaging panel ───────────────────────────────────────────────────────
    [ObservableProperty] private bool   _showConversation;
    [ObservableProperty] private string _conversationFriend = "";
    [ObservableProperty] private string _newMessageText     = "";
    [ObservableProperty] private bool   _isSendingMessage;
    [ObservableProperty] private string _messageError       = "";

    public ObservableCollection<Message> ConversationMessages { get; } = new();

    public bool HasNoFriends => TotalCount == 0 && !IsLoading;

    partial void OnTotalCountChanged(int value)  => OnPropertyChanged(nameof(HasNoFriends));
    partial void OnIsLoadingChanged(bool value)  => OnPropertyChanged(nameof(HasNoFriends));

    public ObservableCollection<FriendEntry>          OnlineFriends   { get; } = new();
    public ObservableCollection<FriendEntry>          OfflineFriends  { get; } = new();
    public ObservableCollection<FriendRequestDisplay> PendingRequests { get; } = new();

    private GameOsClient? _client;
    private string        _username = "";

    public void Load(GameOsClient client, string username)
    {
        _client   = client;
        _username = username;
        _ = LoadAsync();
    }

    /// <summary>
    /// Populates the friends screen with demo data — used when running in
    /// demo / offline mode so the Friends page shows realistic content.
    /// </summary>
    public void LoadDemo()
    {
        IsLoading     = false;
        ErrorMessage  = "";

        OnlineFriends.Clear();
        OfflineFriends.Clear();
        PendingRequests.Clear();

        // Demo online friends
        OnlineFriends.Add(new FriendEntry { Username = "NintendoFan42", Status = "Online", LastSeen = "Now" });
        OnlineFriends.Add(new FriendEntry { Username = "SwitchPlayer99", Status = "Away",  LastSeen = "12 min ago" });
        OnlineFriends.Add(new FriendEntry { Username = "GamingWithLex",  Status = "Online", LastSeen = "Now" });

        // Demo offline friends
        OfflineFriends.Add(new FriendEntry { Username = "ProGamer2025", Status = "Offline", LastSeen = "3h ago" });
        OfflineFriends.Add(new FriendEntry { Username = "RetroKing",    Status = "Offline", LastSeen = "1 Mar" });
        OfflineFriends.Add(new FriendEntry { Username = "SpeedRunner7", Status = "Offline", LastSeen = "28 Feb" });

        // Demo pending request
        PendingRequests.Add(new FriendRequestDisplay
        {
            FromUsername = "MKDeluxeChamp",
            SentAgo      = "2 hours ago"
        });

        OnlineCount = OnlineFriends.Count;
        TotalCount  = OnlineFriends.Count + OfflineFriends.Count;
    }

    // ── Messaging commands ────────────────────────────────────────────────────

    /// <summary>Opens the conversation panel for the specified friend.</summary>
    [RelayCommand]
    private async Task OpenConversation(string friendUsername)
    {
        if (string.IsNullOrEmpty(friendUsername)) return;

        ConversationFriend = friendUsername;
        ConversationMessages.Clear();
        MessageError = "";
        ShowConversation = true;

        if (_client == null) return;

        try
        {
            var messages = await _client.GetMessagesAsync(friendUsername);
            ConversationMessages.Clear();
            foreach (var m in messages)
                ConversationMessages.Add(m);
        }
        catch (Exception ex)
        {
            MessageError = $"Could not load messages: {ex.Message}";
        }
    }

    /// <summary>Sends the current message to the active conversation partner.</summary>
    [RelayCommand]
    private async Task SendMessage()
    {
        if (string.IsNullOrWhiteSpace(NewMessageText) || string.IsNullOrEmpty(ConversationFriend))
            return;
        if (_client == null) return;

        IsSendingMessage = true;
        MessageError     = "";
        string text      = NewMessageText.Trim();
        NewMessageText   = "";

        try
        {
            await _client.SendMessageAsync(ConversationFriend, text);

            // Append the sent message to the local conversation immediately
            ConversationMessages.Add(new Message
            {
                From   = _username,
                Text   = text,
                SentAt = DateTimeOffset.UtcNow.ToString("o"),
            });
        }
        catch (Exception ex)
        {
            MessageError   = $"Send failed: {ex.Message}";
            NewMessageText = text; // restore so the user can retry
        }
        finally
        {
            IsSendingMessage = false;
        }
    }

    /// <summary>Closes the conversation panel.</summary>
    [RelayCommand]
    private void CloseConversation()
    {
        ShowConversation = false;
        ConversationFriend = "";
        ConversationMessages.Clear();
        MessageError = "";
    }

    // ── Friend list loading ───────────────────────────────────────────────────

    private async Task LoadAsync()
    {
        if (_client == null) return;

        IsLoading    = true;
        ErrorMessage = "";

        OnlineFriends.Clear();
        OfflineFriends.Clear();
        PendingRequests.Clear();

        try
        {
            // Load friend usernames and incoming requests in parallel
            var friendsTask  = _client.GetFriendsAsync();
            var requestsTask = _client.GetFriendRequestsAsync(_username);
            await Task.WhenAll(friendsTask, requestsTask);

            var friendUsernames = await friendsTask;
            var requests        = await requestsTask;

            // Build pending requests for display
            foreach (var req in requests)
            {
                PendingRequests.Add(new FriendRequestDisplay
                {
                    FromUsername = req.From,
                    SentAgo      = FormatTimeAgo(req.SentAt)
                });
            }

            // Fetch presence for each friend (in parallel, best-effort)
            var presenceTasks = new List<Task<(string username, string? lastSeen)>>();
            foreach (var friendName in friendUsernames)
            {
                string name = friendName; // capture
                presenceTasks.Add(_client.GetPresenceAsync(name)
                    .ContinueWith(t => (name, t.IsCompletedSuccessfully ? t.Result : null)));
            }

            var presenceResults = await Task.WhenAll(presenceTasks);

            foreach (var (name, lastSeen) in presenceResults)
            {
                var entry = BuildFriendEntry(name, lastSeen);
                if (entry.IsOnline || entry.IsAway)
                    OnlineFriends.Add(entry);
                else
                    OfflineFriends.Add(entry);
            }

            OnlineCount = OnlineFriends.Count;
            TotalCount  = friendUsernames.Count;
        }
        catch (Exception ex)
        {
            // If the API is unreachable (demo mode, no backend), fall back to demo data
            if (!_client.IsAuthenticated)
            {
                LoadDemo();
            }
            else
            {
                ErrorMessage = $"Could not load friends: {ex.Message}";
            }
        }
        finally
        {
            IsLoading = false;
        }
    }

    private static FriendEntry BuildFriendEntry(string username, string? lastSeenIso)
    {
        string status   = "Offline";
        string lastSeen = "Unknown";

        if (!string.IsNullOrEmpty(lastSeenIso) &&
            DateTimeOffset.TryParse(lastSeenIso, out var ts))
        {
            var ago = DateTimeOffset.UtcNow - ts;
            if (ago.TotalMinutes < 5)
            {
                status   = "Online";
                lastSeen = "Now";
            }
            else if (ago.TotalMinutes < 30)
            {
                status   = "Away";
                lastSeen = $"{(int)ago.TotalMinutes} min ago";
            }
            else if (ago.TotalHours < 24)
            {
                lastSeen = $"{(int)ago.TotalHours}h ago";
            }
            else
            {
                lastSeen = ts.LocalDateTime.ToString("dd MMM");
            }
        }

        return new FriendEntry
        {
            Username = username,
            Status   = status,
            LastSeen = lastSeen
        };
    }

    private static string FormatTimeAgo(string? isoTimestamp)
    {
        if (string.IsNullOrEmpty(isoTimestamp) ||
            !DateTimeOffset.TryParse(isoTimestamp, out var ts))
            return "";

        var ago = DateTimeOffset.UtcNow - ts;
        if (ago.TotalMinutes < 60) return $"{(int)ago.TotalMinutes} min ago";
        if (ago.TotalHours   < 24) return $"{(int)ago.TotalHours} hours ago";
        return $"{(int)ago.TotalDays} days ago";
    }
}
