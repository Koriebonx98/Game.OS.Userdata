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
/// requests from the Game.OS backend API.
/// </summary>
public partial class FriendsViewModel : ViewModelBase
{
    [ObservableProperty] private int    _onlineCount;
    [ObservableProperty] private int    _totalCount;
    [ObservableProperty] private bool   _isLoading  = false;
    [ObservableProperty] private string _errorMessage = "";

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
            ErrorMessage = $"Could not load friends: {ex.Message}";
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
