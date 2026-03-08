using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using GameOS.Desktop.Models;

namespace GameOS.Desktop.Services;

public class FriendService
{
    public static async Task<List<string>> GetFriendsAsync(string username)
    {
        var path = Path.Combine(DataService.GetUserDataPath(username), "friends.json");
        return await DataService.ReadJsonAsync<List<string>>(path) ?? new List<string>();
    }

    public static async Task<List<FriendRequest>> GetFriendRequestsAsync(string username)
    {
        var path = Path.Combine(DataService.GetUserDataPath(username), "friend-requests.json");
        return await DataService.ReadJsonAsync<List<FriendRequest>>(path) ?? new List<FriendRequest>();
    }

    public static async Task<List<FriendRequest>> GetSentRequestsAsync(string username)
    {
        var path = Path.Combine(DataService.GetUserDataPath(username), "sent-requests.json");
        return await DataService.ReadJsonAsync<List<FriendRequest>>(path) ?? new List<FriendRequest>();
    }

    public static async Task<(bool Success, string Error)> SendFriendRequestAsync(string username, string toUsername)
    {
        toUsername = toUsername.Trim();
        if (string.IsNullOrWhiteSpace(toUsername))
            return (false, "Please enter a username.");
        if (toUsername.ToLowerInvariant() == username.ToLowerInvariant())
            return (false, "You cannot add yourself.");

        var targetProfile = Path.Combine(DataService.GetUserDataPath(toUsername), "profile.json");
        if (!File.Exists(targetProfile))
            return (false, $"User '{toUsername}' not found.");

        var friends = await GetFriendsAsync(username);
        if (friends.Any(f => f.ToLowerInvariant() == toUsername.ToLowerInvariant()))
            return (false, "Already friends.");

        var sent = await GetSentRequestsAsync(username);
        if (sent.Any(r => r.From.ToLowerInvariant() == toUsername.ToLowerInvariant()))
            return (false, "Request already sent.");

        var incoming = await GetFriendRequestsAsync(username);
        if (incoming.Any(r => r.From.ToLowerInvariant() == toUsername.ToLowerInvariant()))
            return (false, "This user already sent you a request.");

        // Add to sender's sent list
        sent.Add(new FriendRequest { From = toUsername, SentAt = DateTime.UtcNow.ToString("o") });
        var sentPath = Path.Combine(DataService.GetUserDataPath(username), "sent-requests.json");
        await DataService.WriteJsonAsync(sentPath, sent);

        // Add to recipient's incoming list
        var targetIncoming = await GetFriendRequestsAsync(toUsername);
        targetIncoming.Add(new FriendRequest { From = username, SentAt = DateTime.UtcNow.ToString("o") });
        var targetPath = Path.Combine(DataService.GetUserDataPath(toUsername), "friend-requests.json");
        await DataService.WriteJsonAsync(targetPath, targetIncoming);

        return (true, "");
    }

    public static async Task AcceptFriendRequestAsync(string username, string fromUsername)
    {
        // Remove from incoming
        var requests = await GetFriendRequestsAsync(username);
        requests.RemoveAll(r => r.From.ToLowerInvariant() == fromUsername.ToLowerInvariant());
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(username), "friend-requests.json"), requests);

        // Remove from sender's sent list
        var senderSent = await GetSentRequestsAsync(fromUsername);
        senderSent.RemoveAll(r => r.From.ToLowerInvariant() == username.ToLowerInvariant());
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(fromUsername), "sent-requests.json"), senderSent);

        // Add both to friends lists
        var myFriends = await GetFriendsAsync(username);
        if (!myFriends.Contains(fromUsername, StringComparer.OrdinalIgnoreCase))
            myFriends.Add(fromUsername);
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(username), "friends.json"), myFriends);

        var theirFriends = await GetFriendsAsync(fromUsername);
        if (!theirFriends.Contains(username, StringComparer.OrdinalIgnoreCase))
            theirFriends.Add(username);
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(fromUsername), "friends.json"), theirFriends);
    }

    public static async Task DeclineFriendRequestAsync(string username, string fromUsername)
    {
        var requests = await GetFriendRequestsAsync(username);
        requests.RemoveAll(r => r.From.ToLowerInvariant() == fromUsername.ToLowerInvariant());
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(username), "friend-requests.json"), requests);

        var senderSent = await GetSentRequestsAsync(fromUsername);
        senderSent.RemoveAll(r => r.From.ToLowerInvariant() == username.ToLowerInvariant());
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(fromUsername), "sent-requests.json"), senderSent);
    }

    public static async Task CancelFriendRequestAsync(string username, string toUsername)
    {
        var sent = await GetSentRequestsAsync(username);
        sent.RemoveAll(r => r.From.ToLowerInvariant() == toUsername.ToLowerInvariant());
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(username), "sent-requests.json"), sent);

        var theirIncoming = await GetFriendRequestsAsync(toUsername);
        theirIncoming.RemoveAll(r => r.From.ToLowerInvariant() == username.ToLowerInvariant());
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(toUsername), "friend-requests.json"), theirIncoming);
    }

    public static async Task RemoveFriendAsync(string username, string friendUsername)
    {
        var myFriends = await GetFriendsAsync(username);
        myFriends.RemoveAll(f => f.ToLowerInvariant() == friendUsername.ToLowerInvariant());
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(username), "friends.json"), myFriends);

        var theirFriends = await GetFriendsAsync(friendUsername);
        theirFriends.RemoveAll(f => f.ToLowerInvariant() == username.ToLowerInvariant());
        await DataService.WriteJsonAsync(
            Path.Combine(DataService.GetUserDataPath(friendUsername), "friends.json"), theirFriends);
    }
}
