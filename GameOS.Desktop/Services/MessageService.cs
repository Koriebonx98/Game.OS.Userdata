using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using GameOS.Desktop.Models;

namespace GameOS.Desktop.Services;

public class MessageService
{
    private static string ConversationPath(string userA, string userB)
    {
        var a = userA.ToLowerInvariant();
        var b = userB.ToLowerInvariant();
        // Use alphabetical ordering so both users reference the same file path,
        // regardless of which user initiates the lookup.
        var ordered = string.Compare(a, b, StringComparison.Ordinal) < 0
            ? $"{a}_{b}"
            : $"{b}_{a}";
        return Path.Combine(DataService.GetUserDataPath(userA), $"messages-{ordered}.json");
    }

    public static async Task SendMessageAsync(string fromUsername, string toUsername, string text)
    {
        var messages = await GetMessagesAsync(fromUsername, toUsername);
        messages.Add(new Message
        {
            From = fromUsername,
            Text = text,
            SentAt = DateTime.UtcNow.ToString("o")
        });

        // Store in sender's directory
        await DataService.WriteJsonAsync(ConversationPath(fromUsername, toUsername), messages);

        // Mirror to recipient's directory
        var recipientPath = ConversationPath(toUsername, fromUsername);
        await DataService.WriteJsonAsync(recipientPath, messages);
    }

    public static async Task<List<Message>> GetMessagesAsync(string username, string withUsername)
    {
        var path = ConversationPath(username, withUsername);
        return await DataService.ReadJsonAsync<List<Message>>(path) ?? new List<Message>();
    }
}
