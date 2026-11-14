using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    public static class InviteMessageService
    {
        public const string Marker = "\u2063\u2063GOSINV1:";

        private sealed class Envelope
        {
            public GameInvite? Invite { get; set; }
            public string? InviteId { get; set; }
            public string? Response { get; set; }
        }

        public static bool IsInviteMessage(string? text) =>
            text != null && text.StartsWith(Marker, StringComparison.Ordinal);

        public static string EncodeInvite(GameInvite invite) =>
            Marker + JsonSerializer.Serialize(new Envelope { Invite = invite });

        public static string EncodeResponse(string id, string response) =>
            Marker + JsonSerializer.Serialize(new Envelope { InviteId = id, Response = response });

        private static Envelope? Parse(string? text)
        {
            if (!IsInviteMessage(text)) return null;
            try { return JsonSerializer.Deserialize<Envelope>(text!.Substring(Marker.Length)); }
            catch (JsonException) { return null; }
        }

        public static List<GameInvite> Pending(IEnumerable<Message> messages, string friend, string me)
        {
            var all = messages.ToList();
            var responded = new HashSet<string>(all
                .Where(m => string.Equals(m.From, me, StringComparison.OrdinalIgnoreCase))
                .Select(m => Parse(m.Text))
                .Where(e => e?.Response is "accepted" or "declined" && !string.IsNullOrEmpty(e.InviteId))
                .Select(e => e!.InviteId!), StringComparer.Ordinal);
            var pending = new List<GameInvite>();
            foreach (var message in all.Where(m => string.Equals(m.From, friend, StringComparison.OrdinalIgnoreCase)))
            {
                var invite = Parse(message.Text)?.Invite;
                if (invite == null || invite.InviteId == null || !invite.InviteId.StartsWith("msg-", StringComparison.Ordinal)
                    || string.IsNullOrWhiteSpace(invite.GameName) || responded.Contains(invite.InviteId)) continue;
                invite.From = friend;
                invite.SentAt = message.SentAt;
                invite.Status = "pending";
                if (!pending.Any(i => i.InviteId == invite.InviteId)) pending.Add(invite);
            }
            return pending;
        }

        public static string? Response(IEnumerable<Message> messages, string friend, string id) =>
            messages.Where(m => string.Equals(m.From, friend, StringComparison.OrdinalIgnoreCase))
                .Select(m => Parse(m.Text))
                .LastOrDefault(e => e?.InviteId == id && e.Response is "accepted" or "declined")?.Response;
    }
}
