using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>What a friend shares: a mod page/download URL ("link") or a magnet to the mod files ("torrent").</summary>
    public class ModSharePayload
    {
        [JsonPropertyName("kind")]     public string Kind     { get; set; } = "link";
        [JsonPropertyName("name")]     public string Name     { get; set; } = "";
        [JsonPropertyName("url")]      public string Url      { get; set; } = "";
        [JsonPropertyName("platform")] public string Platform { get; set; } = "";
        [JsonPropertyName("game")]     public string Game     { get; set; } = "";
        [JsonPropertyName("modType")]  public string ModType  { get; set; } = "Mod";
        /// <summary>Subfolders under Mods/{Game}/ (e.g. Drivers, Toad) used when a torrent is accepted.</summary>
        [JsonPropertyName("folders")]  public List<string> Folders { get; set; } = new();

        public bool IsTorrent => Kind == "torrent";
    }

    /// <summary>A received share waiting for Accept / Decline.</summary>
    public class PendingModShare
    {
        public string Id { get; set; } = "";
        public string From { get; set; } = "";
        public string SentAt { get; set; } = "";
        public ModSharePayload Payload { get; set; } = new();
        public string Title => $"{From} shared a mod";
        public string Detail => $"{Payload.Name} · {Payload.Game} ({Payload.Platform}) · {(Payload.IsTorrent ? "files via torrent" : "link")}";
    }

    /// <summary>
    /// Mod sharing between friends. Shares travel as hidden chat messages: the text starts with an invisible
    /// marker so the UI can filter them out of conversations while the system still reads them.
    /// </summary>
    public static partial class ModShareService
    {
        private static readonly object Gate = new();
        private static readonly string HandledFile = Path.Combine(UserDataService.DataRoot, "ModSharesHandled.json");

        public static string Encode(ModSharePayload p) => Marker + JsonSerializer.Serialize(p);

        public static ModSharePayload? TryParse(string? text)
        {
            if (!IsShareMessage(text)) return null;
            try
            {
                var p = JsonSerializer.Deserialize<ModSharePayload>(text!.Substring(Marker.Length));
                if (p == null || string.IsNullOrWhiteSpace(p.Url) || string.IsNullOrWhiteSpace(p.Game)) return null;
                bool magnet = DownloadManagerService.IsMagnet(p.Url);
                bool http = Uri.TryCreate(p.Url, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps);
                if (p.IsTorrent ? !magnet : !http) return null;
                p.Folders = (p.Folders ?? new()).Where(f => !string.IsNullOrWhiteSpace(f)).Take(6).ToList();
                return p;
            }
            catch { return null; }
        }

        public static string MessageId(Message m) => $"{m.From}|{m.SentAt}|{m.Text.GetHashCode()}";

        /// <summary>Shares from <paramref name="friend"/> that the user has not accepted or declined yet.</summary>
        public static List<PendingModShare> FindPending(string friend, IEnumerable<Message> messages)
        {
            var handled = LoadHandled();
            var list = new List<PendingModShare>();
            foreach (var m in messages)
            {
                if (!string.Equals(m.From, friend, StringComparison.OrdinalIgnoreCase)) continue;
                var p = TryParse(m.Text);
                if (p == null) continue;
                string id = MessageId(m);
                if (handled.Contains(id)) continue;
                list.Add(new PendingModShare { Id = id, From = friend, SentAt = m.SentAt, Payload = p });
            }
            return list;
        }

        public static void MarkHandled(string id)
        {
            lock (Gate)
            {
                var set = LoadHandled();
                if (!set.Add(id)) return;
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(HandledFile)!);
                    File.WriteAllText(HandledFile, JsonSerializer.Serialize(set));
                }
                catch { /* best-effort */ }
            }
        }

        private static HashSet<string> LoadHandled()
        {
            try
            {
                if (File.Exists(HandledFile))
                    return JsonSerializer.Deserialize<HashSet<string>>(File.ReadAllText(HandledFile)) ?? new();
            }
            catch { }
            return new();
        }

        /// <summary>Accept: link → saved to that game's mod links (like Add mod URL); torrent → queued download into the Mods folder.</summary>
        public static string Accept(PendingModShare share)
        {
            var p = share.Payload;
            string name = string.IsNullOrWhiteSpace(p.Name) ? "Shared mod" : p.Name;
            if (p.IsTorrent)
            {
                string root = DownloadPathResolver.ResolveRoot(AppSettingsService.Load().Downloads.RootFolder);
                string[] sub = new[] { PlatformHelper.StripSpecialSymbols(p.Game) }.Concat(p.Folders).ToArray();
                DownloadManagerService.Instance.Add(p.Url, name, DownloadPathResolver.CategoryMod, p.Platform,
                    game: p.Game, autoExtract: false, subfolders: sub);
                MarkHandled(share.Id);
                return $"Downloading {name} to Mods/{string.Join("/", sub)}.";
            }
            GameLinksService.Add(p.Platform, p.Game, name, p.Url, GameLink.KindMod, p.ModType);
            MarkHandled(share.Id);
            return $"Added {name} to {p.Game} mod links.";
        }

        public static void Decline(PendingModShare share) => MarkHandled(share.Id);
    }
}
