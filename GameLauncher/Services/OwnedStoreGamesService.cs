using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GameLauncher.Services
{
    /// <summary>One game owned on a store account (Epic, GOG, Xbox …).</summary>
    public sealed class OwnedStoreGame
    {
        [JsonPropertyName("store")]    public string Store    { get; set; } = "";
        [JsonPropertyName("id")]       public string Id       { get; set; } = "";
        [JsonPropertyName("title")]    public string Title    { get; set; } = "";
        /// <summary>Id the store client needs to install/launch (Epic: appName / artifact id).</summary>
        [JsonPropertyName("launchId")] public string? LaunchId { get; set; }
        [JsonPropertyName("url")]      public string? Url     { get; set; }
    }

    /// <summary>
    /// Per-account cache of games owned on linked stores plus user-added download URLs, stored in
    /// <c>Data/{user}/Accounts/owned-games.json</c>. Used to merge store libraries into the Games section
    /// (duplicates collapse by normalised title) and to offer an install source per store.
    /// </summary>
    public static class OwnedStoreGamesService
    {
        private sealed class FileModel
        {
            [JsonPropertyName("games")]    public List<OwnedStoreGame> Games { get; set; } = new();
            [JsonPropertyName("downloads")] public Dictionary<string, string> Downloads { get; set; } = new();
        }

        private static readonly object Lock = new();
        private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

        /// <summary>Raised after a store library was replaced so the Games section can merge it.</summary>
        public static event Action? Changed;

        public static string Normalize(string? title)
        {
            if (string.IsNullOrWhiteSpace(title)) return "";
            var sb = new StringBuilder();
            foreach (char c in title) if (char.IsLetterOrDigit(c)) sb.Append(char.ToLowerInvariant(c));
            return sb.ToString();
        }

        private static string FilePath(string user) => Path.Combine(
            UserDataService.DataRoot, UserDataService.SanitiseFolderName(user), "Accounts", "owned-games.json");

        private static FileModel Read(string user)
        {
            try
            {
                string p = FilePath(user);
                if (File.Exists(p)) return JsonSerializer.Deserialize<FileModel>(File.ReadAllText(p)) ?? new();
            }
            catch (Exception ex) { DevLogService.Log($"[OwnedGames] load failed: {ex.Message}"); }
            return new();
        }

        private static void Write(string user, FileModel m)
        {
            try
            {
                string p = FilePath(user);
                Directory.CreateDirectory(Path.GetDirectoryName(p)!);
                File.WriteAllText(p, JsonSerializer.Serialize(m, Json));
            }
            catch (Exception ex) { DevLogService.Log($"[OwnedGames] save failed: {ex.Message}"); }
        }

        public static List<OwnedStoreGame> All(string? user)
        {
            if (string.IsNullOrEmpty(user)) return new();
            lock (Lock) return Read(user).Games;
        }

        /// <summary>Replaces everything cached for <paramref name="store"/>.</summary>
        public static void ReplaceStore(string? user, string store, IEnumerable<OwnedStoreGame> games)
        {
            if (string.IsNullOrEmpty(user)) return;
            lock (Lock)
            {
                var m = Read(user);
                m.Games.RemoveAll(g => string.Equals(g.Store, store, StringComparison.OrdinalIgnoreCase));
                m.Games.AddRange(games.Where(g => !string.IsNullOrWhiteSpace(g.Title)));
                Write(user, m);
            }
            Changed?.Invoke();
        }

        /// <summary>Copies of this title owned on stores, one per store.</summary>
        public static List<OwnedStoreGame> FindOwned(string? user, string title)
        {
            string key = Normalize(title);
            if (key.Length == 0) return new();
            return All(user).Where(g => Normalize(g.Title) == key)
                .GroupBy(g => g.Store, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
        }

        public static string? GetDownloadUrl(string? user, string title)
        {
            if (string.IsNullOrEmpty(user)) return null;
            lock (Lock) return Read(user).Downloads.TryGetValue(Normalize(title), out var u) ? u : null;
        }

        public static void SetDownloadUrl(string? user, string title, string url)
        {
            if (string.IsNullOrEmpty(user) || Normalize(title).Length == 0) return;
            lock (Lock)
            {
                var m = Read(user);
                m.Downloads[Normalize(title)] = url;
                Write(user, m);
            }
        }
    }
}
