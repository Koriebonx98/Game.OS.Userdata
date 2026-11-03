using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GameLauncher.Services
{
    /// <summary>Credentials / cache data for one game store, tied to a single Game.OS account.</summary>
    public sealed class StoreAccount
    {
        [JsonPropertyName("store")]   public string Store   { get; set; } = "";
        /// <summary>API key (Steam Web API key, itch.io key, RAWG-style keys …).</summary>
        [JsonPropertyName("apiKey")]  public string ApiKey  { get; set; } = "";
        /// <summary>Store account / profile id (SteamID64, Epic account id, Xbox gamertag, GOG user …).</summary>
        [JsonPropertyName("userId")]  public string UserId  { get; set; } = "";
        /// <summary>Session token / login cache captured from the built-in browser or pasted by the user.</summary>
        [JsonPropertyName("token")]   public string Token   { get; set; } = "";
        [JsonPropertyName("updated")] public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;

        [JsonIgnore] public bool IsEmpty =>
            string.IsNullOrWhiteSpace(ApiKey) && string.IsNullOrWhiteSpace(UserId) && string.IsNullOrWhiteSpace(Token);
    }

    /// <summary>Static description of a supported store (login page, which fields apply).</summary>
    public sealed record StoreInfo(string Name, string Icon, string LoginUrl, string ApiKeyLabel, string UserIdLabel, string TokenLabel, string StoreUrlHost);

    /// <summary>
    /// Per-account store credentials (Playnite-style): <c>Data/{user}/Accounts/stores.json</c>.
    /// Every Game.OS account has its own keys — nothing is shared between accounts or uploaded to the cloud.
    /// </summary>
    public static class StoreAccountsService
    {
        public static readonly StoreInfo[] Stores =
        {
            new("Steam",      "🎮", "https://store.steampowered.com/login/", "Web API key", "SteamID64", "", "store.steampowered.com"),
            new("Epic Games", "🛒", "https://www.epicgames.com/id/login",    "", "Account ID", "Session / exchange token", "store.epicgames.com"),
            new("GOG",        "🌌", "https://www.gog.com/en/account",        "", "Username", "Session cookie", "gog.com"),
            new("Xbox",       "🟩", "https://www.xbox.com/en-US/auth/msa?action=logIn", "OpenXBL API key", "Gamertag", "", "xbox.com"),
            new("EA",         "⚡", "https://www.ea.com/login",              "", "EA account", "Session token", "ea.com"),
            new("Ubisoft",    "🔷", "https://account.ubisoft.com/login",     "", "Ubisoft account", "Session token", "store.ubisoft.com"),
            new("Battle.net", "❄", "https://account.battle.net/login",       "", "BattleTag", "Session token", "battle.net"),
            new("itch.io",    "🎲", "https://itch.io/login",                 "itch.io API key", "Username", "", "itch.io"),
        };

        private static string Root(string host)
        {
            var parts = host.ToLowerInvariant().Split('.');
            return parts.Length <= 2 ? string.Join(".", parts) : string.Join(".", parts[^2..]);
        }

        /// <summary>The store whose login / store site matches <paramref name="host"/> (e.g. "www.gog.com" → GOG), or null.</summary>
        public static StoreInfo? FindByHost(string? host)
        {
            if (string.IsNullOrEmpty(host)) return null;
            string r = Root(host);
            foreach (var s in Stores)
            {
                if (Root(s.StoreUrlHost) == r) return s;
                if (Uri.TryCreate(s.LoginUrl, UriKind.Absolute, out var u) && Root(u.Host) == r) return s;
            }
            return null;
        }

        private static readonly object Lock = new();
        private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
        private static string? _user;
        private static Dictionary<string, StoreAccount>? _cache;

        public static void SetCurrentUser(string? username)
        {
            lock (Lock)
            {
                _user = string.IsNullOrWhiteSpace(username) ? null : username;
                _cache = null;
            }
        }

        public static string? CurrentUser { get { lock (Lock) return _user; } }

        private static string FilePath => Path.Combine(
            UserDataService.DataRoot, UserDataService.SanitiseFolderName(_user ?? "_shared"), "Accounts", "stores.json");

        /// <summary>True when this account already has a stores file (used to migrate the old global Steam key once).</summary>
        public static bool HasFile { get { lock (Lock) return File.Exists(FilePath); } }

        private static Dictionary<string, StoreAccount> Load()
        {
            if (_cache != null) return _cache;
            var map = new Dictionary<string, StoreAccount>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (File.Exists(FilePath))
                    foreach (var a in JsonSerializer.Deserialize<List<StoreAccount>>(File.ReadAllText(FilePath)) ?? new())
                        map[a.Store] = a;
            }
            catch (Exception ex) { DevLogService.Log($"[StoreAccounts] load failed: {ex.Message}"); }
            return _cache = map;
        }

        /// <summary>Raised after a login was captured from the browser so open settings pages can refresh.</summary>
        public static event Action? Captured;

        public static void CaptureToken(string store, string token)
        {
            var a = Get(store);
            Set(store, a.ApiKey, a.UserId, token);
            Captured?.Invoke();
        }

        public static StoreAccount Get(string store)
        {
            lock (Lock)
                return Load().TryGetValue(store, out var a) ? a : new StoreAccount { Store = store };
        }

        public static IReadOnlyList<StoreAccount> All()
        {
            lock (Lock) return Load().Values.Where(a => !a.IsEmpty).ToList();
        }

        public static void Set(string store, string apiKey, string userId, string token)
        {
            lock (Lock)
            {
                var map = Load();
                var entry = new StoreAccount
                {
                    Store = store, ApiKey = (apiKey ?? "").Trim(), UserId = (userId ?? "").Trim(),
                    Token = (token ?? "").Trim(), UpdatedUtc = DateTime.UtcNow,
                };
                if (entry.IsEmpty) map.Remove(store); else map[store] = entry;
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                    File.WriteAllText(FilePath, JsonSerializer.Serialize(map.Values.ToList(), Json));
                }
                catch (Exception ex) { DevLogService.Log($"[StoreAccounts] save failed: {ex.Message}"); }
            }
        }
    }
}
