using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GameLauncher.Services
{
    /// <summary>A user-saved web link attached to a game / ROM (download page, walkthrough, guide...).</summary>
    public sealed class GameLink
    {
        public const string KindDownload = "Download";
        public const string KindWalkthrough = "Walkthrough";
        public const string KindGuide = "Guide";
        public const string KindOther = "Other";
        public static readonly string[] Kinds = { KindDownload, KindWalkthrough, KindGuide, KindOther };

        [JsonPropertyName("id")]       public string Id { get; set; } = Guid.NewGuid().ToString("N");
        [JsonPropertyName("platform")] public string Platform { get; set; } = "";
        [JsonPropertyName("game")]     public string Game { get; set; } = "";
        [JsonPropertyName("name")]     public string Name { get; set; } = "";
        [JsonPropertyName("url")]      public string Url { get; set; } = "";
        [JsonPropertyName("kind")]     public string Kind { get; set; } = KindOther;
        [JsonPropertyName("created")]  public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

        [JsonIgnore] public bool IsGuideLike => Kind is KindWalkthrough or KindGuide;
        [JsonIgnore] public string Icon => Kind switch { KindDownload => "⬇", KindWalkthrough => "📖", KindGuide => "📘", _ => "🔗" };
    }

    /// <summary>
    /// Client-only per-game link store: <c>Data/GameLinks/{Platform}/{Game}/urls.json</c> (e.g. <c>Xbox 360/Skate 3/urls.json</c>),
    /// next to the other per-game data. Downloads started from a saved page (or while the browser is open for a game) reuse the game's name and platform.
    /// </summary>
    public static class GameLinksService
    {
        private static readonly string Root = Path.Combine(UserDataService.DataRoot, "GameLinks");
        private static readonly string LegacyFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameOS", "Urls.json");
        private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };
        private static readonly object Gate = new();
        private static List<GameLink>? _cache;

        public static event Action? Changed;

        private static string FileFor(string platform, string game) => Path.Combine(
            Root, UserDataService.SanitiseFolderName(platform.Trim()), UserDataService.SanitiseFolderName(game.Trim()), "urls.json");

        // All links across every game (small); loaded once, then kept in memory and written back per game.
        private static List<GameLink> All()
        {
            lock (Gate)
            {
                if (_cache != null) return _cache;
                _cache = new();
                try
                {
                    if (Directory.Exists(Root))
                        foreach (var f in Directory.EnumerateFiles(Root, "urls.json", SearchOption.AllDirectories))
                            _cache.AddRange(JsonSerializer.Deserialize<List<GameLink>>(File.ReadAllText(f)) ?? new());

                    if (File.Exists(LegacyFile))
                    {
                        var old = JsonSerializer.Deserialize<List<GameLink>>(File.ReadAllText(LegacyFile)) ?? new();
                        foreach (var l in old.Where(l => !_cache.Any(c => c.Id == l.Id))) _cache.Add(l);
                        foreach (var key in old.Select(l => (l.Platform, l.Game)).Distinct()) SaveGame(key.Platform, key.Game);
                        File.Move(LegacyFile, LegacyFile + ".migrated", true);
                    }
                }
                catch (Exception ex) { DevLogService.Log($"[Urls] load failed: {ex.Message}"); }
                return _cache;
            }
        }

        private static void SaveGame(string platform, string game)
        {
            try
            {
                string path = FileFor(platform, game);
                var mine = All().Where(l => Norm(l.Platform) == Norm(platform) && Norm(l.Game) == Norm(game)).ToList();
                if (mine.Count == 0) { if (File.Exists(path)) File.Delete(path); return; }
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, JsonSerializer.Serialize(mine, Opts));
            }
            catch (Exception ex) { DevLogService.Log($"[Urls] save failed: {ex.Message}"); }
        }

        public static string Norm(string? s) => (s ?? "").Trim().ToLowerInvariant();

        /// <summary>Compares URLs ignoring scheme, "www.", fragment and trailing slash.</summary>
        public static string NormUrl(string? url)
        {
            if (!Uri.TryCreate((url ?? "").Trim(), UriKind.Absolute, out var u)) return Norm(url);
            string host = u.Host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? u.Host[4..] : u.Host;
            return (host + u.AbsolutePath.TrimEnd('/') + u.Query).ToLowerInvariant();
        }

        public static IReadOnlyList<GameLink> ForGame(string? platform, string? game)
        {
            string p = Norm(platform), g = Norm(game);
            lock (Gate)
                return All().Where(l => Norm(l.Platform) == p && Norm(l.Game) == g)
                    .OrderBy(l => l.IsGuideLike ? 0 : 1).ThenBy(l => l.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static GameLink? FindByUrl(string? url)
        {
            string n = NormUrl(url);
            if (n.Length == 0) return null;
            lock (Gate) return All().FirstOrDefault(l => NormUrl(l.Url) == n);
        }

        public static GameLink Add(string platform, string game, string name, string url, string kind)
        {
            GameLink link;
            lock (Gate)
            {
                var existing = All().FirstOrDefault(l => Norm(l.Platform) == Norm(platform) && Norm(l.Game) == Norm(game) && NormUrl(l.Url) == NormUrl(url));
                if (existing != null)
                {
                    if (!string.IsNullOrWhiteSpace(name)) existing.Name = name.Trim();
                    existing.Kind = kind;
                    link = existing;
                }
                else
                {
                    link = new GameLink { Platform = platform.Trim(), Game = game.Trim(), Name = string.IsNullOrWhiteSpace(name) ? url : name.Trim(), Url = url.Trim(), Kind = kind };
                    All().Add(link);
                }
                SaveGame(platform, game);
            }
            Changed?.Invoke();
            return link;
        }

        public static void Remove(GameLink link)
        {
            lock (Gate)
            {
                All().RemoveAll(l => l.Id == link.Id);
                SaveGame(link.Platform, link.Game);
            }
            Changed?.Invoke();
        }
    }
}
