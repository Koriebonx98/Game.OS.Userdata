using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>
    /// Reads the community Koriebonx98/Game_OS.Mods.switch repository, laid out as
    /// <c>{GameName}/{ModType}/{Mod}/</c>, where each mod folder holds its archive(s) and a
    /// <c>.txt</c> describing the mod (author, version, notes).
    /// </summary>
    public static class SwitchModsRepoService
    {
        public const string Owner = "Koriebonx98";
        public const string Repo = "Game_OS.Mods.switch";
        public const string Branch = "main";

        private static readonly string[] ArchiveExts = { ".zip", ".7z", ".rar" };
        private static List<(string Path, bool IsDir)>? _tree;
        private static readonly SemaphoreSlim Gate = new(1, 1);
        private static readonly Dictionary<string, string> TextCache = new();

        public static string Normalize(string? s) => Regex.Replace((s ?? "").ToLowerInvariant(), @"[^a-z0-9]", "");

        public static async Task<List<GameModEntry>> GetModsForGameAsync(string gameTitle, CancellationToken ct = default)
        {
            var result = new List<GameModEntry>();
            if (string.IsNullOrWhiteSpace(gameTitle)) return result;
            var tree = await LoadTreeAsync(ct);
            if (tree == null) return result;

            string want = Normalize(gameTitle);
            var gameDir = tree.Where(e => e.IsDir && !e.Path.Contains('/'))
                              .Select(e => e.Path)
                              .FirstOrDefault(n => Normalize(n) == want);
            if (gameDir == null) return result;

            // Mod folders are exactly two levels below the game folder: Game/ModType/Mod
            foreach (var modDir in tree.Where(e => e.IsDir && e.Path.StartsWith(gameDir + "/", StringComparison.Ordinal))
                                       .Select(e => e.Path)
                                       .Where(p => p.Split('/').Length == 3)
                                       .OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
            {
                var parts = modDir.Split('/');
                var files = tree.Where(e => !e.IsDir && e.Path.StartsWith(modDir + "/", StringComparison.Ordinal)
                                            && e.Path.IndexOf('/', modDir.Length + 1) < 0)
                                .Select(e => e.Path).ToList();
                var archives = files.Where(f => ArchiveExts.Any(x => f.EndsWith(x, StringComparison.OrdinalIgnoreCase))).ToList();
                var txt = files.FirstOrDefault(f => f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase));

                string info = txt != null ? await FetchTextAsync(txt, ct) : "";
                string description = BuildDescription(info, archives.Count);

                result.Add(new GameModEntry
                {
                    Name = parts[2],
                    Url = archives.Count == 1 ? RawUrl(archives[0]) : TreeUrl(modDir),
                    Description = description,
                    Genres = new List<string> { "Switch Mods", parts[1] },
                });
            }
            return result;
        }

        /// <summary>Collapses the mod's .txt (author, version, notes) into a short single description.</summary>
        public static string BuildDescription(string? info, int archiveCount)
        {
            var text = Regex.Replace((info ?? "").Trim(), @"\s*\r?\n\s*", "\n");
            if (archiveCount > 1) text += (text.Length > 0 ? "\n" : "") + $"{archiveCount} downloads available — opens the repository folder.";
            return text;
        }

        private static string TreeUrl(string path) =>
            $"https://github.com/{Owner}/{Repo}/tree/{Branch}/{Escape(path)}";

        private static string RawUrl(string path) =>
            $"https://raw.githubusercontent.com/{Owner}/{Repo}/{Branch}/{Escape(path)}";

        private static string Escape(string path) => string.Join("/", path.Split('/').Select(Uri.EscapeDataString));

        private static HttpClient NewClient()
        {
            var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher");
            return http;
        }

        private static async Task<List<(string Path, bool IsDir)>?> LoadTreeAsync(CancellationToken ct)
        {
            await Gate.WaitAsync(ct);
            try
            {
                if (_tree != null) return _tree;
                using var http = NewClient();
                http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
                var json = await http.GetStringAsync($"https://api.github.com/repos/{Owner}/{Repo}/git/trees/{Branch}?recursive=1", ct);
                using var doc = JsonDocument.Parse(json);
                var list = new List<(string, bool)>();
                foreach (var e in doc.RootElement.GetProperty("tree").EnumerateArray())
                {
                    var path = e.GetProperty("path").GetString();
                    if (string.IsNullOrEmpty(path)) continue;
                    list.Add((path, e.GetProperty("type").GetString() == "tree"));
                }
                return _tree = list;
            }
            catch (OperationCanceledException) { throw; }
            catch { return null; }
            finally { Gate.Release(); }
        }

        private static async Task<string> FetchTextAsync(string path, CancellationToken ct)
        {
            lock (TextCache) if (TextCache.TryGetValue(path, out var cached)) return cached;
            try
            {
                using var http = NewClient();
                var text = await http.GetStringAsync(RawUrl(path), ct);
                lock (TextCache) TextCache[path] = text;
                return text;
            }
            catch (OperationCanceledException) { throw; }
            catch { return ""; }
        }
    }
}
