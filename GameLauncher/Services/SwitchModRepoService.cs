using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>
    /// Browses the Game OS Switch mods database (<c>Koriebonx98/Game_OS.Mods.switch</c>). Layout:
    /// <c>{Game Name}/{Category}/{Mod}/{mod}.zip|rar|7z</c> (plus optional .txt descriptions); each archive is one mod.
    /// </summary>
    public static class SwitchModRepoService
    {
        public const string Repo = "Koriebonx98/Game_OS.Mods.switch";
        private static readonly string[] ArchiveExts = { ".zip", ".rar", ".7z" };
        private static readonly HttpClient Http = CreateHttp();

        private static HttpClient CreateHttp()
        {
            var h = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            h.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher");
            h.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            return h;
        }

        public sealed record RepoMod(string Name, string Category, string Path, string DownloadUrl);

        public static string CacheDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameOS", "SwitchModsRepo");
        private static string TreeCache => Path.Combine(CacheDir, "tree.json");

        public static bool IsModArchive(string path) =>
            ArchiveExts.Contains(Path.GetExtension(path ?? "").ToLowerInvariant());

        private static string Norm(string? s) =>
            new string((s ?? "").Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();

        /// <summary>True when a repo folder name refers to the game (same name ignoring punctuation/case, or the TitleID).</summary>
        public static bool FolderMatchesGame(string folder, string? gameTitle, string? titleId)
        {
            string f = Norm(folder), g = Norm(gameTitle);
            if (f.Length == 0) return false;
            if (!string.IsNullOrEmpty(titleId) && f == Norm(titleId)) return true;
            return g.Length > 0 && f == g;
        }

        /// <summary>Extracts the archive mods of the game's folder from a git-tree listing (<c>tree[].path</c> / <c>type</c>).</summary>
        public static List<RepoMod> ParseTree(string treeJson, string? gameTitle, string? titleId)
        {
            var list = new List<RepoMod>();
            using var doc = JsonDocument.Parse(treeJson);
            if (!doc.RootElement.TryGetProperty("tree", out var tree) || tree.ValueKind != JsonValueKind.Array) return list;
            foreach (var el in tree.EnumerateArray())
            {
                if (!el.TryGetProperty("type", out var t) || t.GetString() != "blob") continue;
                string path = el.TryGetProperty("path", out var p) ? p.GetString() ?? "" : "";
                var parts = path.Split('/');
                if (parts.Length < 2 || !IsModArchive(path) || !FolderMatchesGame(parts[0], gameTitle, titleId)) continue;

                string name = Path.GetFileNameWithoutExtension(parts[^1]);
                var cat = parts.Skip(1).Take(parts.Length - 2).ToList();
                if (cat.Count > 0 && Norm(cat[^1]) == Norm(name)) cat.RemoveAt(cat.Count - 1);
                string url = $"https://raw.githubusercontent.com/{Repo}/HEAD/" +
                             string.Join("/", parts.Select(Uri.EscapeDataString));
                list.Add(new RepoMod(name, string.Join(" › ", cat), path, url));
            }
            return list.OrderBy(m => m.Category, StringComparer.OrdinalIgnoreCase)
                       .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>Lists the repo's mods for a game; refreshes the cached tree when older than 1 hour and falls back to it offline.</summary>
        public static async Task<List<RepoMod>> GetModsAsync(string? gameTitle, string? titleId, CancellationToken ct = default)
        {
            string? json = null;
            try
            {
                Directory.CreateDirectory(CacheDir);
                if (!File.Exists(TreeCache) || DateTime.UtcNow - File.GetLastWriteTimeUtc(TreeCache) > TimeSpan.FromHours(1))
                {
                    json = await Http.GetStringAsync($"https://api.github.com/repos/{Repo}/git/trees/HEAD?recursive=1", ct);
                    File.WriteAllText(TreeCache, json);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { json = null; }
            try { json ??= File.Exists(TreeCache) ? File.ReadAllText(TreeCache) : null; } catch { }
            if (string.IsNullOrEmpty(json)) return new List<RepoMod>();
            try { return ParseTree(json, gameTitle, titleId); } catch { return new List<RepoMod>(); }
        }

        /// <summary>Downloads the mod and extracts it to <c>{modsContentDir}/{Name}</c> (Ryujinx layout). Returns that folder.</summary>
        public static async Task<string> InstallAsync(string downloadUrl, string modName, string modsContentDir, CancellationToken ct = default)
        {
            string safe = string.Concat(modName.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c)).Trim();
            if (safe.Length == 0) safe = "mod";
            string dest = Path.Combine(modsContentDir, safe);
            if (Directory.Exists(dest)) throw new IOException($"'{safe}' is already installed.");

            Directory.CreateDirectory(modsContentDir);
            string work = Path.Combine(Path.GetTempPath(), "gameos-swmod-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            try
            {
                string archive = Path.Combine(work, "mod" + Path.GetExtension(new Uri(downloadUrl).AbsolutePath));
                using (var resp = await Http.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
                {
                    resp.EnsureSuccessStatusCode();
                    await using var fs = File.Create(archive);
                    await resp.Content.CopyToAsync(fs, ct);
                }
                string extracted = Path.Combine(work, "x");
                await ArchiveExtractor.ExtractAsync(archive, extracted, null, ct);

                string content = extracted;
                string[] ryujinxDirs = { "romfs", "exefs", "cheats" };
                while (!Directory.EnumerateFiles(content).Any() && Directory.GetDirectories(content) is { Length: 1 } one
                       && !ryujinxDirs.Contains(Path.GetFileName(one[0]), StringComparer.OrdinalIgnoreCase))
                    content = one[0];
                Directory.Move(content, dest);
                return dest;
            }
            finally { try { Directory.Delete(work, true); } catch { } }
        }
    }
}
