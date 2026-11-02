using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>A mod type preset a user can tag a mod URL with; also maps to well-known game sub-folders.</summary>
    public sealed record ModTypePreset(string Name, string Icon, string[] Folders);

    /// <summary>A mod / mod folder entry found on disk for a game.</summary>
    public sealed class InstalledMod
    {
        public string Name     { get; set; } = "";
        public string Path     { get; set; } = "";
        public string TypeName { get; set; } = "Mod";
        public string Source   { get; set; } = "Game folder";
        public bool   IsDirectory { get; set; }
        public string Icon => TypeName switch
        {
            "DLC"    => "🎁",
            "Update" => "⬆",
            _        => GameModsService.PresetFor(TypeName)?.Icon ?? "🧩",
        };
        public string Subtitle => $"{TypeName} · {Source}";
    }

    /// <summary>
    /// Per-game mod support: type presets, detection of installed mods (game sub-folders such as
    /// <c>mods</c>/<c>usermaps</c> and Steam Workshop content), move/delete, and Steam Workshop downloads via SteamCMD.
    /// </summary>
    public static class GameModsService
    {
        public static readonly ModTypePreset[] Presets =
        {
            new("Mod Client",   "🎮", new[] { "mods", "mod", "clientmods", "usermods", "user mods", "usermod" }),
            new("Recomp",       "🛠", new[] { "recomp", "recompiled" }),
            new("Usermaps",     "🗺", new[] { "usermaps", "usermap", "custommaps" }),
            new("Texture Pack", "🖼", new[] { "texturepacks", "texture packs", "textures", "texturepack", "resourcepacks" }),
            new("Track",        "🏁", new[] { "tracks", "track" }),
            new("Level",        "🧱", new[] { "levels", "level", "maps" }),
        };

        public static string[] PresetNames => Presets.Select(p => p.Name).ToArray();

        public static ModTypePreset? PresetFor(string? name) =>
            Presets.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));

        /// <summary>Maps a folder name (e.g. "usermaps") to its preset, or null when it isn't a known mod folder.</summary>
        public static ModTypePreset? PresetForFolder(string folderName) =>
            Presets.FirstOrDefault(p => p.Folders.Contains(folderName.Trim(), StringComparer.OrdinalIgnoreCase));

        // ── Installed detection ─────────────────────────────────────────────

        /// <summary>Known mod folders directly inside <paramref name="gameDir"/>, each with its type.</summary>
        public static IReadOnlyList<(string Path, ModTypePreset Type)> DetectModFolders(string? gameDir)
        {
            var list = new List<(string, ModTypePreset)>();
            if (string.IsNullOrWhiteSpace(gameDir) || !Directory.Exists(gameDir)) return list;
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(gameDir))
                    if (PresetForFolder(System.IO.Path.GetFileName(dir)) is { } p) list.Add((dir, p));
            }
            catch { /* best-effort */ }
            return list;
        }

        public static List<InstalledMod> ScanInstalled(string? gameDir, int steamAppId)
        {
            var result = new List<InstalledMod>();
            foreach (var (folder, type) in DetectModFolders(gameDir))
            {
                try
                {
                    foreach (var entry in Directory.EnumerateFileSystemEntries(folder))
                        result.Add(new InstalledMod
                        {
                            Name = System.IO.Path.GetFileName(entry),
                            Path = entry,
                            TypeName = type.Name,
                            Source = System.IO.Path.GetFileName(folder) + " folder",
                            IsDirectory = Directory.Exists(entry),
                        });
                }
                catch { /* best-effort */ }
            }

            if (steamAppId > 0)
            {
                foreach (var content in WorkshopContentDirs(steamAppId))
                {
                    try
                    {
                        foreach (var item in Directory.EnumerateDirectories(content))
                            result.Add(new InstalledMod
                            {
                                Name = "Workshop item " + System.IO.Path.GetFileName(item),
                                Path = item,
                                TypeName = "Mod Client",
                                Source = "Steam Workshop",
                                IsDirectory = true,
                            });
                    }
                    catch { /* best-effort */ }
                }
            }
            return result.OrderBy(m => m.TypeName).ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        // ── Steam locations ─────────────────────────────────────────────────

        public static IEnumerable<string> SteamRoots()
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var cands = new List<string>
            {
                @"C:\Program Files (x86)\Steam", @"C:\Program Files\Steam",
                System.IO.Path.Combine(home, ".steam", "steam"),
                System.IO.Path.Combine(home, ".local", "share", "Steam"),
                System.IO.Path.Combine(home, "Library", "Application Support", "Steam"),
            };
            return cands.Where(Directory.Exists);
        }

        /// <summary>Every Steam library's <c>steamapps</c> folder (from libraryfolders.vdf plus the defaults).</summary>
        public static IEnumerable<string> SteamLibraries()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var root in SteamRoots())
            {
                var apps = System.IO.Path.Combine(root, "steamapps");
                if (Directory.Exists(apps) && seen.Add(apps)) yield return apps;
                var vdf = System.IO.Path.Combine(apps, "libraryfolders.vdf");
                if (!File.Exists(vdf)) continue;
                string text;
                try { text = File.ReadAllText(vdf); } catch { continue; }
                foreach (Match m in Regex.Matches(text, "\"path\"\\s+\"([^\"]+)\""))
                {
                    var lib = System.IO.Path.Combine(m.Groups[1].Value.Replace(@"\\", @"\"), "steamapps");
                    if (Directory.Exists(lib) && seen.Add(lib)) yield return lib;
                }
            }
        }

        public static string? FindSteamGameDir(int appId)
        {
            if (appId <= 0) return null;
            foreach (var lib in SteamLibraries())
            {
                var manifest = System.IO.Path.Combine(lib, $"appmanifest_{appId}.acf");
                if (!File.Exists(manifest)) continue;
                try
                {
                    var m = Regex.Match(File.ReadAllText(manifest), "\"installdir\"\\s+\"([^\"]+)\"");
                    if (!m.Success) continue;
                    var dir = System.IO.Path.Combine(lib, "common", m.Groups[1].Value);
                    if (Directory.Exists(dir)) return dir;
                }
                catch { /* try next library */ }
            }
            return null;
        }

        private static IEnumerable<string> WorkshopContentDirs(int appId)
        {
            foreach (var lib in SteamLibraries())
            {
                var d = System.IO.Path.Combine(lib, "workshop", "content", appId.ToString());
                if (Directory.Exists(d)) yield return d;
            }
            var own = System.IO.Path.Combine(SteamCmdDir, "steamapps", "workshop", "content", appId.ToString());
            if (Directory.Exists(own)) yield return own;
        }

        // ── Move / delete ───────────────────────────────────────────────────

        public static void Delete(InstalledMod mod)
        {
            if (mod.IsDirectory) Directory.Delete(mod.Path, true);
            else File.Delete(mod.Path);
        }

        /// <summary>Moves the mod into <paramref name="destFolder"/> (created if missing). Returns the new path.</summary>
        public static string Move(InstalledMod mod, string destFolder)
        {
            Directory.CreateDirectory(destFolder);
            var dest = System.IO.Path.Combine(destFolder, System.IO.Path.GetFileName(mod.Path));
            if (File.Exists(dest) || Directory.Exists(dest)) throw new IOException("Destination already contains " + System.IO.Path.GetFileName(dest));
            if (mod.IsDirectory) Directory.Move(mod.Path, dest);
            else File.Move(mod.Path, dest);
            return dest;
        }

        // ── GitHub releases ─────────────────────────────────────────────────

        public sealed record GitHubAsset(string Name, string Url);

        /// <summary>Parses "https://github.com/{owner}/{repo}/releases[/...]" into (owner, repo); null for other URLs.</summary>
        public static (string Owner, string Repo)? ParseGitHubReleaseUrl(string? url)
        {
            var m = Regex.Match((url ?? "").Trim(), @"^https?://(?:www\.)?github\.com/([^/\s]+)/([^/\s?#]+)/releases(?:[/?#]|$)", RegexOptions.IgnoreCase);
            return m.Success ? (m.Groups[1].Value, m.Groups[2].Value) : null;
        }

        /// <summary>Picks the release asset to install: skips checksums/signatures, prefers the current OS, then archives/installers.</summary>
        public static GitHubAsset? PickReleaseAsset(IReadOnlyList<GitHubAsset> assets)
        {
            string[] skip = { ".sha256", ".sha512", ".md5", ".sig", ".asc", ".txt", ".json", ".yml", ".yaml", ".blockmap", ".sbom" };
            var cands = assets.Where(a => !skip.Any(x => a.Name.EndsWith(x, StringComparison.OrdinalIgnoreCase))).ToList();
            if (cands.Count == 0) return null;
            string[] os = OperatingSystem.IsWindows() ? new[] { "win", "windows", ".exe", ".msi" }
                        : OperatingSystem.IsMacOS()   ? new[] { "mac", "macos", "osx", "darwin", ".dmg" }
                        :                               new[] { "linux", ".appimage", ".deb" };
            string[] other = { "win", "windows", "mac", "macos", "osx", "darwin", "linux", "android", "ios" };
            int Score(GitHubAsset a)
            {
                string n = a.Name.ToLowerInvariant();
                int sc = 0;
                if (os.Any(n.Contains)) sc += 10;
                else if (other.Any(n.Contains)) sc -= 10;
                if (n.EndsWith(".zip") || n.EndsWith(".7z") || n.EndsWith(".rar") || n.EndsWith(".exe") || n.EndsWith(".msi")) sc += 2;
                return sc;
            }
            return cands.OrderByDescending(Score).First();
        }

        public static async Task<(string Tag, GitHubAsset? Asset)?> GetLatestReleaseAssetAsync(string owner, string repo, CancellationToken ct = default)
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher");
            http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            try
            {
                var json = await http.GetStringAsync($"https://api.github.com/repos/{owner}/{repo}/releases/latest", ct);
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                string tag = doc.RootElement.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
                var assets = new List<GitHubAsset>();
                if (doc.RootElement.TryGetProperty("assets", out var arr))
                    foreach (var a in arr.EnumerateArray())
                        assets.Add(new GitHubAsset(a.GetProperty("name").GetString() ?? "", a.GetProperty("browser_download_url").GetString() ?? ""));
                return (tag, PickReleaseAsset(assets));
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                DevLogService.Log($"[Mods] GitHub release lookup failed: {ex.Message}");
                return null;
            }
        }

        // ── Steam Workshop ──────────────────────────────────────────────────

        public static string WorkshopUrl(int appId) => $"https://steamcommunity.com/app/{appId}/workshop/";

        /// <summary>Extracts a workshop item id from a URL ("...?id=123") or a bare number.</summary>
        public static string? ParseWorkshopId(string? input)
        {
            var s = (input ?? "").Trim();
            if (Regex.IsMatch(s, @"^\d{3,}$")) return s;
            var m = Regex.Match(s, @"steamcommunity\.com/(?:sharedfiles|workshop)/filedetails/?\?(?:[^#]*&)?id=(\d+)", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : null;
        }

        public static string SteamCmdDir => System.IO.Path.Combine(Services.UserDataService.DataRoot, "SteamCMD");

        public static string SteamCmdExe => System.IO.Path.Combine(SteamCmdDir,
            OperatingSystem.IsWindows() ? "steamcmd.exe" : "steamcmd.sh");

        /// <summary>Downloads SteamCMD on first use (Windows zip / Linux & macOS tarball).</summary>
        public static async Task<bool> EnsureSteamCmdAsync(IProgress<string>? status, CancellationToken ct = default)
        {
            if (File.Exists(SteamCmdExe)) return true;
            try
            {
                Directory.CreateDirectory(SteamCmdDir);
                using var http = new HttpClient();
                status?.Report("Downloading SteamCMD…");
                if (OperatingSystem.IsWindows())
                {
                    var zip = System.IO.Path.Combine(SteamCmdDir, "steamcmd.zip");
                    await File.WriteAllBytesAsync(zip, await http.GetByteArrayAsync("https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip", ct), ct);
                    ZipFile.ExtractToDirectory(zip, SteamCmdDir, true);
                    File.Delete(zip);
                }
                else
                {
                    var url = OperatingSystem.IsMacOS()
                        ? "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_osx.tar.gz"
                        : "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz";
                    var tgz = System.IO.Path.Combine(SteamCmdDir, "steamcmd.tar.gz");
                    await File.WriteAllBytesAsync(tgz, await http.GetByteArrayAsync(url, ct), ct);
                    using var tar = Process.Start(new ProcessStartInfo("tar", $"-xzf \"{tgz}\" -C \"{SteamCmdDir}\"") { UseShellExecute = false });
                    if (tar != null) await tar.WaitForExitAsync(ct);
                    File.Delete(tgz);
                }
                return File.Exists(SteamCmdExe);
            }
            catch (Exception ex)
            {
                DevLogService.Log($"[Mods] SteamCMD install failed: {ex.Message}");
                status?.Report("SteamCMD download failed: " + ex.Message);
                return false;
            }
        }

        /// <summary>Downloads a workshop item anonymously with SteamCMD; returns the content folder on success.</summary>
        public static async Task<string?> DownloadWorkshopItemAsync(int appId, string itemId, IProgress<string>? status, CancellationToken ct = default)
        {
            if (appId <= 0 || !Regex.IsMatch(itemId, @"^\d+$")) return null;
            if (!await EnsureSteamCmdAsync(status, ct)) return null;
            try
            {
                status?.Report($"Downloading workshop item {itemId}…");
                var psi = new ProcessStartInfo(SteamCmdExe,
                    $"+force_install_dir \"{SteamCmdDir}\" +login anonymous +workshop_download_item {appId} {itemId} +quit")
                {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
                    WorkingDirectory = SteamCmdDir,
                };
                using var p = Process.Start(psi);
                if (p == null) return null;
                string output = await p.StandardOutput.ReadToEndAsync(ct);
                await p.WaitForExitAsync(ct);
                var dir = System.IO.Path.Combine(SteamCmdDir, "steamapps", "workshop", "content", appId.ToString(), itemId);
                if (Directory.Exists(dir)) { status?.Report("Downloaded workshop item " + itemId); return dir; }
                status?.Report(output.Contains("No subscription", StringComparison.OrdinalIgnoreCase) || output.Contains("Failure", StringComparison.OrdinalIgnoreCase)
                    ? "Workshop download failed — this game may require a Steam account that owns it."
                    : "Workshop download failed.");
                return null;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                DevLogService.Log($"[Mods] workshop download failed: {ex.Message}");
                status?.Report("Workshop download failed: " + ex.Message);
                return null;
            }
        }
    }
}
