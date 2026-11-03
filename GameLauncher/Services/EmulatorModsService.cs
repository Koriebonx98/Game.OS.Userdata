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
    /// Emulator-level game mods that live outside the game itself:
    /// Xenia "optimized settings" (<c>{TitleID}.toml</c> from the xenia-manager/optimized-settings repo)
    /// and PS2 HD texture packs (<c>Roms/Sony - PlayStation 2/Mods/HD Texture packs/{Game}/{TitleID}</c>
    /// copied into PCSX2's <c>textures/{TitleID}</c> folder).
    /// Also lists per-platform <c>Mods</c> / <c>DLC</c> / <c>Updates</c> content under <c>Roms/{Platform}/</c>.
    /// </summary>
    public static class EmulatorModsService
    {
        public const string XeniaSettingsApi = "https://api.github.com/repos/xenia-manager/optimized-settings/contents/settings";
        public const string HdTexturePacksFolder = "HD Texture packs";
        public const string ManagedMarker = ".gameos-managed";

        /// <summary>Per-platform content folders next to <c>Games</c>, in display order.</summary>
        public static readonly (string Folder, string TypeName)[] ContentFolders =
        {
            ("Mods", "Mod"), ("DLC", "DLC"), ("Updates", "Update"),
        };

        private static readonly HttpClient Http = CreateHttp();

        private static HttpClient CreateHttp()
        {
            var h = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            h.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher");
            h.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            return h;
        }

        public static string CacheDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameOS", "XeniaOptimizedSettings");

        // ── Helpers ───────────────────────────────────────────────────────────

        /// <summary>Normalises an ID for comparison (upper-case, only letters/digits): "SLUS-20946" → "SLUS20946".</summary>
        public static string NormalizeId(string? id) =>
            new string((id ?? "").Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

        public static bool IsXeniaTitleId(string? id) =>
            id is { Length: 8 } && id.All(Uri.IsHexDigit);

        /// <summary><c>Roms/{Platform}</c> folder for a ROM inside <c>Roms/{Platform}/Games/…</c>, else null.</summary>
        public static string? PlatformDirForRom(string? romPath)
        {
            if (string.IsNullOrWhiteSpace(romPath)) return null;
            var gamesDir = RomPathHelper.FindRomsGamesDir(romPath);
            return gamesDir == null ? null : Path.GetDirectoryName(gamesDir);
        }

        // ── Xenia optimized settings ──────────────────────────────────────────

        public sealed record XeniaSettingEntry(string TitleId, string Sha, string DownloadUrl);

        private static string IndexPath => Path.Combine(CacheDir, "index.json");
        public static string CachedTomlPath(string titleId) => Path.Combine(CacheDir, titleId.ToUpperInvariant() + ".toml");

        public static List<XeniaSettingEntry> ParseListing(string json)
        {
            var list = new List<XeniaSettingEntry>();
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return list;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                string name = el.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                if (!name.EndsWith(".toml", StringComparison.OrdinalIgnoreCase)) continue;
                string id = Path.GetFileNameWithoutExtension(name).ToUpperInvariant();
                string sha = el.TryGetProperty("sha", out var s) ? s.GetString() ?? "" : "";
                string url = el.TryGetProperty("download_url", out var u) ? u.GetString() ?? "" : "";
                if (id.Length > 0 && url.Length > 0) list.Add(new XeniaSettingEntry(id, sha, url));
            }
            return list;
        }

        /// <summary>
        /// Refreshes the settings listing, then makes sure <paramref name="titleId"/>'s toml is cached and up to date
        /// (re-downloaded when the remote blob sha differs). Returns the cached path or null when none exists.
        /// Works offline using whatever was cached before.
        /// </summary>
        public static async Task<string?> EnsureXeniaSettingsAsync(string titleId, CancellationToken ct = default)
        {
            titleId = (titleId ?? "").Trim().ToUpperInvariant();
            if (!IsXeniaTitleId(titleId)) return null;
            string cached = CachedTomlPath(titleId);
            try
            {
                Directory.CreateDirectory(CacheDir);
                var shas = LoadShaIndex();
                if (shas.Count == 0 || !File.Exists(cached) || DateTime.UtcNow - File.GetLastWriteTimeUtc(IndexPath) > TimeSpan.FromHours(6))
                {
                    var listing = ParseListing(await Http.GetStringAsync(XeniaSettingsApi, ct));
                    var entry = listing.FirstOrDefault(e => e.TitleId == titleId);
                    if (entry == null) return File.Exists(cached) ? cached : null;

                    if (!File.Exists(cached) || !shas.TryGetValue(titleId, out var old) || old != entry.Sha)
                    {
                        var data = await Http.GetByteArrayAsync(entry.DownloadUrl, ct);
                        File.WriteAllBytes(cached, data);
                        shas[titleId] = entry.Sha;
                    }
                    File.WriteAllText(IndexPath, JsonSerializer.Serialize(shas));
                }
            }
            catch { /* offline / rate limited: fall back to cache */ }
            return File.Exists(cached) ? cached : null;
        }

        private static Dictionary<string, string> LoadShaIndex()
        {
            try
            {
                if (File.Exists(IndexPath))
                    return JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(IndexPath)) ?? new();
            }
            catch { }
            return new();
        }

        /// <summary>Xenia per-title config location: <c>{xeniaDir}/config/{TitleID}.config.toml</c>.</summary>
        public static string XeniaConfigPath(string xeniaExePath, string titleId) =>
            Path.Combine(Path.GetDirectoryName(xeniaExePath) ?? "", "config", titleId.ToUpperInvariant() + ".config.toml");

        public static bool IsXeniaSettingsEnabled(string xeniaExePath, string titleId, string cachedToml)
        {
            string cfg = XeniaConfigPath(xeniaExePath, titleId);
            try { return File.Exists(cfg) && (File.Exists(cfg + ManagedMarker) || File.ReadAllText(cfg) == File.ReadAllText(cachedToml)); }
            catch { return false; }
        }

        /// <summary>Installs the optimized toml as Xenia's config for the title; an existing user config is kept as <c>.gameos-bak</c>.</summary>
        public static void EnableXeniaSettings(string xeniaExePath, string titleId, string cachedToml)
        {
            string cfg = XeniaConfigPath(xeniaExePath, titleId);
            Directory.CreateDirectory(Path.GetDirectoryName(cfg)!);
            string bak = cfg + ".gameos-bak";
            if (File.Exists(cfg) && !File.Exists(bak) && File.ReadAllText(cfg) != File.ReadAllText(cachedToml))
                File.Copy(cfg, bak);
            File.Copy(cachedToml, cfg, overwrite: true);
            File.WriteAllText(cfg + ManagedMarker, "");
        }

        /// <summary>Marks the config as Game OS-managed so user edits made in the settings editor keep it "Enabled".</summary>
        public static void MarkXeniaConfigManaged(string xeniaExePath, string titleId) =>
            File.WriteAllText(XeniaConfigPath(xeniaExePath, titleId) + ManagedMarker, "");

        /// <summary>One <c>key = value</c> line of a Xenia toml; <see cref="Line"/> is its index in the file.</summary>
        public sealed record TomlSetting(string Section, string Key, string Value, int Line)
        {
            public bool IsBool => Value == "true" || Value == "false";
        }

        /// <summary>Lists the editable settings (non-comment <c>key = value</c> lines) of a toml, grouped by <c>[section]</c>.</summary>
        public static List<TomlSetting> ParseToml(string text)
        {
            var list = new List<TomlSetting>();
            string section = "";
            var lines = text.Replace("\r\n", "\n").Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                string t = lines[i].Trim();
                if (t.Length == 0 || t[0] == '#') continue;
                if (t[0] == '[' && t.EndsWith("]")) { section = t.Trim('[', ']').Trim(); continue; }
                int eq = t.IndexOf('=');
                if (eq <= 0) continue;
                string key = t[..eq].Trim();
                string val = StripTomlComment(t[(eq + 1)..]).Trim();
                if (key.Length > 0) list.Add(new TomlSetting(section, key, val, i));
            }
            return list;
        }

        private static string StripTomlComment(string v)
        {
            bool inStr = false;
            for (int i = 0; i < v.Length; i++)
            {
                if (v[i] == '"' && (i == 0 || v[i - 1] != '\\')) inStr = !inStr;
                else if (v[i] == '#' && !inStr) return v[..i];
            }
            return v;
        }

        /// <summary>Rewrites the values of the given settings (by line) while keeping comments, order and untouched lines.</summary>
        public static string ApplyToml(string text, IEnumerable<TomlSetting> changed)
        {
            bool crlf = text.Contains("\r\n");
            var lines = text.Replace("\r\n", "\n").Split('\n');
            foreach (var c in changed)
            {
                if (c.Line < 0 || c.Line >= lines.Length) continue;
                string line = lines[c.Line];
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string rest = line[(eq + 1)..];
                string oldVal = StripTomlComment(rest);
                string comment = rest[oldVal.Length..];
                string tail = comment.Length > 0 ? " " + comment.TrimStart() : "";
                lines[c.Line] = line[..(eq + 1)] + " " + c.Value.Trim() + tail;
            }
            return string.Join(crlf ? "\r\n" : "\n", lines);
        }

        /// <summary>
        /// Path of the toml the user edits: Xenia's per-title config. When it doesn't exist yet it is
        /// created from the cached optimized settings so there is always something to tweak.
        /// </summary>
        public static string EnsureXeniaConfigForEditing(string xeniaExePath, string titleId, string? cachedToml)
        {
            string cfg = XeniaConfigPath(xeniaExePath, titleId);
            if (!File.Exists(cfg) && cachedToml != null && File.Exists(cachedToml))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(cfg)!);
                File.Copy(cachedToml, cfg);
                File.WriteAllText(cfg + ManagedMarker, "");
            }
            return cfg;
        }

        /// <summary>Removes the optimized config, restoring the user's previous one if it was backed up.</summary>
        public static void DisableXeniaSettings(string xeniaExePath, string titleId)
        {
            string cfg = XeniaConfigPath(xeniaExePath, titleId);
            string bak = cfg + ".gameos-bak";
            if (File.Exists(cfg)) File.Delete(cfg);
            if (File.Exists(cfg + ManagedMarker)) File.Delete(cfg + ManagedMarker);
            if (File.Exists(bak)) File.Move(bak, cfg);
        }

        // ── Xenia patches ($EmuDir/Patches/{TitleID} - {GameName}.patch.toml) ──

        /// <summary>Patch files in Xenia's <c>patches</c> folder whose name starts with one of the title IDs.</summary>
        public static List<string> FindXeniaPatches(string xeniaExePath, IEnumerable<string> titleIds)
        {
            var result = new List<string>();
            string? emuDir = Path.GetDirectoryName(xeniaExePath);
            if (string.IsNullOrEmpty(emuDir) || !Directory.Exists(emuDir)) return result;
            var ids = titleIds.Where(IsXeniaTitleId).Select(i => i.ToUpperInvariant()).ToList();
            if (ids.Count == 0) return result;
            try
            {
                foreach (string dir in Directory.EnumerateDirectories(emuDir)
                             .Where(d => Path.GetFileName(d).Equals("patches", StringComparison.OrdinalIgnoreCase)))
                    foreach (string f in Directory.EnumerateFiles(dir))
                    {
                        string name = Path.GetFileName(f);
                        string ext = Path.GetExtension(name);
                        if (!ext.Equals(".toml", StringComparison.OrdinalIgnoreCase) && !ext.Equals(".patch", StringComparison.OrdinalIgnoreCase)) continue;
                        if (ids.Any(id => name.StartsWith(id, StringComparison.OrdinalIgnoreCase))) result.Add(f);
                    }
            }
            catch { /* best-effort */ }
            return result.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>Title ID and display name from <c>{TitleID} - {GameName}.patch[.toml]</c>.</summary>
        public static (string TitleId, string Name) ParsePatchFileName(string path)
        {
            string name = Path.GetFileName(path);
            foreach (var suffix in new[] { ".toml", ".patch" })
                if (name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) name = name[..^suffix.Length];
            int dash = name.IndexOf(" - ", StringComparison.Ordinal);
            return dash > 0 ? (name[..dash].Trim().ToUpperInvariant(), name[(dash + 3)..].Trim()) : (name.Length >= 8 ? name[..8].ToUpperInvariant() : name, name);
        }

        /// <summary>A patch file counts as enabled when any of its <c>is_enabled</c> entries is true.</summary>
        public static bool IsXeniaPatchEnabled(string patchPath)
        {
            try { return ParseToml(File.ReadAllText(patchPath)).Any(s => s.Key == "is_enabled" && s.Value == "true"); }
            catch { return false; }
        }

        /// <summary>Sets every <c>is_enabled</c> entry of the patch file, keeping comments and layout.</summary>
        public static void SetXeniaPatchEnabled(string patchPath, bool enabled)
        {
            string text = File.ReadAllText(patchPath);
            var changed = ParseToml(text).Where(s => s.Key == "is_enabled")
                .Select(s => s with { Value = enabled ? "true" : "false" });
            File.WriteAllText(patchPath, ApplyToml(text, changed));
        }

        // ── PS2 HD texture packs ──────────────────────────────────────────────

        /// <summary>A texture pack; <see cref="SourcePath"/> is a folder or an archive (.zip/.rar/.7z…).</summary>
        public sealed record TexturePack(string GameName, string TitleId, string SourcePath)
        {
            public bool IsArchive => File.Exists(SourcePath);
        }

        private static string EntryId(string path) =>
            Directory.Exists(path) ? Path.GetFileName(path) : Path.GetFileNameWithoutExtension(path);

        private static bool IsPackEntry(string path) => Directory.Exists(path) || ArchiveExtractor.IsArchive(path);

        /// <summary>
        /// Packs under <c>{platformDir}/Mods/HD Texture packs</c> that belong to the game. Accepted layouts
        /// (each entry may be a folder or a zip/rar/7z archive):
        /// <c>{GameName}/{TitleID}</c>, <c>{GameName}</c> (archive/folder holding the pack; TitleID taken from the game's known IDs),
        /// and <c>{TitleID}</c> directly. A pack matches by game name or by a known TitleID.
        /// </summary>
        public static List<TexturePack> FindTexturePacks(string? platformDir, string gameName, IEnumerable<string> knownTitleIds)
        {
            var result = new List<TexturePack>();
            if (string.IsNullOrWhiteSpace(platformDir)) return result;
            string root = Path.Combine(platformDir, "Mods", HdTexturePacksFolder);
            if (!Directory.Exists(root)) return result;

            var idList = knownTitleIds.Where(s => NormalizeId(s).Length > 0).ToList();
            var ids = new HashSet<string>(idList.Select(NormalizeId));
            string nameKey = NormalizeId(gameName);
            string? firstId = idList.FirstOrDefault();
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(root).Where(IsPackEntry))
                {
                    string name = EntryId(entry);
                    bool nameMatch = nameKey.Length > 0 && NormalizeId(name) == nameKey;

                    if (ids.Contains(NormalizeId(name)))
                    {
                        result.Add(new TexturePack(name, name, entry));
                        continue;
                    }
                    // {GameName} is a folder of {TitleID}[.zip] entries, or the pack itself.
                    var inner = Directory.Exists(entry)
                        ? Directory.EnumerateFileSystemEntries(entry).Where(IsPackEntry).ToList()
                        : new List<string>();
                    var idEntries = inner.Where(i =>
                        ids.Contains(NormalizeId(EntryId(i))) ||
                        (nameMatch && LooksLikeTitleId(EntryId(i)))).ToList();
                    if (idEntries.Count > 0)
                        foreach (var i in idEntries) result.Add(new TexturePack(name, EntryId(i), i));
                    else if (nameMatch && firstId != null)
                        result.Add(new TexturePack(name, firstId.Trim().ToUpperInvariant(), entry));
                }
            }
            catch { /* best-effort */ }
            return result;
        }

        /// <summary>PS2 serials look like SLUS-21000 / SLES_550.12 / SCUS97328.</summary>
        private static bool LooksLikeTitleId(string s) =>
            System.Text.RegularExpressions.Regex.IsMatch(s, @"^[A-Za-z]{4}[-_.]?\d{3,5}(\.\d+)?$");

        /// <summary>PCSX2 <c>textures</c> folder: portable (next to the exe) when <c>portable.ini</c> exists, else the user data dir.</summary>
        public static string Pcsx2TexturesDir(string pcsx2ExePath)
        {
            string dir = Path.GetDirectoryName(pcsx2ExePath) ?? "";
            if (File.Exists(Path.Combine(dir, "portable.ini")) || Directory.Exists(Path.Combine(dir, "textures")))
                return Path.Combine(dir, "textures");

            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            string winPath = Path.Combine(docs, "PCSX2", "textures");
            if (OperatingSystem.IsWindows() || Directory.Exists(Path.GetDirectoryName(winPath)!)) return winPath;
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return OperatingSystem.IsMacOS()
                ? Path.Combine(home, "Library", "Application Support", "PCSX2", "textures")
                : Path.Combine(home, ".config", "PCSX2", "textures");
        }

        public static string Pcsx2TargetDir(string pcsx2ExePath, TexturePack pack) =>
            Path.Combine(Pcsx2TexturesDir(pcsx2ExePath), pack.TitleId.ToUpperInvariant());

        public static bool IsTexturePackEnabled(string pcsx2ExePath, TexturePack pack) =>
            File.Exists(Path.Combine(Pcsx2TargetDir(pcsx2ExePath, pack), ManagedMarker));

        /// <summary>Copies (folder) or extracts (zip/rar/7z) the pack into PCSX2's textures folder so it is auto-detected by serial.</summary>
        public static void EnableTexturePack(string pcsx2ExePath, TexturePack pack)
        {
            string target = Pcsx2TargetDir(pcsx2ExePath, pack);
            if (Directory.Exists(target) && !File.Exists(Path.Combine(target, ManagedMarker)))
                throw new IOException($"A texture folder for {pack.TitleId} already exists in PCSX2 and was not installed by Game OS.");
            if (Directory.Exists(target)) Directory.Delete(target, true);

            if (pack.IsArchive)
            {
                string tmp = Path.Combine(Path.GetTempPath(), "gameos-tex-" + Guid.NewGuid().ToString("N"));
                try
                {
                    ArchiveExtractor.Extract(pack.SourcePath, tmp);
                    // Archives often wrap everything in one top-level folder (often named after the TitleID); unwrap it.
                    string content = tmp;
                    while (!Directory.EnumerateFiles(content).Any() && Directory.GetDirectories(content) is { Length: 1 } one
                           && !one[0].EndsWith("replacements", StringComparison.OrdinalIgnoreCase))
                        content = one[0];
                    CopyDirectory(content, target);
                }
                finally { try { Directory.Delete(tmp, true); } catch { } }
            }
            else CopyDirectory(pack.SourcePath, target);
            File.WriteAllText(Path.Combine(target, ManagedMarker), pack.SourcePath);
        }

        /// <summary>Removes the copy made by <see cref="EnableTexturePack"/>; never touches folders it didn't create.</summary>
        public static void DisableTexturePack(string pcsx2ExePath, TexturePack pack)
        {
            string target = Pcsx2TargetDir(pcsx2ExePath, pack);
            if (File.Exists(Path.Combine(target, ManagedMarker))) Directory.Delete(target, true);
        }

        private static void CopyDirectory(string src, string dst)
        {
            Directory.CreateDirectory(dst);
            foreach (var f in Directory.EnumerateFiles(src))
                File.Copy(f, Path.Combine(dst, Path.GetFileName(f)), overwrite: true);
            foreach (var d in Directory.EnumerateDirectories(src))
                CopyDirectory(d, Path.Combine(dst, Path.GetFileName(d)));
        }

        // ── Platform Mods / DLC / Updates ─────────────────────────────────────

        /// <summary>
        /// Entries in <c>{platformDir}/{Mods|DLC|Updates}</c> that belong to the game (name contains the title or a TitleID,
        /// or sits in a folder named after them). The HD texture pack folder is handled separately.
        /// </summary>
        public static List<InstalledMod> ScanPlatformContent(string? platformDir, string gameName, IEnumerable<string> knownTitleIds, bool includeMods = true, bool includeDlc = true)
        {
            var result = new List<InstalledMod>();
            if (string.IsNullOrWhiteSpace(platformDir) || !Directory.Exists(platformDir)) return result;
            string nameKey = NormalizeId(gameName);
            var ids = knownTitleIds.Select(NormalizeId).Where(s => s.Length > 0).ToList();
            bool Matches(string s)
            {
                string k = NormalizeId(s);
                return (nameKey.Length > 0 && k.Contains(nameKey)) || ids.Any(k.Contains);
            }

            foreach (var (folder, type) in ContentFolders)
            {
                if ((type == "Mod" && !includeMods) || (type == "DLC" && !includeDlc)) continue;
                string dir = Path.Combine(platformDir, folder);
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var entry in Directory.EnumerateFileSystemEntries(dir))
                    {
                        string name = Path.GetFileName(entry);
                        if (name.Equals(HdTexturePacksFolder, StringComparison.OrdinalIgnoreCase)) continue;
                        if (Matches(name))
                            result.Add(new InstalledMod { Name = name, Path = entry, TypeName = type, Source = folder + " folder", IsDirectory = Directory.Exists(entry),
                                CanToggle = type == "Mod" && GameModsService.CanToggleEntry(entry) });
                    }
                }
                catch { /* best-effort */ }
            }
            return result;
        }

        private static readonly string[] IconExts = { ".png", ".jpg", ".jpeg", ".webp" };

        /// <summary>
        /// Player/track icon for a Switch mod: <c>{Subject}/{Subject}.png</c>, <c>{Category}/{Subject}.png</c>,
        /// a png named like the mod, an icon.png, inside a folder mod, or the only image in the subject folder.
        /// </summary>
        private static string? FindModIcon(string entry, bool isDirectory, string folder)
        {
            string subject = Path.GetFileName(folder);
            string entryName = isDirectory ? Path.GetFileName(entry) : Path.GetFileNameWithoutExtension(entry);
            var names = new List<(string Dir, string Name)>
            {
                (folder, subject), (folder, entryName), (folder, "icon"),
            };
            if (Path.GetDirectoryName(folder) is { Length: > 0 } category) names.Add((category, subject));
            if (isDirectory) { names.Add((entry, entryName)); names.Add((entry, "icon")); }
            foreach (var (dir, name) in names)
                foreach (var ext in IconExts)
                {
                    string p = Path.Combine(dir, name + ext);
                    if (File.Exists(p)) return p;
                }
            try
            {
                var imgs = Directory.EnumerateFiles(folder).Where(f => IconExts.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase)).Take(2).ToList();
                if (imgs.Count == 1) return imgs[0];
            }
            catch { }
            return null;
        }

        private static readonly string[] SwitchDlcExts = { ".nsp", ".xci" };
        private static readonly string[] RyujinxContentDirs = { "romfs", "exefs", "cheats" };

        /// <summary>
        /// Finds individual Switch mods (<paramref name="typeName"/> "Mod": archives or extracted folders under
        /// <c>Mods/{Game}/{Category}/{Subject}/</c>) or DLC ("DLC": .nsp/.xci under <c>DLC/{Game}/…</c>).
        /// An image named after the subject folder (e.g. Toad.png) is attached as the icon.
        /// </summary>
        public static List<InstalledMod> ScanSwitchContent(string? contentDir, string gameName, string typeName = "Mod")
        {
            var result = new List<InstalledMod>();
            if (string.IsNullOrWhiteSpace(contentDir) || !Directory.Exists(contentDir)) return result;
            string gameKey = NormalizeId(gameName);
            if (gameKey.Length == 0) return result;
            bool dlc = typeName == "DLC";

            try
            {
                foreach (string gameDir in Directory.EnumerateDirectories(contentDir))
                {
                    if (NormalizeId(Path.GetFileName(gameDir)) != gameKey) continue;
                    Walk(gameDir, "", 0);
                }
            }
            catch { /* best-effort */ }
            return result.OrderBy(m => m.Source, StringComparer.OrdinalIgnoreCase)
                         .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList();

            void Walk(string folder, string source, int depth)
            {
                try
                {
                    string subject = Path.GetFileName(folder);
                    foreach (string entry in Directory.EnumerateFileSystemEntries(folder))
                    {
                        bool isDirectory = Directory.Exists(entry);
                        string name = Path.GetFileName(entry);
                        if (isDirectory)
                        {
                            bool isMod = !dlc && depth >= 2 && !RyujinxContentDirs.Contains(name, StringComparer.OrdinalIgnoreCase)
                                         && Directory.EnumerateFileSystemEntries(entry).Any();
                            if (isMod) Add(entry, true, folder, source);
                            else if (depth < 2) Walk(entry, source.Length == 0 ? name : source + " › " + name, depth + 1);
                            continue;
                        }
                        bool ok = dlc ? SwitchDlcExts.Contains(Path.GetExtension(name), StringComparer.OrdinalIgnoreCase)
                                      : GameModsService.CanToggleEntry(entry);
                        if (ok) Add(entry, false, folder, source);
                    }
                }
                catch { /* best-effort */ }
            }

            void Add(string entry, bool isDirectory, string folder, string source)
            {
                string? icon = FindModIcon(entry, isDirectory, folder);
                result.Add(new InstalledMod
                {
                    Name = Path.GetFileName(entry),
                    Path = entry,
                    TypeName = typeName,
                    Source = source.Length == 0 ? typeName : source,
                    IsDirectory = isDirectory,
                    CanToggle = true,
                    RyujinxKind = typeName,
                    IconPath = icon,
                });
            }
        }
    }
}
