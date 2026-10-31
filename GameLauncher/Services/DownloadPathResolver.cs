using System;
using System.IO;
using System.Linq;

namespace GameLauncher.Services
{
    /// <summary>
    /// Works out where a finished download belongs:
    /// <c>&lt;Root&gt;/Roms/&lt;Platform&gt;/Games|Mods|Other</c>, and for PC games <c>&lt;Root&gt;/Repacks</c>.
    /// </summary>
    public static class DownloadPathResolver
    {
        public const string CategoryGame  = "Game";
        public const string CategoryMod   = "Mod";
        public const string CategoryOther = "Other";

        public static readonly string[] Categories = { CategoryGame, CategoryMod, CategoryOther };

        /// <summary>Platform name → libretro-style folder used under Roms/ (matches the scanner's layout).</summary>
        public static readonly (string Name, string Folder)[] Platforms =
        {
            ("PC", "PC"),
            ("Switch", "Nintendo - Switch"),
            ("Wii U", "Nintendo - Wii U"),
            ("Wii", "Nintendo - Wii"),
            ("GameCube", "Nintendo - GameCube"),
            ("N64", "Nintendo - Nintendo 64"),
            ("SNES", "Nintendo - Super Nintendo Entertainment System"),
            ("NES", "Nintendo - Nintendo Entertainment System"),
            ("3DS", "Nintendo - Nintendo 3DS"),
            ("DS", "Nintendo - Nintendo DS"),
            ("GBA", "Nintendo - Game Boy Advance"),
            ("PS1", "Sony - PlayStation"),
            ("PS2", "Sony - PlayStation 2"),
            ("PS3", "Sony - PlayStation 3"),
            ("PS4", "Sony - PlayStation 4"),
            ("PS5", "Sony - PlayStation 5"),
            ("PSP", "Sony - PSP"),
            ("PS Vita", "Sony - PS Vita"),
            ("Xbox", "Microsoft - Xbox"),
            ("Xbox 360", "Microsoft - Xbox 360"),
            ("Xbox One", "Microsoft - Xbox One"),
            ("Dreamcast", "Sega - Dreamcast"),
            ("Mega Drive", "Sega - Mega Drive - Genesis"),
        };

        public static string[] PlatformNames => Platforms.Select(p => p.Name).ToArray();

        public static bool IsPc(string platform) =>
            string.Equals(platform?.Trim(), "PC", StringComparison.OrdinalIgnoreCase);

        /// <summary>Folder name under Roms/ for <paramref name="platform"/>; reuses an existing folder with either naming.</summary>
        public static string PlatformFolder(string root, string platform)
        {
            string name = (platform ?? "").Trim();
            string mapped = Platforms.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)).Folder ?? name;
            string roms = Path.Combine(root, "Roms");
            try
            {
                if (Directory.Exists(roms))
                {
                    string? existing = Directory.EnumerateDirectories(roms).Select(Path.GetFileName)
                        .FirstOrDefault(d => string.Equals(d, mapped, StringComparison.OrdinalIgnoreCase)
                                          || string.Equals(d, name, StringComparison.OrdinalIgnoreCase));
                    if (existing != null) return existing;
                }
            }
            catch { /* fall through to the default */ }
            return mapped;
        }

        /// <summary>Destination folder for a download (not created).</summary>
        public static string Resolve(string root, string platform, string category)
        {
            if (IsPc(platform))
            {
                return category switch
                {
                    CategoryGame => Path.Combine(root, "Repacks"),
                    CategoryMod  => Path.Combine(root, "Mods"),
                    _            => Path.Combine(root, "Other"),
                };
            }

            string sub = category switch
            {
                CategoryGame => "Games",
                CategoryMod  => "Mods",
                _            => "Other",
            };
            return Path.Combine(root, "Roms", PlatformFolder(root, platform), sub);
        }

        /// <summary>The configured root, or the first drive that already has Roms/Repacks, else ~/GameOS.</summary>
        public static string ResolveRoot(string? configured)
        {
            if (!string.IsNullOrWhiteSpace(configured)) return configured.Trim();
            try
            {
                foreach (var d in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType != DriveType.CDRom))
                {
                    string r = d.RootDirectory.FullName;
                    if (Directory.Exists(Path.Combine(r, "Roms")) || Directory.Exists(Path.Combine(r, "Repacks")))
                        return r;
                }
            }
            catch { /* ignore */ }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "GameOS");
        }

        public static string SanitizeFileName(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
            name = name.Trim().TrimEnd('.');
            return string.IsNullOrEmpty(name) ? "download" : name;
        }
    }
}
