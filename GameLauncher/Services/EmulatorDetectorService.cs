using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using GameLauncher.Models;

namespace GameLauncher.Services;

/// <summary>An emulator found in the user's emulators folder, with the settings Game OS would apply for it.</summary>
public sealed record DetectedEmulator(string Platform, string Name, string ExePath, string Arguments, string SaveDataPath);

/// <summary>
/// Scans a folder that holds the user's emulators, matches known executables to platforms and
/// pre-fills the emulator settings (path, launch arguments, save-data folder).
/// </summary>
public static class EmulatorDetectorService
{
    // Exe-name prefix (lowercase, no extension) → emulator profile.
    private sealed record Profile(string Prefix, string Name, string[] Platforms, string Args, Func<string, string> SavePath);

    private static string Appdata(params string[] parts) =>
        Path.Combine(new[] { Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) }.Concat(parts).ToArray());

    private static string Documents(params string[] parts) =>
        Path.Combine(new[] { Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) }.Concat(parts).ToArray());

    /// <summary>Uses the emulator's portable data folder when it exists next to the exe, otherwise the installed location.</summary>
    private static string Portable(string dir, string portableRel, string fallback) =>
        Directory.Exists(Path.Combine(dir, portableRel)) ? Path.Combine(dir, portableRel) : fallback;

    // Eden-based emulators keep saves in a portable "user" folder next to the exe, or under %APPDATA%\<exe-folder>.
    private static string Eden2Save(string dir) =>
        Portable(dir, Path.Combine("user", "nand", "user", "save"), Path.Combine(dir, "user", "nand", "user", "save"));

    // Names are compared without '-', '_' or spaces, so "Eden-NX2", "eden_nx2" and "EdenNX2" all match.
    private static string Key(string s) => new string(s.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();

    private static readonly Profile[] Profiles =
    {
        new("ryujinx", "Ryujinx", new[] { "Switch" }, "{rom}",
            d => Portable(d, Path.Combine("portable", "bis", "user", "save"), Appdata("Ryujinx", "bis", "user", "save"))),
        new("pcsx2", "PCSX2", new[] { "PS2" }, "-batch -fullscreen -- {rom}",
            d => Portable(d, "memcards", Documents("PCSX2", "memcards"))),
        new("rpcs3", "RPCS3", new[] { "PS3" }, "--no-gui {rom}",
            d => Path.Combine(d, "dev_hdd0", "home")),
        new("duckstation", "DuckStation", new[] { "PS1" }, "-batch -fullscreen -- {rom}",
            d => Portable(d, "memcards", Documents("DuckStation", "memcards"))),
        new("ppsspp", "PPSSPP", new[] { "PSP" }, "{rom}",
            d => Portable(d, Path.Combine("memstick", "PSP", "SAVEDATA"), Documents("PPSSPP", "PSP", "SAVEDATA"))),
        new("vita3k", "Vita3K", new[] { "PS Vita" }, "{rom}",
            d => Appdata("Vita3K", "Vita3K", "ux0", "user")),
        new("xeniacanary", "Xenia Canary", new[] { "Xbox 360" }, "{rom}",
            d => Path.Combine(d, "content")),
        new("xenia", "Xenia", new[] { "Xbox 360" }, "{rom}",
            d => Path.Combine(d, "content")),
        new("dolphin", "Dolphin", new[] { "GameCube", "Wii" }, "-b -e {rom}",
            d => Portable(d, "User", Documents("Dolphin Emulator"))),
        new("citra", "Citra", new[] { "Nintendo - 3DS" }, "{rom}",
            d => Portable(d, "user", Appdata("Citra"))),
        new("lime3ds", "Lime3DS", new[] { "Nintendo - 3DS" }, "{rom}",
            d => Portable(d, "user", Appdata("Lime3DS"))),
        new("azahar", "Azahar", new[] { "Nintendo - 3DS" }, "{rom}",
            d => Portable(d, "user", Appdata("Azahar"))),
        new("mgba", "mGBA", new[] { "Nintendo - GameBoy" }, "{rom}",
            d => Path.Combine(d, "saves")),
        new("visualboyadvance", "VisualBoyAdvance-M", new[] { "Nintendo - GameBoy" }, "{rom}",
            d => d),
        new("yuzu", "Yuzu", new[] { "Switch" }, "-f -g {rom}",
            d => Portable(d, Path.Combine("user", "nand", "user", "save"), Appdata("yuzu", "nand", "user", "save"))),
        new("sudachi", "Sudachi", new[] { "Switch" }, "-f -g {rom}",
            d => Appdata("sudachi", "nand", "user", "save")),
        new("edennx2", "Eden NX2", new[] { "Nintendo - Switch 2" }, "-f -g {rom}", d => Eden2Save(d)),
        new("edenns2", "Eden-NS2", new[] { "Nintendo - Switch 2" }, "-f -g {rom}", d => Eden2Save(d)),
        new("eglantine", "Eglantine", new[] { "Nintendo - Switch 2" }, "-f -g {rom}", d => Eden2Save(d)),
        new("lichii", "Lichii", new[] { "Nintendo - Switch 2" }, "-f -g {rom}", d => Eden2Save(d)),
        new("pokedinner", "PokeDinner", new[] { "Nintendo - Switch 2" }, "-f -g {rom}", d => Eden2Save(d)),
        new("orchid", "Orchid", new[] { "Nintendo - Switch 2" }, "-f -g {rom}", d => Eden2Save(d)),
        new("droplet", "Droplet", new[] { "Nintendo - Switch 2" }, "-f -g {rom}", d => Eden2Save(d)),
        new("chungus", "Chungus Emulation", new[] { "Nintendo - Switch 2" }, "-f -g {rom}", d => Eden2Save(d)),
        new("nexo", "NeXo 2", new[] { "Nintendo - Switch 2" }, "-f -g {rom}", d => Eden2Save(d)),
        new("switch2", "Switch 2 emulator", new[] { "Nintendo - Switch 2" }, "{rom}", d => Eden2Save(d)),
        new("eden", "Eden", new[] { "Switch" }, "-f -g {rom}",
            d => Appdata("eden", "nand", "user", "save")),
    };

    // Exes that share a prefix with an emulator but are helpers, not the emulator itself.
    private static readonly string[] IgnoredFragments =
        { "unins", "setup", "updater", "crash", "helper", "cli", "nogui", "headless", "installer" };

    /// <summary>Finds known emulators under <paramref name="root"/> (up to <paramref name="maxDepth"/> levels deep).</summary>
    public static List<DetectedEmulator> Detect(string root, int maxDepth = 3)
    {
        var found = new List<DetectedEmulator>();
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root)) return found;

        foreach (var exe in EnumerateExes(root, maxDepth))
        {
            string file = Key(Path.GetFileNameWithoutExtension(exe));
            if (IgnoredFragments.Any(file.Contains)) continue;
            // Longest prefix first so "xeniacanary" wins over "xenia".
            var profile = Profiles.Where(p => file.StartsWith(Key(p.Prefix))).OrderByDescending(p => p.Prefix.Length).FirstOrDefault();
            if (profile == null) continue;
            string dir = Path.GetDirectoryName(exe) ?? "";
            foreach (var platform in profile.Platforms)
            {
                if (found.Any(f => f.Platform == platform && f.Name == profile.Name)) continue;
                found.Add(new DetectedEmulator(platform, profile.Name, exe, profile.Args, profile.SavePath(dir)));
            }
        }
        return found;
    }

    /// <summary>Saves the detected emulators, keeping any emulators already configured for the same platform.</summary>
    public static int Apply(IEnumerable<DetectedEmulator> detected)
    {
        int applied = 0;
        foreach (var group in detected.GroupBy(d => d.Platform))
        {
            var existing = EmulatorSettingsService.LoadAll(group.Key);
            bool hasEnabled = existing.Any(e => e.Enabled && !string.IsNullOrEmpty(e.EmulatorPath));
            foreach (var d in group)
            {
                if (existing.Any(e => string.Equals(e.EmulatorPath, d.ExePath, StringComparison.OrdinalIgnoreCase))) continue;
                EmulatorSettingsService.Save(new EmulatorSettings
                {
                    Platform = d.Platform, EmulatorName = d.Name, EmulatorPath = d.ExePath,
                    Arguments = d.Arguments, SaveDataPath = d.SaveDataPath,
                    // Never take over from an emulator the user already set up.
                    Enabled = !hasEnabled,
                });
                hasEnabled = true;
                applied++;
            }
        }
        return applied;
    }

    private static IEnumerable<string> EnumerateExes(string root, int maxDepth)
    {
        var queue = new Queue<(string Dir, int Depth)>();
        queue.Enqueue((root, 0));
        int visited = 0;
        while (queue.Count > 0 && visited++ < 2000)
        {
            var (dir, depth) = queue.Dequeue();
            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*.exe"); } catch { /* inaccessible */ }
            foreach (var f in files) yield return f;
            if (depth >= maxDepth) continue;
            string[] subs = Array.Empty<string>();
            try { subs = Directory.GetDirectories(dir); } catch { /* inaccessible */ }
            foreach (var s in subs) queue.Enqueue((s, depth + 1));
        }
    }
}
