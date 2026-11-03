using System.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using GameLauncher.Models;

namespace GameLauncher.Services;

/// <summary>
/// Reads and writes Ryujinx mod configuration files (<c>mods.json</c>) for a
/// given Nintendo Switch TitleID.
///
/// <para>Ryujinx stores per-game mod lists at:</para>
/// <list type="bullet">
///   <item>Portable mode — <c>{ryujinxDir}\portable\games\{titleId}\mods.json</c></item>
///   <item>Standard mode — <c>%APPDATA%\Ryujinx\games\{titleId}\mods.json</c></item>
/// </list>
/// </summary>
public static class RyujinxModService
{
    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        WriteIndented        = true,
        PropertyNamingPolicy = null,  // preserve exact property names from the model
    };

    /// <summary>
    /// Searches for the <c>mods.json</c> file for the given <paramref name="titleId"/>
    /// relative to the Ryujinx executable at <paramref name="ryujinxExePath"/>.
    /// Portable mode is checked first; falls back to the standard AppData location.
    /// Returns <see langword="null"/> when neither file exists.
    /// </summary>
    public static string? FindModsJson(string ryujinxExePath, string titleId)
    {
        if (string.IsNullOrEmpty(ryujinxExePath) || string.IsNullOrEmpty(titleId))
            return null;

        string ryujinxDir = Path.GetDirectoryName(ryujinxExePath) ?? "";
        string tid        = titleId.ToLowerInvariant();

        // ── Portable mode ─────────────────────────────────────────────────────
        string portablePath = Path.Combine(ryujinxDir, "portable", "games", tid, "mods.json");
        if (File.Exists(portablePath)) return portablePath;

        // ── Standard AppData path ─────────────────────────────────────────────
        string appData       = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string standardPath  = Path.Combine(appData, "Ryujinx", "games", tid, "mods.json");
        if (File.Exists(standardPath)) return standardPath;

        return null;
    }

    /// <summary>
    /// Returns the path where a new <c>mods.json</c> would be created for the given
    /// TitleID.  Prefers portable mode when the portable directory exists; falls back
    /// to the standard AppData location.
    /// </summary>
    public static string GetDefaultModsJsonPath(string ryujinxExePath, string titleId)
    {
        string ryujinxDir  = Path.GetDirectoryName(ryujinxExePath) ?? "";
        string tid         = titleId.ToLowerInvariant();
        string portableDir = Path.Combine(ryujinxDir, "portable");

        if (Directory.Exists(portableDir))
            return Path.Combine(portableDir, "games", tid, "mods.json");

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        return Path.Combine(appData, "Ryujinx", "games", tid, "mods.json");
    }

    /// <summary>
    /// Ryujinx mod content folder for the game that owns <paramref name="modsJsonPath"/>:
    /// <c>{root}/games/{tid}/mods.json</c> → <c>{root}/mods/contents/{tid}</c>.
    /// </summary>
    public static string GetModsContentDir(string modsJsonPath)
    {
        string gameDir = Path.GetDirectoryName(modsJsonPath) ?? "";
        string tid     = Path.GetFileName(gameDir);
        string root    = Path.GetDirectoryName(Path.GetDirectoryName(gameDir)) ?? "";
        return Path.Combine(root, "mods", "contents", tid);
    }

    /// <summary>Deserialises <paramref name="modsJsonPath"/> and returns the mod list.</summary>
    public static List<RyujinxMod> LoadMods(string modsJsonPath)
    {
        try
        {
            string json = File.ReadAllText(modsJsonPath);
            var cfg = JsonSerializer.Deserialize<RyujinxModConfig>(json,
                          new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return cfg?.Mods ?? new List<RyujinxMod>();
        }
        catch { return new List<RyujinxMod>(); }
    }

    /// <summary>
    /// Serialises <paramref name="mods"/> back to <paramref name="modsJsonPath"/>,
    /// creating the parent directory if needed.
    /// </summary>
    public static void SaveMods(string modsJsonPath, List<RyujinxMod> mods)
    {
        string? dir = Path.GetDirectoryName(modsJsonPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var cfg  = new RyujinxModConfig { Mods = mods };
        string json = JsonSerializer.Serialize(cfg, _jsonOpts);
        File.WriteAllText(modsJsonPath, json);
    }

    private static string SafeName(string name)
    {
        foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        return name.Trim();
    }

    /// <summary>Folder name used inside Ryujinx's mods/contents/{tid} for a library mod (archive or folder).</summary>
    public static string ModEntryName(string sourcePath)
    {
        string n = Directory.Exists(sourcePath) ? Path.GetFileName(sourcePath) : Path.GetFileNameWithoutExtension(sourcePath);
        return SafeName(n);
    }

    public static bool IsModEnabled(string modsJsonPath, string sourcePath)
    {
        if (!File.Exists(modsJsonPath)) return false;
        string name = ModEntryName(sourcePath);
        return LoadMods(modsJsonPath).Any(m => string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase) && m.Enabled);
    }

    /// <summary>
    /// Registers a library mod with Ryujinx: extracts/copies it into mods/contents/{tid}/{name}
    /// (once) and adds or updates its mods.json entry with the requested enabled state.
    /// </summary>
    public static void SetModEnabled(string modsJsonPath, string sourcePath, bool enabled)
    {
        string name = ModEntryName(sourcePath);
        string target = Path.Combine(GetModsContentDir(modsJsonPath), name);
        var mods = File.Exists(modsJsonPath) ? LoadMods(modsJsonPath) : new List<RyujinxMod>();
        var entry = mods.FirstOrDefault(m => string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase));

        if (enabled && !Directory.Exists(target))
        {
            string tmp = target + ".tmp";
            if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
            Directory.CreateDirectory(tmp);
            if (Directory.Exists(sourcePath)) CopyDir(sourcePath, tmp);
            else ArchiveExtractor.Extract(sourcePath, tmp);
            string root = tmp;
            // Unwrap a lone wrapper folder unless it is a Ryujinx content folder.
            while (Directory.GetFiles(root).Length == 0 && Directory.GetDirectories(root).Length == 1
                   && !new[] { "romfs", "exefs", "cheats" }.Contains(Path.GetFileName(Directory.GetDirectories(root)[0]), StringComparer.OrdinalIgnoreCase))
                root = Directory.GetDirectories(root)[0];
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            Directory.Move(root, target);
            if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
        }

        if (entry == null)
        {
            if (!enabled) return;
            entry = new RyujinxMod { Name = name, Path = target };
            mods.Add(entry);
        }
        entry.Enabled = enabled;
        SaveMods(modsJsonPath, mods);
    }

    private static void CopyDir(string src, string dst)
    {
        foreach (string d in Directory.GetDirectories(src, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(dst, Path.GetRelativePath(src, d)));
        foreach (string f in Directory.GetFiles(src, "*", SearchOption.AllDirectories))
            File.Copy(f, Path.Combine(dst, Path.GetRelativePath(src, f)), true);
    }

    /// <summary>{root}/games/{tid}/mods.json → {root}/games/{tid}/dlc.json.</summary>
    public static string GetDlcJsonPath(string modsJsonPath) =>
        Path.Combine(Path.GetDirectoryName(modsJsonPath) ?? "", "dlc.json");

    /// <summary>Returns true/false when the container is registered in dlc.json (enabled if any NCA is enabled); null when not registered.</summary>
    public static bool? GetDlcEnabled(string dlcJsonPath, string containerPath)
    {
        var entry = FindDlcEntry(dlcJsonPath, containerPath, out _);
        if (entry == null) return null;
        var list = entry["dlc_nca_list"] as System.Text.Json.Nodes.JsonArray;
        return list != null && list.Any(n => n?["is_enabled"]?.GetValue<bool>() == true);
    }

    /// <summary>Sets is_enabled on every NCA of a registered container. Returns false when it is not registered with Ryujinx.</summary>
    public static bool SetDlcEnabled(string dlcJsonPath, string containerPath, bool enabled)
    {
        var entry = FindDlcEntry(dlcJsonPath, containerPath, out var root);
        if (entry == null || root == null) return false;
        if (entry["dlc_nca_list"] is System.Text.Json.Nodes.JsonArray list)
            foreach (var n in list)
                if (n is System.Text.Json.Nodes.JsonObject o) o["is_enabled"] = enabled;
        File.WriteAllText(dlcJsonPath, root.ToJsonString(_jsonOpts));
        return true;
    }

    private static System.Text.Json.Nodes.JsonNode? FindDlcEntry(string dlcJsonPath, string containerPath, out System.Text.Json.Nodes.JsonArray? root)
    {
        root = null;
        try
        {
            if (!File.Exists(dlcJsonPath)) return null;
            root = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(dlcJsonPath)) as System.Text.Json.Nodes.JsonArray;
            string want = Path.GetFullPath(containerPath);
            return root?.FirstOrDefault(n => n?["path"]?.GetValue<string>() is { } p
                && string.Equals(Path.GetFullPath(p), want, StringComparison.OrdinalIgnoreCase));
        }
        catch { return null; }
    }
}
