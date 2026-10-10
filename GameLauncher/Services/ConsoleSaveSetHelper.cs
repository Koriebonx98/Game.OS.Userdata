using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace GameLauncher.Services
{
    /// <summary>
    /// Handles emulator save layouts that span several folders/files per game:
    /// PS3 (RPCS3) "TITLEID*" folders, Wii (Dolphin) "title/&lt;high&gt;/&lt;low&gt;/data" and
    /// GameCube (Dolphin) "GC/&lt;region&gt;/Card X/*.gci".
    /// </summary>
    internal static class ConsoleSaveSetHelper
    {
        internal enum Kind { None, Ps3, Wii, GameCube }

        internal static Kind GetKind(string? platform)
        {
            string p = (platform ?? "").Replace(" ", "").Replace("-", "").Trim().ToLowerInvariant();
            return p switch
            {
                "ps3" or "playstation3" or "sonyplaystation3" => Kind.Ps3,
                "wii" or "nintendowii" => Kind.Wii,
                "gamecube" or "gc" or "nintendogamecube" => Kind.GameCube,
                _ => Kind.None,
            };
        }

        /// <summary>Splits a 16-hex-digit Wii title ID into (high, low) words.</summary>
        internal static bool TrySplitWiiTitleId(string? titleId, out string high, out string low)
        {
            high = low = "";
            string t = (titleId ?? "").Trim();
            if (t.Length != 16 || !t.All(Uri.IsHexDigit)) return false;
            high = t[..8].ToLowerInvariant();
            low  = t[8..].ToLowerInvariant();
            return true;
        }

        /// <summary>
        /// Returns (source, destination relative to the game's backup folder) pairs.
        /// <paramref name="resolvedPath"/> is the path from EmulatorSavePathResolver.
        /// </summary>
        internal static List<(string Source, string RelDest, bool IsFile)> FindBackupItems(
            Kind kind, string? titleId, string resolvedPath)
        {
            var items = new List<(string, string, bool)>();
            string id = (titleId ?? "").Trim();
            if (string.IsNullOrWhiteSpace(resolvedPath) || string.IsNullOrWhiteSpace(id)) return items;
            try
            {
                switch (kind)
                {
                    case Kind.Ps3:
                        string? savedata = Path.GetDirectoryName(resolvedPath.TrimEnd('/', '\\'));
                        if (savedata == null || !Directory.Exists(savedata)) break;
                        foreach (string dir in Directory.EnumerateDirectories(savedata))
                        {
                            string name = Path.GetFileName(dir);
                            if (name.StartsWith(id, StringComparison.OrdinalIgnoreCase))
                                items.Add((dir, name, false));
                        }
                        break;

                    case Kind.Wii:
                        if (TrySplitWiiTitleId(id, out string hi, out string lo) && Directory.Exists(resolvedPath))
                            items.Add((resolvedPath, Path.Combine(hi, lo), false));
                        break;

                    case Kind.GameCube:
                        string? gcRoot = Path.GetDirectoryName(resolvedPath.TrimEnd('/', '\\'));
                        if (gcRoot == null || !Directory.Exists(gcRoot)) break;
                        // Dolphin game ID "GP7P01" => 4-char game code "GP7P" + 2-char maker "01";
                        // .gci files are named "<maker>-<gameCode>-<name>.gci".
                        string code  = id.Length >= 4 ? id[..4] : id;
                        string maker = id.Length >= 6 ? id.Substring(4, 2) : "";
                        foreach (string file in Directory.EnumerateFiles(gcRoot, "*.gci", SearchOption.AllDirectories))
                        {
                            string fn = Path.GetFileName(file);
                            bool match = fn.Contains("-" + code + "-", StringComparison.OrdinalIgnoreCase)
                                && (maker.Length == 0 || fn.StartsWith(maker + "-", StringComparison.OrdinalIgnoreCase));
                            if (match)
                                items.Add((file, Path.GetRelativePath(gcRoot, file), true));
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                DevLogService.Log($"[ConsoleSaveSetHelper] enumerate failed: {ex.Message}");
            }
            return items;
        }

        /// <summary>Copies the backup items into <paramref name="gameBackupDir"/>.</summary>
        internal static int Backup(Kind kind, string? titleId, string resolvedPath, string gameBackupDir)
        {
            var items = FindBackupItems(kind, titleId, resolvedPath);
            foreach (var (src, rel, isFile) in items)
            {
                string dest = Path.Combine(gameBackupDir, rel);
                if (isFile)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                    File.Copy(src, dest, overwrite: true);
                }
                else CopyDir(src, dest);
            }
            return items.Count;
        }

        /// <summary>Restores a backup made by <see cref="Backup"/>. Returns false when nothing was restored.</summary>
        internal static bool Restore(Kind kind, string? titleId, string backupDir, string resolvedPath)
        {
            string id = (titleId ?? "").Trim();
            if (!Directory.Exists(backupDir)) return false;
            bool any = false;
            switch (kind)
            {
                case Kind.Ps3:
                    string? savedata = Path.GetDirectoryName(resolvedPath.TrimEnd('/', '\\'));
                    if (savedata == null) return false;
                    foreach (string dir in Directory.EnumerateDirectories(backupDir))
                    {
                        string name = Path.GetFileName(dir);
                        if (id.Length > 0 && name.StartsWith(id, StringComparison.OrdinalIgnoreCase))
                        { CopyDir(dir, Path.Combine(savedata, name)); any = true; }
                    }
                    break;
                case Kind.Wii:
                    if (TrySplitWiiTitleId(id, out string hi, out string lo))
                    {
                        string src = Path.Combine(backupDir, hi, lo);
                        if (Directory.Exists(src)) { CopyDir(src, resolvedPath); any = true; }
                    }
                    break;
                case Kind.GameCube:
                    string? gcRoot = Path.GetDirectoryName(resolvedPath.TrimEnd('/', '\\'));
                    if (gcRoot == null) return false;
                    foreach (string file in Directory.EnumerateFiles(backupDir, "*.gci", SearchOption.AllDirectories))
                    {
                        string dest = Path.Combine(gcRoot, Path.GetRelativePath(backupDir, file));
                        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                        File.Copy(file, dest, overwrite: true);
                        any = true;
                    }
                    break;
            }
            return any;
        }

        private static void CopyDir(string source, string dest)
        {
            Directory.CreateDirectory(dest);
            foreach (string f in Directory.GetFiles(source))
                File.Copy(f, Path.Combine(dest, Path.GetFileName(f)), overwrite: true);
            foreach (string d in Directory.GetDirectories(source))
                CopyDir(d, Path.Combine(dest, Path.GetFileName(d)));
        }
    }
}
